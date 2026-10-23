// End-to-end tests for registering a release where the user provides the
// checksums files. The register-assets endpoint routes such payloads to the
// release actor, which persists the client's exact index bytes and records
// the client's signature in the release signatures file. The mocked checksums
// are served on the loopback interface by httpmock, so the code under test
// runs with the rest-api test-utils feature.
pub mod tests {
    use anyhow::Result;
    use axum::http::StatusCode;
    use common::fs::names::{find_global_signers_for, local_signers_path_for};
    use features_lib::{
        AsfaloadPublicKeyTrait, AsfaloadSecretKeyTrait, AsfaloadSignatureTrait, HashAlgorithm,
        sha512_for_content,
    };
    use httpmock::{Method, MockServer};
    use rest_api::server::run_server;
    use rest_api_auth::{HEADER_NONCE, HEADER_PUBLIC_KEY, HEADER_SIGNATURE, HEADER_TIMESTAMP};
    use rest_api_test_helpers::{
        SignatureFileState, assert_recorded_signature, build_test_config, get_random_port,
        init_git_repo, print_logs, read_on_disk_index, url_for, wait_for_server,
    };
    use rest_api_types::models::ChecksumFilesPayload;
    use rest_api_types::rustls::setup_crypto_provider;
    use rest_api_types::{RegisterAssetsPayload, validate_common_parent};
    use serde_json::Value;

    // Builds the `ClientProvidedData` a client would send to register a
    // release whose index is the one built from the checksums files served
    // at `urls`:
    // - the index is built the same way the rest-api builds its own index
    //   from the checksums files, so the sets of published files of both
    //   match,
    // - the sha512 of the exact index string sent is signed with the given
    //   secret key, as the rest-api verifies the signature over those bytes.
    async fn client_provided_data_for_checksums_urls(
        public_key: &features_lib::AsfaloadPublicKeys,
        secret_key: &features_lib::AsfaloadSecretKeys,
        urls: &[Url],
    ) -> Result<forge_release::common::ClientProvidedData> {
        use forge_release::checksums::index_from_shasums_urls;
        use forge_release::common::{ClientIndexSources, ReleaseHandlingError};

        let index = index_from_shasums_urls(&reqwest::Client::new(), urls)
            .await
            .map_err(|e| anyhow::anyhow!("failed to build the client index: {e}"))?;
        let index_string = common::to_posix_json(&index)
            .map_err(|e| anyhow::anyhow!("failed to serialize the client index: {e}"))?;
        let hash = sha512_for_content(index_string.as_bytes())
            .map_err(|e| anyhow::anyhow!("failed to hash the client index: {e}"))?;
        let signature = secret_key
            .sign(&hash)
            .map_err(|e| anyhow::anyhow!("failed to sign the client index: {e}"))?;
        let source_release = forge_release::checksums::ChecksumsReleaseSource::new(urls.to_vec())
            .map_err(|e: ReleaseHandlingError| {
            anyhow::anyhow!("invalid checksums urls: {e}")
        })?;

        Ok(forge_release::common::ClientProvidedData {
            sources: ClientIndexSources::FileServer(source_release),
            client_pub_key: public_key.to_base64(),
            client_sent_index: common::base64_for_string(&index_string),
            client_sent_signature: signature.to_base64(),
        })
    }
    use std::fs;
    use std::path::PathBuf;
    use std::process::Command;
    use tempfile::TempDir;
    use tokio::time::Duration;
    use url::Url;

    // Hashes of the two release artifacts served by the mocked file server:
    // two builds of the same tool published as separate archives. Any
    // valid-format hash works: the digests are never verified against actual
    // artifacts.
    const LINUX_AMD64_ARTIFACT: &str = "mytool_2.1.0-linux_amd64.tar.gz";
    const WINDOWS_X86_64_ARTIFACT: &str = "mytool_2.1.0-windows_x86_64.zip";
    const SHA256_OF_LINUX_AMD64: &str =
        "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890";
    const SHA256_OF_WINDOWS_X86_64: &str =
        "9876543210fedcba9876543210fedcba9876543210fedcba9876543210fedcba";
    const SHA256SUMS: &str = "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890  mytool_2.1.0-linux_amd64.tar.gz\n9876543210fedcba9876543210fedcba9876543210fedcba9876543210fedcba  mytool_2.1.0-windows_x86_64.zip\n";

    // Hash values of the sha512 sums file entries, in the same order as the
    // two lines served.
    const SHA512_LINUX_16: &str = "bcdef1234567890a";
    const SHA512_WINDOWS_16: &str = "cdef1234567890ab";
    fn sha512_of_linux_amd64() -> String {
        SHA512_LINUX_16.repeat(8)
    }
    fn sha512_of_windows_x86_64() -> String {
        SHA512_WINDOWS_16.repeat(8)
    }
    fn sha512sums_body() -> String {
        format!(
            "{}  {}\n{}  {}\n",
            sha512_of_linux_amd64(),
            LINUX_AMD64_ARTIFACT,
            sha512_of_windows_x86_64(),
            WINDOWS_X86_64_ARTIFACT
        )
    }

    // Serves the checksums files of the release at paths sharing one parent
    // directory, and returns the urls of the served files, as a client would
    // send them.
    fn serve_checksums_files(server: &MockServer) -> Vec<Url> {
        let sha256_body = SHA256SUMS;
        let sha512_body = sha512sums_body();
        server.mock(|when, then| {
            when.method(Method::GET).path("/releases/v1.0/SHA256SUMS");
            then.status(200).body(sha256_body);
        });
        server.mock(|when, then| {
            when.method(Method::GET).path("/releases/v1.0/SHA512SUMS");
            then.status(200).body(sha512_body);
        });
        vec![
            Url::parse(&format!("{}/releases/v1.0/SHA256SUMS", server.url("")))
                .expect("the mocked sha256 sums url is valid"),
            Url::parse(&format!("{}/releases/v1.0/SHA512SUMS", server.url("")))
                .expect("the mocked sha512 sums url is valid"),
        ]
    }

    // A rest-api server, its git-backed repository, and the mocked file
    // server whose urls the registration requests carry.
    struct ChecksumsServer {
        _temp_dir: TempDir,
        git_repo_path: PathBuf,
        _mock_server: MockServer,
        checksums_urls: Vec<Url>,
        release_dir_rel: String,
        port: u16,
        keys: test_helpers::TestKeys,
        client: reqwest::Client,
        server_handle: tokio::task::JoinHandle<()>,
    }

    impl ChecksumsServer {
        // Start a server whose signers config declares exactly the keys whose
        // indices are given as the project's artifact signers, with the
        // `threshold`.
        async fn start(artifact_signers: &[usize], threshold: u32) -> Result<Self> {
            setup_crypto_provider();
            print_logs();
            let temp_dir = TempDir::new().expect("Failed to create temp directory");
            let git_repo_path = temp_dir.path().to_path_buf();
            init_git_repo(&git_repo_path).expect("Failed to initialize git repository");

            // Start the mocked file server first: the git repo directory the
            // release lands in derives from its randomly assigned port.
            let mock_server = MockServer::start();
            let checksums_urls = serve_checksums_files(&mock_server);
            let base = validate_common_parent(&checksums_urls)
                .expect("the mocked urls share origin and parent");
            let release_dir_rel = format!("{}{}", base.prefix(), base.parent_path());

            let port = get_random_port().await?;

            let keys = test_helpers::TestKeys::new(2);
            test_helpers::write_artifact_signers_config(
                &git_repo_path.join(base.prefix()),
                &keys,
                artifact_signers,
                threshold,
            )?;

            let config = build_test_config(&git_repo_path, port);
            let config_clone = config.clone();
            let server_handle = tokio::spawn(async move {
                let _ = run_server(&config_clone).await;
            });
            wait_for_server(&config, None).await?;

            Ok(Self {
                _temp_dir: temp_dir,
                git_repo_path,
                _mock_server: mock_server,
                checksums_urls,
                release_dir_rel,
                port,
                keys,
                client: reqwest::Client::new(),
                server_handle,
            })
        }

        fn public_key(&self) -> &features_lib::AsfaloadPublicKeys {
            self.keys.pub_key(0).unwrap()
        }

        fn secret_key(&self) -> &features_lib::AsfaloadSecretKeys {
            self.keys.sec_key(0).unwrap()
        }

        // Build and send a register-assets request whose checksums point at
        // the mocked file server, authenticated as key 0. Returns the
        // response and the index string the client built, so tests can
        // compare the persisted index with the exact bytes the client signed.
        async fn post_checksums(&self) -> Result<(reqwest::Response, String)> {
            let data = client_provided_data_for_checksums_urls(
                self.public_key(),
                self.secret_key(),
                &self.checksums_urls,
            )
            .await
            .map_err(|e| anyhow::anyhow!("failed to build client data: {e}"))?;
            let client_index = common::string_from_base64(&data.client_sent_index)
                .expect("the client data index is base64-encoded index json");

            let payload =
                serde_json::to_value(RegisterAssetsPayload::ChecksumFiles(ChecksumFilesPayload {
                    csum_files: self.checksums_urls.iter().map(|u| u.to_string()).collect(),
                    index: data.client_sent_index.clone(),
                    signature: data.client_sent_signature.clone(),
                }))
                .expect("failed to serialize ChecksumFiles payload");
            let payload_str = payload.to_string();

            let auth_info = rest_api_auth::AuthInfo::new(payload_str.clone());
            let auth_signature = rest_api_auth::AuthSignature::new(&auth_info, self.secret_key())?;

            let response = tokio::time::timeout(
                Duration::from_secs(10),
                self.client
                    .post(url_for("assets", self.port))
                    .header(HEADER_TIMESTAMP, auth_info.timestamp().to_rfc3339())
                    .header(HEADER_NONCE, auth_info.nonce())
                    .header(HEADER_SIGNATURE, auth_signature.signature().to_base64())
                    .header(HEADER_PUBLIC_KEY, self.public_key().to_base64())
                    .json(&payload)
                    .send(),
            )
            .await
            .map_err(|e| anyhow::anyhow!("Timeout: {}", e))??;

            Ok((response, client_index))
        }

        fn index_path_relative(&self) -> String {
            format!("{}asfaload.index.json", self.release_dir_rel)
        }

        // The artifacts published by the mocked file server, with their
        // declared digest in each sums file and the url of the sums file
        // declaring it.
        fn expected_entries(&self) -> Vec<(&'static str, HashAlgorithm, String, String)> {
            let sha256_source = self.checksums_urls[0].to_string();
            let sha512_source = self.checksums_urls[1].to_string();
            vec![
                (
                    LINUX_AMD64_ARTIFACT,
                    HashAlgorithm::Sha256,
                    SHA256_OF_LINUX_AMD64.to_string(),
                    sha256_source.clone(),
                ),
                (
                    WINDOWS_X86_64_ARTIFACT,
                    HashAlgorithm::Sha256,
                    SHA256_OF_WINDOWS_X86_64.to_string(),
                    sha256_source,
                ),
                (
                    LINUX_AMD64_ARTIFACT,
                    HashAlgorithm::Sha512,
                    sha512_of_linux_amd64(),
                    sha512_source.clone(),
                ),
                (
                    WINDOWS_X86_64_ARTIFACT,
                    HashAlgorithm::Sha512,
                    sha512_of_windows_x86_64(),
                    sha512_source,
                ),
            ]
        }

        fn stop(self) {
            self.server_handle.abort();
        }
    }

    // A registration for a user-provided checksums release through the
    // register-assets endpoint persists the client-sent index bytes and
    // records the client's signature in the pending signatures file. A
    // second registration is rejected with 409 and leaves the index bytes
    // unchanged.
    #[tokio::test]
    async fn test_register_checksums_release_via_assets_endpoint() -> Result<()> {
        // Threshold 2 with the submitter as one of two signers: the release
        // stays pending after registration.
        let server = ChecksumsServer::start(&[0, 1], 2).await?;

        let (response, client_index) = server.post_checksums().await?;

        assert_eq!(response.status(), StatusCode::OK, "Expected 200 OK status");
        let response_json: Value = response.json().await?;
        assert_eq!(response_json["success"], true, "Expected success=true");

        let index_rel_path = server.index_path_relative();
        assert_eq!(
            response_json["index_file_path"], index_rel_path,
            "The index path in the response is the release directory index"
        );

        let index_path = server.git_repo_path.join(&index_rel_path);
        assert!(
            index_path.exists(),
            "Index file should exist at {}",
            index_path.display()
        );

        // The persisted index must be exactly the bytes the client signed.
        let persisted_index = fs::read_to_string(&index_path)?;
        assert_eq!(
            persisted_index, client_index,
            "the persisted index must be exactly the bytes the client signed"
        );

        // The on-disk index parses, and publishes every checksums value
        // declared by the file server: iterate over the declared artifacts
        // and check each one is present in the index. The two checksums
        // files are downloaded in parallel, so their entries order in the
        // index is not stable: entries are matched by their full content.
        let index = read_on_disk_index(&index_path)?;
        assert_eq!(index.version, 1);
        let declared = server.expected_entries();
        for (file_name, algo, hash, source) in &declared {
            assert!(
                index
                    .published_files
                    .iter()
                    .any(|c| &c.file_name == file_name
                        && c.algo == *algo
                        && &c.hash == hash
                        && &c.source == source),
                "the index must publish {file_name} ({algo:?}) with the declared hash from {source}"
            );
        }
        assert_eq!(
            index.published_files.len(),
            declared.len(),
            "the index must publish nothing more than the declared checksums entries"
        );

        // The client signature recorded at registration sits in the pending
        // signatures file, as the threshold is not reached by one signer.
        assert_recorded_signature(
            &index_path,
            server.public_key(),
            SignatureFileState::Pending,
            1,
        );

        // The registration commit touches exactly the index and the pending
        // signatures file: no other file must sneak into the release
        // directory between index creation and commit.
        let names_output = Command::new("git")
            .arg("-C")
            .arg(&server.git_repo_path)
            .args([
                "show",
                "--pretty=format:",
                "--name-only",
                "HEAD",
                "--",
                &server.release_dir_rel,
            ])
            .output()
            .expect("failed to run git show");
        assert!(
            names_output.status.success(),
            "git show failed: {}",
            String::from_utf8_lossy(&names_output.stderr)
        );
        let committed_paths = String::from_utf8(names_output.stdout)?;
        let committed_files: Vec<&str> = committed_paths
            .lines()
            .map(|l| {
                l.rsplit('/')
                    .next()
                    .expect("git lists paths with a file name")
            })
            .collect();
        assert_eq!(
            committed_files,
            vec![
                "asfaload.index.json",
                "asfaload.index.json.signatures.json.pending"
            ],
            "the registration commit must hold exactly the index and its signatures file"
        );

        // attempt re-registration
        // -----------------------
        let (response, _) = server.post_checksums().await?;
        assert_eq!(
            response.status(),
            StatusCode::CONFLICT,
            "Expected 409 Conflict for release re-registration"
        );
        let response_text = response.text().await?;
        assert!(
            response_text.contains("already registered"),
            "the re-registration must report the release as already registered: {}",
            response_text
        );
        assert_eq!(
            fs::read_to_string(&index_path)?,
            persisted_index,
            "the re-registration must not alter the persisted index"
        );

        server.stop();
        Ok(())
    }

    // With a threshold-1 signers config the client's signature completes the
    // aggregate at registration: the pending signatures file is renamed to
    // the complete one, and a local copy of the signers file is created next
    // to the index.
    #[tokio::test]
    async fn test_register_checksums_release_threshold_1_completes() -> Result<()> {
        let server = ChecksumsServer::start(&[0], 1).await?;

        let (response, _) = server.post_checksums().await?;
        assert_eq!(response.status(), StatusCode::OK, "Expected 200 OK status");

        let index_path = server.git_repo_path.join(server.index_path_relative());
        assert!(
            index_path.exists(),
            "Index file should exist at {}",
            index_path.display()
        );

        // The aggregate signature is complete with 1 signature at
        // registration, and the pending file is gone after the rename.
        assert_recorded_signature(
            &index_path,
            server.public_key(),
            SignatureFileState::Complete,
            1,
        );

        // A local copy of the signers file is created next to the index,
        // with the same content as the global signers file.
        let local_signers_path = local_signers_path_for(&index_path)?;
        assert!(
            local_signers_path.exists(),
            "A local signers copy must exist at {}",
            local_signers_path.display()
        );
        let global_signers_path = find_global_signers_for(&index_path)?;
        assert_eq!(
            fs::read_to_string(&local_signers_path)?,
            fs::read_to_string(&global_signers_path)?,
            "The local signers copy must match the global signers file"
        );

        // The whole release directory is committed exactly once, with the
        // registration message, and the registration leaves no untracked or
        // modified files in the release directory.
        let log_output = Command::new("git")
            .arg("-C")
            .arg(&server.git_repo_path)
            .args(["log", "--format=%s", "--", &server.release_dir_rel])
            .output()
            .expect("failed to run git log");
        assert!(
            log_output.status.success(),
            "git log failed: {}",
            String::from_utf8_lossy(&log_output.stderr)
        );
        let commits = String::from_utf8(log_output.stdout)?;
        // The registration message names the index file it registers, as an
        // absolute path: build the expected message from the on-disk index.
        let expected_commit_message = format!(
            "Add index and signature for {}\n",
            index_path.canonicalize()?.display()
        );
        assert_eq!(
            commits, expected_commit_message,
            "Exactly one commit must touch the release directory, with the registration message"
        );

        let status_output = Command::new("git")
            .arg("-C")
            .arg(&server.git_repo_path)
            .args(["status", "--porcelain", "--", &server.release_dir_rel])
            .output()
            .expect("failed to run git status");
        assert_eq!(
            String::from_utf8(status_output.stdout)?,
            "",
            "The registration must leave no untracked or modified files in the release directory"
        );

        server.stop();
        Ok(())
    }

    // A submitter whose key is not declared as an artifact signer cannot
    // register the release, and nothing is written for it.
    #[tokio::test]
    async fn test_register_checksums_release_rejects_unauthorized_signer() -> Result<()> {
        // The submitter is key 0, the artifact signer is another key.
        let server = ChecksumsServer::start(&[1], 1).await?;

        let (response, _) = server.post_checksums().await?;
        assert_eq!(
            response.status(),
            StatusCode::FORBIDDEN,
            "Expected 403 Forbidden for a submitter not in the signers config"
        );

        assert!(
            !server.git_repo_path.join(&server.release_dir_rel).exists(),
            "A rejected registration must leave no release directory behind"
        );

        server.stop();
        Ok(())
    }
}
