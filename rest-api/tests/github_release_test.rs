// Client data verification requires the mock github fetcher shipped with
// the rest-api test-utils build: every test runs with that feature.
#[cfg(all(test, feature = "test-utils"))]
pub mod tests {

    use anyhow::Result;
    use axum::http::StatusCode;
    use common::fs::names::pending_signatures_path_for;
    use constants::{SIGNERS_DIR, SIGNERS_FILE};
    use features_lib::SignaturesFile;
    use features_lib::{AsfaloadKeyPairTrait, AsfaloadPublicKeyTrait, AsfaloadSignatureTrait};
    use features_lib::{ChecksumSourceFormat, FileChecksum, HashAlgorithm};
    use forge_release::github::ClientProvidedData;
    use forge_release::github::test_utils::{
        MOCK_RELEASE_PAGE_URL, client_provided_data_for_index,
        mocked_client_provided_data_with_keys, mocked_release_index,
    };
    use rest_api::server::run_server;
    use rest_api_auth::{HEADER_NONCE, HEADER_PUBLIC_KEY, HEADER_SIGNATURE, HEADER_TIMESTAMP};
    use rest_api_test_helpers::{build_test_config, get_random_port, url_for, wait_for_server};
    use rest_api_test_helpers::{init_git_repo, print_logs};
    use rest_api_types::RegisterAssetsPayload;
    use rest_api_types::models::GithubReleasePayload;
    use rest_api_types::rustls::setup_crypto_provider;
    use serde_json::Value;
    use std::fs;
    use tempfile::TempDir;
    use tokio::time::Duration;

    /// Body of the register-assets endpoint, in the tagged form sent by the
    /// client library: the index is the one the rest-api generates itself
    /// from the mocked release, signed as the client library signs it. The
    /// server verifies the signature against the public key header sent
    /// with the request.
    fn github_release_body(
        github_release_url: &str,
        public_key: &features_lib::AsfaloadPublicKeys,
        secret_key: &features_lib::AsfaloadSecretKeys,
    ) -> Value {
        let client_data = mocked_client_provided_data_with_keys(public_key, secret_key);
        // Note: the index and signature always cover the mocked release
        // url, even when the payload advertises a different release url:
        // tests passing an invalid url rely on the handler rejecting the
        // url before the client data is verified.
        serde_json::to_value(RegisterAssetsPayload::GithubRelease(GithubReleasePayload {
            github_release_url: github_release_url.to_string(),
            index: client_data.client_sent_index,
            signature: client_data.client_sent_signature,
        }))
        .expect("failed to serialize GithubRelease payload")
    }

    #[tokio::test]
    async fn test_register_github_release_via_assets_endpoint() -> Result<()> {
        setup_crypto_provider();
        let temp_dir = TempDir::new().expect("Failed to create temp directory");
        let git_repo_path = temp_dir.path().to_path_buf();
        print_logs();

        // Initialize a git repository for the test
        init_git_repo(&git_repo_path).expect("Failed to initialize git repository");

        let port = get_random_port().await?;

        let test_key_path = temp_dir.path().join("test_key.json");
        let test_keys = test_helpers::TestKeys::new_generated(1);
        let test_key_pair = test_keys.key_pair(0).unwrap();
        test_key_pair.save(&test_key_path)?;
        let test_secret_key = test_keys.sec_key(0).unwrap();
        let test_public_key = test_keys.pub_key(0).unwrap();
        let public_key_b64 = test_public_key.to_base64();

        let signers_dir = git_repo_path
            .join("https/github.com/443/testowner/testrepo")
            .join(SIGNERS_DIR);
        fs::create_dir_all(&signers_dir).expect("Failed to create signers directory");

        let signers_json = r#"{
            "version": 1,
            "required_signers": 1,
            "signers": [
                {
                    "public_key": "test_key",
                    "name": "Test Signer"
                }
            ]
        }"#;
        fs::write(signers_dir.join(SIGNERS_FILE), signers_json)
            .expect("Failed to write signers file");

        let config = build_test_config(&git_repo_path, port);

        let config_clone = config.clone();
        let server_handle = tokio::spawn(async move { run_server(&config_clone).await });
        wait_for_server(&config, None).await?;

        let client = reqwest::Client::new();

        let payload = github_release_body(
            "https://github.com/testowner/testrepo/releases/tag/v1.0.0",
            test_public_key,
            test_secret_key,
        );
        let payload_str = payload.to_string();

        // Index timestamps are set by the client building the index. Note
        // the send of the index is not part of the registration timing.

        let auth_info = rest_api_auth::AuthInfo::new(payload_str.clone());
        let auth_signature = rest_api_auth::AuthSignature::new(&auth_info, test_secret_key)?;

        let response = tokio::time::timeout(
            Duration::from_secs(10),
            client
                .post(url_for("assets", port))
                .header(HEADER_TIMESTAMP, auth_info.timestamp().to_rfc3339())
                .header(HEADER_NONCE, auth_info.nonce())
                .header(HEADER_SIGNATURE, auth_signature.signature().to_base64())
                .header(HEADER_PUBLIC_KEY, &public_key_b64)
                .json(&payload)
                .send(),
        )
        .await
        .map_err(|e| anyhow::anyhow!("Timeout: {}", e))??
        .error_for_status()
        .map_err(|e| anyhow::anyhow!("HTTP error: {}", e))?;

        let status = response.status();

        let response_json: Value = response.json().await?;

        assert_eq!(status, StatusCode::OK, "Expected 200 OK status");
        assert_eq!(response_json["success"], true, "Expected success=true");
        assert!(
            response_json["index_file_path"].is_string(),
            "Expected index_file_path to be a string"
        );

        // Verify index file exists and get its path from response
        let index_path_str = response_json["index_file_path"]
            .as_str()
            .expect("index_file_path should be a string");

        assert_eq!(
            index_path_str,
            "https/github.com/443/testowner/testrepo/releases/tag/v1.0.0/asfaload.index.json"
        );

        // The response gives a relative path, so we need to join it with git_repo_path
        let index_path = git_repo_path.join(index_path_str);
        assert!(
            index_path.exists(),
            "Index file should exist at {}",
            index_path.display()
        );

        // The on-disk index is what consumers read: registration persists
        // the client-provided index unchanged, so the file must be
        // byte-identical to the index the client sent, those being the only
        // bytes its signature covers. Field assertions below pin the data
        // served by the mocked github api, from which the client index is
        // built.
        assert_eq!(
            fs::read_to_string(&index_path)?,
            common::string_from_base64(payload["GithubRelease"]["index"].as_str().unwrap())
                .expect("the payload index is base64-encoded index json"),
            "the persisted index must be exactly the bytes the client signed"
        );
        let index = rest_api_test_helpers::read_on_disk_index(&index_path)?;
        assert_eq!(index.version, 1);
        assert_eq!(
            index.published_on,
            "2024-01-01T00:00:00Z".parse::<chrono::DateTime<chrono::Utc>>()?,
            "published_on must come from the release's published_at timestamp"
        );
        assert_eq!(
            index.published_files,
            vec![FileChecksum {
                file_name: "test.tar.gz".to_string(),
                algo: HashAlgorithm::Sha256,
                source: "https://api.github.com/repos/testowner/testrepo/releases/123".to_string(),
                source_format: ChecksumSourceFormat::GithubRelease,
                hash: "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890"
                    .to_string(),
            }]
        );

        // Verify signature file exists
        let sig_path = pending_signatures_path_for(&index_path)?;
        assert!(
            sig_path.exists(),
            "Signature file should exist at {}",
            sig_path.display()
        );

        let sig_content = tokio::fs::read_to_string(&sig_path).await?;
        let sig_file: SignaturesFile = serde_json::from_str(&sig_content)?;
        assert!(
            sig_file.entries.is_empty(),
            "Signature file should contain empty entries"
        );

        // attempt re-registration
        // -----------------------
        let auth_info = rest_api_auth::AuthInfo::new(payload_str.clone());
        let auth_signature = rest_api_auth::AuthSignature::new(&auth_info, test_secret_key)?;
        let response = tokio::time::timeout(
            Duration::from_secs(10),
            client
                .post(url_for("assets", port))
                .header(HEADER_TIMESTAMP, auth_info.timestamp().to_rfc3339())
                .header(HEADER_NONCE, auth_info.nonce())
                .header(HEADER_SIGNATURE, auth_signature.signature().to_base64())
                .header(HEADER_PUBLIC_KEY, &public_key_b64)
                .json(&payload)
                .send(),
        )
        .await
        .map_err(|e| anyhow::anyhow!("Timeout: {}", e))??;

        let status = response.status();
        assert_eq!(
            status,
            StatusCode::CONFLICT,
            "Expected 409 Conflict for release re-registration"
        );

        let response_text = response.text().await?;
        assert!(response_text.contains("already registered"));

        server_handle.abort();
        Ok(())
    }

    #[tokio::test]
    async fn test_register_github_release_no_signers_file() -> Result<()> {
        setup_crypto_provider();
        let temp_dir = TempDir::new().expect("Failed to create temp directory");
        let git_repo_path = temp_dir.path().to_path_buf();

        let port = get_random_port().await?;

        let test_keys = test_helpers::TestKeys::new(1);
        let test_secret_key = test_keys.sec_key(0).unwrap();
        let test_public_key = test_keys.pub_key(0).unwrap();
        let public_key_b64 = test_public_key.to_base64();

        let config = build_test_config(&git_repo_path, port);

        let config_clone = config.clone();
        let server_handle = tokio::spawn(async move { run_server(&config_clone).await });
        wait_for_server(&config, None).await?;

        let client = reqwest::Client::new();

        let json_body = github_release_body(
            "https://github.com/testowner/testrepo/releases/tag/v1.0.0",
            test_public_key,
            test_secret_key,
        );
        let payload_str = json_body.to_string();

        let auth_info = rest_api_auth::AuthInfo::new(payload_str.clone());
        let auth_signature = rest_api_auth::AuthSignature::new(&auth_info, test_secret_key)?;

        let response = tokio::time::timeout(
            Duration::from_secs(5),
            client
                .post(url_for("assets", port))
                .header(HEADER_TIMESTAMP, auth_info.timestamp().to_rfc3339())
                .header(HEADER_NONCE, auth_info.nonce())
                .header(HEADER_SIGNATURE, auth_signature.signature().to_base64())
                .header(HEADER_PUBLIC_KEY, public_key_b64)
                .json(&json_body)
                .send(),
        )
        .await
        .map_err(|e| anyhow::anyhow!("Timeout: {}", e))??;

        let status = response.status();
        let text = response.text().await?;

        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert!(
            text.contains("signers"),
            "Expected error about signers file, got: {}",
            text
        );

        server_handle.abort();
        Ok(())
    }

    #[tokio::test]
    async fn test_register_github_release_invalid_url_format() -> Result<()> {
        setup_crypto_provider();
        let temp_dir = TempDir::new().expect("Failed to create temp directory");
        let git_repo_path = temp_dir.path().to_path_buf();

        let port = get_random_port().await?;

        let test_keys = test_helpers::TestKeys::new(1);
        let test_secret_key = test_keys.sec_key(0).unwrap();
        let test_public_key = test_keys.pub_key(0).unwrap();
        let public_key_b64 = test_public_key.to_base64();

        let signers_dir = git_repo_path
            .join("https/github.com/443/testowner/testrepo")
            .join(SIGNERS_DIR);
        fs::create_dir_all(&signers_dir).expect("Failed to create signers directory");

        let signers_json = r#"{
            "version": 1,
            "required_signers": 1,
            "signers": []
        }"#;
        fs::write(signers_dir.join(SIGNERS_FILE), signers_json)
            .expect("Failed to write signers file");

        let config = build_test_config(&git_repo_path, port);

        let config_clone = config.clone();
        let server_handle = tokio::spawn(async move { run_server(&config_clone).await });
        wait_for_server(&config, None).await?;

        let client = reqwest::Client::new();

        let json_body = github_release_body("invalid", test_public_key, test_secret_key);
        let payload_str = json_body.to_string();

        let auth_info = rest_api_auth::AuthInfo::new(payload_str.clone());
        let auth_signature = rest_api_auth::AuthSignature::new(&auth_info, test_secret_key)?;

        let response = tokio::time::timeout(
            Duration::from_secs(5),
            client
                .post(url_for("assets", port))
                .header(HEADER_TIMESTAMP, auth_info.timestamp().to_rfc3339())
                .header(HEADER_NONCE, auth_info.nonce())
                .header(HEADER_SIGNATURE, auth_signature.signature().to_base64())
                .header(HEADER_PUBLIC_KEY, public_key_b64)
                .json(&json_body)
                .send(),
        )
        .await
        .map_err(|e| anyhow::anyhow!("Timeout: {}", e))??;

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);

        server_handle.abort();
        Ok(())
    }

    #[tokio::test]
    async fn test_register_github_release_missing_auth() -> Result<()> {
        setup_crypto_provider();
        let temp_dir = TempDir::new().expect("Failed to create temp directory");
        let git_repo_path = temp_dir.path().to_path_buf();

        let port = get_random_port().await?;

        let signers_dir = git_repo_path
            .join("https/github.com/443/testowner/testrepo")
            .join(SIGNERS_DIR);
        fs::create_dir_all(&signers_dir).expect("Failed to create signers directory");

        let signers_json = r#"{
            "version": 1,
            "required_signers": 1,
            "signers": []
        }"#;
        fs::write(signers_dir.join(SIGNERS_FILE), signers_json)
            .expect("Failed to write signers file");

        let config = build_test_config(&git_repo_path, port);

        let config_clone = config.clone();
        let server_handle = tokio::spawn(async move { run_server(&config_clone).await });
        wait_for_server(&config, None).await?;

        let client = reqwest::Client::new();

        let keys = test_helpers::TestKeys::new(1);
        let body = github_release_body(
            "https://github.com/testowner/testrepo/releases/tag/v1.0.0",
            keys.pub_key(0).unwrap(),
            keys.sec_key(0).unwrap(),
        );
        // Send without auth headers
        let response = tokio::time::timeout(
            Duration::from_secs(5),
            client.post(url_for("assets", port)).json(&body).send(),
        )
        .await
        .map_err(|e| anyhow::anyhow!("Timeout: {}", e))??;

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

        server_handle.abort();
        Ok(())
    }

    // ---------------------------------------------------------------------
    // Rejection of invalid client provided data at the endpoint.
    // ---------------------------------------------------------------------

    /// A running server configured for the mocked github release, plus the
    /// test keys: key 0 authenticates the requests, key 1 is an unrelated
    /// key usable by tests needing a signature from another signer.
    struct InvalidDataServer {
        _temp_dir: TempDir,
        git_repo_path: std::path::PathBuf,
        port: u16,
        client: reqwest::Client,
        keys: test_helpers::TestKeys,
        server_handle: tokio::task::JoinHandle<()>,
    }

    impl InvalidDataServer {
        async fn start() -> Result<Self> {
            setup_crypto_provider();
            let temp_dir = TempDir::new().expect("Failed to create temp directory");
            let git_repo_path = temp_dir.path().to_path_buf();
            print_logs();
            init_git_repo(&git_repo_path).expect("Failed to initialize git repository");

            let port = get_random_port().await?;

            // The signers file must exist for the owner/repo of the mocked
            // release, otherwise registration is rejected before the
            // client data is verified.
            let signers_dir = git_repo_path
                .join("https/github.com/443/testowner/testrepo")
                .join(SIGNERS_DIR);
            fs::create_dir_all(&signers_dir).expect("Failed to create signers directory");
            let signers_json = r#"{
                "version": 1,
                "required_signers": 1,
                "signers": [
                    {
                        "public_key": "test_key",
                        "name": "Test Signer"
                    }
                ]
            }"#;
            fs::write(signers_dir.join(SIGNERS_FILE), signers_json)
                .expect("Failed to write signers file");

            let config = build_test_config(&git_repo_path, port);
            let config_clone = config.clone();
            let server_handle = tokio::spawn(async move {
                let _ = run_server(&config_clone).await;
            });
            wait_for_server(&config, None).await?;

            Ok(Self {
                _temp_dir: temp_dir,
                git_repo_path,
                port,
                client: reqwest::Client::new(),
                keys: test_helpers::TestKeys::new(2),
                server_handle,
            })
        }

        // The path the server would create the index in if a registration
        // succeeded: rejections must leave it absent.
        fn release_dir(&self) -> std::path::PathBuf {
            self.git_repo_path
                .join("https/github.com/443/testowner/testrepo/releases/tag/v1.0.0")
        }

        fn public_key(&self) -> &features_lib::AsfaloadPublicKeys {
            self.keys.pub_key(0).unwrap()
        }

        fn secret_key(&self) -> &features_lib::AsfaloadSecretKeys {
            self.keys.sec_key(0).unwrap()
        }

        // Send a register-assets request for the mocked release page with
        // the given client provided data, authenticated as key 0.
        async fn post_release(&self, data: &ClientProvidedData) -> Result<reqwest::Response> {
            let payload =
                serde_json::to_value(RegisterAssetsPayload::GithubRelease(GithubReleasePayload {
                    github_release_url: MOCK_RELEASE_PAGE_URL.to_string(),
                    index: data.client_sent_index.clone(),
                    signature: data.client_sent_signature.clone(),
                }))
                .expect("failed to serialize GithubRelease payload");
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

            Ok(response)
        }

        fn stop(self) {
            self.server_handle.abort();
        }
    }

    // The signature must be produced by the key of the declared public
    // key: a signature from another key must be rejected with a bad request
    // and must not write any file for the release.
    #[tokio::test]
    async fn test_register_github_release_rejects_signature_of_other_key() -> Result<()> {
        let ctx = InvalidDataServer::start().await?;

        let data =
            mocked_client_provided_data_with_keys(ctx.public_key(), ctx.keys.sec_key(1).unwrap());
        let response = ctx.post_release(&data).await?;
        let status = response.status();
        let text = response.text().await?;

        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert!(
            text.contains("Signature sent by client"),
            "Expected error about the client signature, got: {}",
            text
        );
        assert!(
            !ctx.release_dir().exists(),
            "A rejected registration must not create the release directory"
        );

        ctx.stop();
        Ok(())
    }

    // The client index must be identical to the index the server builds
    // from the release: a validly signed but different index is rejected,
    // without writing any file for the release.
    #[tokio::test]
    async fn test_register_github_release_rejects_index_not_matching_release() -> Result<()> {
        let ctx = InvalidDataServer::start().await?;

        let mut value: Value = serde_json::from_str(&mocked_release_index())?;
        value["publishedFiles"][0]["hash"] = Value::String("f".repeat(64));
        let index_string = value.to_string();
        let data =
            client_provided_data_for_index(ctx.public_key(), ctx.secret_key(), &index_string);

        let response = ctx.post_release(&data).await?;
        let status = response.status();
        let text = response.text().await?;

        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert!(
            text.contains("not identical to index generated server side"),
            "Expected error about the mismatching index, got: {}",
            text
        );
        assert!(
            !ctx.release_dir().exists(),
            "A rejected registration must not create the release directory"
        );

        ctx.stop();
        Ok(())
    }

    // An index that decodes but parses no valid index json is invalid
    // client data, not a server-side failure, and must be rejected early
    // without writing any file for the release.
    #[tokio::test]
    async fn test_register_github_release_rejects_index_that_is_not_valid_json() -> Result<()> {
        let ctx = InvalidDataServer::start().await?;

        let data = client_provided_data_for_index(
            ctx.public_key(),
            ctx.secret_key(),
            "not index json at all",
        );

        let response = ctx.post_release(&data).await?;
        let status = response.status();
        let text = response.text().await?;

        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert!(
            text.contains("Could not parse index sent by client"),
            "Expected error about the unparsable index, got: {}",
            text
        );
        assert!(
            !ctx.release_dir().exists(),
            "A rejected registration must not create the release directory"
        );

        ctx.stop();
        Ok(())
    }

    // An index that cannot be decoded from base64 is rejected early, and
    // no file may be written for the release.
    #[tokio::test]
    async fn test_register_github_release_rejects_index_encoded_with_invalid_base64() -> Result<()>
    {
        let ctx = InvalidDataServer::start().await?;

        let mut data = mocked_client_provided_data_with_keys(ctx.public_key(), ctx.secret_key());
        data.client_sent_index = "!!! not base64 !!!".to_string();

        let response = ctx.post_release(&data).await?;
        let status = response.status();
        let text = response.text().await?;

        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert!(
            text.contains("Could not decode index sent by client"),
            "Expected error about the undecodable index, got: {}",
            text
        );
        assert!(
            !ctx.release_dir().exists(),
            "A rejected registration must not create the release directory"
        );

        ctx.stop();
        Ok(())
    }
}
