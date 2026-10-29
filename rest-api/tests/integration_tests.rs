use anyhow::Result;
use features_lib::{AsfaloadSecretKeyTrait, AsfaloadSignatureTrait};

/// Signature over the sha512 of `content`, made with `secret_key`.
///
/// The registration endpoints carry a signature over the signers file
/// content the backend fetches from the forge. When the mocked forge
/// serves the same content to the test and to the backend, a signature
/// built on those exact bytes is the one the backend verifies.
pub fn signature_for_sha(
    content: &[u8],
    secret_key: &features_lib::AsfaloadSecretKeys,
) -> Result<String> {
    let digest = common::sha512_for_content(content)?;
    Ok(secret_key.sign(&digest)?.to_base64())
}

/// Build the base64-encoded metadata and its base64-encoded signature the
/// same way the admin client does, so the backend validation accepts them.
///
/// `signers_content` must be the exact content the mocked forge serves for
/// `signers_file_url`: the backend computes the metadata content hash from
/// the bytes it fetches, so signing metadata built on the same bytes is the
/// only way to pass the backend validation.
pub fn metadata_and_signature_for(
    signers_file_url: &str,
    signers_content: &str,
    secret_key: &features_lib::AsfaloadSecretKeys,
) -> Result<(String, String)> {
    metadata_and_signature_for_at(
        signers_file_url,
        signers_content,
        chrono::Utc::now(),
        secret_key,
    )
}

/// Same as `metadata_and_signature_for`, but with a caller-chosen
/// `retrieved_at` timestamp, to exercise the backend timestamp checks.
pub fn metadata_and_signature_for_at(
    signers_file_url: &str,
    signers_content: &str,
    retrieved_at: chrono::DateTime<chrono::Utc>,
    secret_key: &features_lib::AsfaloadSecretKeys,
) -> Result<(String, String)> {
    let serialised_metadata =
        metadata_json_for_at(signers_file_url, signers_content, retrieved_at)?;
    let metadata_hash = common::sha512_for_content(serialised_metadata.as_bytes())?;
    let metadata_signature = secret_key.sign(&metadata_hash)?.to_base64();
    let serialised_metadata_b64 = common::base64_for_string(serialised_metadata);
    Ok((serialised_metadata_b64, metadata_signature))
}

/// The serialised metadata the admin client sends, without its signature.
///
/// Tests that supply a wrongly signed or modified metadata need the raw
/// JSON bytes: the backend verifies the signature over these exact bytes
/// before it parses them.
pub fn metadata_json_for_at(
    signers_file_url: &str,
    signers_content: &str,
    retrieved_at: chrono::DateTime<chrono::Utc>,
) -> Result<String> {
    use rest_api::file_auth::forges::{ForgeInfo, ForgeTrait};
    use signers_file_types::VerifiedForgeContent;

    let parsed_url = url::Url::parse(signers_file_url)?;
    let info = ForgeInfo::new(&parsed_url)?;
    let raw_url = info.url_info().raw_url().to_string();

    let verified_content = VerifiedForgeContent::new_for_test(raw_url, signers_content.to_string());

    let forge = match info {
        ForgeInfo::Github(_) => signers_file_types::Forge::Github,
        ForgeInfo::Gitlab(_) => signers_file_types::Forge::Gitlab,
        ForgeInfo::FileServer(_) => signers_file_types::Forge::FileServer,
    };
    let metadata = signers_file_types::SignersConfigMetadata::new(
        forge,
        signers_file_url.to_string(),
        verified_content,
        retrieved_at,
    );

    Ok(common::to_posix_json(&metadata)?)
}

#[cfg(all(test, not(feature = "test-utils")))]
pub mod tests {

    use crate::signature_for_sha;
    use anyhow::Result;
    use axum::http::StatusCode;
    use constants::SIGNERS_FILE;
    use constants::SIGNERS_HISTORY_FILE;
    use rest_api::file_auth::actors::forge_signers_validator::SignersInfo;
    use rest_api::file_auth::github::get_project_normalised_paths;
    use rest_api::server::run_server;
    use rest_api_auth::{HEADER_NONCE, HEADER_PUBLIC_KEY, HEADER_SIGNATURE, HEADER_TIMESTAMP};
    use rest_api_test_helpers::parse_log_lines;
    use rest_api_test_helpers::setup_file_logging;
    use rest_api_test_helpers::wait_for_log_entry_with_request_id;
    use rest_api_test_helpers::{
        TestAuthHeaders, build_test_config, create_auth_headers, create_auth_headers_with_key,
        get_random_port, init_git_repo, url_for, wait_for_server,
    };
    use rest_api_types::git_backend::{GitBackend, GitBackendKind, Sha256GitBackend};
    use serde_json::{Value, json};
    use std::fs;
    use std::sync::Arc;
    use tempfile::TempDir;
    use tokio::time::Duration;

    /// Read the git backend from the `ASFALOAD_GIT_BACKEND` environment variable.
    /// Duplicated in tests module that need it. Moving it to a test helpers crate implies
    /// too much code to move due to its return type GitBackendType
    /// Only recognised sha256 since Sha1 was removed.
    pub fn backend_kind_from_env() -> GitBackendKind {
        match std::env::var("ASFALOAD_GIT_BACKEND").as_deref() {
            Ok("sha256") => GitBackendKind::Sha256,
            Ok(other) => panic!("unrecognised value for ASFALOAD_GIT_BACKEND: {other}"),
            Err(_e) => GitBackendKind::Sha256,
        }
    }

    // Test case: Authentication required for API endpoints
    #[tokio::test]
    async fn test_authentication_required() -> Result<()> {
        // Create a temporary directory for the git repository
        let temp_dir = TempDir::new().expect("Failed to create temp directory");
        let repo_path_buf = temp_dir.path().to_path_buf();

        // Initialize git repository
        init_git_repo(&repo_path_buf).expect("Failed to initialize git repo");

        let port = get_random_port().await?;
        let config = build_test_config(&repo_path_buf, port);
        // Start the server in the background
        let config_clone = config.clone();
        let server_handle = tokio::spawn(async move { run_server(&config_clone).await });
        wait_for_server(&config, None).await?;

        // Create a client to send requests
        let client = reqwest::Client::new();

        // Try to send a request without authentication headers
        let response = client
            .post(url_for("revoke", port))
            .json(&json!({
                "file_path": "test_file.txt",
                "content": "This should fail due to missing authentication"
            }))
            .send()
            .await
            .expect("Failed to send request");

        // Check the response status - should be 401 Unauthorized
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

        // Parse the response body
        let response_body: Value = response.json().await.expect("Failed to parse response");
        assert_eq!(response_body["error"], "Missing authentication headers");

        // Clean up - abort the server task
        server_handle.abort();
        Ok(())
    }

    // Test case: Verify request ID header is present in response
    #[tokio::test]
    async fn test_request_id_tracing() -> Result<()> {
        // Create a temporary directory for the git repository
        let temp_dir = TempDir::new().expect("Failed to create temp directory");
        let repo_path_buf = temp_dir.path().to_path_buf();

        let port = get_random_port().await?;
        // Initialize git repository
        init_git_repo(&repo_path_buf).expect("Failed to initialize git repo");

        let config = build_test_config(&repo_path_buf, port);

        // Start the server in the background
        let config_clone = config.clone();
        let server_handle = tokio::spawn(async move { run_server(&config_clone).await });
        wait_for_server(&config, None).await?;

        // Create a client to send requests
        let client = reqwest::Client::new();

        // Create authentication headers for a request to the revoke endpoint
        let payload = json!({
            "file_path": "test_request_id.txt",
            "revocation_json": "{}",
            "signature": "dGVzdA==",
            "public_key": "dGVzdA=="
        });
        let payload_string = payload.to_string();
        let TestAuthHeaders {
            timestamp,
            nonce,
            signature,
            public_key,
        } = create_auth_headers(&payload_string).await;

        // Send the request with authentication headers
        let response = client
            .post(url_for("revoke", port))
            .header(HEADER_TIMESTAMP, timestamp)
            .header(HEADER_NONCE, nonce)
            .header(HEADER_SIGNATURE, signature)
            .header(HEADER_PUBLIC_KEY, public_key)
            .json(&payload)
            .send()
            .await
            .expect("Failed to send request");

        // Auth should pass (handler may reject the payload, but that's fine)
        assert_ne!(
            response.status(),
            StatusCode::UNAUTHORIZED,
            "Auth should pass"
        );

        // Verify request ID header is present in response
        let request_id = response
            .headers()
            .get("x-request-id")
            .expect("x-request-id header should be present in response")
            .to_str()
            .expect("x-request-id header should be valid UTF-8");

        // Verify request ID is not empty
        assert!(!request_id.is_empty(), "x-request-id should not be empty");

        // Clean up - abort the server task
        server_handle.abort();
        Ok(())
    }

    // ============================================================================
    // Structured Logging Tests
    // ============================================================================

    // Note: This test validates the basic setup of our logging (json format, timestamp,...).
    // It was generated by AI, and if it proves unnecessary can be removed.
    #[tokio::test]
    async fn test_structured_logging_json_format() -> Result<()> {
        let temp_dir = TempDir::new()?;
        let (_guard, log_path, _subscriber_guard) = setup_file_logging(temp_dir.path())?;

        tracing::info!(test_event = "json_validation", "Test info message");
        tracing::warn!(test_event = "json_validation", "Test warning message");
        tracing::error!(test_event = "json_validation", "Test error message");

        drop(_guard);

        let content = fs::read_to_string(&log_path)?;
        let log_lines = parse_log_lines(&content)?;

        assert_eq!(log_lines.len(), 3, "Should have 3 log entries");

        for entry in log_lines {
            assert!(entry.is_object(), "Each line must be a JSON object");
            assert!(entry.get("timestamp").is_some(), "Must have timestamp");
            assert!(entry.get("level").is_some(), "Must have level");
            assert!(
                entry.get("message").is_some()
                    || entry.get("fields").and_then(|f| f.get("message")).is_some(),
                "Must have message"
            );
            assert!(
                entry
                    .get("test_event")
                    .or_else(|| entry.get("fields").and_then(|f| f.get("test_event")))
                    .is_some(),
                "Must have our test_event field"
            );
        }

        Ok(())
    }

    // This test validates that a request sent to the server is logged
    #[tokio::test]
    async fn test_request_id_logging_flow() -> Result<()> {
        let temp_dir = TempDir::new()?;
        let (_guard, log_path, _subscriber_guard) = setup_file_logging(temp_dir.path())?;

        let port = get_random_port().await?;
        let repo_path = temp_dir.path().join("repo");
        init_git_repo(&repo_path)?;
        let config = build_test_config(&repo_path, port);

        let config_clone = config.clone();
        let server_handle = tokio::spawn(async move { run_server(&config_clone).await });
        wait_for_server(&config, None).await?;

        let client = reqwest::Client::new();
        let payload = json!({
            "file_path": "test.txt",
            "revocation_json": "{}",
            "signature": "dGVzdA==",
            "public_key": "dGVzdA=="
        });
        let TestAuthHeaders {
            timestamp,
            nonce,
            signature,
            public_key,
        } = create_auth_headers(&payload.to_string()).await;

        let response = client
            .post(url_for("revoke", port))
            .header(HEADER_TIMESTAMP, timestamp)
            .header(HEADER_NONCE, nonce)
            .header(HEADER_SIGNATURE, signature)
            .header(HEADER_PUBLIC_KEY, public_key)
            .json(&payload)
            .send()
            .await?;

        let request_id = response
            .headers()
            .get("x-request-id")
            .and_then(|h| h.to_str().ok())
            .expect("Should have request ID");

        // FIXME: sleeping to let server handle the request
        // Removing this sleep, I've had this test fail once
        // which makes it hard to validate if another way to
        // wait works (eg drop the guard before aborting)
        tokio::time::sleep(Duration::from_millis(500)).await;

        wait_for_log_entry_with_request_id(&log_path, request_id).await?;

        let content = fs::read_to_string(&log_path)?;
        let log_lines = parse_log_lines(&content)?;

        let entries_with_request_id: Vec<_> = log_lines
            .iter()
            .filter(|entry| {
                entry
                    .get("request_id")
                    .or_else(|| entry.get("fields").and_then(|f| f.get("request_id")))
                    .and_then(|v| v.as_str())
                    == Some(request_id)
            })
            .collect();

        assert!(
            !entries_with_request_id.is_empty(),
            "Should have at least 1 log entry with request_id"
        );

        let levels: Vec<_> = entries_with_request_id
            .iter()
            .filter_map(|e| e.get("level").and_then(|l| l.as_str()))
            .collect();
        assert!(levels.contains(&"INFO"), "Should have INFO level entries");

        server_handle.abort();

        Ok(())
    }

    // This test was generated by AI. It validates our tracing setup logs errors.
    // If it proves unnecessary, it can be removed.
    #[tokio::test]
    async fn test_error_logging_structure() -> Result<()> {
        let temp_dir = TempDir::new()?;
        let (_guard, log_path, _subscriber_guard) = setup_file_logging(temp_dir.path())?;

        tracing::error!(
            error_type = "validation",
            error_code = "invalid_path",
            "Test error message"
        );

        drop(_guard);

        let content = fs::read_to_string(&log_path)?;
        let log_lines = parse_log_lines(&content)?;

        let error_entry = log_lines.first().expect("Should have error entry");

        assert_eq!(
            error_entry.get("level").and_then(|l| l.as_str()),
            Some("ERROR"),
            "Level should be ERROR"
        );
        assert_eq!(
            error_entry
                .get("error_type")
                .or_else(|| error_entry.get("fields").and_then(|f| f.get("error_type")))
                .and_then(|t| t.as_str()),
            Some("validation"),
            "Should have error_type field"
        );
        assert_eq!(
            error_entry
                .get("error_code")
                .or_else(|| error_entry.get("fields").and_then(|f| f.get("error_code")))
                .and_then(|c| c.as_str()),
            Some("invalid_path"),
            "Should have error_code field"
        );
        assert_eq!(
            error_entry
                .get("message")
                .or_else(|| error_entry.get("fields").and_then(|f| f.get("message")))
                .and_then(|m| m.as_str()),
            Some("Test error message"),
            "Should have message"
        );

        Ok(())
    }

    // ============================================================================
    // Register Repo Integration Tests (non-feature)
    // ============================================================================

    #[tokio::test]
    async fn test_register_repo_cleans_up_on_repo_handler_failure() -> Result<(), anyhow::Error> {
        use constants::PENDING_SIGNERS_DIR;
        use kameo::actor::Spawn;
        use rest_api::file_auth::actors::git_actor::GitActor;
        use rest_api::file_auth::actors::signers_initialiser::{
            CleanupSignersRequest, InitialiseSignersRequest, SignersInitialiser,
        };
        use signers_file_types::{Forge, SignersConfigMetadata, VerifiedForgeContent};
        use std::fs;

        let temp_dir = TempDir::new()?;
        let git_repo_path = temp_dir.path().join("git_repo");
        let git_repo_path_clone = git_repo_path.clone();

        init_git_repo(&git_repo_path)?;

        let test_keys = test_helpers::TestKeys::new(2);

        let signers_config = signers_file_types::SignersConfig::with_artifact_signers_only(
            1,
            (
                vec![
                    test_keys.pub_key(0).unwrap().clone(),
                    test_keys.pub_key(1).unwrap().clone(),
                ],
                2,
            ),
        )?;
        let signers_json = serde_json::to_string_pretty(&signers_config)?;
        // SignersInfo only initialises from string to ensure we keep the string
        // that is signed intact.
        let signers_info = SignersInfo::from_string(&signers_json)?;

        let metadata = SignersConfigMetadata::new(
            Forge::Github,
            "https://github.com/test/repo/blob/main/signers.json".to_string(),
            VerifiedForgeContent::new_for_test(
                "https://github.com/test/repo/blob/main/signers.json".to_string(),
                "test_hash_placeholder".to_string(),
            ),
            chrono::Utc::now(),
        );
        // The signatures a registering client sends: over the signers file
        // content and over the metadata, both made with key 0.
        let metadata_json = serde_json::to_string_pretty(&metadata)?;
        let metadata_info =
            rest_api::file_auth::actors::forge_signers_validator::MetadataInfo::from_string(
                &metadata_json,
            )?;
        let signers_signature = {
            use features_lib::AsfaloadSecretKeyTrait;
            let digest = common::sha512_for_content(signers_json.as_bytes())?;
            test_keys.sec_key(0).unwrap().sign(&digest)?
        };
        let metadata_signature = {
            use features_lib::AsfaloadSecretKeyTrait;
            let digest = common::sha512_for_content(metadata_json.as_bytes())?;
            test_keys.sec_key(0).unwrap().sign(&digest)?
        };

        let project_id = "github.com/test/repo";
        let project_dir = git_repo_path.join(project_id);
        let signers_pending_dir = project_dir.join(PENDING_SIGNERS_DIR);
        let signers_file_path = signers_pending_dir.join(SIGNERS_FILE);
        let history_file_path = project_dir.join(SIGNERS_HISTORY_FILE);
        let project_path = get_project_normalised_paths(&git_repo_path, project_id).await?;

        let signers_initialiser = SignersInitialiser::spawn(());
        let init_request = InitialiseSignersRequest {
            project_path,
            signers_info,
            signers_signature,
            metadata_info,
            metadata_signature,
            pubkey: test_keys.pub_key(0).unwrap().clone(),
            git_repo_path: git_repo_path.clone(),
            request_id: "test-123".to_string(),
        };

        let init_result = signers_initialiser.ask(init_request).await?;

        assert!(
            signers_file_path.exists(),
            "Signers file should exist after initialization"
        );
        assert!(
            history_file_path.exists(),
            "History file should exist after initialization"
        );
        assert!(
            signers_pending_dir.exists(),
            "Pending directory should exist after initialization"
        );

        let git_dir = git_repo_path.join(".git");
        fs::remove_dir_all(&git_dir)?;

        let key = test_helpers::git_signing_pub_key_path();
        let backend: Arc<dyn GitBackend> = match backend_kind_from_env() {
            GitBackendKind::Sha256 => Arc::new(Sha256GitBackend::new(&git_repo_path_clone, &key)),
        };
        let git_actor = GitActor::spawn(backend);

        let write_commit_request = rest_api::file_auth::actors::git_actor::CommitFile {
            file_paths: vec![init_result.project_path.clone()],
            commit_message: "commit of test-123".to_string(),
            request_id: "test-123".to_string(),
        };

        let result = git_actor.ask(write_commit_request).await;

        assert!(
            result.is_err(),
            "RepoHandler should fail when git repo is corrupted"
        );

        let pending_dir = init_result.project_path.join(PENDING_SIGNERS_DIR).await?;

        let cleanup_request = CleanupSignersRequest {
            signers_file_path: init_result.signers_file_path.clone(),
            history_file_path: Some(init_result.history_file_path.clone()),
            pending_dir,
            request_id: "test-123".to_string(),
        };

        let cleanup_result = signers_initialiser.ask(cleanup_request).await;

        assert!(cleanup_result.is_ok(), "Cleanup should succeed");

        tokio::time::sleep(Duration::from_millis(100)).await;

        assert!(
            !signers_file_path.exists(),
            "Signers file should be cleaned up after failure"
        );
        assert!(
            !history_file_path.exists(),
            "History file should be cleaned up after failure"
        );
        assert!(
            !signers_pending_dir.exists(),
            "Pending directory should be cleaned up after failure"
        );

        Ok(())
    }

    #[tokio::test]
    async fn test_register_repo_errors_dont_leak_internal_details() -> Result<(), anyhow::Error> {
        use features_lib::AsfaloadPublicKeyTrait;
        use httpmock::Method;
        use rest_api_types::RegisterRepoRequest;

        let temp_dir = TempDir::new()?;
        let git_repo_path = temp_dir.path().join("git_repo");
        init_git_repo(&git_repo_path)?;

        // Mock a forge answering 404 for the signers file, so registration fails
        // at the fetch without any real network access. A localhost host routes
        // through the FileServerForge path (see forge_info.rs), but the
        // sanitised error response must be the same whichever forge kind serves
        // the URL.
        let mock_server = httpmock::MockServer::start();
        let _mock = mock_server.mock(|when, then| {
            when.method(Method::GET)
                .path("/owner/repo/main/nonexistent.json");
            then.status(404);
        });
        let signers_file_url = format!("{}/owner/repo/main/nonexistent.json", mock_server.url(""));

        let port = get_random_port().await?;
        let config = build_test_config(&git_repo_path, port);
        let config_clone = config.clone();
        let server_handle = tokio::spawn(async move { run_server(&config_clone).await });
        wait_for_server(&config, None).await?;

        let client = reqwest::Client::new();

        let test_keys = test_helpers::TestKeys::new(1);
        let public_key = test_keys.pub_key(0).unwrap();
        let secret_key = test_keys.sec_key(0).unwrap();

        // Build valid client metadata so the flow fails at the forge fetch, not
        // at metadata parsing or its timestamp checks. The fetched content is
        // never compared against this metadata, as registration aborts at the
        // fetch. The signers and metadata signatures are also never verified,
        // as the fetch fails before the backend checks the signature.
        let (metadata, metadata_signature) =
            crate::metadata_and_signature_for(&signers_file_url, "not fetched", secret_key)?;
        let request_body = RegisterRepoRequest {
            signers_file_url: signers_file_url.clone(),
            public_key: public_key.to_base64(),
            signature: signature_for_sha(b"not fetched", secret_key)?,
            metadata,
            metadata_signature,
        };
        let payload_string = serde_json::to_string(&request_body)?;
        let TestAuthHeaders {
            timestamp,
            nonce,
            signature: auth_signature,
            public_key: auth_public_key,
        } = create_auth_headers_with_key(secret_key, &payload_string).await;

        let response = client
            .post(format!("http://localhost:{}/v1/register_repo", port))
            .header(HEADER_TIMESTAMP, timestamp)
            .header(HEADER_NONCE, nonce)
            .header(HEADER_SIGNATURE, auth_signature)
            .header(HEADER_PUBLIC_KEY, auth_public_key)
            .json(&request_body)
            .send()
            .await?;

        // A failed forge fetch must answer ActorOperationFailed, and so 500.
        assert_eq!(
            response.status(),
            StatusCode::INTERNAL_SERVER_ERROR,
            "A failed signers file fetch must answer 500"
        );

        let response_body: serde_json::Value = response.json().await?;

        let error_msg = response_body
            .get("error")
            .and_then(|e| e.as_str())
            .unwrap_or("");

        assert!(
            !error_msg.contains("ActorOperationFailed"),
            "Should not expose actor errors"
        );
        assert!(!error_msg.contains("/"), "Should not expose file paths");
        assert!(
            error_msg.len() < 200,
            "Error message should be concise: {}",
            error_msg
        );

        server_handle.abort();

        Ok(())
    }

    // ============================================================================
    // Signature Status Tests (non-feature)
    // ============================================================================

    #[tokio::test]
    async fn test_get_signature_status() -> Result<(), anyhow::Error> {
        use rest_api_test_helpers::TestSetupBuilder;
        use rest_api_types::GetSignatureStatusResponse;

        let setup = TestSetupBuilder::new()
            .with_artifact("data.txt")
            .with_artifact_content(b"test data".to_vec())
            .build()
            .await?;

        let auth = create_auth_headers("").await;

        let client = reqwest::Client::new();
        let response = client
            .get(format!(
                "http://127.0.0.1:{}/v1/signatures/{}",
                setup.port(),
                setup.artifact_path()
            ))
            .header(HEADER_TIMESTAMP, &auth.timestamp)
            .header(HEADER_NONCE, &auth.nonce)
            .header(HEADER_SIGNATURE, &auth.signature)
            .header(HEADER_PUBLIC_KEY, &auth.public_key)
            .send()
            .await?;

        assert_eq!(response.status(), StatusCode::OK);

        let status_body: GetSignatureStatusResponse = response.json().await?;

        assert_eq!(status_body.file_path, "data.txt");
        assert!(!status_body.is_complete);

        Ok(())
    }

    #[tokio::test]
    async fn test_get_signature_status_rejects_unauthenticated() -> Result<(), anyhow::Error> {
        use rest_api_test_helpers::TestSetupBuilder;

        let setup = TestSetupBuilder::new()
            .with_artifact("data.txt")
            .with_artifact_content(b"test data".to_vec())
            .build()
            .await?;

        let client = reqwest::Client::new();
        let response = client
            .get(format!(
                "http://127.0.0.1:{}/v1/signatures/{}",
                setup.port(),
                setup.artifact_path()
            ))
            .send()
            .await?;

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

        Ok(())
    }

    #[tokio::test]
    async fn test_get_signature_status_rejects_non_signer() -> Result<(), anyhow::Error> {
        use rest_api_test_helpers::TestSetupBuilder;

        // Setup with 1 key (key index 0)
        let setup = TestSetupBuilder::new()
            .with_artifact("data.txt")
            .with_artifact_content(b"test data".to_vec())
            .build()
            .await?;

        // Create auth headers with a DIFFERENT key (not in signers file)
        let extra_keys = test_helpers::TestKeys::new_from(5, 1);
        let secret_key = extra_keys.sec_key(0).unwrap();
        let auth = rest_api_test_helpers::create_auth_headers_with_key(secret_key, "").await;

        let client = reqwest::Client::new();
        let response = client
            .get(format!(
                "http://127.0.0.1:{}/v1/signatures/{}",
                setup.port(),
                setup.artifact_path()
            ))
            .header(rest_api_auth::HEADER_TIMESTAMP, &auth.timestamp)
            .header(rest_api_auth::HEADER_NONCE, &auth.nonce)
            .header(rest_api_auth::HEADER_SIGNATURE, &auth.signature)
            .header(rest_api_auth::HEADER_PUBLIC_KEY, &auth.public_key)
            .send()
            .await?;

        assert_eq!(response.status(), StatusCode::FORBIDDEN);

        Ok(())
    }

    #[tokio::test]
    async fn test_get_signature_status_returns_404_for_missing_file() -> Result<(), anyhow::Error> {
        use rest_api_test_helpers::TestSetupBuilder;

        let setup = TestSetupBuilder::new()
            .with_artifact("data.txt")
            .with_artifact_content(b"test data".to_vec())
            .build()
            .await?;

        let auth = create_auth_headers("").await;

        let client = reqwest::Client::new();
        let response = client
            .get(format!(
                "http://127.0.0.1:{}/v1/signatures/does/not/exist.txt",
                setup.port()
            ))
            .header(HEADER_TIMESTAMP, &auth.timestamp)
            .header(HEADER_NONCE, &auth.nonce)
            .header(HEADER_SIGNATURE, &auth.signature)
            .header(HEADER_PUBLIC_KEY, &auth.public_key)
            .send()
            .await?;

        assert_eq!(response.status(), StatusCode::NOT_FOUND);

        Ok(())
    }
}

#[cfg(all(test, feature = "test-utils"))]
pub mod test_utils_tests {

    use crate::signature_for_sha;
    use axum::http::StatusCode;
    use rest_api::server::run_server;
    use rest_api_auth::{HEADER_NONCE, HEADER_PUBLIC_KEY, HEADER_SIGNATURE, HEADER_TIMESTAMP};
    use rest_api_test_helpers::setup_file_logging;
    use rest_api_test_helpers::{
        TestAuthHeaders, build_test_config, create_auth_headers_with_key,
        file_exists_in_latest_commit, file_is_tracked_in_git, get_latest_commit, get_random_port,
        init_git_repo, url_for, wait_for_commit, wait_for_server,
    };
    use rest_api_types::RegisterRepoRequest;
    use serde_json::json;
    use tempfile::TempDir;

    // ============================================================================
    // Register Repo Integration Tests
    //
    // NOTE: These tests establish the integration test infrastructure pattern for
    // register_repo endpoint. They mock the forge with httpmock and use
    // localhost signers file URLs, so requests go through the forge server
    // parsing path (ForgeInfo::FileServer) rather than through the GitHub or
    // GitLab URL rewriting logic.
    // ============================================================================

    #[tokio::test]
    async fn test_register_repo_success() -> Result<(), anyhow::Error> {
        use features_lib::AsfaloadPublicKeyTrait;
        use httpmock::Method;
        use rest_api_types::RegisterRepoRequest;
        use rest_api_types::RegisterRepoResponse;

        let temp_dir = TempDir::new()?;
        let git_repo_path = temp_dir.path().join("git_repo");

        init_git_repo(&git_repo_path)?;

        let mock_server = httpmock::MockServer::start();

        let test_keys = test_helpers::TestKeys::new(1);
        let public_key = test_keys.pub_key(0).unwrap();
        let secret_key = test_keys.sec_key(0).unwrap();

        let signers_config = signers_file_types::SignersConfig::with_artifact_signers_only(
            1,
            (vec![public_key.clone()], 1),
        )?;

        let signers_json = serde_json::to_string_pretty(&signers_config)?;

        let signers_json_clone = signers_json.clone();
        let mock = mock_server.mock(|when, then| {
            when.method(Method::GET)
                .path("/owner/repo/main/signers.json");
            then.status(200)
                .header("Content-Type", "application/json")
                .body(signers_json_clone);
        });

        let signers_url = format!("{}/owner/repo/main/signers.json", mock_server.url(""));

        let port = get_random_port().await?;
        let config = build_test_config(&git_repo_path, port);
        let config_clone = config.clone();
        let server_handle = tokio::spawn(async move { run_server(&config_clone).await });
        wait_for_server(&config, None).await?;

        let client = reqwest::Client::new();

        let (metadata, metadata_signature) =
            crate::metadata_and_signature_for(&signers_url, &signers_json, &secret_key)?;
        let request_body = RegisterRepoRequest {
            signers_file_url: signers_url,
            public_key: public_key.to_base64(),
            signature: signature_for_sha(signers_json.as_bytes(), &secret_key)?,
            metadata,
            metadata_signature,
        };
        let payload_string = serde_json::to_string(&request_body)?;
        let TestAuthHeaders {
            timestamp,
            nonce,
            signature: auth_signature,
            public_key: auth_public_key,
        } = create_auth_headers_with_key(secret_key, &payload_string).await;

        let response = client
            .post(format!("http://localhost:{}/v1/register_repo", port))
            .header(HEADER_TIMESTAMP, timestamp)
            .header(HEADER_NONCE, nonce)
            .header(HEADER_SIGNATURE, auth_signature)
            .header(HEADER_PUBLIC_KEY, auth_public_key)
            .json(&request_body)
            .send()
            .await?;

        assert_eq!(response.status(), StatusCode::OK);

        let response_body = response.json::<RegisterRepoResponse>().await?;
        assert!(response_body.success);
        let expected_project_id = format!("http/127.0.0.1/{}/owner/repo", mock_server.port());
        assert_eq!(response_body.project_id, expected_project_id);
        assert_eq!(
            response_body.message,
            "Project registered successfully, and signers file activated."
        );
        // The submitter signed the signers file and the metadata with the
        // registration, so the single signer activated the file.
        assert!(response_body.required_signers.is_empty());

        mock.assert();
        server_handle.abort();

        Ok(())
    }

    /// The server must store the exact bytes the client signed. The stored
    /// signers file and metadata file must equal the request bytes, so the
    /// recorded signatures verify against what is on disk.
    #[tokio::test]
    async fn test_register_repo_records_client_signatures() -> Result<(), anyhow::Error> {
        use common::fs::names::metadata_path_for;
        use constants::{PENDING_SIGNERS_DIR, SIGNERS_DIR, SIGNERS_FILE};
        use features_lib::AsfaloadPublicKeyTrait;
        use httpmock::Method;
        use rest_api_types::RegisterRepoResponse;

        let temp_dir = TempDir::new()?;
        let git_repo_path = temp_dir.path().join("git_repo");
        init_git_repo(&git_repo_path)?;

        // Mock publishing server where signers file is published as trust anchor
        let mock_server = httpmock::MockServer::start();
        let test_keys = test_helpers::TestKeys::new(1);
        let public_key = test_keys.pub_key(0).unwrap();
        let secret_key = test_keys.sec_key(0).unwrap();

        let signers_config = signers_file_types::SignersConfig::with_artifact_signers_only(
            1,
            (vec![public_key.clone()], 1),
        )?;
        let signers_json = serde_json::to_string_pretty(&signers_config)?;

        let signers_json_clone = signers_json.clone();
        let mock = mock_server.mock(|when, then| {
            when.method(Method::GET)
                .path("/owner/repo/main/signers.json");
            then.status(200)
                .header("Content-Type", "application/json")
                .body(signers_json_clone);
        });

        let signers_url = format!("{}/owner/repo/main/signers.json", mock_server.url(""));
        let (metadata, metadata_signature) =
            crate::metadata_and_signature_for(&signers_url, &signers_json, &secret_key)?;

        let port = get_random_port().await?;
        let config = build_test_config(&git_repo_path, port);
        let config_clone = config.clone();
        let server_handle = tokio::spawn(async move { run_server(&config_clone).await });
        wait_for_server(&config, None).await?;

        let request_body = RegisterRepoRequest {
            signers_file_url: signers_url,
            public_key: public_key.to_base64(),
            signature: signature_for_sha(signers_json.as_bytes(), &secret_key)?,
            metadata: metadata.clone(),
            metadata_signature,
        };
        let payload_string = serde_json::to_string(&request_body)?;
        let TestAuthHeaders {
            timestamp,
            nonce,
            signature: auth_signature,
            public_key: auth_public_key,
        } = create_auth_headers_with_key(secret_key, &payload_string).await;

        let response = reqwest::Client::new()
            .post(format!("http://localhost:{}/v1/register_repo", port))
            .header(HEADER_TIMESTAMP, timestamp)
            .header(HEADER_NONCE, nonce)
            .header(HEADER_SIGNATURE, auth_signature)
            .header(HEADER_PUBLIC_KEY, auth_public_key)
            .json(&request_body)
            .send()
            .await?;

        assert_eq!(response.status(), StatusCode::OK);

        let response_body = response.json::<RegisterRepoResponse>().await?;
        assert!(response_body.success);
        assert_eq!(
            response_body.message,
            "Project registered successfully, and signers file activated."
        );

        let project_id = format!("http/127.0.0.1/{}/owner/repo", mock_server.port());
        let project_paths =
            rest_api::file_auth::github::get_project_normalised_paths(&git_repo_path, &project_id)
                .await?;
        let project_dir = project_paths.absolute_path();
        let signers_file_path = project_dir.join(SIGNERS_DIR).join(SIGNERS_FILE);

        let stored_signers = tokio::fs::read(&signers_file_path).await?;
        assert_eq!(
            stored_signers,
            signers_json.as_bytes(),
            "the stored signers file must equal the signed bytes"
        );

        let stored_metadata = tokio::fs::read(metadata_path_for(&signers_file_path)?).await?;
        let sent_metadata = common::string_from_base64(&metadata).map_err(anyhow::Error::msg)?;
        assert_eq!(
            stored_metadata,
            sent_metadata.as_bytes(),
            "the stored metadata must equal the signed bytes"
        );

        assert!(
            !project_dir.join(PENDING_SIGNERS_DIR).exists(),
            "an activated registration must not leave a pending directory"
        );

        mock.assert();
        server_handle.abort();

        Ok(())
    }

    #[tokio::test]
    async fn test_register_repo_success_without_immediate_activation() -> Result<(), anyhow::Error>
    {
        use features_lib::AsfaloadPublicKeyTrait;
        use httpmock::Method;
        use rest_api_types::RegisterRepoRequest;
        use rest_api_types::RegisterRepoResponse;

        let temp_dir = TempDir::new()?;
        let git_repo_path = temp_dir.path().join("git_repo");

        init_git_repo(&git_repo_path)?;

        let mock_server = httpmock::MockServer::start();

        let test_keys = test_helpers::TestKeys::new(2);
        let public_key = test_keys.pub_key(0).unwrap();
        let secret_key = test_keys.sec_key(0).unwrap();

        let public_key_2 = test_keys.pub_key(1).unwrap();
        let signers_config = signers_file_types::SignersConfig::with_artifact_signers_only(
            1,
            (vec![public_key.clone(), public_key_2.clone()], 1),
        )?;

        let signers_json = serde_json::to_string_pretty(&signers_config)?;

        let signers_json_clone = signers_json.clone();
        let mock = mock_server.mock(|when, then| {
            when.method(Method::GET)
                .path("/owner/repo/main/signers.json");
            then.status(200)
                .header("Content-Type", "application/json")
                .body(signers_json_clone);
        });

        let signers_url = format!("{}/owner/repo/main/signers.json", mock_server.url(""));

        let port = get_random_port().await?;
        let config = build_test_config(&git_repo_path, port);
        let config_clone = config.clone();
        let server_handle = tokio::spawn(async move { run_server(&config_clone).await });
        wait_for_server(&config, None).await?;

        let client = reqwest::Client::new();

        let (metadata, metadata_signature) =
            crate::metadata_and_signature_for(&signers_url, &signers_json, &secret_key)?;
        let request_body = RegisterRepoRequest {
            signers_file_url: signers_url,
            public_key: public_key.to_base64(),
            signature: signature_for_sha(signers_json.as_bytes(), &secret_key)?,
            metadata,
            metadata_signature,
        };
        let payload_string = serde_json::to_string(&request_body)?;
        let TestAuthHeaders {
            timestamp,
            nonce,
            signature: auth_signature,
            public_key: auth_public_key,
        } = create_auth_headers_with_key(secret_key, &payload_string).await;

        let response = client
            .post(format!("http://localhost:{}/v1/register_repo", port))
            .header(HEADER_TIMESTAMP, timestamp)
            .header(HEADER_NONCE, nonce)
            .header(HEADER_SIGNATURE, auth_signature)
            .header(HEADER_PUBLIC_KEY, auth_public_key)
            .json(&request_body)
            .send()
            .await?;

        assert_eq!(response.status(), StatusCode::OK);

        let response_body = response.json::<RegisterRepoResponse>().await?;
        assert!(response_body.success);
        let expected_project_id = format!("http/127.0.0.1/{}/owner/repo", mock_server.port());
        assert_eq!(response_body.project_id, expected_project_id);
        assert_eq!(
            response_body.message,
            "Project registered successfully. Collect signatures to activate."
        );
        // The submitter's registration signatures are recorded, so only the
        // second signer is still missing.
        assert_eq!(response_body.required_signers.len(), 1);
        assert_eq!(response_body.required_signers[0], public_key_2.to_base64());
        assert_eq!(response_body.signature_submission_url, "/v1/signatures");

        mock.assert();
        server_handle.abort();

        Ok(())
    }

    #[tokio::test]
    async fn test_register_repo_rejects_metadata_from_the_future() -> Result<(), anyhow::Error> {
        use features_lib::AsfaloadPublicKeyTrait;
        use httpmock::Method;
        use rest_api_types::RegisterRepoRequest;

        let temp_dir = TempDir::new()?;
        let git_repo_path = temp_dir.path().join("git_repo");
        init_git_repo(&git_repo_path)?;

        let mock_server = httpmock::MockServer::start();

        let test_keys = test_helpers::TestKeys::new(1);
        let public_key = test_keys.pub_key(0).unwrap();
        let secret_key = test_keys.sec_key(0).unwrap();

        let signers_config = signers_file_types::SignersConfig::with_artifact_signers_only(
            1,
            (vec![public_key.clone()], 1),
        )?;
        let signers_json = serde_json::to_string_pretty(&signers_config)?;

        let signers_json_clone = signers_json.clone();
        let mock = mock_server.mock(|when, then| {
            when.method(Method::GET)
                .path("/owner/repo/main/signers.json");
            then.status(200)
                .header("Content-Type", "application/json")
                .body(signers_json_clone);
        });

        let signers_url = format!("{}/owner/repo/main/signers.json", mock_server.url(""));

        let port = get_random_port().await?;
        let config = build_test_config(&git_repo_path, port);
        let config_clone = config.clone();
        let server_handle = tokio::spawn(async move { run_server(&config_clone).await });
        wait_for_server(&config, None).await?;

        let client = reqwest::Client::new();

        // A retrieved_at beyond the accepted clock skew must be rejected,
        // even though the metadata is otherwise perfectly valid. The check
        // runs before the forge fetch, so no mock call is expected.
        let retrieved_at = chrono::Utc::now() + chrono::Duration::seconds(60);
        let (metadata, metadata_signature) = crate::metadata_and_signature_for_at(
            &signers_url,
            &signers_json,
            retrieved_at,
            &secret_key,
        )?;
        let request_body = RegisterRepoRequest {
            signers_file_url: signers_url,
            public_key: public_key.to_base64(),
            signature: signature_for_sha(signers_json.as_bytes(), &secret_key)?,
            metadata,
            metadata_signature,
        };
        let payload_string = serde_json::to_string(&request_body)?;
        let TestAuthHeaders {
            timestamp,
            nonce,
            signature: auth_signature,
            public_key: auth_public_key,
        } = create_auth_headers_with_key(secret_key, &payload_string).await;

        let response = client
            .post(format!("http://localhost:{}/v1/register_repo", port))
            .header(HEADER_TIMESTAMP, timestamp)
            .header(HEADER_NONCE, nonce)
            .header(HEADER_SIGNATURE, auth_signature)
            .header(HEADER_PUBLIC_KEY, auth_public_key)
            .json(&request_body)
            .send()
            .await?;

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let response_body: serde_json::Value = response.json().await?;
        let error_msg = response_body
            .get("error")
            .and_then(|e| e.as_str())
            .unwrap_or("");
        assert!(
            error_msg.contains("too far in the future"),
            "Unexpected error message: {}",
            error_msg
        );
        mock.assert_calls(0);

        server_handle.abort();

        Ok(())
    }

    #[tokio::test]
    async fn test_register_repo_rejects_stale_metadata() -> Result<(), anyhow::Error> {
        use features_lib::AsfaloadPublicKeyTrait;
        use httpmock::Method;
        use rest_api_types::RegisterRepoRequest;

        let temp_dir = TempDir::new()?;
        let git_repo_path = temp_dir.path().join("git_repo");
        init_git_repo(&git_repo_path)?;

        let mock_server = httpmock::MockServer::start();

        let test_keys = test_helpers::TestKeys::new(1);
        let public_key = test_keys.pub_key(0).unwrap();
        let secret_key = test_keys.sec_key(0).unwrap();

        let signers_config = signers_file_types::SignersConfig::with_artifact_signers_only(
            1,
            (vec![public_key.clone()], 1),
        )?;
        let signers_json = serde_json::to_string_pretty(&signers_config)?;

        let signers_json_clone = signers_json.clone();
        let mock = mock_server.mock(|when, then| {
            when.method(Method::GET)
                .path("/owner/repo/main/signers.json");
            then.status(200)
                .header("Content-Type", "application/json")
                .body(signers_json_clone);
        });

        let signers_url = format!("{}/owner/repo/main/signers.json", mock_server.url(""));

        let port = get_random_port().await?;
        let config = build_test_config(&git_repo_path, port);
        let config_clone = config.clone();
        let server_handle = tokio::spawn(async move { run_server(&config_clone).await });
        wait_for_server(&config, None).await?;

        let client = reqwest::Client::new();

        // A retrieved_at older than the accepted metadata age must be
        // rejected, even though the metadata is otherwise perfectly valid.
        // The check runs before the forge fetch, so no mock call is
        // expected.
        let retrieved_at = chrono::Utc::now() - chrono::Duration::seconds(120);
        let (metadata, metadata_signature) = crate::metadata_and_signature_for_at(
            &signers_url,
            &signers_json,
            retrieved_at,
            &secret_key,
        )?;
        let request_body = RegisterRepoRequest {
            signers_file_url: signers_url,
            public_key: public_key.to_base64(),
            signature: signature_for_sha(signers_json.as_bytes(), &secret_key)?,
            metadata,
            metadata_signature,
        };
        let payload_string = serde_json::to_string(&request_body)?;
        let TestAuthHeaders {
            timestamp,
            nonce,
            signature: auth_signature,
            public_key: auth_public_key,
        } = create_auth_headers_with_key(secret_key, &payload_string).await;

        let response = client
            .post(format!("http://localhost:{}/v1/register_repo", port))
            .header(HEADER_TIMESTAMP, timestamp)
            .header(HEADER_NONCE, nonce)
            .header(HEADER_SIGNATURE, auth_signature)
            .header(HEADER_PUBLIC_KEY, auth_public_key)
            .json(&request_body)
            .send()
            .await?;

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let response_body: serde_json::Value = response.json().await?;
        let error_msg = response_body
            .get("error")
            .and_then(|e| e.as_str())
            .unwrap_or("");
        assert!(
            error_msg.contains("too far in the past"),
            "Unexpected error message: {}",
            error_msg
        );
        mock.assert_calls(0);

        server_handle.abort();

        Ok(())
    }

    /// Every client-provided metadata failure must be reported as a client
    /// error. A 5xx here would blame the server for input it rejected on
    /// purpose, and would leak parsing details.
    #[tokio::test]
    async fn test_register_repo_rejects_invalid_client_metadata() -> Result<(), anyhow::Error> {
        use features_lib::AsfaloadPublicKeyTrait;
        use httpmock::Method;

        let temp_dir = TempDir::new()?;
        let git_repo_path = temp_dir.path().join("git_repo");
        init_git_repo(&git_repo_path)?;

        let mock_server = httpmock::MockServer::start();

        let test_keys = test_helpers::TestKeys::new(2);
        let public_key = test_keys.pub_key(0).unwrap();
        let secret_key = test_keys.sec_key(0).unwrap();
        let other_secret_key = test_keys.sec_key(1).unwrap();

        let signers_config = signers_file_types::SignersConfig::with_artifact_signers_only(
            1,
            (vec![public_key.clone()], 1),
        )?;
        let signers_json = serde_json::to_string_pretty(&signers_config)?;

        let signers_json_clone = signers_json.clone();
        let mock = mock_server.mock(|when, then| {
            when.method(Method::GET)
                .path("/owner/repo/main/signers.json");
            then.status(200)
                .header("Content-Type", "application/json")
                .body(signers_json_clone);
        });

        let signers_url = format!("{}/owner/repo/main/signers.json", mock_server.url(""));

        let port = get_random_port().await?;
        let config = build_test_config(&git_repo_path, port);
        let config_clone = config.clone();
        let server_handle = tokio::spawn(async move { run_server(&config_clone).await });
        wait_for_server(&config, None).await?;

        let now = chrono::Utc::now();
        let valid_metadata_json = crate::metadata_json_for_at(&signers_url, &signers_json, now)?;
        // Valid metadata structure, but its content hash is that of another
        // signers file, so the backend metadata comparison must fail.
        let metadata_for_other_content =
            crate::metadata_json_for_at(&signers_url, "another signers file content", now)?;

        let signed = |content: &str, key: &features_lib::AsfaloadSecretKeys| {
            signature_for_sha(content.as_bytes(), key)
        };

        // (case name, metadata field, metadata signature, expected status,
        // expected error fragment, whether the forge is fetched)
        let cases = vec![
            (
                "metadata is not base64",
                "not base64 at all!".to_string(),
                signed(&valid_metadata_json, secret_key)?,
                StatusCode::BAD_REQUEST,
                "Could not base64 decode metadata",
                false,
            ),
            (
                "metadata is not a metadata document",
                common::base64_for_string(r#"{"data":{"Forge":{}}}"#),
                signed(r#"{"data":{"Forge":{}}}"#, secret_key)?,
                StatusCode::BAD_REQUEST,
                "Could not deserialise metadata",
                false,
            ),
            (
                "metadata is empty",
                common::base64_for_string(""),
                // A valid signature over different content. The server must
                // reject the empty content before it verifies the signature,
                // so the signature is never checked.
                signed("some other content", secret_key)?,
                StatusCode::BAD_REQUEST,
                "Could not deserialise metadata",
                false,
            ),
            (
                "metadata signature is not base64",
                common::base64_for_string(valid_metadata_json.clone()),
                "not base64 at all!".to_string(),
                StatusCode::BAD_REQUEST,
                "Invalid signature",
                true,
            ),
            (
                "metadata is signed by another key",
                common::base64_for_string(valid_metadata_json.clone()),
                signed(&valid_metadata_json, other_secret_key)?,
                StatusCode::UNAUTHORIZED,
                "Signature verification failed",
                true,
            ),
            (
                "metadata describes other signers content",
                common::base64_for_string(metadata_for_other_content.clone()),
                signed(&metadata_for_other_content, secret_key)?,
                StatusCode::BAD_REQUEST,
                "different from the client-provided",
                true,
            ),
        ];

        for (
            name,
            metadata,
            metadata_signature,
            expected_status,
            expected_error,
            expects_forge_fetch,
        ) in cases
        {
            let hits_before = mock.hits();
            let request_body = RegisterRepoRequest {
                signers_file_url: signers_url.clone(),
                public_key: public_key.to_base64(),
                signature: signature_for_sha(signers_json.as_bytes(), secret_key)?,
                metadata,
                metadata_signature,
            };
            let payload_string = serde_json::to_string(&request_body)?;
            let TestAuthHeaders {
                timestamp,
                nonce,
                signature: auth_signature,
                public_key: auth_public_key,
            } = create_auth_headers_with_key(secret_key, &payload_string).await;

            let response = reqwest::Client::new()
                .post(format!("http://localhost:{}/v1/register_repo", port))
                .header(HEADER_TIMESTAMP, timestamp)
                .header(HEADER_NONCE, nonce)
                .header(HEADER_SIGNATURE, auth_signature)
                .header(HEADER_PUBLIC_KEY, auth_public_key)
                .json(&request_body)
                .send()
                .await?;

            assert_eq!(
                response.status(),
                expected_status,
                "case '{}' got an unexpected status",
                name
            );
            let response_body: serde_json::Value = response.json().await?;
            let error_msg = response_body
                .get("error")
                .and_then(|e| e.as_str())
                .unwrap_or("");
            assert!(
                error_msg.contains(expected_error),
                "case '{}': expected an error containing '{}', got: {}",
                name,
                expected_error,
                error_msg
            );

            let expected_hits = if expects_forge_fetch { 1 } else { 0 };
            assert_eq!(
                mock.hits() - hits_before,
                expected_hits,
                "case '{}': expected {} forge fetch(es)",
                name,
                expected_hits
            );
        }

        // Only the cases rejected at deserialization time (invalid base64,
        // not a metadata document, empty) are handled before the forge
        // fetch; the remaining three reach the metadata validation.
        mock.assert_calls(3);

        // Rejected registrations must not create the project directory.
        let project_id = format!("http/127.0.0.1/{}/owner/repo", mock_server.port());
        let project_paths =
            rest_api::file_auth::github::get_project_normalised_paths(&git_repo_path, &project_id)
                .await?;
        assert!(
            !project_paths.absolute_path().exists(),
            "a rejected registration must not create the project directory"
        );

        server_handle.abort();

        Ok(())
    }

    /// Starts the REST server on a random port for the given git repo.
    /// Returns the server port and the server task handle.
    async fn start_test_server(
        git_repo_path: &std::path::Path,
    ) -> anyhow::Result<(
        u16,
        tokio::task::JoinHandle<Result<(), rest_api_types::errors::ApiError>>,
    )> {
        let port = get_random_port().await?;
        let config = build_test_config(git_repo_path, port);
        let config_clone = config.clone();
        let server_handle = tokio::spawn(async move { run_server(&config_clone).await });
        wait_for_server(&config, None).await?;
        Ok((port, server_handle))
    }

    /// Seeds an active signers file (with its metadata and signature files)
    /// directly in the project directory of `project_id`, the way
    /// `TestSetupBuilder` does, and commits it. The submitter must be an
    /// admin key of `signers_config` to be allowed to propose updates.
    async fn seed_active_project(
        git_repo_path: &std::path::Path,
        project_id: &str,
        signers_config: &signers_file_types::SignersConfig,
        public_key: &features_lib::AsfaloadPublicKeys,
        secret_key: &features_lib::AsfaloadSecretKeys,
    ) -> anyhow::Result<()> {
        use common::fs::names::{
            metadata_path_for, metadata_signatures_path_for, signatures_path_for,
        };
        use constants::{SIGNERS_DIR, SIGNERS_FILE};
        use features_lib::{
            AsfaloadPublicKeyTrait, AsfaloadSecretKeyTrait, AsfaloadSignatureTrait, SignaturesFile,
            TaggedSignature,
        };

        let project_paths =
            rest_api::file_auth::github::get_project_normalised_paths(git_repo_path, project_id)
                .await?;
        let project_dir = project_paths.absolute_path();

        let signers_dir = project_dir.join(SIGNERS_DIR);
        tokio::fs::create_dir_all(&signers_dir).await?;
        let signers_json = signers_config.to_json()?;
        tokio::fs::write(signers_dir.join(SIGNERS_FILE), &signers_json).await?;

        // Metadata file. Its content is replaced by the update proposal, so
        // the test metadata is good enough here.
        let metadata = test_helpers::test_metadata();
        let metadata_path = metadata_path_for(signers_dir.join(SIGNERS_FILE))?;
        tokio::fs::write(&metadata_path, serde_json::to_string_pretty(&metadata)?).await?;

        // Signatures file for the signers config, signed by the submitter.
        let signers_hash = common::sha512_for_content(signers_json.as_bytes())?;
        let mut signers_signatures = SignaturesFile::new();
        signers_signatures.entries.insert(
            public_key.to_base64(),
            TaggedSignature {
                format: public_key.key_format(),
                signature: secret_key.sign(&signers_hash)?.to_base64(),
            },
        );
        tokio::fs::write(
            signatures_path_for(&signers_dir.join(SIGNERS_FILE))?,
            serde_json::to_string(&signers_signatures)?,
        )
        .await?;

        // Signatures file for the metadata, signed by the submitter.
        let metadata_content = tokio::fs::read(&metadata_path).await?;
        let metadata_hash = common::sha512_for_content(metadata_content.as_slice())?;
        let mut metadata_signatures = SignaturesFile::new();
        metadata_signatures.entries.insert(
            public_key.to_base64(),
            TaggedSignature {
                format: public_key.key_format(),
                signature: secret_key.sign(&metadata_hash)?.to_base64(),
            },
        );
        tokio::fs::write(
            metadata_signatures_path_for(&signers_dir.join(SIGNERS_FILE))?,
            serde_json::to_string(&metadata_signatures)?,
        )
        .await?;

        let signers_rel_path = format!(
            "{}/{}",
            project_paths.relative_path().display(),
            SIGNERS_DIR
        );
        rest_api_test_helpers::git_commit(
            git_repo_path,
            &[signers_rel_path.as_str()],
            "initial signers config",
        )?;

        Ok(())
    }

    /// Submit a signers file update for the project served on `port`, with
    /// metadata carrying the given `retrieved_at` timestamp.
    ///
    /// Returns the response together with the metadata content the client
    /// sent, so tests checking the stored proposal can compare the stored
    /// bytes against the signed ones.
    async fn post_update_signers(
        port: u16,
        signers_url: &str,
        signers_json: &str,
        retrieved_at: chrono::DateTime<chrono::Utc>,
        public_key: &features_lib::AsfaloadPublicKeys,
        secret_key: &features_lib::AsfaloadSecretKeys,
    ) -> anyhow::Result<(reqwest::Response, String)> {
        use features_lib::AsfaloadPublicKeyTrait;

        let (metadata, metadata_signature) = crate::metadata_and_signature_for_at(
            signers_url,
            signers_json,
            retrieved_at,
            secret_key,
        )?;
        let request_body = RegisterRepoRequest {
            signers_file_url: signers_url.to_string(),
            public_key: public_key.to_base64(),
            signature: signature_for_sha(signers_json.as_bytes(), secret_key)?,
            metadata,
            metadata_signature,
        };
        let response = post_update_signers_request(port, &request_body, secret_key).await?;
        let sent_metadata =
            common::string_from_base64(&request_body.metadata).map_err(anyhow::Error::msg)?;
        Ok((response, sent_metadata))
    }

    /// POST an already-built update request to the update endpoint, with the
    /// authentication headers computed over the serialised request.
    ///
    /// Used by tests that need full control over the request fields to
    /// exercise the backend input validation.
    async fn post_update_signers_request(
        port: u16,
        request_body: &RegisterRepoRequest,
        secret_key: &features_lib::AsfaloadSecretKeys,
    ) -> anyhow::Result<reqwest::Response> {
        let payload_string = serde_json::to_string(request_body)?;
        let TestAuthHeaders {
            timestamp,
            nonce,
            signature: auth_signature,
            public_key: auth_public_key,
        } = create_auth_headers_with_key(secret_key, &payload_string).await;

        let client = reqwest::Client::new();
        Ok(client
            .post(format!("http://localhost:{}/v1/update_signers", port))
            .header(HEADER_TIMESTAMP, timestamp)
            .header(HEADER_NONCE, nonce)
            .header(HEADER_SIGNATURE, auth_signature)
            .header(HEADER_PUBLIC_KEY, auth_public_key)
            .json(request_body)
            .send()
            .await?)
    }

    #[tokio::test]
    async fn test_update_signers_success() -> Result<(), anyhow::Error> {
        use constants::{PENDING_SIGNERS_DIR, SIGNERS_FILE};
        use httpmock::Method;
        use rest_api_types::RegisterRepoResponse;

        let temp_dir = TempDir::new()?;
        let git_repo_path = temp_dir.path().join("git_repo");
        init_git_repo(&git_repo_path)?;

        let mock_server = httpmock::MockServer::start();

        let test_keys = test_helpers::TestKeys::new(2);
        let public_key = test_keys.pub_key(0).unwrap();
        let secret_key = test_keys.sec_key(0).unwrap();
        let added_public_key = test_keys.pub_key(1).unwrap();

        // The submitter must be an admin key of the active signers file to
        // be allowed to propose an update.
        let initial_config = signers_file_types::SignersConfig::with_keys(
            1,
            (vec![public_key.clone()], 1),
            Some((vec![public_key.clone()], 1)),
            None,
            None,
        )?;
        let project_id = format!("http/127.0.0.1/{}/owner/repo", mock_server.port());
        seed_active_project(
            &git_repo_path,
            &project_id,
            &initial_config,
            &public_key,
            &secret_key,
        )
        .await?;

        let (port, server_handle) = start_test_server(&git_repo_path).await?;

        // The updated signers file adds an artifact signer. Its timestamp is
        // set at creation time, so it is always newer than the active file's.
        let updated_config = signers_file_types::SignersConfig::with_keys(
            2,
            (vec![public_key.clone(), added_public_key.clone()], 2),
            Some((vec![public_key.clone()], 1)),
            None,
            None,
        )?;
        let updated_signers_json = updated_config.to_json()?;

        let updated_json_clone = updated_signers_json.clone();
        let update_mock = mock_server.mock(|when, then| {
            when.method(Method::GET)
                .path("/owner/repo/main/signers.json");
            then.status(200)
                .header("Content-Type", "application/json")
                .body(updated_json_clone);
        });

        let signers_url = format!("{}/owner/repo/main/signers.json", mock_server.url(""));
        let (response, sent_metadata) = post_update_signers(
            port,
            &signers_url,
            &updated_signers_json,
            chrono::Utc::now(),
            &public_key,
            &secret_key,
        )
        .await?;

        assert_eq!(response.status(), StatusCode::OK);

        let response_body = response.json::<RegisterRepoResponse>().await?;
        assert!(response_body.success);
        assert_eq!(response_body.project_id, project_id);
        assert_eq!(
            response_body.message,
            "Signers update proposed successfully. Collect signatures to activate."
        );
        // The submitter's signatures are recorded with the proposal: only the
        // second artifact signer is still missing.
        assert_eq!(response_body.required_signers.len(), 1);

        // The proposal must be stored in the pending directory with the
        // exact bytes the client sent and signed.
        use common::fs::names::{
            metadata_path_for, metadata_signatures_path_for, pending_signatures_path_for,
        };
        use features_lib::{
            AsfaloadPublicKeyTrait, AsfaloadSignatureTrait, SignaturesFile, TaggedSignature,
        };

        let project_paths =
            rest_api::file_auth::github::get_project_normalised_paths(&git_repo_path, &project_id)
                .await?;
        let project_dir = project_paths.absolute_path();
        let pending_signers_file = project_dir.join(PENDING_SIGNERS_DIR).join(SIGNERS_FILE);

        let stored_signers = tokio::fs::read(&pending_signers_file).await?;
        assert_eq!(
            stored_signers,
            updated_signers_json.as_bytes(),
            "the stored proposed signers file must equal the signed bytes"
        );

        let pending_metadata_file = metadata_path_for(&pending_signers_file)?;
        let stored_metadata = tokio::fs::read(&pending_metadata_file).await?;
        assert_eq!(
            stored_metadata,
            sent_metadata.as_bytes(),
            "the stored proposed metadata must equal the signed bytes"
        );

        // The submitter's signatures over both stored files must be
        // recorded, and must verify against the stored bytes. The metadata
        // signatures are in the complete signatures file when the metadata
        // aggregate is complete, else in the pending one.
        let signers_sigs_path = pending_signatures_path_for(&pending_signers_file)?;
        let metadata_sigs_path = {
            let complete_path = metadata_signatures_path_for(&pending_signers_file)?;
            if complete_path.exists() {
                complete_path
            } else {
                pending_signatures_path_for(&pending_metadata_file)?
            }
        };

        for (sigs_path, stored_content) in [
            (&signers_sigs_path, &stored_signers),
            (&metadata_sigs_path, &stored_metadata),
        ] {
            assert!(
                sigs_path.exists(),
                "signatures must be stored for the proposal: {}",
                sigs_path.display()
            );
            let sigs: SignaturesFile = serde_json::from_reader(std::fs::File::open(sigs_path)?)?;
            let recorded: &TaggedSignature =
                sigs.entries.get(&public_key.to_base64()).ok_or_else(|| {
                    anyhow::anyhow!(
                        "the submitter's signature must be recorded in {}",
                        sigs_path.display()
                    )
                })?;
            let recorded_signature =
                features_lib::AsfaloadSignatures::from_base64(&recorded.signature)?;
            let hash = common::sha512_for_content(stored_content.as_slice())?;
            assert!(
                public_key.verify(&recorded_signature, &hash).is_ok(),
                "the recorded signature must verify against the stored bytes"
            );
            assert!(
                !sigs.entries.contains_key(&added_public_key.to_base64()),
                "the second signer must not be recorded before its signature submission"
            );
        }

        update_mock.assert_calls(1);
        server_handle.abort();

        Ok(())
    }

    /// The submitter is the only required signer of the updated config, so its
    /// signature completes the update and the signers file becomes active at
    /// once.
    #[tokio::test]
    async fn test_update_signers_activates_at_once() -> Result<(), anyhow::Error> {
        use constants::{PENDING_SIGNERS_DIR, SIGNERS_DIR};
        use httpmock::Method;
        use rest_api_types::RegisterRepoResponse;

        let temp_dir = TempDir::new()?;
        let git_repo_path = temp_dir.path().join("git_repo");
        init_git_repo(&git_repo_path)?;

        let mock_server = httpmock::MockServer::start();

        let test_keys = test_helpers::TestKeys::new(1);
        let public_key = test_keys.pub_key(0).unwrap();
        let secret_key = test_keys.sec_key(0).unwrap();

        // The submitter must be an admin key of the active signers file to
        // be allowed to propose an update.
        let initial_config = signers_file_types::SignersConfig::with_keys(
            1,
            (vec![public_key.clone()], 1),
            Some((vec![public_key.clone()], 1)),
            None,
            None,
        )?;
        let project_id = format!("http/127.0.0.1/{}/owner/repo", mock_server.port());
        seed_active_project(
            &git_repo_path,
            &project_id,
            &initial_config,
            &public_key,
            &secret_key,
        )
        .await?;

        let (port, server_handle) = start_test_server(&git_repo_path).await?;

        // The updated config requires only the submitter. Its signature
        // therefore completes the update.
        let updated_config = signers_file_types::SignersConfig::with_keys(
            2,
            (vec![public_key.clone()], 1),
            Some((vec![public_key.clone()], 1)),
            None,
            None,
        )?;
        let updated_signers_json = updated_config.to_json()?;

        let updated_json_clone = updated_signers_json.clone();
        let update_mock = mock_server.mock(|when, then| {
            when.method(Method::GET)
                .path("/owner/repo/main/signers.json");
            then.status(200)
                .header("Content-Type", "application/json")
                .body(updated_json_clone);
        });

        let signers_url = format!("{}/owner/repo/main/signers.json", mock_server.url(""));
        let (response, _sent_metadata) = post_update_signers(
            port,
            &signers_url,
            &updated_signers_json,
            chrono::Utc::now(),
            &public_key,
            &secret_key,
        )
        .await?;

        assert_eq!(response.status(), StatusCode::OK);

        let response_body = response.json::<RegisterRepoResponse>().await?;
        assert!(response_body.success);
        assert_eq!(response_body.project_id, project_id);
        assert_eq!(
            response_body.message,
            "Signers updated successfully, and signers file activated."
        );
        assert!(response_body.required_signers.is_empty());

        // The updated file is active and the pending directory is gone.
        let project_paths =
            rest_api::file_auth::github::get_project_normalised_paths(&git_repo_path, &project_id)
                .await?;
        let project_dir = project_paths.absolute_path();
        assert!(
            project_dir
                .join(SIGNERS_DIR)
                .join(constants::SIGNERS_FILE)
                .exists(),
            "the updated signers file must be active"
        );
        assert!(
            !project_dir.join(PENDING_SIGNERS_DIR).exists(),
            "no pending signers directory must remain"
        );

        update_mock.assert_calls(1);
        server_handle.abort();

        Ok(())
    }

    #[tokio::test]
    async fn test_update_signers_rejects_stale_metadata() -> Result<(), anyhow::Error> {
        use httpmock::Method;

        let temp_dir = TempDir::new()?;
        let git_repo_path = temp_dir.path().join("git_repo");
        init_git_repo(&git_repo_path)?;

        let mock_server = httpmock::MockServer::start();

        let test_keys = test_helpers::TestKeys::new(2);
        let public_key = test_keys.pub_key(0).unwrap();
        let secret_key = test_keys.sec_key(0).unwrap();
        let added_public_key = test_keys.pub_key(1).unwrap();

        let initial_config = signers_file_types::SignersConfig::with_keys(
            1,
            (vec![public_key.clone()], 1),
            Some((vec![public_key.clone()], 1)),
            None,
            None,
        )?;
        let project_id = format!("http/127.0.0.1/{}/owner/repo", mock_server.port());
        seed_active_project(
            &git_repo_path,
            &project_id,
            &initial_config,
            &public_key,
            &secret_key,
        )
        .await?;

        let (port, server_handle) = start_test_server(&git_repo_path).await?;

        let updated_config = signers_file_types::SignersConfig::with_keys(
            2,
            (vec![public_key.clone(), added_public_key.clone()], 2),
            Some((vec![public_key.clone()], 1)),
            None,
            None,
        )?;
        let updated_signers_json = updated_config.to_json()?;

        let updated_json_clone = updated_signers_json.clone();
        let update_mock = mock_server.mock(|when, then| {
            when.method(Method::GET)
                .path("/owner/repo/main/signers.json");
            then.status(200)
                .header("Content-Type", "application/json")
                .body(updated_json_clone);
        });

        let signers_url = format!("{}/owner/repo/main/signers.json", mock_server.url(""));

        // A retrieved_at older than the accepted metadata age must be
        // rejected, even though the metadata is otherwise perfectly valid.
        let (response, _sent_metadata) = post_update_signers(
            port,
            &signers_url,
            &updated_signers_json,
            chrono::Utc::now() - chrono::Duration::seconds(120),
            &public_key,
            &secret_key,
        )
        .await?;

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let response_body: serde_json::Value = response.json().await?;
        let error_msg = response_body
            .get("error")
            .and_then(|e| e.as_str())
            .unwrap_or("");
        assert!(
            error_msg.contains("too far in the past"),
            "Unexpected error message: {}",
            error_msg
        );
        // The metadata timing check runs before the forge fetch, so the
        // request is rejected before any write and without a mock call.
        update_mock.assert_calls(0);

        server_handle.abort();

        Ok(())
    }

    #[tokio::test]
    async fn test_update_signers_rejects_metadata_from_the_future() -> Result<(), anyhow::Error> {
        use httpmock::Method;

        let temp_dir = TempDir::new()?;
        let git_repo_path = temp_dir.path().join("git_repo");
        init_git_repo(&git_repo_path)?;

        let mock_server = httpmock::MockServer::start();

        let test_keys = test_helpers::TestKeys::new(2);
        let public_key = test_keys.pub_key(0).unwrap();
        let secret_key = test_keys.sec_key(0).unwrap();
        let added_public_key = test_keys.pub_key(1).unwrap();

        let initial_config = signers_file_types::SignersConfig::with_keys(
            1,
            (vec![public_key.clone()], 1),
            Some((vec![public_key.clone()], 1)),
            None,
            None,
        )?;
        let project_id = format!("http/127.0.0.1/{}/owner/repo", mock_server.port());
        seed_active_project(
            &git_repo_path,
            &project_id,
            &initial_config,
            &public_key,
            &secret_key,
        )
        .await?;

        let (port, server_handle) = start_test_server(&git_repo_path).await?;

        let updated_config = signers_file_types::SignersConfig::with_keys(
            2,
            (vec![public_key.clone(), added_public_key.clone()], 2),
            Some((vec![public_key.clone()], 1)),
            None,
            None,
        )?;
        let updated_signers_json = updated_config.to_json()?;

        let updated_json_clone = updated_signers_json.clone();
        let update_mock = mock_server.mock(|when, then| {
            when.method(Method::GET)
                .path("/owner/repo/main/signers.json");
            then.status(200)
                .header("Content-Type", "application/json")
                .body(updated_json_clone);
        });

        let signers_url = format!("{}/owner/repo/main/signers.json", mock_server.url(""));

        // A retrieved_at beyond the accepted clock skew must be rejected,
        // even though the metadata is otherwise perfectly valid.
        let (response, _sent_metadata) = post_update_signers(
            port,
            &signers_url,
            &updated_signers_json,
            chrono::Utc::now() + chrono::Duration::seconds(60),
            &public_key,
            &secret_key,
        )
        .await?;

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let response_body: serde_json::Value = response.json().await?;
        let error_msg = response_body
            .get("error")
            .and_then(|e| e.as_str())
            .unwrap_or("");
        assert!(
            error_msg.contains("too far in the future"),
            "Unexpected error message: {}",
            error_msg
        );
        update_mock.assert_calls(0);

        server_handle.abort();

        Ok(())
    }

    #[tokio::test]
    async fn test_register_repo_already_exists() -> Result<(), anyhow::Error> {
        use features_lib::AsfaloadPublicKeyTrait;
        use httpmock::Method;
        use rest_api_types::RegisterRepoRequest;

        let temp_dir = TempDir::new()?;
        let git_repo_path = temp_dir.path().join("git_repo");

        init_git_repo(&git_repo_path)?;

        let mock_server = httpmock::MockServer::start();

        // Create the project dir using the new path prefix format (scheme/host/port/owner/repo)
        let project_dir =
            git_repo_path.join(format!("http/127.0.0.1/{}/owner/repo", mock_server.port()));
        tokio::fs::create_dir_all(&project_dir).await?;

        let test_keys = test_helpers::TestKeys::new(1);
        let public_key = test_keys.pub_key(0).unwrap();
        let secret_key = test_keys.sec_key(0).unwrap();

        let signers_config = signers_file_types::SignersConfig::with_artifact_signers_only(
            1,
            (vec![public_key.clone()], 1),
        )?;

        let signers_json = serde_json::to_string_pretty(&signers_config)?;

        let signers_json_clone = signers_json.clone();
        let mock = mock_server.mock(|when, then| {
            when.method(Method::GET)
                .path("/owner/repo/main/signers.json");
            then.status(200).body(signers_json_clone);
        });

        let signers_url = format!("{}/owner/repo/main/signers.json", mock_server.url(""));

        let port = get_random_port().await?;
        let config = build_test_config(&git_repo_path, port);
        let config_clone = config.clone();
        let server_handle = tokio::spawn(async move { run_server(&config_clone).await });
        wait_for_server(&config, None).await?;

        let client = reqwest::Client::new();

        let (metadata, metadata_signature) =
            crate::metadata_and_signature_for(&signers_url, &signers_json, &secret_key)?;
        let request_body = RegisterRepoRequest {
            signers_file_url: signers_url,
            public_key: public_key.to_base64(),
            signature: signature_for_sha(signers_json.as_bytes(), &secret_key)?,
            metadata,
            metadata_signature,
        };
        let payload_string = serde_json::to_string(&request_body)?;
        let TestAuthHeaders {
            timestamp,
            nonce,
            signature: auth_signature,
            public_key: auth_public_key,
        } = create_auth_headers_with_key(secret_key, &payload_string).await;

        let response = client
            .post(format!("http://localhost:{}/v1/register_repo", port))
            .header(HEADER_TIMESTAMP, timestamp)
            .header(HEADER_NONCE, nonce)
            .header(HEADER_SIGNATURE, auth_signature)
            .header(HEADER_PUBLIC_KEY, auth_public_key)
            .json(&request_body)
            .send()
            .await?;

        assert_eq!(response.status(), StatusCode::CONFLICT);

        let response_body: serde_json::Value = response.json().await?;
        assert!(response_body.get("error").is_some());

        // project existence is detected before sending out request
        mock.assert_calls(0);

        server_handle.abort();

        Ok(())
    }

    // A request whose signature does not verify with the declared public key
    // is rejected: the submitter must prove possession of the secret key of
    // the public key sent in the request.
    #[tokio::test]
    async fn test_register_repo_fails_with_signature_by_another_key() -> Result<(), anyhow::Error> {
        use features_lib::AsfaloadPublicKeyTrait;
        use httpmock::Method;

        let temp_dir = TempDir::new()?;
        let git_repo_path = temp_dir.path().join("git_repo");
        init_git_repo(&git_repo_path)?;

        let mock_server = httpmock::MockServer::start();

        let test_keys = test_helpers::TestKeys::new(2);
        let public_key = test_keys.pub_key(0).unwrap();
        let secret_key = test_keys.sec_key(0).unwrap();
        let other_secret_key = test_keys.sec_key(1).unwrap();

        let signers_config = signers_file_types::SignersConfig::with_artifact_signers_only(
            1,
            (vec![public_key.clone()], 1),
        )?;
        let signers_json = serde_json::to_string_pretty(&signers_config)?;

        let signers_json_clone = signers_json.clone();
        let mock = mock_server.mock(|when, then| {
            when.method(Method::GET)
                .path("/owner/repo/main/signers.json");
            then.status(200)
                .header("Content-Type", "application/json")
                .body(signers_json_clone);
        });

        let signers_url = format!("{}/owner/repo/main/signers.json", mock_server.url(""));

        let port = get_random_port().await?;
        let config = build_test_config(&git_repo_path, port);
        let config_clone = config.clone();
        let server_handle = tokio::spawn(async move { run_server(&config_clone).await });
        wait_for_server(&config, None).await?;

        let client = reqwest::Client::new();

        let (metadata, metadata_signature) =
            crate::metadata_and_signature_for(&signers_url, &signers_json, &secret_key)?;
        let request_body = RegisterRepoRequest {
            signers_file_url: signers_url,
            public_key: public_key.to_base64(),
            signature: signature_for_sha(signers_json.as_bytes(), &other_secret_key)?,
            metadata,
            metadata_signature,
        };
        let payload_string = serde_json::to_string(&request_body)?;
        let TestAuthHeaders {
            timestamp,
            nonce,
            signature: auth_signature,
            public_key: auth_public_key,
        } = create_auth_headers_with_key(test_keys.sec_key(0).unwrap(), &payload_string).await;

        let response = client
            .post(format!("http://localhost:{}/v1/register_repo", port))
            .header(HEADER_TIMESTAMP, timestamp)
            .header(HEADER_NONCE, nonce)
            .header(HEADER_SIGNATURE, auth_signature)
            .header(HEADER_PUBLIC_KEY, auth_public_key)
            .json(&request_body)
            .send()
            .await?;

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        mock.assert_calls(1);

        server_handle.abort();

        Ok(())
    }

    // A signature that does not decode as a valid signature is an invalid
    // request body.
    #[tokio::test]
    async fn test_register_repo_fails_with_invalid_signature_format() -> Result<(), anyhow::Error> {
        use features_lib::AsfaloadPublicKeyTrait;
        use httpmock::Method;

        let temp_dir = TempDir::new()?;
        let git_repo_path = temp_dir.path().join("git_repo");
        init_git_repo(&git_repo_path)?;

        let mock_server = httpmock::MockServer::start();

        let test_keys = test_helpers::TestKeys::new(1);
        let public_key = test_keys.pub_key(0).unwrap();
        let secret_key = test_keys.sec_key(0).unwrap();

        let signers_config = signers_file_types::SignersConfig::with_artifact_signers_only(
            1,
            (vec![public_key.clone()], 1),
        )?;
        let signers_json = serde_json::to_string_pretty(&signers_config)?;

        let signers_json_clone = signers_json.clone();
        let mock = mock_server.mock(|when, then| {
            when.method(Method::GET)
                .path("/owner/repo/main/signers.json");
            then.status(200)
                .header("Content-Type", "application/json")
                .body(signers_json_clone);
        });

        let signers_url = format!("{}/owner/repo/main/signers.json", mock_server.url(""));

        let port = get_random_port().await?;
        let config = build_test_config(&git_repo_path, port);
        let config_clone = config.clone();
        let server_handle = tokio::spawn(async move { run_server(&config_clone).await });
        wait_for_server(&config, None).await?;

        let client = reqwest::Client::new();

        let (metadata, metadata_signature) =
            crate::metadata_and_signature_for(&signers_url, &signers_json, &secret_key)?;
        let request_body = RegisterRepoRequest {
            signers_file_url: signers_url,
            public_key: public_key.to_base64(),
            signature: "not-a-signature".to_string(),
            metadata,
            metadata_signature,
        };
        let payload_string = serde_json::to_string(&request_body)?;
        let TestAuthHeaders {
            timestamp,
            nonce,
            signature: auth_signature,
            public_key: auth_public_key,
        } = create_auth_headers_with_key(secret_key, &payload_string).await;

        let response = client
            .post(format!("http://localhost:{}/v1/register_repo", port))
            .header(HEADER_TIMESTAMP, timestamp)
            .header(HEADER_NONCE, nonce)
            .header(HEADER_SIGNATURE, auth_signature)
            .header(HEADER_PUBLIC_KEY, auth_public_key)
            .json(&request_body)
            .send()
            .await?;

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        mock.assert_calls(1);

        server_handle.abort();

        Ok(())
    }

    // ============================================================================
    // Signature Collection Integration Tests
    // ============================================================================

    #[tokio::test]
    async fn test_submit_signature_for_artifact_file() -> Result<(), anyhow::Error> {
        use constants::SIGNATURES_SUFFIX;
        use rest_api_test_helpers::{
            TestSetupBuilder, file_exists_in_latest_commit, file_is_tracked_in_git,
            get_latest_commit,
        };

        let setup = TestSetupBuilder::new()
            .with_artifact("releases/release.txt")
            .build()
            .await?;

        let response = setup.submit_signature_and_wait(0).await?;

        assert!(response.is_complete);

        // Verify the commit was created with correct message
        let expected_commit_message = format!(
            "completed signature collection for {}",
            setup.artifact_path()
        );
        let commit_msg = get_latest_commit(setup.repo_path())?;
        assert!(
            commit_msg.contains(&expected_commit_message),
            "Commit message doesn't match expected format"
        );

        let sig_rel_path = format!("{}.{}", setup.artifact_path(), SIGNATURES_SUFFIX);

        // Verify the signature file was created
        assert!(
            setup.repo_path().join(&sig_rel_path).exists(),
            "Signature file should be created"
        );

        assert!(
            file_exists_in_latest_commit(setup.repo_path(), &sig_rel_path)?,
            "Signature file should be in the latest git commit"
        );

        // Verify the signature file is tracked in git
        assert!(
            file_is_tracked_in_git(setup.repo_path(), &sig_rel_path)?,
            "Signature file should be tracked in git"
        );

        Ok(())
    }

    #[tokio::test]
    async fn test_submit_signature_for_signers_file() -> Result<(), anyhow::Error> {
        use common::fs::names::{metadata_path_for, pending_signatures_path_for};
        use constants::PENDING_SIGNERS_DIR;
        use constants::SIGNATURES_SUFFIX;
        use constants::SIGNERS_DIR;
        use constants::SIGNERS_FILE;
        use features_lib::{
            AsfaloadPublicKeyTrait, AsfaloadSecretKeyTrait, AsfaloadSignatureTrait, SignaturesFile,
            sha512_for_file,
        };
        use rest_api_types::SubmitSignatureRequest;
        use rest_api_types::SubmitSignatureResponse;
        use rest_api_types::models::ClientPendingFile;
        use std::collections::HashMap;

        let temp_dir = TempDir::new()?;
        let git_repo_path = temp_dir.path().join("git_repo");

        let test_keys = test_helpers::TestKeys::new(1);
        let public_key = test_keys.pub_key(0).unwrap();

        let signers_config = signers_file_types::SignersConfig::with_artifact_signers_only(
            1,
            (vec![public_key.clone()], 1),
        )?;

        let signers_json = serde_json::to_string_pretty(&signers_config)?;

        let project_dir = git_repo_path.join("github.com/test/repo");
        let pending_dir = project_dir.join(PENDING_SIGNERS_DIR);
        let complete_dir = project_dir.join(SIGNERS_DIR);
        tokio::fs::create_dir_all(&pending_dir).await?;
        let pending_signers_path = pending_dir.join(SIGNERS_FILE);
        let complete_signers_path = complete_dir.join(SIGNERS_FILE);
        tokio::fs::write(pending_signers_path.clone(), &signers_json).await?;

        // Create pending signatures file for the signers file
        let pending_sig_path = pending_signatures_path_for(&pending_signers_path)?;
        let empty_sigs = SignaturesFile::new();
        tokio::fs::write(
            &pending_sig_path,
            serde_json::to_string_pretty(&empty_sigs)?,
        )
        .await?;

        // Create metadata file
        let metadata_path = metadata_path_for(&pending_signers_path)?;
        let metadata = test_helpers::test_metadata();
        tokio::fs::write(&metadata_path, serde_json::to_string_pretty(&metadata)?).await?;

        // Create pending signatures for metadata file
        let metadata_pending_sig_path = pending_signatures_path_for(&metadata_path)?;
        tokio::fs::write(
            &metadata_pending_sig_path,
            serde_json::to_string_pretty(&empty_sigs)?,
        )
        .await?;

        // Create signatures
        let digest = sha512_for_file(&pending_signers_path)?;
        let secret_key = test_keys.sec_key(0).unwrap();
        let signature = secret_key.sign(&digest)?;

        let metadata_digest = sha512_for_file(&metadata_path)?;
        let metadata_signature = secret_key.sign(&metadata_digest)?;

        // Build the relative file path and metadata path
        let signers_rel_path = format!(
            "github.com/test/repo/{}/{}",
            PENDING_SIGNERS_DIR, SIGNERS_FILE
        );
        let metadata_rel_path = format!("{}.{}", signers_rel_path, constants::METADATA_SUFFIX);

        let port = get_random_port().await?;
        init_git_repo(&git_repo_path)?;
        let config = build_test_config(&git_repo_path, port);
        let config_clone = config.clone();
        let (guard, log_path, _subscriber_guard) = setup_file_logging(temp_dir.path())?;
        println!("Logs of server available at {}", log_path.display());
        let server_handle = tokio::spawn(async move { run_server(&config_clone).await });
        wait_for_server(&config, None).await?;

        let client = reqwest::Client::new();
        let mut signatures = HashMap::new();
        signatures.insert(signers_rel_path.clone(), signature.to_base64());
        signatures.insert(metadata_rel_path, metadata_signature.to_base64());
        let payload = json!(&SubmitSignatureRequest {
            pending_file: ClientPendingFile::new(signers_rel_path, digest),
            public_key: public_key.to_base64(),
            signatures,
        });
        let payload_string = payload.to_string();
        let TestAuthHeaders {
            timestamp,
            nonce,
            signature: auth_signature,
            public_key: auth_public_key,
        } = create_auth_headers_with_key(secret_key, &payload_string).await;
        let response = client
            .post(url_for("signatures", port))
            .header(HEADER_TIMESTAMP, timestamp)
            .header(HEADER_NONCE, nonce)
            .header(HEADER_SIGNATURE, auth_signature)
            .header(HEADER_PUBLIC_KEY, auth_public_key)
            .json(&payload)
            .send()
            .await?;

        assert_eq!(response.status(), StatusCode::OK);

        let response_body = response.json::<SubmitSignatureResponse>().await?;

        assert!(
            response_body.is_complete,
            "Signers file signature should complete"
        );

        // Wait for the commit to be processed
        let expected_commit_message = format!(
            "completed signature collection for {}/{}",
            "github.com/test/repo", SIGNERS_DIR
        );

        wait_for_commit(git_repo_path.clone(), &expected_commit_message, None).await?;

        // Verify the commit was created with correct message
        let commit_msg = get_latest_commit(&git_repo_path)?;
        assert!(
            commit_msg.contains(&expected_commit_message),
            "Commit message doesn't match expected format"
        );

        let signature_file = format!("{}.{}", complete_signers_path.display(), SIGNATURES_SUFFIX);
        let signature_file = std::path::PathBuf::from(signature_file);

        // The recorded signature must verify over the activated signers
        // file bytes: activation must not modify the signed content.
        use rest_api_test_helpers::{SignatureFileState, assert_recorded_signature};
        assert_recorded_signature(
            &complete_signers_path,
            public_key,
            SignatureFileState::Complete,
            1,
        );

        // Verify the signature file is tracked in git
        let signature_file_path_string = signature_file
            .strip_prefix(&git_repo_path)?
            .to_string_lossy()
            .to_string();
        let signature_file_path = signature_file_path_string.as_str();
        drop(guard);
        assert!(
            file_is_tracked_in_git(&git_repo_path, signature_file_path)?,
            "Signature file should be tracked in git"
        );

        // Verify the signature file is in the latest git commit
        assert!(
            file_exists_in_latest_commit(&git_repo_path, signature_file_path)?,
            "Signature file should be in the latest git commit"
        );

        server_handle.abort();
        Ok(())
    }

    #[tokio::test]
    async fn test_submit_partial_signature() -> Result<(), anyhow::Error> {
        use constants::SIGNATURES_SUFFIX;
        use rest_api_test_helpers::{
            TestSetupBuilder, file_exists_in_latest_commit, file_is_tracked_in_git,
            get_latest_commit,
        };

        let setup = TestSetupBuilder::new()
            .with_keys(2)
            .with_threshold(2)
            .with_artifact("releases/release.txt")
            .build()
            .await?;

        // Submit first signature (should be partial)
        let response = setup.submit_signature_and_wait(0).await?;
        assert!(!response.is_complete, "First signature should not complete");

        // Verify partial commit message
        let commit_msg = get_latest_commit(setup.repo_path())?;
        assert!(
            commit_msg.contains(&format!(
                "added partial signature for {}",
                setup.artifact_path()
            )),
            "Partial commit message doesn't match"
        );

        // Submit second signature (should complete)
        let response2 = setup.submit_signature_and_wait(1).await?;
        assert!(response2.is_complete, "Second signature should complete");

        // Verify completion commit message
        let commit_msg2 = get_latest_commit(setup.repo_path())?;
        assert!(
            commit_msg2.contains(&format!(
                "completed signature collection for {}",
                setup.artifact_path()
            )),
            "Completion commit message doesn't match"
        );

        let sig_rel_path = format!("{}.{}", setup.artifact_path(), SIGNATURES_SUFFIX);

        // Verify the signature file is tracked in git
        assert!(
            file_is_tracked_in_git(setup.repo_path(), &sig_rel_path)?,
            "Signature file should be tracked in git"
        );

        // Verify the signature file is in the latest git commit
        assert!(
            file_exists_in_latest_commit(setup.repo_path(), &sig_rel_path)?,
            "Signature file should be in the latest git commit"
        );

        Ok(())
    }

    #[tokio::test]
    async fn test_submit_signature_file_not_found() -> Result<(), anyhow::Error> {
        use features_lib::AsfaloadPublicKeyTrait;
        use rest_api_test_helpers::create_auth_headers;

        let temp_dir = TempDir::new()?;
        let git_repo_path = temp_dir.path().join("git_repo");

        init_git_repo(&git_repo_path)?;

        let test_keys = test_helpers::TestKeys::new(1);
        let public_key = test_keys.pub_key(0).unwrap();

        let port = get_random_port().await?;
        let config = build_test_config(&git_repo_path, port);
        let config_clone = config.clone();
        let server_handle = tokio::spawn(async move { run_server(&config_clone).await });
        rest_api_test_helpers::wait_for_server(&config, None).await?;

        let payload = json!({
            "pending_file": {
                "path": "nonexistent.txt",
                "digest": format!("sha512:{}", "a".repeat(128)),
            },
            "public_key": public_key.to_base64(),
            "signatures": {
                "nonexistent.txt": "invalid_signature"
            },
        });
        let payload_string = payload.to_string();
        let auth = create_auth_headers(&payload_string).await;

        let client = reqwest::Client::new();
        let response = client
            .post(url_for("signatures", port))
            .header(HEADER_TIMESTAMP, &auth.timestamp)
            .header(HEADER_NONCE, &auth.nonce)
            .header(HEADER_SIGNATURE, &auth.signature)
            .header(HEADER_PUBLIC_KEY, &auth.public_key)
            .json(&payload)
            .send()
            .await?;

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);

        let body: serde_json::Value = response.json().await?;

        assert!(body.get("error").is_some());
        assert!(
            body["error"]
                .as_str()
                .unwrap_or("")
                .contains("File not found")
        );

        server_handle.abort();
        Ok(())
    }

    #[tokio::test]
    async fn test_submit_signature_rejects_wrong_digest() -> Result<(), anyhow::Error> {
        use features_lib::AsfaloadPublicKeyTrait;
        use rest_api_test_helpers::TestSetupBuilder;

        let setup = TestSetupBuilder::new()
            .with_artifact("releases/artifact.bin")
            .build()
            .await?;

        let public_key = setup.test_keys().pub_key(0).unwrap();
        let secret_key = setup.test_keys().sec_key(0).unwrap();

        // Valid path, but digest does not match the file on disk
        let wrong_digest = "sha512:00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";
        let payload = serde_json::json!({
            "pending_file": {
                "path": setup.artifact_path(),
                "digest": wrong_digest,
            },
            "public_key": public_key.to_base64(),
            "signatures": {
                setup.artifact_path(): "invalid_signature",
            },
        });

        let payload_string = payload.to_string();
        let auth = create_auth_headers_with_key(secret_key, &payload_string).await;

        let response = setup
            .client()
            .post(url_for("signatures", setup.port()))
            .header(HEADER_TIMESTAMP, &auth.timestamp)
            .header(HEADER_NONCE, &auth.nonce)
            .header(HEADER_SIGNATURE, &auth.signature)
            .header(HEADER_PUBLIC_KEY, &auth.public_key)
            .json(&payload)
            .send()
            .await?;

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);

        let body: serde_json::Value = response.json().await?;
        assert!(
            body["error"]
                .as_str()
                .unwrap_or("")
                .to_lowercase()
                .contains("digest"),
            "Expected digest mismatch error, got: {}",
            body
        );

        Ok(())
    }

    #[tokio::test]
    async fn test_revoke_fully_signed_artifact() -> Result<(), anyhow::Error> {
        use features_lib::{
            AsfaloadPublicKeyTrait, AsfaloadSecretKeyTrait, AsfaloadSignatureTrait,
            sha512_for_content, sha512_for_file,
        };
        use rest_api_test_helpers::{TestSetupBuilder, send_authenticated_request_with_key};
        use rest_api_types::RevokeFileResponse;

        let setup = TestSetupBuilder::new()
            .with_artifact("releases/release.txt")
            .build_and_sign()
            .await?;

        // Build and submit revocation
        let artifact_file = setup.repo_path().join(setup.artifact_path());
        let subject_digest = sha512_for_file(&artifact_file)?;
        let public_key = setup.test_keys().pub_key(0).unwrap();
        let secret_key = setup.test_keys().sec_key(0).unwrap();

        let revocation = signers_file_types::revocation::RevocationInfo {
            timestamp: chrono::Utc::now(),
            subject_digest,
            initiator: public_key.clone(),
        };
        let revocation_json = serde_json::to_string_pretty(&revocation)?;

        let revocation_hash = sha512_for_content(revocation_json.as_bytes().to_vec())?;
        let revoke_signature = secret_key.sign(&revocation_hash)?;

        let revoke_payload = json!({
            "file_path": "releases/release.txt",
            "revocation_json": revocation_json,
            "signature": revoke_signature.to_base64(),
            "public_key": public_key.to_base64(),
        });

        let client = reqwest::Client::new();
        let response =
            send_authenticated_request_with_key(&client, setup.port(), secret_key, &revoke_payload)
                .await;

        assert_eq!(response.status(), StatusCode::OK);

        let revoke_body: RevokeFileResponse = response.json().await?;
        assert!(revoke_body.success);
        assert_eq!(revoke_body.message, "File revoked successfully");

        Ok(())
    }

    #[tokio::test]
    async fn test_submit_signature_for_revoked_file_rejected() -> Result<(), anyhow::Error> {
        use constants::SIGNERS_DIR;
        use constants::SIGNERS_FILE;
        use features_lib::{
            AsfaloadPublicKeyTrait, AsfaloadSecretKeyTrait, AsfaloadSignatureTrait, sha512_for_file,
        };
        use rest_api_types::SubmitSignatureRequest;
        use rest_api_types::models::ClientPendingFile;

        let temp_dir = TempDir::new()?;
        let git_repo_path = temp_dir.path().join("git_repo");

        init_git_repo(&git_repo_path)?;

        let test_keys = test_helpers::TestKeys::new(1);
        let public_key = test_keys.pub_key(0).unwrap();

        let signers_config = signers_file_types::SignersConfig::with_artifact_signers_only(
            1,
            (vec![public_key.clone()], 1),
        )?;

        let signers_json = serde_json::to_string_pretty(&signers_config)?;

        let signers_dir = git_repo_path.join(SIGNERS_DIR);
        tokio::fs::create_dir_all(&signers_dir).await?;
        tokio::fs::write(signers_dir.join(SIGNERS_FILE), &signers_json).await?;

        let artifact_file = git_repo_path.join("releases/release.tar.gz");
        tokio::fs::create_dir_all(artifact_file.parent().unwrap()).await?;
        tokio::fs::write(&artifact_file, "artifact content").await?;

        let revocation_path = common::fs::names::revocation_path_for(&artifact_file)?;
        tokio::fs::write(&revocation_path, r#"{"revoked": true}"#).await?;

        let digest = sha512_for_file(&artifact_file)?;
        let secret_key = test_keys.sec_key(0).unwrap();
        let signature = secret_key.sign(&digest)?;

        let port = get_random_port().await?;
        let config = build_test_config(&git_repo_path, port);
        let config_clone = config.clone();
        let server_handle = tokio::spawn(async move { run_server(&config_clone).await });
        wait_for_server(&config, None).await?;

        let client = reqwest::Client::new();
        let mut signatures = std::collections::HashMap::new();
        signatures.insert("releases/release.tar.gz".to_string(), signature.to_base64());
        let payload = json!(&SubmitSignatureRequest {
            pending_file: ClientPendingFile::new("releases/release.tar.gz".to_string(), digest),
            public_key: public_key.to_base64(),
            signatures,
        });
        let payload_string = payload.to_string();
        let TestAuthHeaders {
            timestamp,
            nonce,
            signature: auth_signature,
            public_key: auth_public_key,
        } = create_auth_headers_with_key(secret_key, &payload_string).await;
        let response = client
            .post(url_for("signatures", port))
            .header(HEADER_TIMESTAMP, timestamp)
            .header(HEADER_NONCE, nonce)
            .header(HEADER_SIGNATURE, auth_signature)
            .header(HEADER_PUBLIC_KEY, auth_public_key)
            .json(&payload)
            .send()
            .await?;

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);

        let response_body: serde_json::Value = response.json().await?;
        let error_msg = response_body["error"].as_str().unwrap_or("");

        assert!(
            error_msg.contains("revoked"),
            "Error message should mention 'revoked', got: {}",
            error_msg
        );

        server_handle.abort();
        Ok(())
    }

    /// Test that register-assets (checksums mode) can find signers created by register-repo.
    ///
    /// This exercises the full cross-flow path:
    /// 1. register-repo creates signers via ForgeInfo (FileServer type) at `http/127.0.0.1/<port>/owner/repo/`
    /// 2. register-assets with csum_files uses path_prefix_from_url + find_global_signers_for
    ///    to locate those signers from a checksums URL under the same origin
    ///
    /// This test would have caught the bug where register-assets used bare `host` paths
    /// instead of `scheme/host/port` origin prefix paths.
    #[tokio::test]
    async fn test_register_assets_finds_signers_created_by_register_repo()
    -> Result<(), anyhow::Error> {
        use features_lib::AsfaloadPublicKeyTrait;
        use httpmock::Method;
        use rest_api_types::{RegisterAssetsResponse, RegisterRepoRequest, RegisterRepoResponse};

        let temp_dir = TempDir::new()?;
        let git_repo_path = temp_dir.path().join("git_repo");
        init_git_repo(&git_repo_path)?;

        let mock_server = httpmock::MockServer::start();

        let test_keys = test_helpers::TestKeys::new(1);
        let public_key = test_keys.pub_key(0).unwrap();
        let secret_key = test_keys.sec_key(0).unwrap();

        // --- Step 1: Set up mock signers file and register repo ---

        let signers_config = signers_file_types::SignersConfig::with_artifact_signers_only(
            1,
            (vec![public_key.clone()], 1),
        )?;
        let signers_json = serde_json::to_string_pretty(&signers_config)?;

        let signers_json_clone = signers_json.clone();
        let signers_mock = mock_server.mock(|when, then| {
            when.method(Method::GET)
                .path("/owner/repo/main/signers.json");
            then.status(200)
                .header("Content-Type", "application/json")
                .body(signers_json_clone);
        });

        let signers_url = format!("{}/owner/repo/main/signers.json", mock_server.url(""));

        let port = get_random_port().await?;
        let config = build_test_config(&git_repo_path, port);
        let config_clone = config.clone();
        let server_handle = tokio::spawn(async move { run_server(&config_clone).await });
        wait_for_server(&config, None).await?;

        let client = reqwest::Client::new();

        // Register the repo (creates signers at http/127.0.0.1/<mock_port>/owner/repo/)
        let (metadata, metadata_signature) =
            crate::metadata_and_signature_for(&signers_url, &signers_json, &secret_key)?;
        let register_body = RegisterRepoRequest {
            signers_file_url: signers_url,
            public_key: public_key.to_base64(),
            signature: signature_for_sha(signers_json.as_bytes(), &secret_key)?,
            metadata,
            metadata_signature,
        };
        let payload_string = serde_json::to_string(&register_body)?;
        let TestAuthHeaders {
            timestamp,
            nonce,
            signature: auth_signature,
            public_key: auth_public_key,
        } = create_auth_headers_with_key(secret_key, &payload_string).await;

        let response = client
            .post(format!("http://localhost:{}/v1/register_repo", port))
            .header(HEADER_TIMESTAMP, &timestamp)
            .header(HEADER_NONCE, &nonce)
            .header(HEADER_SIGNATURE, &auth_signature)
            .header(HEADER_PUBLIC_KEY, &auth_public_key)
            .json(&register_body)
            .send()
            .await?;

        assert_eq!(response.status(), StatusCode::OK);
        let register_response = response.json::<RegisterRepoResponse>().await?;
        assert!(register_response.success);
        // The single signer signed the signers file and the metadata with the
        // registration, so the signers file is already active: register-assets
        // can find it without a signing step.
        assert!(register_response.required_signers.is_empty());
        signers_mock.assert();

        // --- Step 2: Set up mock checksums file and register assets ---

        let sha256_hex = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
        let checksums_content = format!("{}  artifact.bin", sha256_hex);

        let checksums_content_clone = checksums_content.clone();
        let checksums_mock = mock_server.mock(|when, then| {
            when.method(Method::GET)
                .path("/owner/repo/releases/v1.0/SHA256SUMS");
            then.status(200)
                .header("Content-Type", "text/plain")
                .body(checksums_content_clone);
        });

        let checksums_url = format!(
            "{}/owner/repo/releases/v1.0/SHA256SUMS",
            mock_server.url("")
        );

        // Index timestamps are set while the server processes the request.
        let registration_started_at = chrono::Utc::now();

        // The client (as the real one does) downloads the checksums files,
        // builds its index, signs it and base64 encodes both in the payload.
        let assets_body = build_signed_checksums_assets_payload(
            &client,
            std::slice::from_ref(&checksums_url),
            secret_key,
        )
        .await?;
        let assets_payload_string = serde_json::to_string(&assets_body)?;

        let TestAuthHeaders {
            timestamp,
            nonce,
            signature: auth_signature,
            public_key: auth_public_key,
        } = create_auth_headers_with_key(secret_key, &assets_payload_string).await;

        let response = client
            .post(format!("http://localhost:{}/v1/assets", port))
            .header(HEADER_TIMESTAMP, &timestamp)
            .header(HEADER_NONCE, &nonce)
            .header(HEADER_SIGNATURE, &auth_signature)
            .header(HEADER_PUBLIC_KEY, &auth_public_key)
            .json(&assets_body)
            .send()
            .await?;

        // This is the key assertion: if path prefixes mismatch between register-repo
        // and register-assets, this returns 400 "No active signers file found"
        assert_eq!(
            response.status(),
            StatusCode::OK,
            "register-assets should find signers created by register-repo"
        );

        let assets_response = response.json::<RegisterAssetsResponse>().await?;
        assert!(assets_response.success);

        // Verify the index file was created at the expected origin-prefix path
        let index_path_str = assets_response
            .index_file_path
            .expect("index_file_path should be present");
        let expected_prefix = format!("http/127.0.0.1/{}/owner/repo", mock_server.port());
        assert!(
            index_path_str.starts_with(&expected_prefix),
            "Index path '{}' should start with origin prefix '{}'",
            index_path_str,
            expected_prefix
        );

        // The on-disk index is what consumers read: its content must match
        // the entries of the checksums file the server downloaded.
        let index = rest_api_test_helpers::read_on_disk_index(&git_repo_path.join(index_path_str))?;
        assert_eq!(index.version, 1);
        // A checksums file carries no upstream publication date: both
        // timestamps are set at registration time.
        assert_eq!(
            index.published_on, index.mirrored_on,
            "published_on must equal mirrored_on when registering from a checksums file"
        );
        assert!(
            index.mirrored_on >= registration_started_at && index.mirrored_on <= chrono::Utc::now(),
            "mirrored_on must be the registration time, got {}",
            index.mirrored_on
        );
        assert_eq!(
            index.published_files,
            vec![features_lib::FileChecksum {
                file_name: "artifact.bin".to_string(),
                algo: features_lib::HashAlgorithm::Sha256,
                source: checksums_url.clone(),
                source_format: features_lib::ChecksumSourceFormat::ShaSum,
                hash: sha256_hex.to_string(),
            }]
        );

        // The checksums file is fetched twice: once by the test helper that
        // builds the index it signs, once by the server to verify the
        // client-provided index against the release content.
        checksums_mock.assert_calls(2);
        server_handle.abort();

        Ok(())
    }

    /// Build the checksums-file assets registration payload the way a real
    /// client does: download the checksums files, build the index, sign it
    /// with the submitting key, and base64 encode both in the payload.
    ///
    /// See `admin_lib`'s `build_register_assets_payload` for the reference
    /// implementation.
    async fn build_signed_checksums_assets_payload(
        client: &reqwest::Client,
        checksums_urls: &[String],
        secret_key: &features_lib::AsfaloadSecretKeys,
    ) -> Result<rest_api_types::RegisterAssetsPayload, anyhow::Error> {
        use features_lib::{AsfaloadSecretKeyTrait, AsfaloadSignatureTrait};

        let index =
            forge_release::checksums::index_from_shasums_urls(client, checksums_urls).await?;
        let index_json = index.to_json()?;
        let index_hash = common::sha512_for_content(index_json.as_bytes())?;
        let signature = secret_key.sign(&index_hash)?.to_base64();

        Ok(rest_api_types::RegisterAssetsPayload::ChecksumFiles(
            rest_api_types::models::ChecksumFilesPayload {
                csum_files: checksums_urls.to_vec(),
                index: common::base64_for_string(&index_json),
                signature,
            },
        ))
    }
}
