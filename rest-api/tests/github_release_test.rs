pub mod tests {

    use anyhow::Result;
    use axum::http::StatusCode;
    use constants::{SIGNERS_DIR, SIGNERS_FILE};
    #[cfg(feature = "test-utils")]
    use features_lib::AsfaloadKeyPairTrait;
    use features_lib::{AsfaloadPublicKeyTrait, AsfaloadSignatureTrait};
    use rest_api::server::run_server;
    use rest_api_auth::{HEADER_NONCE, HEADER_PUBLIC_KEY, HEADER_SIGNATURE, HEADER_TIMESTAMP};
    use rest_api_test_helpers::{build_test_config, get_random_port, url_for, wait_for_server};
    use rest_api_types::rustls::setup_crypto_provider;
    use std::fs;
    use tempfile::TempDir;
    use tokio::time::Duration;

    #[cfg(feature = "test-utils")]
    use common::fs::names::pending_signatures_path_for;
    #[cfg(feature = "test-utils")]
    use features_lib::SignaturesFile;
    #[cfg(feature = "test-utils")]
    use rest_api_test_helpers::init_git_repo;
    #[cfg(feature = "test-utils")]
    use rest_api_test_helpers::print_logs;
    use rest_api_types::RegisterAssetsPayload;
    use rest_api_types::models::GithubReleasePayload;
    use serde_json::Value;

    /// Body of the register-assets endpoint, in the tagged form sent by the
    /// client library. The index and signature values are placeholders: the
    /// server builds its own index for now.
    fn github_release_body(github_release_url: &str) -> Value {
        serde_json::to_value(RegisterAssetsPayload::GithubRelease(GithubReleasePayload {
            github_release_url: github_release_url.to_string(),
            index: "aW5kZXg=".to_string(),
            signature: "c2lnbmF0dXJl".to_string(),
        }))
        .expect("failed to serialize GithubRelease payload")
    }

    #[tokio::test]
    #[cfg(feature = "test-utils")]
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

        let payload =
            github_release_body("https://github.com/testowner/testrepo/releases/tag/v1.0.0");
        let payload_str = payload.to_string();

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

        let json_body =
            github_release_body("https://github.com/testowner/testrepo/releases/tag/v1.0.0");
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

        let json_body = github_release_body("invalid");
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

        // Send without auth headers
        let body = github_release_body("https://github.com/testowner/testrepo/releases/tag/v1.0.0");
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
}
