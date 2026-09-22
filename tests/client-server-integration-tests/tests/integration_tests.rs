#[cfg(test)]
mod tests {
    use client_server_integration_tests::test_harness;
    use common::fs::names::pending_signatures_path_for;
    use features_lib::constants::{PENDING_SIGNERS_DIR, SIGNERS_FILE};
    use features_lib::AsfaloadPublicKeyTrait;
    use features_lib::AsfaloadPublicKeys;
    use features_lib::AsfaloadSecretKeyTrait;
    use signers_file::initialize_signers_file;
    use signers_file_types::SignersConfig;
    use std::fs;
    use std::path::Path;

    /// Initialize signers file and create the empty pending signatures file
    /// that list-pending needs to discover it.
    ///
    /// The metadata written for the signers file points at a mock HTTP server
    /// serving the same content as the signers file, mimicking the forge where
    /// the project publishes it. The returned server guard must be kept alive
    /// for the duration of the test: dropping it stops the server, and
    /// sign-pending on the signers file would then fail the validation of the
    /// file against its forge source.
    async fn initialize_signers_file_with_pending_sigs(
        project_dir: &Path,
        signers_content: &str,
        pubkey: &AsfaloadPublicKeys,
    ) -> mockito::ServerGuard {
        let mut signers_source_server = mockito::Server::new_async().await;
        signers_source_server
            .mock("GET", "/signers.json")
            .with_status(200)
            .with_body(signers_content)
            .create_async()
            .await;

        let metadata =
            features_lib::SignersConfigMetadata::from_forge(features_lib::ForgeOrigin::new(
                features_lib::Forge::Github,
                "https://example.com/test".to_string(),
                features_lib::VerifiedForgeContent::new_for_test(
                    format!("{}/signers.json", signers_source_server.url()),
                    signers_content.to_string(),
                ),
                chrono::Utc::now(),
            ));

        initialize_signers_file(project_dir, signers_content, metadata, pubkey)
            .expect("Failed to initialize signers file");
        let signers_path = project_dir.join(PENDING_SIGNERS_DIR).join(SIGNERS_FILE);
        let pending_sig_path =
            pending_signatures_path_for(&signers_path).expect("Failed to compute pending sig path");
        fs::write(&pending_sig_path, r#"{"entries":{}}"#)
            .expect("Failed to write pending signatures file");
        signers_source_server
    }

    // ========================================
    // LIST-PENDING COMMAND TESTS
    // ========================================

    #[tokio::test]
    async fn test_list_pending_empty() {
        let state = test_harness::initialize().await;
        let guard = state.lock().await;
        // Use key 3 which is not included in any other test's signers config,
        // so list-pending returns empty regardless of test execution order.
        let secret_key_path = guard.secret_key_paths[3].clone();
        let backend_url = guard.server.base_url();
        drop(guard);

        let file_paths = client_cli::commands::list_pending::handle_list_pending_command(
            &backend_url,
            &secret_key_path,
            test_harness::TEST_PASSWORD,
            None,
            false,
        )
        .await
        .expect("list-pending command should succeed");

        assert!(
            file_paths.is_empty(),
            "Expected no pending files, got: {:?}",
            file_paths
        );
    }

    // ========================================
    // ADD FILE + LIST-PENDING TESTS
    // ========================================

    #[tokio::test]
    async fn test_add_file_and_list_pending() {
        let state = test_harness::initialize().await;
        let guard = state.lock().await;
        let git_repo_path = guard.server.git_repo_path();
        let secret_key_path = guard.secret_key_paths[0].clone();
        let backend_url = guard.server.base_url();
        drop(guard);

        let secret_key = features_lib::AsfaloadSecretKeys::from_file(
            &secret_key_path,
            test_harness::TEST_PASSWORD,
        )
        .expect("Failed to load secret key");
        let public_key = features_lib::AsfaloadPublicKeys::from_secret_key(&secret_key)
            .expect("Failed to derive public key");

        let (project_dir_sub, file_path) =
            test_harness::unique_test_paths("add_file_list", "test_file.txt");
        let project_dir = git_repo_path.join(&project_dir_sub);
        fs::create_dir_all(&project_dir).expect("Failed to create project dir");

        let signers_config =
            SignersConfig::with_artifact_signers_only(1, (vec![public_key.clone()], 1))
                .expect("Failed to build signers config");
        let signers_content = signers_config
            .to_json()
            .expect("Failed to serialize signers config");

        let _signers_source_server =
            initialize_signers_file_with_pending_sigs(&project_dir, &signers_content, &public_key)
                .await;
        // The pending signers file needs to be signed first (two-phase signing).
        // list-pending should show it.
        let file_paths = client_cli::commands::list_pending::handle_list_pending_command(
            &backend_url,
            &secret_key_path,
            test_harness::TEST_PASSWORD,
            None,
            false,
        )
        .await
        .expect("list-pending should succeed");

        let signers_pending_path = file_paths
            .iter()
            .find(|pending| {
                let p = pending.path();
                p.starts_with(&format!("{}/", project_dir_sub.to_string_lossy()))
                    && p.contains(PENDING_SIGNERS_DIR)
            })
            .expect("Signers file should be in pending list")
            .clone();

        // Sign the pending signers file to activate it (threshold=all for InitialSignersFile)
        let r = client_cli::commands::sign_pending::handle_sign_pending_command(
            signers_pending_path.unseal(),
            &backend_url,
            &secret_key_path,
            test_harness::TEST_PASSWORD,
            false,
        )
        .await
        .expect("sign-pending for signers should succeed");
        assert!(
            r.is_complete,
            "Signers file should be complete with 1 of 1 signer"
        );

        // Now create the artifact file
        test_harness::create_file_in_repo(&file_path, "This is a test file.")
            .await
            .expect("Failed to create file");

        test_harness::create_pending_signatures_for(&file_path)
            .await
            .expect("Failed to create pending signatures file");

        let file_paths = client_cli::commands::list_pending::handle_list_pending_command(
            &backend_url,
            &secret_key_path,
            test_harness::TEST_PASSWORD,
            None,
            false,
        )
        .await
        .expect("list-pending should succeed");

        assert!(
            file_paths.iter().any(|p| p.path() == file_path),
            "Expected pending list to contain '{}', got: {:?}",
            file_path,
            file_paths
        );
    }

    // ========================================
    // SIGN-PENDING COMMAND TESTS
    // ========================================

    #[tokio::test]
    async fn test_sign_pending_file() {
        let state = test_harness::initialize().await;
        let guard = state.lock().await;
        let git_repo_path = guard.server.git_repo_path();
        let secret_key_path = guard.secret_key_paths[0].clone();
        let backend_url = guard.server.base_url();
        drop(guard);

        let secret_key = features_lib::AsfaloadSecretKeys::from_file(
            &secret_key_path,
            test_harness::TEST_PASSWORD,
        )
        .expect("Failed to load secret key");
        let public_key = features_lib::AsfaloadPublicKeys::from_secret_key(&secret_key)
            .expect("Failed to derive public key");

        // Setup signers
        let (project_dir_sub, file_path) =
            test_harness::unique_test_paths("sign_pending", "artifact.txt");
        let project_dir = git_repo_path.join(&project_dir_sub);
        fs::create_dir_all(&project_dir).expect("Failed to create project dir");

        let signers_config =
            SignersConfig::with_artifact_signers_only(1, (vec![public_key.clone()], 1))
                .expect("Failed to build signers config");
        let signers_content = signers_config
            .to_json()
            .expect("Failed to serialize signers config");

        let _signers_source_server =
            initialize_signers_file_with_pending_sigs(&project_dir, &signers_content, &public_key)
                .await;
        // Sign the pending signers file first (two-phase signing)
        let file_paths = client_cli::commands::list_pending::handle_list_pending_command(
            &backend_url,
            &secret_key_path,
            test_harness::TEST_PASSWORD,
            None,
            false,
        )
        .await
        .expect("list-pending should succeed");

        let signers_pending_path = file_paths
            .iter()
            .find(|pending| {
                let p = pending.path();
                p.starts_with(&format!("{}/", project_dir_sub.to_string_lossy()))
                    && p.contains(PENDING_SIGNERS_DIR)
            })
            .expect("Signers file should be in pending list")
            .clone();

        let r = client_cli::commands::sign_pending::handle_sign_pending_command(
            signers_pending_path.unseal(),
            &backend_url,
            &secret_key_path,
            test_harness::TEST_PASSWORD,
            false,
        )
        .await
        .expect("sign-pending for signers should succeed");
        assert!(
            r.is_complete,
            "Signers file should be complete with 1 of 1 signer"
        );

        // Create artifact file
        test_harness::create_file_in_repo(&file_path, "This is an artifact to be signed.")
            .await
            .expect("Failed to create file");

        test_harness::create_pending_signatures_for(&file_path)
            .await
            .expect("Failed to create pending signatures file");

        // Verify the file appears in pending list
        let file_paths = client_cli::commands::list_pending::handle_list_pending_command(
            &backend_url,
            &secret_key_path,
            test_harness::TEST_PASSWORD,
            None,
            false,
        )
        .await
        .expect("list-pending should succeed");

        assert!(
            file_paths.iter().any(|p| p.path() == file_path),
            "Expected '{}' in pending list, got: {:?}",
            file_path,
            file_paths
        );

        // Sign the pending file
        let artifact_client_file = file_paths
            .iter()
            .find(|p| p.path() == file_path)
            .expect("file should be in pending list")
            .clone()
            .unseal();
        let sign_response = client_cli::commands::sign_pending::handle_sign_pending_command(
            artifact_client_file,
            &backend_url,
            &secret_key_path,
            test_harness::TEST_PASSWORD,
            false,
        )
        .await
        .expect("sign-pending should succeed");

        assert!(
            sign_response.is_complete,
            "Expected signature to be complete (threshold=1, signers=1)"
        );
    }

    #[tokio::test]
    async fn test_sign_pending_server_digest_mismatch() {
        use client_cli::error::ClientCliError;
        use common::AsfaloadHashes;
        use rest_api_types::models::ClientPendingFile;

        let state = test_harness::initialize().await;
        let guard = state.lock().await;
        let git_repo_path = guard.server.git_repo_path();
        let secret_key_path = guard.secret_key_paths[0].clone();
        let backend_url = guard.server.base_url();
        drop(guard);

        let secret_key = features_lib::AsfaloadSecretKeys::from_file(
            &secret_key_path,
            test_harness::TEST_PASSWORD,
        )
        .expect("Failed to load secret key");
        let public_key = features_lib::AsfaloadPublicKeys::from_secret_key(&secret_key)
            .expect("Failed to derive public key");

        let (project_dir_sub, file_path) =
            test_harness::unique_test_paths("sign_pending_digest_mismatch", "artifact.txt");
        let project_dir = git_repo_path.join(&project_dir_sub);
        fs::create_dir_all(&project_dir).expect("Failed to create project dir");

        let signers_config =
            SignersConfig::with_artifact_signers_only(1, (vec![public_key.clone()], 1))
                .expect("Failed to build signers config");
        let signers_content = signers_config
            .to_json()
            .expect("Failed to serialize signers config");

        let _signers_source_server =
            initialize_signers_file_with_pending_sigs(&project_dir, &signers_content, &public_key)
                .await;
        // Sign the pending signers file to activate it
        let file_paths = client_cli::commands::list_pending::handle_list_pending_command(
            &backend_url,
            &secret_key_path,
            test_harness::TEST_PASSWORD,
            None,
            false,
        )
        .await
        .expect("list-pending should succeed");

        let signers_pending_path = file_paths
            .iter()
            .find(|pending| {
                let p = pending.path();
                p.starts_with(&format!("{}/", project_dir_sub.to_string_lossy()))
                    && p.contains(PENDING_SIGNERS_DIR)
            })
            .expect("Signers file should be in pending list")
            .clone();

        client_cli::commands::sign_pending::handle_sign_pending_command(
            signers_pending_path.unseal(),
            &backend_url,
            &secret_key_path,
            test_harness::TEST_PASSWORD,
            false,
        )
        .await
        .expect("sign-pending for signers should succeed");

        // Create artifact and its pending signatures file
        test_harness::create_file_in_repo(&file_path, "artifact content")
            .await
            .expect("Failed to create artifact file");
        test_harness::create_pending_signatures_for(&file_path)
            .await
            .expect("Failed to create pending signatures file");

        // Supply the correct path but a wrong digest — simulates a tampered or
        // mismatched server response
        let tampered =
            ClientPendingFile::new(file_path.clone(), AsfaloadHashes::Sha512([0u8; 64].into()));

        let err = client_cli::commands::sign_pending::handle_sign_pending_sec_key(
            tampered,
            &backend_url,
            &secret_key,
            false,
        )
        .await
        .expect_err("Should fail due to digest mismatch");

        assert!(
            matches!(err, ClientCliError::ServerDigestError(..)),
            "Expected ServerDigestError, got: {:?}",
            err
        );
    }

    // ========================================
    // MULTI-SIGNER WORKFLOW TEST
    // ========================================

    #[tokio::test]
    async fn test_multi_signer_workflow() {
        let state = test_harness::initialize().await;
        let guard = state.lock().await;
        let git_repo_path = guard.server.git_repo_path();
        let backend_url = guard.server.base_url();
        let key_paths = guard.secret_key_paths.clone();
        let test_keys = &guard.test_keys;

        // Build 3-key signers config with artifact threshold=2
        let pub_keys: Vec<_> = (0..3)
            .map(|i| test_keys.pub_key(i).expect("key exists").clone())
            .collect();
        let signers_config = SignersConfig::with_artifact_signers_only(1, (pub_keys, 2))
            .expect("Failed to build signers config");
        let signers_json = signers_config.to_json().expect("Failed to serialize");

        // --- Phase 1: Initialize signers ---
        let (project_dir_sub, _) = test_harness::unique_test_paths("multi_signer", "dummy");
        let project_dir = git_repo_path.join(&project_dir_sub);
        fs::create_dir_all(&project_dir).expect("Failed to create project dir");

        let _signers_source_server = initialize_signers_file_with_pending_sigs(
            &project_dir,
            &signers_json,
            test_keys.pub_key(0).unwrap(),
        )
        .await;

        drop(guard);

        // --- Phase 2: Sign signers file with all 3 keys ---
        // list-pending for key[0] should show the pending signers file
        let file_paths = client_cli::commands::list_pending::handle_list_pending_command(
            &backend_url,
            &key_paths[0],
            test_harness::TEST_PASSWORD,
            None,
            false,
        )
        .await
        .expect("list-pending should succeed for key[0]");

        // Find the signers file for this project in the pending list
        let signers_pending_path = file_paths
            .iter()
            .find(|pending| {
                let p = pending.path();
                p.starts_with(&format!("{}/", project_dir_sub.to_string_lossy()))
                    && p.contains(PENDING_SIGNERS_DIR)
            })
            .expect("Signers file should be in pending list")
            .clone();

        // sign-pending with key[0]: 1 of 3, not yet complete
        let r0 = client_cli::commands::sign_pending::handle_sign_pending_command(
            signers_pending_path.unseal(),
            &backend_url,
            &key_paths[0],
            test_harness::TEST_PASSWORD,
            false,
        )
        .await
        .expect("sign-pending key[0] should succeed");
        assert!(
            !r0.is_complete,
            "Should not be complete after 1 of 3 signatures"
        );

        // sign-pending with key[1]: 2 of 3, not yet complete
        let r1 = client_cli::commands::sign_pending::handle_sign_pending_command(
            signers_pending_path.unseal(),
            &backend_url,
            &key_paths[1],
            test_harness::TEST_PASSWORD,
            false,
        )
        .await
        .expect("sign-pending key[1] should succeed");
        assert!(
            !r1.is_complete,
            "Should not be complete after 2 of 3 signatures"
        );

        // sign-pending with key[2]: 3 of 3, complete -> signers activate
        let r2 = client_cli::commands::sign_pending::handle_sign_pending_command(
            signers_pending_path.unseal(),
            &backend_url,
            &key_paths[2],
            test_harness::TEST_PASSWORD,
            false,
        )
        .await
        .expect("sign-pending key[2] should succeed");
        assert!(r2.is_complete, "Should be complete after all 3 signatures");

        // --- Phase 3: Create artifact file ---
        let (_, artifact_path) = test_harness::unique_test_paths("multi_signer", "artifact.txt");

        test_harness::create_file_in_repo(&artifact_path, "artifact content")
            .await
            .expect("Failed to create artifact file");

        test_harness::create_pending_signatures_for(&artifact_path)
            .await
            .expect("Failed to create pending signatures file");

        // --- Phase 4: Sign artifact (threshold=2) ---
        let file_paths = client_cli::commands::list_pending::handle_list_pending_command(
            &backend_url,
            &key_paths[0],
            test_harness::TEST_PASSWORD,
            None,
            false,
        )
        .await
        .expect("list-pending should succeed for key[0]");

        assert!(
            file_paths.iter().any(|p| p.path() == artifact_path),
            "Expected artifact '{}' in pending list, got: {:?}",
            artifact_path,
            file_paths
        );

        let artifact_client_file = file_paths
            .iter()
            .find(|p| p.path() == artifact_path)
            .expect("artifact should be in pending list")
            .clone()
            .unseal();

        // sign with key[0]: 1 of 2, not complete
        let r3 = client_cli::commands::sign_pending::handle_sign_pending_command(
            artifact_client_file.clone(),
            &backend_url,
            &key_paths[0],
            test_harness::TEST_PASSWORD,
            false,
        )
        .await
        .expect("sign key[0] for artifact should succeed");
        assert!(
            !r3.is_complete,
            "Should not be complete after 1 of 2 required signatures"
        );

        // sign with key[1]: 2 of 2, complete
        let r4 = client_cli::commands::sign_pending::handle_sign_pending_command(
            artifact_client_file.clone(),
            &backend_url,
            &key_paths[1],
            test_harness::TEST_PASSWORD,
            false,
        )
        .await
        .expect("sign key[1] for artifact should succeed");
        assert!(
            r4.is_complete,
            "Should be complete after 2 of 2 required signatures"
        );

        // --- Phase 5: Signing after completion should error ---
        let r5 = client_cli::commands::sign_pending::handle_sign_pending_command(
            artifact_client_file.clone(),
            &backend_url,
            &key_paths[2],
            test_harness::TEST_PASSWORD,
            false,
        )
        .await;
        assert!(r5.is_err(), "Signing after completion should fail");
    }
}
