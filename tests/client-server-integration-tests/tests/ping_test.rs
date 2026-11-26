#[cfg(test)]
mod tests {
    use client_server_integration_tests::test_harness;
    use features_lib::AsfaloadPublicKeyTrait;
    use features_lib::AsfaloadSecretKeyTrait;
    use rest_api_types::PingAuthStatus;

    // Unauthenticated and authenticated ping against a real server, going
    // through the same code path as the CLI binary.
    #[tokio::test]
    async fn test_ping_command_against_server() {
        let state = test_harness::initialize().await;
        let guard = state.lock().await;
        let backend_url = guard.server.base_url();
        let key_path = guard.secret_key_paths[0].clone();
        let expected_public_key = guard.test_keys.pub_key(0).unwrap().to_base64();
        drop(guard);

        // Unauthenticated ping
        let response = client_cli::commands::ping::handle_ping_command(&backend_url, None, false)
            .await
            .expect("unauthenticated ping should succeed");
        assert_eq!(response.message, "pong");
        assert_eq!(response.auth, PingAuthStatus::Unauthenticated);

        // Authenticated ping with the first test key
        let secret_key =
            features_lib::AsfaloadSecretKeys::from_file(&key_path, test_harness::TEST_PASSWORD)
                .expect("Failed to load secret key");
        let response =
            client_cli::commands::ping::handle_ping_command(&backend_url, Some(&secret_key), false)
                .await
                .expect("authenticated ping should succeed");
        assert_eq!(response.message, "pong");
        assert_eq!(
            response.auth,
            PingAuthStatus::Success {
                public_key: expected_public_key
            }
        );
    }
}
