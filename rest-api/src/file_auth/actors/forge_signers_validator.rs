use std::path::PathBuf;

use kameo::message::Context;
use kameo::prelude::{Actor, Message};
use reqwest::Client;
use rest_api_types::errors::ApiError;
use signers_file_types::SignersConfig;

use crate::file_auth::forges::{ForgeInfo, ForgeTrait};

const ACTOR_NAME: &str = "forge_signers_validator";
#[derive(Debug, Clone)]
pub struct ValidateProjectRequest {
    pub signers_file_url: url::Url,
    pub request_id: String,
}

#[derive(Debug, Clone)]
pub struct SignersInfo {
    signers_config: SignersConfig,
    signers_json: String,
}

impl SignersInfo {
    pub fn from_string(signers_json: &str) -> Result<Self, serde_json::Error> {
        let signers_config = signers_file_types::parse_signers_config(signers_json)?;
        Ok(Self {
            signers_config,
            signers_json: signers_json.to_string(),
        })
    }
    pub fn json(&self) -> String {
        self.signers_json.clone()
    }
    pub fn config(&self) -> &SignersConfig {
        &self.signers_config
    }
}

#[derive(Debug, Clone)]
pub struct ProjectSignersProposal {
    pub project_id: String,
    pub signers_info: SignersInfo,
    pub verified_content: signers_file_types::VerifiedForgeContent,
    pub request_id: String,
}

pub struct ForgeProjectValidator {
    http_client: Client,
}

const MAX_SIGNERS_FILE_SIZE: usize = 64 * 1024; // 64KB
const ALLOWED_EXTENSIONS: &[&str] = &["json"];

const MAX_RETRIES: u32 = 3;
const INITIAL_BACKOFF_SEC: u64 = 1;
const MAX_BACKOFF_SEC: u64 = 3600;

pub fn validate_file_extension(file_path: &std::path::Path) -> Result<(), String> {
    let extension = file_path.extension().and_then(|e| e.to_str());
    if !ALLOWED_EXTENSIONS.iter().any(|&ext| Some(ext) == extension) {
        let file_ext = extension.unwrap_or("none");
        return Err(format!(
            "Signers file must have extension in [ {} ], got .{}",
            ALLOWED_EXTENSIONS.join(","),
            file_ext
        ));
    }
    Ok(())
}

pub fn validate_body_size(body: &[u8]) -> Result<(), String> {
    if body.len() > MAX_SIGNERS_FILE_SIZE {
        return Err(format!(
            "Signers file too large: {} bytes exceeds {} byte limit",
            body.len(),
            MAX_SIGNERS_FILE_SIZE
        ));
    }
    Ok(())
}

impl ForgeProjectValidator {
    pub fn new() -> Self {
        tracing::info!(actor_name = ACTOR_NAME, "ForgeProjectAuthenticator created");
        Self {
            http_client: Client::builder()
                .connect_timeout(std::time::Duration::from_secs(10))
                .build()
                .expect("Failed to build reqwest client"),
        }
    }

    #[allow(dead_code)]
    async fn fetch_with_retry(&self, url: &url::Url, request_id: &str) -> Result<String, ApiError> {
        let mut retries = 0;
        let mut backoff_sec = INITIAL_BACKOFF_SEC;

        loop {
            let response = self.http_client.get(url.to_owned()).send().await.map_err(|e| {
                tracing::error!(actor_name = ACTOR_NAME, request_id = %request_id, url = %url, error = %e, "Failed to fetch signers file");
                ApiError::ActorOperationFailed(format!("Failed to fetch: {}", e))
            })?;

            // Too many requests, we need to wait before next try
            if response.status() == 429 {
                if retries >= MAX_RETRIES {
                    return Err(ApiError::ActorOperationFailed(
                        "Forge rate limit exceeded after max retries".to_string(),
                    ));
                }

                let retry_after = response
                    .headers()
                    .get("Retry-After")
                    .and_then(|h| h.to_str().ok())
                    .and_then(|s| s.parse().ok())
                    .unwrap_or(backoff_sec)
                    .min(MAX_BACKOFF_SEC);

                tracing::warn!(actor_name = ACTOR_NAME,request_id = %request_id, retry_after_sec = %retry_after, "Rate limited by Forge, waiting before retry");

                tokio::time::sleep(std::time::Duration::from_secs(retry_after)).await;

                retries += 1;
                backoff_sec = (backoff_sec * 2).min(MAX_BACKOFF_SEC);
                // We can now try again, so start a new loop iteration
                continue;
            }

            if !response.status().is_success() {
                tracing::error!(actor_name = ACTOR_NAME, request_id = %request_id, url = %url, status = %response.status(), "Forge returned non success status");
                return Err(ApiError::ActorOperationFailed(format!(
                    "Forge returned status: {}",
                    response.status()
                )));
            }

            let content = response.text().await.map_err(|e| {
                tracing::error!(actor_name = ACTOR_NAME,request_id = %request_id, error = %e, "Failed to read response body");
                ApiError::ActorOperationFailed(format!("Failed to read response: {}", e))
            })?;

            return Ok(content);
        }
    }

    async fn validate_project(
        &self,
        signers_file_url: &url::Url,
        request_id: &str,
    ) -> Result<ProjectSignersProposal, ApiError> {
        tracing::info!(
            actor_name = ACTOR_NAME,request_id = %request_id,
            signers_file_url = %signers_file_url,
            "Attempting to validate project"
        );

        let repo_info: ForgeInfo = ForgeInfo::new(signers_file_url).map_err(|e| {
            tracing::error!(
                actor_name = ACTOR_NAME,request_id = %request_id,
                url = %signers_file_url,
                error = %e,
                "Failed to parse Forge URL"
            );
            ApiError::InvalidRequestBody(format!("Invalid Forge URL: {}", e))
        })?;

        tracing::info!(
            actor_name = ACTOR_NAME,
            request_id = %request_id,
            owner = %repo_info.owner(),
            repo = %repo_info.repo(),
            branch = %repo_info.branch(),
            file_path = %repo_info.url_info().file_path().unwrap_or(&PathBuf::new()).display(),
            "Parsed Forge URL successfully"
        );

        validate_file_extension(repo_info.url_info().file_path().unwrap_or(&PathBuf::new())).map_err(|e| {
            tracing::error!(actor_name = ACTOR_NAME,request_id = %request_id, error = %e, "Invalid file extension");
            ApiError::InvalidRequestBody(e)
        })?;

        let verified_content = signers_file_types::VerifiedForgeContent::new(
            repo_info.url_info().raw_url().to_string(),
        )
        .await
        .map_err(|e| {
            tracing::error!(
                actor_name = ACTOR_NAME,
                request_id = %request_id,
                error = %e,
                "Failed to fetch and verify forge content"
            );
            ApiError::ActorOperationFailed("Failed to fetch signers file from forge".to_string())
        })?;

        let content = verified_content.content().await.map_err(|e| {
            tracing::error!(actor_name = ACTOR_NAME, request_id = %request_id, error = %e, "Failed to read content");
            ApiError::ActorOperationFailed(
                "Failed to read signers file content".to_string(),
            )
        })?;

        tracing::info!(
            actor_name = ACTOR_NAME,request_id = %request_id,
            content_length = content.len(),
            "Fetched signers file content successfully"
        );

        validate_body_size(content.as_bytes()).map_err(|e| {
            tracing::error!(actor_name = ACTOR_NAME,request_id = %request_id, error = %e, "Body size exceeds limit");
            ApiError::InvalidRequestBody(e)
        })?;

        let signers_info: SignersInfo = SignersInfo::from_string(&content).map_err(|e| {
            tracing::error!(
                request_id = %request_id,
                raw_url = %repo_info.url_info().raw_url(),
                error = %e,
                "Failed to parse signers config JSON"
            );
            ApiError::InvalidRequestBody(format!("Invalid signers config JSON: {}", e))
        })?;

        tracing::info!(
        actor_name = ACTOR_NAME,    request_id = %request_id,
            owner = %repo_info.owner(),
            repo = %repo_info.repo(),
            "Signers config validated successfully"
        );

        let project_id = repo_info.url_info().project_id();

        tracing::info!(
        actor_name = ACTOR_NAME,    request_id = %request_id,
            project_id = %project_id,
            "Project authentication successful"
        );

        Ok(ProjectSignersProposal {
            project_id,
            signers_info,
            verified_content,
            request_id: request_id.to_string(),
        })
    }
}

impl Message<ValidateProjectRequest> for ForgeProjectValidator {
    type Reply = Result<ProjectSignersProposal, ApiError>;

    #[tracing::instrument(skip(self, msg, _ctx))]
    async fn handle(
        &mut self,
        msg: ValidateProjectRequest,
        _ctx: &mut Context<Self, Self::Reply>,
    ) -> Self::Reply {
        tracing::info!(
        actor_name = ACTOR_NAME,    request_id = %msg.request_id,
            signers_file_url = %msg.signers_file_url,
            "ForgeProjectValidator received authentication request"
        );

        self.validate_project(&msg.signers_file_url, &msg.request_id)
            .await
    }
}

impl Actor for ForgeProjectValidator {
    type Args = ();
    type Error = String;

    async fn on_start(
        _args: Self::Args,
        _actor_ref: kameo::prelude::ActorRef<Self>,
    ) -> Result<Self, Self::Error> {
        tracing::info!(
            actor_name = ACTOR_NAME,
            "ForgeProjectAuthenticator starting"
        );
        Ok(Self::new())
    }
}

impl Default for ForgeProjectValidator {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(all(test, not(feature = "test-utils")))]
mod tests {
    use std::path::PathBuf;

    use super::*;

    #[test]
    fn test_validate_file_extension_accepts_json() {
        let result = validate_file_extension(PathBuf::from("signers.json").as_path());
        assert!(result.is_ok(), "Should accept .json extension");
    }

    #[test]
    fn test_validate_file_extension_rejects_txt() {
        let result = validate_file_extension(PathBuf::from("signers.txt").as_path());
        assert!(result.is_err(), "Should reject .txt extension");
        let err = result.unwrap_err();
        assert!(
            err.contains(&ALLOWED_EXTENSIONS.join(",")),
            "Error should mention .json, got: {}",
            err
        );
    }

    #[test]
    fn test_validate_file_extension_rejects_no_extension() {
        let result = validate_file_extension(PathBuf::from("signers").as_path());
        assert!(result.is_err(), "Should reject files without extension");
    }

    #[test]
    fn test_validate_body_size_accepts_small() {
        let result = validate_body_size(b"small content");
        assert!(result.is_ok(), "Should accept small body");
    }

    #[test]
    fn test_validate_body_size_rejects_over_max() {
        let large_content = vec![b'x'; MAX_SIGNERS_FILE_SIZE + 1];
        let result = validate_body_size(&large_content);
        assert!(result.is_err(), "Should reject body over max size");
        let err = result.unwrap_err();
        assert!(
            err.contains("too large") || err.contains("limit"),
            "Error should mention size limit, got: {}",
            err
        );
    }

    #[tokio::test]
    async fn test_fetch_network_error_propagates() {
        // Use a port that is unlikely to have a server
        let unreachable_url = url::Url::parse("http://127.0.0.1:1").unwrap();

        let authenticator = ForgeProjectValidator::new();

        let err = authenticator
            .fetch_with_retry(&unreachable_url, "req-6")
            .await
            .unwrap_err();

        match err {
            ApiError::ActorOperationFailed(msg) => {
                assert!(msg.contains("Failed to fetch"))
            }
            e => panic!("Expected ActorOperationFailed, got {}", e),
        }
    }
}

#[cfg(all(test, feature = "test-utils"))]
mod test_utils_tests {
    use super::*;
    use httpmock::{Method::GET, MockServer};
    use std::time::Duration;
    use std::time::Instant;

    #[tokio::test]
    async fn test_retries_on_rate_limiting() {
        let mock_server = httpmock::MockServer::start();

        let signers_json = r#"{
            "version": 1,
            "timestamp": "2024-01-01T00:00:00Z",
            "artifact_signers": []
        }"#;

        // Test with a localhost URL
        let url = url::Url::parse(&format!(
            "{}/owner/repo/main/signers.json",
            mock_server.url("")
        ))
        .unwrap();

        let mut mock_429 = mock_server.mock(|when, then| {
            when.method(httpmock::Method::GET)
                .path("/owner/repo/main/signers.json");
            then.status(429).header("Retry-After", "2");
        });

        let authenticator = ForgeProjectValidator::new();

        // Start the authentication in the background
        let handle = tokio::spawn({
            async move {
                authenticator
                    .validate_project(&url, "test-rate-limit")
                    .await
            }
        });

        let start = std::time::Instant::now();

        // Poll for the first hit, then delete the mock and create the success mock
        loop {
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
            if mock_429.calls() > 0 {
                mock_429.delete();
                mock_server.mock(|when, then| {
                    when.method(httpmock::Method::GET)
                        .path("/owner/repo/main/signers.json");
                    then.status(200)
                        .header("Content-Type", "application/json")
                        .body(signers_json);
                });
                break;
            }
            if start.elapsed().as_secs() > 5 {
                panic!("Timeout waiting for first hit, calls: {}", mock_429.calls());
            }
        }

        // Wait for the result
        let result = handle.await.unwrap();
        let elapsed = start.elapsed();

        assert!(
            result.is_ok(),
            "Should eventually succeed after retry: {:?}",
            result
        );
        assert!(
            elapsed.as_secs() >= 2,
            "Should have waited for Retry-After, got: {:?}",
            elapsed
        );
    }

    #[tokio::test]
    async fn test_authenticate_with_localhost_url() {
        let mock_server = httpmock::MockServer::start();

        let test_keys = test_helpers::TestKeys::new(1);
        let public_key = test_keys.pub_key(0).unwrap();

        let signers_config = signers_file_types::SignersConfig::with_artifact_signers_only(
            1,
            (vec![public_key.clone()], 1),
        )
        .unwrap();

        let signers_json = serde_json::to_string_pretty(&signers_config).unwrap();

        let mock = mock_server.mock(|when, then| {
            when.method(httpmock::Method::GET)
                .path("/owner/repo/main/signers.json");
            then.status(200)
                .header("Content-Type", "application/json")
                .body(signers_json);
        });

        let url = url::Url::parse(&format!(
            "{}/owner/repo/main/signers.json",
            mock_server.url("")
        ))
        .unwrap();

        let validator = ForgeProjectValidator::new();
        let result = validator.validate_project(&url, "test-request").await;

        assert!(
            result.is_ok(),
            "Should authenticate with localhost URL: {:?}",
            result
        );
        let auth_result = result.unwrap();
        let expected_project_id = format!("http/127.0.0.1/{}/owner/repo", mock_server.port());
        assert_eq!(auth_result.project_id, expected_project_id);

        mock.assert();
    }

    #[tokio::test]
    async fn test_fetch_success_on_first_try() {
        let server = MockServer::start_async().await;
        let mock = server.mock(|when, then| {
            when.method(GET).path("/");
            then.status(200).body("success content");
        });

        let authenticator = ForgeProjectValidator::new();

        let result = authenticator
            .fetch_with_retry(&url::Url::parse(&server.url("/")).unwrap(), "req-1")
            .await
            .unwrap();

        assert_eq!(result, "success content");
        mock.assert_calls_async(1).await;
    }

    #[tokio::test]
    async fn test_fetch_non_429_error_status_fails_immediately() {
        let server = MockServer::start_async().await;
        let mock = server.mock(|when, then| {
            when.method(GET).path("/");
            then.status(500);
        });

        let authenticator = ForgeProjectValidator::new();

        let err = authenticator
            .fetch_with_retry(&url::Url::parse(&server.url("/")).unwrap(), "req-2")
            .await
            .unwrap_err();

        assert!(matches!(err, ApiError::ActorOperationFailed(msg) if msg.contains("500")));
        mock.assert_calls_async(1).await;
    }

    #[tokio::test]
    async fn test_fetch_429_without_retry_after_uses_backoff_and_retries() {
        let server = MockServer::start_async().await;
        let mock = server.mock(|when, then| {
            when.method(GET).path("/");
            then.status(429); // No Retry-After header
        });

        let authenticator = ForgeProjectValidator::new();

        let start = Instant::now();
        let err = authenticator
            .fetch_with_retry(&url::Url::parse(&server.url("/")).unwrap(), "req-3")
            .await
            .unwrap_err();

        // Should retry MAX_RETRIES + 1 times (initial + 3 retries = 4 total attempts)
        mock.assert_calls_async((MAX_RETRIES + 1) as usize).await;

        // Total sleep time: 1 + 2 + 4 = 7 seconds (backoff: 1→2→4; stops before 8 due to max retries)
        let elapsed = start.elapsed();
        assert!(
            elapsed >= Duration::from_secs(7),
            "Expected at least 7s backoff, got {:?}",
            elapsed
        );

        assert!(
            matches!(err, ApiError::ActorOperationFailed(msg) if msg.contains("rate limit exceeded"))
        );
    }

    #[tokio::test]
    async fn test_fetch_429_with_retry_after_header_uses_it_instead_of_backoff() {
        let server = MockServer::start_async().await;
        let mock = server.mock(|when, then| {
            when.method(GET).path("/");
            then.status(429).header("Retry-After", "2");
        });

        let authenticator = ForgeProjectValidator::new();

        let start = Instant::now();
        let err = authenticator
            .fetch_with_retry(&url::Url::parse(&server.url("/")).unwrap(), "req-4")
            .await
            .unwrap_err();

        mock.assert_calls_async((MAX_RETRIES + 1) as usize).await;

        // Each retry waits 2s → 3 retries = 6s total wait
        let elapsed = start.elapsed();
        assert!(
            elapsed >= Duration::from_secs(6),
            "Expected at least 6s due to Retry-After, got {:?}",
            elapsed
        );

        assert!(
            matches!(err, ApiError::ActorOperationFailed(msg) if msg.contains("rate limit exceeded"))
        );
    }

    #[tokio::test]
    async fn test_fetch_succeeds_on_second_attempt_after_429() {
        let server = MockServer::start_async().await;

        let signers_json = r#"{
            "version": 1,
            "timestamp": "2024-01-01T00:00:00Z",
            "artifact_signers": []
        }"#;
        let mut mock_429 = server.mock(move |when, then| {
            when.method(GET).path("/");
            then.status(429).header("Retry-After", "1");
        });

        let authenticator = ForgeProjectValidator::new();

        let server_url = url::Url::parse(&server.url("/")).unwrap();

        // Start fetch loop
        let handle = tokio::spawn({
            async move { authenticator.fetch_with_retry(&server_url, "req-5").await }
        });

        let start = std::time::Instant::now();
        // The mock returning 429 gets a hit, it is replaced by a success responder
        loop {
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
            if mock_429.calls() > 0 {
                mock_429.delete();
                server.mock(|when, then| {
                    when.method(httpmock::Method::GET).path("/");
                    then.status(200)
                        .header("Content-Type", "application/json")
                        .body(signers_json);
                });
                break;
            }
            if start.elapsed().as_secs() > 5 {
                panic!("Timeout waiting for first hit, calls: {}", mock_429.calls());
            }
        }

        // Get the result of the fetch loop
        let result = handle.await.unwrap();

        match result {
            Ok(s) => {
                assert_eq!(s, signers_json);
            }
            Err(e) => {
                panic!("Should have been success: {}", e)
            }
        }

        let elapsed = start.elapsed();
        assert!(
            elapsed >= Duration::from_secs(1),
            "Should have waited at least 1s"
        );
    }
}
