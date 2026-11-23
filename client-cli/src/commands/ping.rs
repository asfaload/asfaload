use crate::error::{ClientCliError, Result};
use features_lib::AsfaloadSecretKeys;
use rest_api_types::{PingAuthStatus, PingResponse};

/// Render the human-readable ping result line.
fn render_ping_output(response: &PingResponse, backend_url: &str) -> String {
    match &response.auth {
        PingAuthStatus::Unauthenticated => {
            format!(
                "{} from {} — unauthenticated",
                response.message, backend_url
            )
        }
        PingAuthStatus::Success { public_key } => format!(
            "{} from {} — authenticated as {}",
            response.message, backend_url, public_key
        ),
        PingAuthStatus::Failed {
            public_key: Some(public_key),
            reason,
        } => format!(
            "{} from {} — auth FAILED for key {}: {}",
            response.message, backend_url, public_key, reason
        ),
        PingAuthStatus::Failed {
            public_key: None,
            reason,
        } => format!(
            "{} from {} — auth FAILED: {}",
            response.message, backend_url, reason
        ),
    }
}

/// Return the failure reason when authentication was attempted and failed.
fn auth_failure_reason(response: &PingResponse) -> Option<String> {
    match &response.auth {
        PingAuthStatus::Failed { reason, .. } => Some(reason.clone()),
        _ => None,
    }
}

/// Handle the ping command.
///
/// Sends a ping request to the backend. Without a secret key the request is
/// unauthenticated; with a key it is authenticated and the server reports
/// whether the authentication succeeded and for which public key.
///
/// # Arguments
///
/// * `backend_url` - Backend API URL
/// * `secret_key` - Optional secret key of the user
/// * `json` - Output the raw response as JSON
///
/// # Errors
///
/// Returns an error when the backend is unreachable, and
/// `ClientCliError::PingAuthenticationFailed` when authentication was
/// attempted but failed (so the process exits with a non-zero code).
pub async fn handle_ping_command(
    backend_url: &str,
    secret_key: Option<&AsfaloadSecretKeys>,
    json: bool,
) -> Result<PingResponse> {
    let client = admin_lib::v1::Client::new(backend_url);
    let response = client.ping(secret_key).await?;

    if json {
        println!("{}", serde_json::to_string(&response)?);
    } else {
        println!("{}", render_ping_output(&response, backend_url));
    }

    if let Some(reason) = auth_failure_reason(&response) {
        return Err(ClientCliError::PingAuthenticationFailed(reason));
    }

    Ok(response)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rest_api_types::{PingAuthStatus, PingResponse};

    fn response_with(auth: PingAuthStatus) -> PingResponse {
        PingResponse {
            message: "pong".to_string(),
            auth,
        }
    }

    #[test]
    fn test_render_ping_output_unauthenticated() {
        let response = response_with(PingAuthStatus::Unauthenticated);
        let output = render_ping_output(&response, "http://localhost:3000");
        assert_eq!(output, "pong from http://localhost:3000 — unauthenticated");
    }

    #[test]
    fn test_render_ping_output_success() {
        let response = response_with(PingAuthStatus::Success {
            public_key: "base64pk".to_string(),
        });
        let output = render_ping_output(&response, "http://localhost:3000");
        assert_eq!(
            output,
            "pong from http://localhost:3000 — authenticated as base64pk"
        );
    }

    #[test]
    fn test_render_ping_output_failed_with_key() {
        let response = response_with(PingAuthStatus::Failed {
            public_key: Some("base64pk".to_string()),
            reason: "Replay attack detected: nonce already used".to_string(),
        });
        let output = render_ping_output(&response, "http://localhost:3000");
        assert_eq!(
            output,
            "pong from http://localhost:3000 — auth FAILED for key base64pk: Replay attack detected: nonce already used"
        );
    }

    #[test]
    fn test_render_ping_output_failed_without_key() {
        let response = response_with(PingAuthStatus::Failed {
            public_key: None,
            reason: "Missing authentication headers".to_string(),
        });
        let output = render_ping_output(&response, "http://localhost:3000");
        assert_eq!(
            output,
            "pong from http://localhost:3000 — auth FAILED: Missing authentication headers"
        );
    }

    #[test]
    fn test_auth_failure_reason_is_none_for_success_and_unauthenticated() {
        assert_eq!(
            auth_failure_reason(&response_with(PingAuthStatus::Unauthenticated)),
            None
        );
        assert_eq!(
            auth_failure_reason(&response_with(PingAuthStatus::Success {
                public_key: "base64pk".to_string()
            })),
            None
        );
    }

    #[test]
    fn test_auth_failure_reason_is_some_for_failed() {
        let response = response_with(PingAuthStatus::Failed {
            public_key: None,
            reason: "Missing authentication headers".to_string(),
        });
        assert_eq!(
            auth_failure_reason(&response),
            Some("Missing authentication headers".to_string())
        );
    }
}
