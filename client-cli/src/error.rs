use client_lib::ClientLibError;
use common::AsfaloadHashes;
use features_lib::SignersConfigMetadata;
use features_lib::errors::AggregateSignatureError;
use features_lib::errors::keys::{KeyError, SignError, SignatureError, VerifyError};
use rest_api_types::errors::ApiError;
use rest_api_types::models::ErrorResponse;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum ClientCliError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Key error: {0}")]
    KeyError(#[from] KeyError),

    #[error("Sign error: {0}")]
    SignError(#[from] SignError),

    #[error("Verify error: {0}")]
    VerifyError(#[from] VerifyError),

    #[error("Signature error: {0}")]
    SignatureError(#[from] SignatureError),

    #[error("AggregateSignature error: {0}")]
    AggregateSignatureError(#[from] AggregateSignatureError),

    #[error("Invalid input: {0}")]
    InvalidInput(String),

    #[error("Password is too week")]
    PasswordStrengthError(String),

    #[error("Password confirmation does not match")]
    PasswordConfirmationError,

    #[error("Key generation error: {0}")]
    KeyGeneration(String),

    #[error("Signers file error: {0}")]
    SignersFile(String),

    #[error("Client library error: {0}")]
    ClientLib(#[from] client_lib::ClientLibError),

    #[error("Admin library error: {0}")]
    AdminLib(#[from] admin_lib::AdminLibError),

    #[error("Ping authentication failed: {0}")]
    PingAuthenticationFailed(String),

    #[error("JSON serialization error: {0}")]
    JsonSerializationError(#[from] serde_json::Error),

    #[error("No pending signature found")]
    NoPendingSignature,

    #[error("Computed digest ({0}) does not match the digest advertised by the server ({1})")]
    ServerDigestError(String, AsfaloadHashes),

    #[error("Index validation failed: {0}")]
    IndexValidation(#[from] common::index_validation::IndexValidationError),

    #[error("Backend data error: {0}")]
    BackendDataError(String),

    #[error("Your signature for {0} was already collected. You do not need to sign it again.")]
    SignatureAlreadyCollected(String),

    #[error(
        "The aggregate signature for {0} is already complete. It does not accept more signatures."
    )]
    SignatureAlreadyComplete(String),

    #[error("Revocation failed: {0}")]
    RevocationFailed(String),

    #[error("Asset registration failed: {0}")]
    AssetRegistrationFailed(String),

    #[error("Repository registration failed: {0}")]
    RepoRegistrationFailed(String),

    #[error("Signers update failed: {0}")]
    SignersUpdateFailed(String),
}

/// Return the error built by `failure` with the backend message when the
/// backend reports a failed operation, so that the process exits with a
/// non-zero code and prints nothing on stdout.
pub(crate) fn ensure_backend_success(
    success: bool,
    message: &str,
    failure: fn(String) -> ClientCliError,
) -> Result<()> {
    if success {
        Ok(())
    } else {
        Err(failure(message.to_string()))
    }
}

/// Report unparsable signers metadata as corrupted backend data.
///
/// The metadata file comes from the backend, so a parse failure means the
/// backend serves corrupted data, not a generic JSON error the user could
/// act on.
pub(crate) fn signers_metadata_parse_error(error: serde_json::Error) -> ClientCliError {
    ClientCliError::BackendDataError(format!("Failed to parse metadata: {error}"))
}

/// Report digest sources that do not come from the right account on the publishing platform.
pub(crate) fn index_digest_source_error(error: ClientLibError) -> ClientCliError {
    match error {
        ClientLibError::UrlOutsideRealm {
            path,
            url,
            project_id: _project_id,
        } => ClientCliError::BackendDataError(format!(
            "Digest source ({}) not in index path realm ({})",
            url, path
        )),
        other => other.into(),
    }
}

/// Translate a signers-metadata verification failure into a CLI error.
///
/// A `HashMismatch` means the pending signers file differs from the content
/// served at the retrieval URL recorded in its metadata; the message names
/// that URL so the user can inspect the diverging source. A
/// `UrlOutsideRealm` means the retrieval URL is outside the project of the
/// file's backend path, typically a compromised backend rewriting the
/// metadata; the message names the url, the project it resolves to and the
/// backend path, so the user can compare them. Any other error is passed
/// through as a `ClientLib` error.
pub(crate) fn signers_metadata_verification_error(
    metadata: &SignersConfigMetadata,
    error: client_lib::ClientLibError,
) -> ClientCliError {
    match error {
        client_lib::ClientLibError::HashMismatch { .. } => {
            let retrieval_url = metadata.verified_content().retrieval_url();
            ClientCliError::BackendDataError(format!(
                "The pending signers file on the backend does not match the file on the publishing platform at url {}: {}",
                retrieval_url, error
            ))
        }
        client_lib::ClientLibError::UrlOutsideRealm {
            path,
            url,
            project_id,
        } => {
            let source_detail = match &project_id {
                Some(project) => format!(
                    "points at url {url}, which resolves to the project {project}. That project does not match the file's backend path {path}."
                ),
                None => format!(
                    "points at url {url}, which cannot be resolved to a forge project. The file's backend path is {path}."
                ),
            };
            ClientCliError::BackendDataError(format!(
                "The pending signers file on the backend {source_detail} The metadata may have been tampered with."
            ))
        }
        _ => ClientCliError::ClientLib(error),
    }
}

/// Translate a refused signature submission into a CLI error.
///
/// The backend refuses a signature that it already has, and a signature for
/// an aggregate signature that is already complete. Both refusals are normal
/// situations for the user, so they get a plain message that names the file.
/// Any other error is passed through as an `AdminLib` error.
pub(crate) fn submit_signature_error(
    error: admin_lib::AdminLibError,
    file_path: &str,
) -> ClientCliError {
    if let admin_lib::AdminLibError::RequestFailed(message) = &error {
        if is_refusal_with(message, &ApiError::SignatureAlreadyCollected(String::new())) {
            return ClientCliError::SignatureAlreadyCollected(file_path.to_string());
        }
        if is_refusal_with(message, &ApiError::SignatureAlreadyComplete(String::new())) {
            return ClientCliError::SignatureAlreadyComplete(file_path.to_string());
        }
    }
    ClientCliError::AdminLib(error)
}

/// Tell if a failed request message reports the error `expected` sent by the
/// backend.
///
/// The status and the message prefix come from `ApiError`, so the check
/// follows the backend if its messages change. The message is expected in the
/// format `admin_lib` uses for failed requests: the status, then the body.
fn is_refusal_with(message: &str, expected: &ApiError) -> bool {
    let status_prefix = format!("{}: ", expected.to_http_status());
    // An error built with an empty detail displays only its prefix.
    let error_prefix = expected.to_string();
    message
        .strip_prefix(&status_prefix)
        .and_then(|body| serde_json::from_str::<ErrorResponse>(body).ok())
        .is_some_and(|response| response.error.starts_with(&error_prefix))
}

// FIXME: remove this, creates more confusion than necessary
pub type Result<T> = std::result::Result<T, ClientCliError>;

#[cfg(test)]
mod tests {
    use super::*;
    use client_lib::ClientLibError;
    use features_lib::{Forge, SignersConfigMetadata, VerifiedForgeContent};

    const SOURCE_URL: &str = "https://files.example.com/acme/tool/asfaload.signers/index.json";

    fn metadata(source_url: &str) -> SignersConfigMetadata {
        SignersConfigMetadata::new(
            Forge::Github,
            "https://github.com/acme/tool/raw/main/asfaload.signers/index.json".to_string(),
            VerifiedForgeContent::new_for_test(source_url.to_string(), "{}".to_string()),
            chrono::Utc::now(),
        )
    }

    #[test]
    fn hash_mismatch_error_names_retrieval_url() {
        let error = ClientLibError::HashMismatch {
            expected: "a".repeat(128),
            computed: "b".repeat(128),
        };

        let mapped = signers_metadata_verification_error(&metadata(SOURCE_URL), error);

        match mapped {
            ClientCliError::BackendDataError(message) => {
                assert!(message.contains(SOURCE_URL), "message: {message}");
                assert!(message.contains("Hash mismatch"), "message: {message}");
            }
            other => panic!("Expected BackendDataError but got {other}"),
        }
    }

    #[test]
    fn unparsable_metadata_is_reported_as_backend_data_error() {
        let json_error = serde_json::from_slice::<SignersConfigMetadata>(b"not json")
            .expect_err("raw text is not valid metadata JSON");

        let mapped = signers_metadata_parse_error(json_error);

        match mapped {
            ClientCliError::BackendDataError(message) => {
                assert!(
                    message.contains("Failed to parse metadata"),
                    "Unexpected BackendDataError message: {message}"
                );
            }
            other => panic!("Expected BackendDataError but got {other}"),
        }
    }

    #[test]
    fn url_outside_realm_names_resolved_project() {
        let error = ClientLibError::UrlOutsideRealm {
            path: "https/github.com/443/acme/tool/asfaload.signers.pending/index.json".to_string(),
            url: "https://raw.githubusercontent.com/attacker/evil/main/signers.json".to_string(),
            project_id: Some("https/github.com/443/attacker/evil".to_string()),
        };

        let mapped = signers_metadata_verification_error(&metadata(SOURCE_URL), error);

        match mapped {
            ClientCliError::BackendDataError(message) => {
                assert!(
                    message.contains("resolves to the project https/github.com/443/attacker/evil"),
                    "message: {message}"
                );
                assert!(message.contains("tampered"), "message: {message}");
            }
            other => panic!("Expected BackendDataError but got {other}"),
        }
    }

    #[test]
    fn url_outside_realm_without_project_reports_unresolvable_url() {
        let error = ClientLibError::UrlOutsideRealm {
            path: "https/github.com/443/acme/tool/asfaload.signers.pending/index.json".to_string(),
            url: "not a url".to_string(),
            project_id: None,
        };

        let mapped = signers_metadata_verification_error(&metadata(SOURCE_URL), error);

        match mapped {
            ClientCliError::BackendDataError(message) => {
                assert!(
                    message.contains("cannot be resolved to a forge project"),
                    "message: {message}"
                );
                assert!(message.contains("tampered"), "message: {message}");
            }
            other => panic!("Expected BackendDataError but got {other}"),
        }
    }

    #[test]
    fn other_errors_pass_through_unmapped() {
        let error = ClientLibError::SignersMetadataSourceFetchError("backend down".to_string());

        let mapped = signers_metadata_verification_error(&metadata(SOURCE_URL), error);

        match mapped {
            ClientCliError::ClientLib(ClientLibError::SignersMetadataSourceFetchError(message)) => {
                assert_eq!(message, "backend down");
            }
            other => panic!("Expected ClientLib passthrough but got {other}"),
        }
    }

    type FailureVariant = fn(String) -> ClientCliError;

    #[test]
    fn ensure_backend_success_cases() {
        // (failure variant, expected message of the error)
        let cases: Vec<(FailureVariant, &str)> = vec![
            (
                ClientCliError::RevocationFailed,
                "Revocation failed: backend refused",
            ),
            (
                ClientCliError::AssetRegistrationFailed,
                "Asset registration failed: backend refused",
            ),
            (
                ClientCliError::RepoRegistrationFailed,
                "Repository registration failed: backend refused",
            ),
            (
                ClientCliError::SignersUpdateFailed,
                "Signers update failed: backend refused",
            ),
        ];
        for (failure, expected_message) in cases {
            assert!(ensure_backend_success(true, "unused", failure).is_ok());
            match ensure_backend_success(false, "backend refused", failure) {
                Err(e) => assert_eq!(e.to_string(), expected_message),
                Ok(()) => panic!("expected an error for {expected_message:?}, got Ok"),
            }
        }
    }

    type ErrorCheck = fn(&ClientCliError) -> bool;

    /// Build a failed request message in the format `admin_lib` uses.
    fn refusal_message(api_error: &ApiError) -> String {
        let body = serde_json::to_string(&ErrorResponse {
            error: api_error.to_string(),
        })
        .unwrap();
        format!("{}: {}", api_error.to_http_status(), body)
    }

    #[test]
    fn submit_signature_error_cases() {
        let file_path = "github.com/acme/tool/releases/v1/asfaload.index.json";
        let collected = ApiError::SignatureAlreadyCollected(
            "Signature already collected for this key".to_string(),
        );
        let complete =
            ApiError::SignatureAlreadyComplete("Cannot accept additional signatures".to_string());
        let other_conflict = ApiError::FileNotFullySigned("not signed".to_string());
        let collected_body = serde_json::to_string(&ErrorResponse {
            error: collected.to_string(),
        })
        .unwrap();

        // (description, failed request message, expected error)
        let cases: Vec<(&str, String, ErrorCheck)> = vec![
            ("already collected", refusal_message(&collected), |e| {
                matches!(e, ClientCliError::SignatureAlreadyCollected(_))
            }),
            (
                "already added",
                refusal_message(&ApiError::SignatureAlreadyCollected(
                    "Signature already added".to_string(),
                )),
                |e| matches!(e, ClientCliError::SignatureAlreadyCollected(_)),
            ),
            ("already complete", refusal_message(&complete), |e| {
                matches!(e, ClientCliError::SignatureAlreadyComplete(_))
            }),
            ("other conflict", refusal_message(&other_conflict), |e| {
                matches!(e, ClientCliError::AdminLib(_))
            }),
            (
                "wrong status",
                format!("400 Bad Request: {collected_body}"),
                |e| matches!(e, ClientCliError::AdminLib(_)),
            ),
            (
                "body is not json",
                format!("{}: {}", collected.to_http_status(), collected),
                |e| matches!(e, ClientCliError::AdminLib(_)),
            ),
        ];

        for (description, message, is_expected) in cases {
            let error =
                submit_signature_error(admin_lib::AdminLibError::RequestFailed(message), file_path);
            assert!(
                is_expected(&error),
                "{description}: unexpected error {error}"
            );
        }
    }

    #[test]
    fn submit_signature_error_names_file() {
        let file_path = "github.com/acme/tool/releases/v1/asfaload.index.json";
        let message = refusal_message(&ApiError::SignatureAlreadyCollected(
            "Signature already collected for this key".to_string(),
        ));

        let error =
            submit_signature_error(admin_lib::AdminLibError::RequestFailed(message), file_path);

        assert!(error.to_string().contains(file_path), "message: {error}");
    }

    #[test]
    fn submit_signature_error_passes_other_errors_through() {
        let error = submit_signature_error(
            admin_lib::AdminLibError::InvalidInput("bad".to_string()),
            "some/file",
        );

        match error {
            ClientCliError::AdminLib(admin_lib::AdminLibError::InvalidInput(msg)) => {
                assert_eq!(msg, "bad")
            }
            other => panic!("Expected AdminLib InvalidInput passthrough but got {other}"),
        }
    }
}
