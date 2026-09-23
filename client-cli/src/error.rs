use common::AsfaloadHashes;
use features_lib::SignersConfigMetadata;
use features_lib::errors::AggregateSignatureError;
use features_lib::errors::keys::{KeyError, SignError, SignatureError, VerifyError};
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
}

/// Translate a signers-metadata verification failure into a CLI error.
///
/// A `HashMismatch` means the pending signers file differs from the content
/// served at the retrieval URL recorded in its metadata; the message names
/// that URL so the user can inspect the diverging source. Any other error is
/// passed through as a `ClientLib` error.
pub(crate) fn signers_metadata_verification_error(
    metadata: &SignersConfigMetadata,
    error: client_lib::ClientLibError,
) -> ClientCliError {
    match error {
        client_lib::ClientLibError::HashMismatch { .. } => {
            let retrieval_url = match metadata.origin() {
                features_lib::SignersConfigOrigin::Forge(origin) => {
                    origin.verified_content().retrieval_url()
                }
            };
            ClientCliError::BackendDataError(format!(
                "The pending signers file on the backend does not match the file on the publishing platform at url {}: {}",
                retrieval_url, error
            ))
        }
        _ => ClientCliError::ClientLib(error),
    }
}

// FIXME: remove this, creates more confusion than necessary
pub type Result<T> = std::result::Result<T, ClientCliError>;

#[cfg(test)]
mod tests {
    use super::*;
    use client_lib::ClientLibError;
    use features_lib::{Forge, ForgeOrigin, SignersConfigMetadata, VerifiedForgeContent};

    const SOURCE_URL: &str = "https://files.example.com/acme/tool/asfaload.signers/index.json";

    fn metadata(source_url: &str) -> SignersConfigMetadata {
        SignersConfigMetadata::from_forge(ForgeOrigin::new(
            Forge::Github,
            "https://github.com/acme/tool/raw/main/asfaload.signers/index.json".to_string(),
            VerifiedForgeContent::new_for_test(source_url.to_string(), "{}".to_string()),
            chrono::Utc::now(),
        ))
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
}
