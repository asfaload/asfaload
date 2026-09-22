use common::AsfaloadHashes;
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

// FIXME: remove this, creates more confusion than necessary
pub type Result<T> = std::result::Result<T, ClientCliError>;
