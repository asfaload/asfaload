use common::errors::keys::SignError;
use forge_release::common::ReleaseHandlingError;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum AdminLibError {
    #[error("Authentication error: {0}")]
    AuthError(#[from] rest_api_auth::AuthError),

    #[error("Invalid header value: {0}")]
    InvalidHeaderValue(#[from] reqwest::header::InvalidHeaderValue),

    #[error("Request error: {0}")]
    RequestError(#[from] reqwest::Error),

    #[error("Error response from server: {0}")]
    RequestFailed(String),

    #[error("Json serialisation error: {0}")]
    JsonError(#[from] serde_json::Error),

    #[error("Invalid input: {0}")]
    InvalidInput(String),

    #[error("Release handling error: {0}")]
    ReleaseHandling(#[from] ReleaseHandlingError),

    #[error("I/O error: {0}")]
    IOError(#[from] std::io::Error),

    #[error("Sign error: {0}")]
    SignError(#[from] SignError),
}

pub type AdminLibResult<T> = std::result::Result<T, AdminLibError>;
