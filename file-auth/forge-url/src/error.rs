use thiserror::Error;

#[derive(Debug, Error)]
pub enum UrlInfoError {
    #[error("Invalid Forge URL format: {0}")]
    InvalidFormat(String),
}

#[derive(Debug, Error)]
pub enum ForgeUrlError {
    #[error("Invalid Forge URL format: {0}")]
    InvalidFormat(String),
    #[error("Missing branch in URL")]
    MissingBranch,
    #[error("Missing file path in URL")]
    MissingFilePath,
    #[error("Unsupported forge: {0}")]
    UnsupportedForge(String),
    #[error("Url parsing error: {0}")]
    UrlParsingError(#[from] UrlInfoError),
}
