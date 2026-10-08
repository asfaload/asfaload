use thiserror::Error;

pub trait ReleaseInfo: std::fmt::Debug + Send + Sync {
    fn origin_prefix(&self) -> &str;
    fn owner(&self) -> &str;
    fn repo(&self) -> &str;
    fn tag(&self) -> &str;
}

#[derive(Debug, Error)]
pub enum ReleaseHandlingError {
    #[error("InvalidUrl: {0}")]
    InvalidUrl(String),

    #[error("Fetch error: {0}")]
    FetchError(#[from] common::http::FetchError),

    #[error("Parse error: {0}")]
    ParseError(#[from] serde_json::Error),

    #[error("An error occured: {0}")]
    Generic(String),
}

pub trait ReleaseFetcher<T> {
    fn fetch(&self, url: url::Url) -> impl Future<Output = Result<T, ReleaseHandlingError>> + Send;
}
