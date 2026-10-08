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
}
