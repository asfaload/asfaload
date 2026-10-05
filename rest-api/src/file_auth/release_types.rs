use crate::file_auth::releasers::ReleaseInfos;
use common::fs::names::find_global_signers_for;
use rest_api_types::errors::ApiError;
use rest_api_types::path_validation::NormalisedPaths;
use std::path::PathBuf;
use thiserror::Error;
use tokio::{fs::File, io::AsyncWriteExt};

#[derive(Debug, Error)]
pub enum ReleaseError {
    #[error("Invalid release URL format: {0}")]
    ReleaseUrlError(#[from] ReleaseUrlError),
    #[error("Client error: {0}")]
    ClientError(String),
}

#[derive(Debug, Error)]
pub enum ReleaseUrlError {
    #[error("Invalid release URL format: {0}")]
    InvalidFormat(String),
    #[error("Missing tag in release URL")]
    MissingTag,
    #[error("Unsupported release platform: {0}. Supported platforms: GitHub")]
    UnsupportedPlatform(String),
    #[error("Missing {0} in URL")]
    MissingComponent(String),
}

pub trait ReleaseInfo: std::fmt::Debug + Send + Sync {
    fn origin_prefix(&self) -> &str;
    fn owner(&self) -> &str;
    fn repo(&self) -> &str;
    fn tag(&self) -> &str;
}
pub trait BackendReleaseInfo: ReleaseInfo + std::fmt::Debug + Send + Sync {
    fn release_path(&self) -> &NormalisedPaths;
}

#[allow(async_fn_in_trait)]
pub(super) trait ReleaseIndexWriter: std::fmt::Debug {
    /// Unconditionally writes the index file to disk.
    /// This is an implementation detail — callers should use `ReleaseAdder::create_index` instead.
    async fn write_index(&self, f: &mut File, content: &[u8]) -> Result<(), ApiError> {
        f.write(content)
            .await
            .map_err(|e| ApiError::FileWriteFailed(format!("Failed to write index file: {}", e)))?;
        Ok(())
    }
}

#[allow(async_fn_in_trait, private_bounds)]
pub trait ReleaseAdder: ReleaseIndexWriter {
    async fn new(
        release_url: &url::Url,
        git_repo_path: PathBuf,
        config: &crate::config::AppConfig,
    ) -> Result<Self, ReleaseError>
    where
        Self: Sized;

    async fn index_path(&self) -> Result<NormalisedPaths, ApiError>;
    async fn index_content(&self) -> Result<String, ApiError>;

    // Error if index already exists
    async fn create_index(&self) -> Result<NormalisedPaths, ApiError> {
        let index_path = self.index_path().await?;
        find_global_signers_for(&index_path.absolute_path())
            .map_err(|_| ApiError::NoActiveSignersFile)?;
        let abs_path = index_path.absolute_path();
        if let Some(parent) = abs_path.parent() {
            tokio::fs::create_dir_all(parent).await.map_err(|e| {
                ApiError::FileWriteFailed(format!("Failed to create directory: {}", e))
            })?;
        }
        let mut oo = tokio::fs::OpenOptions::new();
        match oo.write(true).create_new(true).open(&abs_path).await {
            Ok(mut f) => {
                let content = self.index_content().await?;
                let content_bytes = content.as_bytes();
                self.write_index(&mut f, content_bytes).await?;
                Ok(index_path)
            }
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                Err(ApiError::ReleaseAlreadyRegistered(format!(
                    "Path: {}",
                    index_path.relative_path().display()
                )))
            }
            Err(e) => Err(ApiError::FileWriteFailed(format!(
                "Failed to create index file: {}",
                e
            ))),
        }
    }

    fn release_info(&self) -> ReleaseInfos;
}
