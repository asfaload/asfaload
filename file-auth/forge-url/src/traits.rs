use std::path::Path;

use crate::error::{ForgeUrlError, UrlInfoError};
use crate::path_prefix_from_url;
use constants::INDEX_FILE;
use url::Url;

pub trait UrlInfoTrait {
    fn new(url: &url::Url) -> Result<Self, UrlInfoError>
    where
        Self: Sized;

    // Identity
    fn project_id(&self) -> String;
}

pub trait ForgeTrait
where
    Self: Sized,
{
    fn new(url: &url::Url) -> Result<Self, ForgeUrlError>;

    // Accessors
    fn owner(&self) -> &str;
    fn repo(&self) -> &str;
    fn branch(&self) -> &str;
    fn url_info(&self) -> &dyn UrlInfoTrait;
}

/// Build repository paths from artifact *download* URLs.
///
/// Distinct from `ForgeTrait`, which parses signers/blob/raw URLs into repo
/// info. Implementors only provide `translate_download_to_release_path`; the
/// path builders are default methods.
pub trait ForgesPathMethods {
    fn construct_index_file_path(&self, file_url: &Url) -> Result<String, ForgeUrlError> {
        self.construct_file_repo_path(file_url, INDEX_FILE)
    }

    fn construct_file_repo_path(
        &self,
        file_url: &Url,
        filename: &str,
    ) -> Result<String, ForgeUrlError> {
        let prefix = path_prefix_from_url(file_url)?;
        let path = file_url.path();
        let path = path.strip_prefix('/').unwrap_or(path);
        let dir_path = path.rsplit_once('/').map(|(dir, _)| dir).unwrap_or("");
        let translated_path = self.translate_download_to_release_path(dir_path);
        Ok(format!("{}/{}/{}", prefix, translated_path, filename))
    }

    fn translate_download_to_release_path(&self, path: &str) -> String;
}
