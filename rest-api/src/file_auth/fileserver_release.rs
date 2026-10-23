use std::path::PathBuf;

use features_lib::{AsfaloadPublicKeys, AsfaloadSignatures};
use forge_release::checksums::FileServerReleaseFetcher;
use forge_release::common::{
    ClientIndexSources, ClientProvidedData, ReleaseHandlingError, VerifiedClientData,
};
use rest_api_types::errors::ApiError;
use rest_api_types::path_validation::NormalisedPaths;

use crate::constants::INDEX_FILE;
use crate::file_auth::release_types::{ReleaseError, ReleaseIndexWriter};
use crate::file_auth::releases::ReleaseAdder;

pub struct FileServerReleaseAdder {
    urls: Vec<url::Url>,
    git_repo_path: PathBuf,
    release_path: NormalisedPaths,
    pub verified_client_data: VerifiedClientData,
}

impl ReleaseIndexWriter for FileServerReleaseAdder {}

impl std::fmt::Debug for FileServerReleaseAdder {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FileServerReleaseAdder")
            .field("urls", &self.urls)
            .field("git_repo_path", &self.git_repo_path)
            .field("release_path", &self.release_path)
            .finish()
    }
}

impl FileServerReleaseAdder {
    pub async fn new(
        client_provided_data: ClientProvidedData,
        git_repo_path: PathBuf,
        _config: &crate::config::AppConfig,
    ) -> Result<Self, ReleaseError> {
        let ClientIndexSources::FileServer(source) = &client_provided_data.sources else {
            return Err(ReleaseHandlingError::Generic(format!(
                "Unexpected index sources, expected fileserver: {}",
                client_provided_data.sources
            ))
            .into());
        };
        let checksums_urls = source.urls().to_vec();

        let urls_path = source.base().to_path();
        let release_path = NormalisedPaths::new(&git_repo_path, &urls_path)
            .await
            .map_err(|e| {
                ReleaseHandlingError::Generic(format!(
                    "Could not build normalised path for {}: {} ",
                    urls_path, e
                ))
            })?;

        let fetcher = FileServerReleaseFetcher::new();

        // We verify the client data here. See `ReleaseAdders::new` for the rationale.
        let verified_client_data = VerifiedClientData::new(client_provided_data, &fetcher).await?;
        Ok(Self {
            urls: checksums_urls.to_vec(),
            git_repo_path,
            release_path,
            verified_client_data,
        })
    }
}

impl ReleaseAdder for FileServerReleaseAdder {
    async fn index_path(&self) -> Result<NormalisedPaths, ApiError> {
        self.release_path.join(INDEX_FILE).await
    }
    async fn index_content(&self) -> Result<String, ApiError> {
        Ok(self.verified_client_data.index_string().to_string())
    }
    fn pub_key(&self) -> &AsfaloadPublicKeys {
        self.verified_client_data.pub_key()
    }
    fn signature(&self) -> &AsfaloadSignatures {
        self.verified_client_data.signature()
    }
}
