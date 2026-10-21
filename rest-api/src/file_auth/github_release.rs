use crate::constants::INDEX_FILE;
use crate::file_auth::release_types::{
    ReleaseAdder, ReleaseError, ReleaseIndexWriter, ReleaseUrlError,
};
use features_lib::{AsfaloadPublicKeys, AsfaloadSignatures};
use forge_release::common::ReleaseHandlingError;
use forge_release::common::{ClientIndexSources, ClientProvidedData, VerifiedClientData};
#[cfg(not(feature = "test-utils"))]
use forge_release::github::GithubReleaseFetcher;
#[cfg(feature = "test-utils")]
use forge_release::github::test_utils::MockGithubReleaseFetcher;
use forge_url::github::{is_github_release_host, validate_github_release_url};
use forge_url::path_prefix_from_url;
use rest_api_types::errors::ApiError;
use rest_api_types::path_validation::NormalisedPaths;
use std::path::{Path, PathBuf};

#[cfg(not(feature = "test-utils"))]
fn create_github_fetcher(config: &crate::config::AppConfig) -> GithubReleaseFetcher {
    GithubReleaseFetcher::new(config.github_api_key.clone())
}

#[cfg(feature = "test-utils")]
fn create_github_fetcher(_config: &crate::config::AppConfig) -> MockGithubReleaseFetcher {
    MockGithubReleaseFetcher::new()
}

pub struct GithubReleaseAdder {
    release_url: url::Url,
    git_repo_path: PathBuf,
    release_path: NormalisedPaths,
    pub verified_client_data: VerifiedClientData,
}

impl ReleaseIndexWriter for GithubReleaseAdder {}

impl GithubReleaseAdder {
    pub async fn new(
        client_provided_data: ClientProvidedData,
        git_repo_path: PathBuf,
        config: &crate::config::AppConfig,
    ) -> Result<Self, ReleaseError> {
        let ClientIndexSources::Github(source) = &client_provided_data.sources else {
            return Err(ReleaseHandlingError::Generic(format!(
                "Unexpected index sources, expected github: {}",
                client_provided_data.sources
            ))
            .into());
        };
        let release_url = source.url().clone();

        // The release url must target a github release page: the api host
        // is not a release page host.
        let host = release_url
            .host_str()
            .ok_or_else(|| ReleaseUrlError::InvalidFormat("Missing host".to_string()))?;
        if !is_github_release_host(host) {
            return Err(ReleaseUrlError::UnsupportedPlatform(format!(
                "Host {} is not recognised as a Github release host",
                host,
            ))
            .into());
        }

        let release_path = release_path_from_url(&release_url, &git_repo_path)
            .await
            .map_err(|e| ReleaseUrlError::InvalidFormat(e.to_string()))?;

        let fetcher = create_github_fetcher(config);

        // We verify the client data here. See `ReleaseAdders::new` for the rationale.
        let verified_client_data = VerifiedClientData::new(client_provided_data, &fetcher).await?;
        Ok(Self {
            release_url,
            git_repo_path,
            release_path,
            verified_client_data,
        })
    }
}

impl ReleaseAdder for GithubReleaseAdder {
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

impl std::fmt::Debug for GithubReleaseAdder {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GithubReleaseAdder")
            .field("release_url", &self.release_url)
            .field("git_repo_path", &self.git_repo_path)
            .field("release_path", &self.release_path)
            .finish()
    }
}

/// Build the directory of the release under the git repository.
///
/// The path mirrors the release url: the scheme, host, and port prefix is
/// followed by the url path.
pub async fn release_path_from_url(
    url: &url::Url,
    git_repo: &Path,
) -> Result<NormalisedPaths, ApiError> {
    validate_github_release_url(url).map_err(|e| ApiError::InvalidReleaseUrl(e.to_string()))?;
    let origin_prefix =
        path_prefix_from_url(url).map_err(|e| ApiError::InvalidReleaseUrl(e.to_string()))?;
    let url_path = format!("{}{}", origin_prefix, url.path());
    NormalisedPaths::new(git_repo.to_path_buf(), PathBuf::from(&url_path)).await
}

#[cfg(all(test, feature = "test-utils"))]
mod feature_gated_tests {
    use features_lib::AsfaloadIndex;
    use forge_release::github::GithubReleaseResponse;
    use forge_release::github::test_utils::{MOCK_RELEASE_JSON, create_mock_release_response};

    // Gives the added asset its own download url so a regression to
    // browser_download_url as digest source cannot pass silently.
    fn release_with_extra_asset(name: &str, digest: Option<&str>) -> GithubReleaseResponse {
        let mut value: serde_json::Value = serde_json::from_str(MOCK_RELEASE_JSON).unwrap();
        let mut asset = value["assets"][0].clone();
        asset["name"] = serde_json::Value::String(name.to_string());
        asset["browser_download_url"] =
            serde_json::Value::String(format!("https://example.com/download/{}", name));
        if let Some(digest) = digest {
            asset["digest"] = serde_json::Value::String(digest.to_string());
        } else {
            asset.as_object_mut().unwrap().remove("digest");
        }
        value["assets"].as_array_mut().unwrap().push(asset);
        serde_json::from_value(value).unwrap()
    }

    #[test]
    fn extract_assets_sets_source_to_release_api_url_for_all_assets() {
        let release = release_with_extra_asset(
            "other.tar.gz",
            Some("sha256:1111111111111111111111111111111111111111111111111111111111111111"),
        );

        let assets = release.extract_assets();

        assert_eq!(assets.len(), 2);
        for (asset_info, _asset) in assets.iter().zip(release.assets.iter()) {
            let checksum = asset_info
                .hash
                .as_ref()
                .expect("mocked assets all carry a digest");
            // The sources is not the asset's download url, but the release's GH rest-api url
            assert_eq!(checksum.source, release.url.to_string());
        }
    }

    #[test]
    fn generate_index_json_serializes_digest_source_as_release_api_url() {
        let release = release_with_extra_asset(
            "other.tar.gz",
            Some("sha256:1111111111111111111111111111111111111111111111111111111111111111"),
        );

        let json = release.generate_index_json().unwrap();

        // Go through the serialized form, as the index file is what
        // consumers (e.g. a future check-index command) will read.
        let index: AsfaloadIndex = serde_json::from_str(&json).unwrap();
        assert_eq!(index.published_files.len(), 2);
        for checksum in &index.published_files {
            assert_eq!(checksum.source, release.url.to_string());
        }
    }

    #[test]
    fn assets_without_digest_are_excluded_from_index() {
        let release = release_with_extra_asset("no-digest.tar.gz", None);

        let json = release.generate_index_json().unwrap();

        let index: AsfaloadIndex = serde_json::from_str(&json).unwrap();
        assert_eq!(index.published_files.len(), 1);
        assert_eq!(index.published_files[0].file_name, "test.tar.gz");
        assert_eq!(index.published_files[0].source, release.url.to_string());
    }

    #[test]
    fn generate_index_json_has_trailing_newline() {
        let release = create_mock_release_response();

        let json = release.generate_index_json().unwrap();

        assert!(
            json.ends_with("}\n"),
            "index JSON should end with exactly one trailing newline, got: {:?}",
            &json[json.len().saturating_sub(20)..]
        );
        assert!(
            !json.ends_with("\n\n"),
            "index JSON should not end with double newline"
        );
    }
}

#[cfg(all(test, not(feature = "test-utils")))]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[tokio::test]
    async fn test_parse_release_url_full_url() {
        let temp_dir = TempDir::new().unwrap();
        let git_repo = temp_dir.path().to_path_buf();
        let url =
            url::Url::parse("https://github.com/asfaload/asfald/releases/tag/v0.9.0").unwrap();
        let result = release_path_from_url(&url, &git_repo).await.unwrap();

        assert_eq!(
            result.relative_path(),
            PathBuf::from("https/github.com/443/asfaload/asfald/releases/tag/v0.9.0")
        );
    }

    #[tokio::test]
    async fn test_parse_release_url_invalid_too_short() {
        let temp_dir = TempDir::new().unwrap();
        let git_repo = temp_dir.path().to_path_buf();
        let url = url::Url::parse("https://github.com/owner/repo").unwrap();
        let result = release_path_from_url(&url, &git_repo).await;

        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_parse_release_url_empty_values() {
        let temp_dir = TempDir::new().unwrap();
        let git_repo = temp_dir.path().to_path_buf();
        let url = url::Url::parse("https://github.com/asfaload/releases/tag/").unwrap();
        let result = release_path_from_url(&url, &git_repo).await;

        assert!(result.is_err());
    }
}
