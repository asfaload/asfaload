use crate::constants::INDEX_FILE;
use crate::file_auth::release_types::{
    BackendReleaseInfo, ReleaseAdder, ReleaseError, ReleaseIndexWriter, ReleaseUrlError,
};
use crate::file_auth::releasers::BackendReleaseInfos;
use features_lib::{AsfaloadPublicKeys, AsfaloadSignatures};
use forge_release::common::ReleaseInfo;
use forge_release::common::{ClientIndexSources, ClientProvidedData, VerifiedClientData};
#[cfg(not(feature = "test-utils"))]
use forge_release::github::GithubReleaseFetcher;
use forge_release::github::GithubReleaseInfo;
#[cfg(feature = "test-utils")]
use forge_release::github::test_utils::MockGithubReleaseFetcher;
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
    pub verified_client_data: VerifiedClientData,
    release_info: BackendGithubReleaseInfo,
}

/// Information of a release on the backend
#[derive(Debug, Clone)]
pub struct BackendGithubReleaseInfo {
    pub release_info: GithubReleaseInfo,
    pub release_path: NormalisedPaths,
}

impl ReleaseInfo for BackendGithubReleaseInfo {
    fn origin_prefix(&self) -> &str {
        self.release_info.origin_prefix()
    }

    fn owner(&self) -> &str {
        self.release_info.owner()
    }

    fn repo(&self) -> &str {
        self.release_info.repo()
    }

    fn tag(&self) -> &str {
        self.release_info.tag()
    }
}

impl BackendReleaseInfo for BackendGithubReleaseInfo {
    fn release_path(&self) -> &NormalisedPaths {
        &self.release_path
    }
}

impl ReleaseIndexWriter for GithubReleaseAdder {}

impl GithubReleaseAdder {
    pub async fn new(
        client_provided_data: ClientProvidedData,
        git_repo_path: PathBuf,
        config: &crate::config::AppConfig,
    ) -> Result<Self, ReleaseError> {
        let ClientIndexSources::Github(source) = &client_provided_data.sources;
        let release_url = source.url().clone();

        let release_info = parse_release_url(&release_url, &git_repo_path)
            .await
            .map_err(|e| ReleaseUrlError::InvalidFormat(e.to_string()))?;

        let fetcher = create_github_fetcher(config);

        // We verify the client data here because:
        // - our caller has access to all data we need such as the config to create a github
        // fetcher.
        // - validation of the data depends of the forge we will interact with, and so only a
        // specific release adder can do the validation.
        let verified_client_data = VerifiedClientData::new(client_provided_data, &fetcher).await?;
        Ok(Self {
            release_url,
            git_repo_path,
            release_info,
            verified_client_data,
        })
    }
}

impl ReleaseAdder for GithubReleaseAdder {
    async fn index_path(&self) -> Result<NormalisedPaths, ApiError> {
        let full_index_path = self.release_info.release_path.join(INDEX_FILE).await?;
        Ok(full_index_path)
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

    fn release_info(&self) -> BackendReleaseInfos {
        BackendReleaseInfos::Github(self.release_info.clone())
    }
}

impl std::fmt::Debug for GithubReleaseAdder {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GithubReleaseAdder")
            .field("release_url", &self.release_url)
            .field("git_repo_path", &self.git_repo_path)
            .field("release_info", &self.release_info)
            .finish()
    }
}

pub async fn parse_release_url(
    url: &url::Url,
    git_repo: &Path,
) -> Result<BackendGithubReleaseInfo, ApiError> {
    let release_info =
        GithubReleaseInfo::from_url(url).map_err(|e| ApiError::InvalidReleaseUrl(e.to_string()))?;
    let url_path = format!("{}{}", release_info.origin_prefix, url.path());
    let release_path =
        NormalisedPaths::new(git_repo.to_path_buf(), PathBuf::from(&url_path)).await?;

    Ok(BackendGithubReleaseInfo {
        release_info,
        release_path,
    })
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
        let result = parse_release_url(&url, &git_repo).await.unwrap();

        assert_eq!(result.owner(), "asfaload");
        assert_eq!(result.repo(), "asfald");
        assert_eq!(result.tag(), "v0.9.0");
        assert_eq!(result.origin_prefix(), "https/github.com/443");
        assert_eq!(
            result.release_path.relative_path(),
            PathBuf::from("https/github.com/443/asfaload/asfald/releases/tag/v0.9.0")
        );
    }

    #[tokio::test]
    async fn test_parse_release_url_invalid_too_short() {
        let temp_dir = TempDir::new().unwrap();
        let git_repo = temp_dir.path().to_path_buf();
        let url = url::Url::parse("https://github.com/owner/repo").unwrap();
        let result = parse_release_url(&url, &git_repo).await;

        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_parse_release_url_empty_values() {
        let temp_dir = TempDir::new().unwrap();
        let git_repo = temp_dir.path().to_path_buf();
        let url = url::Url::parse("https://github.com/asfaload/releases/tag/").unwrap();
        let result = parse_release_url(&url, &git_repo).await;

        assert!(result.is_err());
    }
}
