use crate::constants::INDEX_FILE;
use crate::file_auth::release_types::{
    BackendReleaseInfo, ReleaseAdder, ReleaseIndexWriter, ReleaseUrlError,
};
use crate::file_auth::releasers::BackendReleaseInfos;
use common::index_types::ChecksumSourceFormat;
use features_lib::{AsfaloadIndex, FileChecksum, HashAlgorithm};
use forge_release::common::{ReleaseFetcher, ReleaseInfo};
#[cfg(not(feature = "test-utils"))]
use forge_release::github::GithubReleaseFetcher;
use forge_release::github::{GithubReleaseInfo, GithubReleaseResponse};
use forge_url::github::validate_github_release_url;
use forge_url::path_prefix_from_url;
use rest_api_types::errors::ApiError;
use rest_api_types::path_validation::NormalisedPaths;
use std::path::{Path, PathBuf};

// Fetcher type used by the release adder. In tests it is replaced by a
// fetcher returning a fixed response, so no request hits github.
#[cfg(not(feature = "test-utils"))]
pub type GithubFetcher = forge_release::github::GithubReleaseFetcher;
#[cfg(feature = "test-utils")]
pub type GithubFetcher = crate::file_auth::github_release::test_utils::MockGithubReleaseFetcher;

#[cfg(not(feature = "test-utils"))]
fn create_github_fetcher(config: &crate::config::AppConfig) -> GithubFetcher {
    GithubReleaseFetcher::new(config.github_api_key.clone())
}

#[cfg(feature = "test-utils")]
fn create_github_fetcher(_config: &crate::config::AppConfig) -> GithubFetcher {
    test_utils::MockGithubReleaseFetcher::new()
}

pub struct GithubReleaseAdder<C: ReleaseFetcher<GithubReleaseResponse>> {
    release_url: url::Url,
    git_repo_path: PathBuf,
    pub fetcher: C,
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

struct ReleaseAssetInfo {
    hash: Option<FileChecksum>,
}

impl ReleaseIndexWriter for GithubReleaseAdder<GithubFetcher> {}

impl ReleaseAdder for GithubReleaseAdder<GithubFetcher> {
    async fn new(
        release_url: &url::Url,
        git_repo_path: PathBuf,
        config: &crate::config::AppConfig,
    ) -> Result<Self, crate::file_auth::release_types::ReleaseError>
    where
        Self: Sized,
    {
        let release_info = parse_release_url(release_url, &git_repo_path)
            .await
            .map_err(|e| ReleaseUrlError::InvalidFormat(e.to_string()))?;

        let fetcher = create_github_fetcher(config);

        Ok(Self {
            release_url: release_url.clone(),
            git_repo_path,
            fetcher,
            release_info,
        })
    }

    async fn index_path(&self) -> Result<NormalisedPaths, ApiError> {
        let full_index_path = self.release_info.release_path.join(INDEX_FILE).await?;
        Ok(full_index_path)
    }
    async fn index_content(&self) -> Result<String, ApiError> {
        let release: GithubReleaseResponse = self
            .fetcher
            .fetch(self.release_url.clone())
            .await
            .map_err(|e| ApiError::Generic(format!("Could not retrieve github release: {}", e)))?;

        let assets = self.extract_assets(&release);

        if assets.is_empty() {
            return Err(ApiError::ReleaseApiError(
                "GitHub".to_string(),
                "No assets found in release".to_string(),
            ));
        }

        self.generate_index_json(&assets, &release)
    }

    fn release_info(&self) -> BackendReleaseInfos {
        BackendReleaseInfos::Github(self.release_info.clone())
    }
}

impl<C: ReleaseFetcher<GithubReleaseResponse>> GithubReleaseAdder<C> {
    fn extract_assets(&self, release: &GithubReleaseResponse) -> Vec<ReleaseAssetInfo> {
        release
            .assets
            .iter()
            .map(|asset| {
                let hash = asset.digest.as_ref().and_then(|d| {
                    d.strip_prefix("sha256:").map(|hash| FileChecksum {
                        file_name: asset.name.clone(),
                        algo: HashAlgorithm::Sha256,
                        // For a github release, the source is the url to get from the GH rest-api
                        // to retrieve the release info, incl. assets and their digest.
                        source: release.url.to_string(),
                        source_format: ChecksumSourceFormat::GithubRelease,
                        hash: hash.to_string(),
                    })
                });
                ReleaseAssetInfo { hash }
            })
            .collect()
    }

    fn generate_index_json(
        &self,
        assets: &[ReleaseAssetInfo],
        release: &GithubReleaseResponse,
    ) -> Result<String, ApiError> {
        let published_files: Vec<FileChecksum> = assets
            .iter()
            .filter_map(|asset| asset.hash.clone())
            .collect();

        let published_on = release.published_at.or(release.created_at).ok_or_else(|| {
            ApiError::ReleaseApiError(
                "GitHub".to_string(),
                "No publication timestamp found in release".to_string(),
            )
        })?;
        let mirrored_on = chrono::Utc::now();

        let index = AsfaloadIndex {
            mirrored_on,
            published_on: published_on.to_utc(),
            version: 1,
            published_files,
        };

        common::to_posix_json(&index)
            .map_err(|e| ApiError::InternalServerError(format!("Failed to serialize index: {}", e)))
    }
}

impl<C: ReleaseFetcher<GithubReleaseResponse>> std::fmt::Debug for GithubReleaseAdder<C> {
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
    let (_host, owner, repo, tag) =
        validate_github_release_url(url).map_err(|e| ApiError::InvalidReleaseUrl(e.to_string()))?;
    let origin_prefix =
        path_prefix_from_url(url).map_err(|e| ApiError::InvalidReleaseUrl(e.to_string()))?;
    let url_path = format!("{}{}", origin_prefix, url.path());
    let release_path =
        NormalisedPaths::new(git_repo.to_path_buf(), PathBuf::from(&url_path)).await?;
    let release_info = GithubReleaseInfo {
        origin_prefix,
        owner,
        repo,
        tag,
    };

    Ok(BackendGithubReleaseInfo {
        release_info,
        release_path,
    })
}

#[cfg(feature = "test-utils")]
pub mod test_utils {
    use super::*;

    // Minimal shape of the github rest-api release response as parsed by
    // GithubReleaseResponse.
    pub const MOCK_RELEASE_JSON: &str = r#"{
        "url": "https://api.github.com/repos/testowner/testrepo/releases/123",
        "published_at": "2024-01-01T00:00:00Z",
        "created_at": "2024-01-01T00:00:00Z",
        "assets": [{
            "name": "test.tar.gz",
            "digest": "sha256:abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890"
        }]
    }"#;

    pub fn create_mock_release_response() -> GithubReleaseResponse {
        serde_json::from_str(MOCK_RELEASE_JSON).unwrap()
    }

    // Fetcher returning a fixed release response so tests never hit github.
    // Serving error responses will be added later.
    pub struct MockGithubReleaseFetcher;

    impl MockGithubReleaseFetcher {
        pub fn new() -> Self {
            Self
        }
    }

    impl Default for MockGithubReleaseFetcher {
        fn default() -> Self {
            Self::new()
        }
    }

    impl ReleaseFetcher<GithubReleaseResponse> for MockGithubReleaseFetcher {
        async fn fetch(
            &self,
            _url: url::Url,
        ) -> Result<GithubReleaseResponse, forge_release::common::ReleaseHandlingError> {
            Ok(create_mock_release_response())
        }
    }
}

#[cfg(all(test, feature = "test-utils"))]
mod feature_gated_tests {
    use super::test_utils::*;
    use super::*;
    use tempfile::TempDir;

    async fn build_adder(git_repo: PathBuf) -> GithubReleaseAdder<MockGithubReleaseFetcher> {
        let url =
            url::Url::parse("https://github.com/testowner/testrepo/releases/tag/v1.0.0").unwrap();
        let release_info = parse_release_url(&url, &git_repo).await.unwrap();
        GithubReleaseAdder {
            release_url: url,
            git_repo_path: git_repo,
            fetcher: MockGithubReleaseFetcher::new(),
            release_info,
        }
    }

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

    #[tokio::test]
    async fn extract_assets_sets_source_to_release_api_url_for_all_assets() {
        let release = release_with_extra_asset(
            "other.tar.gz",
            Some("sha256:1111111111111111111111111111111111111111111111111111111111111111"),
        );

        let adder = build_adder(TempDir::new().unwrap().path().to_path_buf()).await;
        let assets = adder.extract_assets(&release);

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

    #[tokio::test]
    async fn generate_index_json_serializes_digest_source_as_release_api_url() {
        let release = release_with_extra_asset(
            "other.tar.gz",
            Some("sha256:1111111111111111111111111111111111111111111111111111111111111111"),
        );

        let adder = build_adder(TempDir::new().unwrap().path().to_path_buf()).await;
        let assets = adder.extract_assets(&release);
        let json = adder.generate_index_json(&assets, &release).unwrap();

        // Go through the serialized form, as the index file is what
        // consumers (e.g. a future check-index command) will read.
        let index: AsfaloadIndex = serde_json::from_str(&json).unwrap();
        assert_eq!(index.published_files.len(), 2);
        for checksum in &index.published_files {
            assert_eq!(checksum.source, release.url.to_string());
        }
    }

    #[tokio::test]
    async fn assets_without_digest_are_excluded_from_index() {
        let release = release_with_extra_asset("no-digest.tar.gz", None);

        let adder = build_adder(TempDir::new().unwrap().path().to_path_buf()).await;
        let assets = adder.extract_assets(&release);
        let json = adder.generate_index_json(&assets, &release).unwrap();

        let index: AsfaloadIndex = serde_json::from_str(&json).unwrap();
        assert_eq!(index.published_files.len(), 1);
        assert_eq!(index.published_files[0].file_name, "test.tar.gz");
        assert_eq!(index.published_files[0].source, release.url.to_string());
    }

    #[tokio::test]
    async fn generate_index_json_has_trailing_newline() {
        let release = create_mock_release_response();
        let temp_dir = TempDir::new().unwrap();
        let git_repo = temp_dir.path().to_path_buf();
        let url =
            url::Url::parse("https://github.com/testowner/testrepo/releases/tag/v1.0.0").unwrap();
        let release_info = parse_release_url(&url, &git_repo).await.unwrap();

        let adder = GithubReleaseAdder {
            release_url: url,
            git_repo_path: git_repo,
            fetcher: MockGithubReleaseFetcher::new(),
            release_info,
        };

        let assets = adder.extract_assets(&release);

        let json = adder.generate_index_json(&assets, &release).unwrap();

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
