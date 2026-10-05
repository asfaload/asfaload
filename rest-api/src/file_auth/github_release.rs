use crate::constants::INDEX_FILE;
use crate::file_auth::release_types::{
    BackendReleaseInfo, ReleaseAdder, ReleaseError, ReleaseIndexWriter, ReleaseInfo,
    ReleaseUrlError,
};
use crate::file_auth::releasers::ReleaseInfos;
use common::index_types::ChecksumSourceFormat;
use features_lib::{AsfaloadIndex, FileChecksum, HashAlgorithm};
use forge_url::path_prefix_from_url;
use octocrab::models::repos::Release;
use rest_api_types::errors::ApiError;
use rest_api_types::github_helpers::validate_github_url;
use rest_api_types::path_validation::NormalisedPaths;
use std::path::{Path, PathBuf};

#[cfg(not(feature = "test-utils"))]
pub type GithubClient = ProductionGithubClient;
#[cfg(feature = "test-utils")]
pub type GithubClient = test_utils::MockGithubClient;

#[async_trait::async_trait]
pub trait GithubClientTrait: Send + Sync {
    async fn get_release_by_tag(
        &self,
        owner: &str,
        repo: &str,
        tag: &str,
    ) -> Result<Release, ApiError>;
}

pub struct ProductionGithubClient {
    client: octocrab::Octocrab,
}

impl ProductionGithubClient {
    pub fn new(client: octocrab::Octocrab) -> Self {
        Self { client }
    }
}

#[async_trait::async_trait]
impl GithubClientTrait for ProductionGithubClient {
    async fn get_release_by_tag(
        &self,
        owner: &str,
        repo: &str,
        tag: &str,
    ) -> Result<Release, ApiError> {
        self.client
            .repos(owner, repo)
            .releases()
            .get_by_tag(tag)
            .await
            .map_err(|e| {
                ApiError::ReleaseApiError(
                    "GitHub".to_string(),
                    format!("Failed to fetch release: {}", e),
                )
            })
    }
}

#[cfg(not(feature = "test-utils"))]
fn create_github_client(
    config: &crate::config::AppConfig,
) -> Result<ProductionGithubClient, ApiError> {
    let client = if let Some(api_key) = &config.github_api_key {
        octocrab::Octocrab::builder()
            .personal_token(api_key.clone())
            .build()
            .map_err(|e| {
                ApiError::ReleaseApiError(
                    "GitHub".to_string(),
                    format!("Failed to create client with API key: {}", e),
                )
            })?
    } else {
        tracing::warn!("No GitHub API key provided, using anonymous client (rate limited)");
        octocrab::Octocrab::default()
    };
    Ok(ProductionGithubClient::new(client))
}

#[cfg(feature = "test-utils")]
fn create_github_client(
    _config: &crate::config::AppConfig,
) -> Result<test_utils::MockGithubClient, ApiError> {
    Ok(test_utils::MockGithubClient::new())
}

pub struct GithubReleaseAdder<C: GithubClientTrait> {
    release_url: url::Url,
    git_repo_path: PathBuf,
    pub client: C,
    release_info: BackendGithubReleaseInfo,
}

/// Information of a Github release
#[derive(Debug, Clone)]
pub struct GithubReleaseInfo {
    pub origin_prefix: String,
    pub owner: String,
    pub repo: String,
    pub tag: String,
}

/// Information of a release on the backend
#[derive(Debug, Clone)]
pub struct BackendGithubReleaseInfo {
    pub release_info: GithubReleaseInfo,
    pub release_path: NormalisedPaths,
}

impl ReleaseInfo for GithubReleaseInfo {
    fn origin_prefix(&self) -> &str {
        &self.origin_prefix
    }

    fn owner(&self) -> &str {
        &self.owner
    }

    fn repo(&self) -> &str {
        &self.repo
    }

    fn tag(&self) -> &str {
        &self.tag
    }
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

impl ReleaseIndexWriter for GithubReleaseAdder<GithubClient> {}

impl ReleaseAdder for GithubReleaseAdder<GithubClient> {
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

        let client = create_github_client(config).map_err(|e| {
            ReleaseError::ClientError(format!("Failed to create GitHub client: {}", e))
        })?;

        Ok(Self {
            release_url: release_url.clone(),
            git_repo_path,
            client,
            release_info,
        })
    }

    async fn index_path(&self) -> Result<NormalisedPaths, ApiError> {
        let full_index_path = self.release_info.release_path.join(INDEX_FILE).await?;
        Ok(full_index_path)
    }
    async fn index_content(&self) -> Result<String, ApiError> {
        let release: Release = self
            .client
            .get_release_by_tag(
                self.release_info.owner(),
                self.release_info.repo(),
                self.release_info.tag(),
            )
            .await?;

        let assets = self.extract_assets(&release);

        if assets.is_empty() {
            return Err(ApiError::ReleaseApiError(
                "GitHub".to_string(),
                "No assets found in release".to_string(),
            ));
        }

        self.generate_index_json(&assets, &release)
    }

    fn release_info(&self) -> ReleaseInfos {
        ReleaseInfos::Github(self.release_info.clone())
    }
}

impl<C: GithubClientTrait> GithubReleaseAdder<C> {
    pub fn release_info_concrete(&self) -> &BackendGithubReleaseInfo {
        &self.release_info
    }

    fn extract_assets(&self, release: &Release) -> Vec<ReleaseAssetInfo> {
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
        release: &Release,
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

impl<C: GithubClientTrait> std::fmt::Debug for GithubReleaseAdder<C> {
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
    let (_host, owner, repo, tag) = validate_github_url(url)?;
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

    pub struct MockGithubClient {
        release_response: Option<Release>,
    }

    impl MockGithubClient {
        pub fn new() -> Self {
            let release = create_mock_release();
            Self {
                release_response: Some(release),
            }
        }

        pub fn mock_release(&mut self, release: Release) {
            self.release_response = Some(release);
        }
    }

    impl Default for MockGithubClient {
        fn default() -> Self {
            Self::new()
        }
    }

    #[async_trait::async_trait]
    impl GithubClientTrait for MockGithubClient {
        async fn get_release_by_tag(
            &self,
            _owner: &str,
            _repo: &str,
            _tag: &str,
        ) -> Result<Release, ApiError> {
            self.release_response.clone().ok_or_else(|| {
                ApiError::ReleaseApiError(
                    "GitHub".to_string(),
                    "No mock release configured".to_string(),
                )
            })
        }
    }

    pub fn create_mock_release() -> Release {
        let json_str = r#"{
            "id": 123,
            "node_id": "test_node_id",
            "tag_name": "v1.0.0",
            "name": "Test Release",
            "html_url": "https://github.com/testowner/testrepo/releases/tag/v1.0.0",
            "url": "https://api.github.com/repos/testowner/testrepo/releases/123",
            "assets_url": "https://api.github.com/repos/testowner/testrepo/releases/123/assets",
            "upload_url": "https://uploads.github.com/repos/testowner/testrepo/releases/123/assets{?name,label}",
            "tarball_url": "https://api.github.com/repos/testowner/testrepo/tarball/v1.0.0",
            "zipball_url": "https://api.github.com/repos/testowner/testrepo/zipball/v1.0.0",
            "author": {
                "login": "testowner",
                "id": 1,
                "node_id": "test_node_id",
                "avatar_url": "https://github.com/images/error/testowner_happy.gif",
                "gravatar_id": "",
                "url": "https://api.github.com/users/testowner",
                "html_url": "https://github.com/testowner",
                "type": "User",
                "site_admin": false,
                "name": "Test Owner",
                "email": "test@example.com",
                "patch_url": "https://github.com/testowner/testrepo/patch/v1.0.0",
                "events_url": "https://api.github.com/users/testowner/events{/privacy}",
                "followers_url": "https://api.github.com/users/testowner/followers",
                "following_url": "https://api.github.com/users/testowner/following{/other_user}",
                "gists_url": "https://api.github.com/users/testowner/gists{/gist_id}",
                "starred_url": "https://api.github.com/users/testowner/starred{/owner}{/repo}",
                "subscriptions_url": "https://api.github.com/users/testowner/subscriptions",
                "organizations_url": "https://api.github.com/users/testowner/orgs",
                "repos_url": "https://api.github.com/users/testowner/repos",
                "received_events_url": "https://api.github.com/users/testowner/received_events"
            },
            "assets": [{
                "id": 456,
                "node_id": "asset_node_id",
                "name": "test.tar.gz",
                "label": "Test Asset",
                "state": "uploaded",
                "content_type": "application/gzip",
                "size": 1024,
                "download_count": 10,
                "created_at": "2024-01-01T00:00:00Z",
                "updated_at": "2024-01-01T00:00:00Z",
                "browser_download_url": "https://github.com/testowner/testrepo/releases/download/v1.0.0/test.tar.gz",
                "digest": "sha256:abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890",
                "url": "https://api.github.com/repos/testowner/testrepo/releases/assets/456",
                "uploader": {
                    "login": "testowner",
                    "id": 1,
                    "node_id": "test_node_id",
                    "avatar_url": "https://github.com/images/error/testowner_happy.gif",
                    "gravatar_id": "",
                    "url": "https://api.github.com/users/testowner",
                    "html_url": "https://github.com/testowner",
                    "type": "User",
                    "site_admin": false,
                    "name": "Test Owner",
                    "email": "test@example.com",
                    "patch_url": "https://github.com/testowner/testrepo/patch/v1.0.0",
                    "events_url": "https://api.github.com/users/testowner/events{/privacy}",
                    "followers_url": "https://api.github.com/users/testowner/followers",
                    "following_url": "https://api.github.com/users/testowner/following{/other_user}",
                    "gists_url": "https://api.github.com/users/testowner/gists{/gist_id}",
                    "starred_url": "https://api.github.com/users/testowner/starred{/owner}{/repo}",
                    "subscriptions_url": "https://api.github.com/users/testowner/subscriptions",
                    "organizations_url": "https://api.github.com/users/testowner/orgs",
                    "repos_url": "https://api.github.com/users/testowner/repos",
                    "received_events_url": "https://api.github.com/users/testowner/received_events"
                }
            }],
            "published_at": "2024-01-01T00:00:00Z",
            "created_at": "2024-01-01T00:00:00Z",
            "draft": false,
            "prerelease": false,
            "target_commitish": "main"
        }"#;
        serde_json::from_str(json_str).unwrap()
    }
}

#[cfg(all(test, feature = "test-utils"))]
mod feature_gated_tests {
    use super::test_utils::*;
    use super::*;
    use tempfile::TempDir;

    async fn build_adder(git_repo: PathBuf) -> GithubReleaseAdder<MockGithubClient> {
        let url =
            url::Url::parse("https://github.com/testowner/testrepo/releases/tag/v1.0.0").unwrap();
        let release_info = parse_release_url(&url, &git_repo).await.unwrap();
        GithubReleaseAdder {
            release_url: url,
            git_repo_path: git_repo,
            client: MockGithubClient::new(),
            release_info,
        }
    }

    // Gives the added asset its own download url so a regression to
    // browser_download_url as digest source cannot pass silently.
    fn release_with_extra_asset(name: &str, digest: Option<&str>) -> Release {
        let mut value = serde_json::to_value(create_mock_release()).unwrap();
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
        let release = create_mock_release();
        let temp_dir = TempDir::new().unwrap();
        let git_repo = temp_dir.path().to_path_buf();
        let url =
            url::Url::parse("https://github.com/testowner/testrepo/releases/tag/v1.0.0").unwrap();
        let release_info = parse_release_url(&url, &git_repo).await.unwrap();

        let adder = GithubReleaseAdder {
            release_url: url,
            git_repo_path: git_repo,
            client: MockGithubClient::new(),
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
