#[cfg(not(feature = "test-utils"))]
use crate::file_auth::github_release::ProductionGithubClient;
use crate::file_auth::github_release::{BackendGithubReleaseInfo, GithubReleaseAdder};
use crate::file_auth::release_types::{
    BackendReleaseInfo, ReleaseAdder, ReleaseError, ReleaseIndexWriter, ReleaseUrlError,
};
use forge_release::common::ReleaseInfo;
use forge_url::github::is_github_release_host;
use rest_api_types::errors::ApiError;
use rest_api_types::path_validation::NormalisedPaths;
#[cfg(all(test, feature = "test-utils"))]
use std::net::{IpAddr, Ipv4Addr};
use std::path::PathBuf;
use tokio::fs::File;

#[cfg(feature = "test-utils")]
use crate::file_auth::github_release::test_utils::MockGithubClient;

#[derive(Debug)]
pub enum ReleaseAdders {
    #[cfg(not(feature = "test-utils"))]
    Github(Box<GithubReleaseAdder<ProductionGithubClient>>),
    #[cfg(feature = "test-utils")]
    Github(Box<GithubReleaseAdder<MockGithubClient>>),
}

impl ReleaseIndexWriter for ReleaseAdders {
    async fn write_index(&self, f: &mut File, content: &[u8]) -> Result<(), ApiError> {
        match self {
            Self::Github(github) => github.as_ref().write_index(f, content).await,
        }
    }
}

impl ReleaseAdder for ReleaseAdders {
    async fn new(
        release_url: &url::Url,
        git_repo_path: PathBuf,
        config: &crate::config::AppConfig,
    ) -> Result<Self, ReleaseError>
    where
        Self: Sized,
    {
        let host = release_url
            .host_str()
            .ok_or_else(|| ReleaseUrlError::InvalidFormat("Missing host".to_string()))?;

        if is_github_release_host(host) {
            let github_adder = GithubReleaseAdder::new(release_url, git_repo_path, config).await?;
            Ok(Self::Github(Box::new(github_adder)))
        } else {
            Err(ReleaseUrlError::UnsupportedPlatform(format!(
                "Host {} is not recognised as a Github Relaese host",
                host,
            ))
            .into())
        }
    }

    async fn index_content(&self) -> Result<String, ApiError> {
        match self {
            Self::Github(github) => github.as_ref().index_content().await,
        }
    }

    async fn index_path(&self) -> Result<NormalisedPaths, ApiError> {
        match self {
            Self::Github(github) => github.as_ref().index_path().await,
        }
    }

    fn release_info(&self) -> BackendReleaseInfos {
        match self {
            Self::Github(github) => github.release_info(),
        }
    }
}

#[derive(Debug)]
pub enum BackendReleaseInfos {
    Github(BackendGithubReleaseInfo),
}

impl ReleaseInfo for BackendReleaseInfos {
    fn origin_prefix(&self) -> &str {
        match self {
            Self::Github(github) => github.origin_prefix(),
        }
    }

    fn owner(&self) -> &str {
        match self {
            Self::Github(github) => github.owner(),
        }
    }

    fn repo(&self) -> &str {
        match self {
            Self::Github(github) => github.repo(),
        }
    }

    fn tag(&self) -> &str {
        match self {
            Self::Github(github) => github.tag(),
        }
    }
}

impl BackendReleaseInfo for BackendReleaseInfos {
    fn release_path(&self) -> &NormalisedPaths {
        match self {
            Self::Github(github) => github.release_path(),
        }
    }
}
#[cfg(all(test, not(feature = "test-utils")))]
mod tests {
    use forge_url::github::GITHUB_REPO_HOSTS;

    #[test]
    fn test_github_release_host_detection() {
        let github_url =
            url::Url::parse("https://github.com/owner/repo/releases/tag/v1.0.0").unwrap();
        assert!(GITHUB_REPO_HOSTS.contains(&github_url.host_str().unwrap()));
    }

    #[test]
    fn test_unsupported_host() {
        let bitbucket_url = url::Url::parse("https://bitbucket.org/owner/repo/v1.0.0").unwrap();
        assert!(!GITHUB_REPO_HOSTS.contains(&bitbucket_url.host_str().unwrap()));
    }
}

#[cfg(all(test, feature = "test-utils"))]
mod test_utils_tests {
    use super::*;
    use rest_api_test_helpers::get_random_port;

    // The github rest api serves release info, but a release url must target
    // the project's release pages: the api host is not a repo host.
    #[tokio::test]
    async fn test_release_adders_reject_github_api_url() {
        use crate::file_auth::release_types::ReleaseAdder;
        use tempfile::TempDir;

        let temp_dir = TempDir::new().unwrap();
        let release_url =
            url::Url::parse("https://api.github.com/repos/owner/repo/releases/123").unwrap();

        let port = get_random_port().await.unwrap();
        let mock_config = crate::config::AppConfig {
            server_port: port,
            server_address: IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
            git_repo_path: temp_dir.path().to_path_buf(),
            log_level: "info".to_string(),
            git_backend: crate::config::GitBackendConfig::Sha256,
            git_signing_pub_key_path: test_helpers::git_signing_pub_key_path(),
            github_api_key: None,
            gitlab_api_key: None,
        };

        match ReleaseAdders::new(&release_url, temp_dir.path().to_path_buf(), &mock_config).await {
            Err(ReleaseError::ReleaseUrlError(ReleaseUrlError::UnsupportedPlatform(host))) => {
                assert!(
                    host.contains("api.github.com"),
                    "unexpected rejected host: {host}"
                );
            }
            Err(e) => panic!("Expected UnsupportedPlatform but got {e}"),
            Ok(_) => panic!("Expected UnsupportedPlatform error, but an adder was built!"),
        }
    }

    #[tokio::test]
    async fn test_release_adders_github_release() {
        use crate::file_auth::release_types::ReleaseAdder;
        use constants::{SIGNERS_DIR, SIGNERS_FILE};
        use tempfile::TempDir;
        use tokio::fs;

        let temp_dir = TempDir::new().unwrap();
        let git_repo_path = temp_dir.path().to_path_buf();

        let signers_dir = git_repo_path
            .join("https/github.com/443/testowner/testrepo")
            .join(SIGNERS_DIR);
        fs::create_dir_all(&signers_dir).await.unwrap();

        let signers_json = r#"{
            "version": 1,
            "required_signers": 1,
            "signers": [
                {
                    "public_key": "test_key",
                    "name": "Test Signer"
                }
            ]
        }"#;
        fs::write(signers_dir.join(SIGNERS_FILE), signers_json)
            .await
            .unwrap();

        let release_url =
            url::Url::parse("https://github.com/testowner/testrepo/releases/tag/v1.0.0").unwrap();

        let port = get_random_port().await.unwrap();
        let git_backend = match std::env::var("ASFALOAD_GIT_BACKEND").as_deref() {
            Ok("sha256") => crate::config::GitBackendConfig::Sha256,
            Ok(other) => panic!("Unrecognised value for ASFALOAD_GIT_BACKEND: {other}"),
            Err(_e) => crate::config::GitBackendConfig::Sha256,
        };
        let mock_config = crate::config::AppConfig {
            server_port: port,
            server_address: IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
            git_repo_path: temp_dir.path().to_path_buf(),
            log_level: "info".to_string(),
            git_backend,
            git_signing_pub_key_path: test_helpers::git_signing_pub_key_path(),
            github_api_key: None,
            gitlab_api_key: None,
        };

        let adder = ReleaseAdders::new(&release_url, git_repo_path.clone(), &mock_config)
            .await
            .unwrap();

        let index_content = adder.index_content().await.unwrap();
        let json: serde_json::Value = serde_json::from_str(&index_content).unwrap();

        assert_eq!(json["version"], 1);
        assert!(json["publishedFiles"].is_array());
        let files = json["publishedFiles"].as_array().unwrap();
        assert_eq!(files.len(), 1);
        assert_eq!(files[0]["fileName"], "test.tar.gz");
        assert_eq!(files[0]["algo"], "Sha256");
        assert_eq!(
            files[0]["hash"],
            "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890"
        );
    }

    #[tokio::test]
    async fn test_create_index_finds_signers_at_origin_prefix_path() {
        use crate::file_auth::release_types::ReleaseAdder;
        use constants::{SIGNERS_DIR, SIGNERS_FILE};
        use tempfile::TempDir;
        use tokio::fs;

        let temp_dir = TempDir::new().unwrap();
        let git_repo_path = temp_dir.path().to_path_buf();

        let signers_dir = git_repo_path
            .join("https/github.com/443/testowner/testrepo")
            .join(SIGNERS_DIR);
        fs::create_dir_all(&signers_dir).await.unwrap();
        fs::write(signers_dir.join(SIGNERS_FILE), "{}")
            .await
            .unwrap();

        let release_url =
            url::Url::parse("https://github.com/testowner/testrepo/releases/tag/v1.0.0").unwrap();

        let port = get_random_port().await.unwrap();
        let git_backend = match std::env::var("ASFALOAD_GIT_BACKEND").as_deref() {
            Ok("sha256") => crate::config::GitBackendConfig::Sha256,
            Ok(other) => panic!("Unrecognised value for ASFALOAD_GIT_BACKEND: {other}"),
            Err(_e) => crate::config::GitBackendConfig::Sha256,
        };
        let mock_config = crate::config::AppConfig {
            server_port: port,
            server_address: IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
            git_repo_path: temp_dir.path().to_path_buf(),
            log_level: "info".to_string(),
            git_backend,
            git_signing_pub_key_path: test_helpers::git_signing_pub_key_path(),
            github_api_key: None,
            gitlab_api_key: None,
        };

        let adder = ReleaseAdders::new(&release_url, git_repo_path.clone(), &mock_config)
            .await
            .unwrap();

        let result = adder.create_index().await;
        assert!(
            result.is_ok(),
            "create_index should succeed when signers file exists at origin prefix path"
        );
    }

    #[tokio::test]
    async fn test_create_index_fails_without_signers() {
        use crate::file_auth::release_types::ReleaseAdder;
        use tempfile::TempDir;

        let temp_dir = TempDir::new().unwrap();
        let git_repo_path = temp_dir.path().to_path_buf();

        let release_url =
            url::Url::parse("https://github.com/testowner/testrepo/releases/tag/v1.0.0").unwrap();

        let port = get_random_port().await.unwrap();
        let git_backend = match std::env::var("ASFALOAD_GIT_BACKEND").as_deref() {
            Ok("sha256") => crate::config::GitBackendConfig::Sha256,
            Ok(other) => panic!("Unrecognised value for ASFALOAD_GIT_BACKEND: {other}"),
            Err(_e) => crate::config::GitBackendConfig::Sha256,
        };
        let mock_config = crate::config::AppConfig {
            server_port: port,
            server_address: IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
            git_repo_path: temp_dir.path().to_path_buf(),
            log_level: "info".to_string(),
            git_backend,
            git_signing_pub_key_path: test_helpers::git_signing_pub_key_path(),
            github_api_key: None,
            gitlab_api_key: None,
        };

        let adder = ReleaseAdders::new(&release_url, git_repo_path.clone(), &mock_config)
            .await
            .unwrap();

        let result = adder.create_index().await;
        assert!(
            result.is_err(),
            "create_index should fail when no signers file exists"
        );
    }
}
