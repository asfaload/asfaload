use crate::file_auth::github_release::{BackendGithubReleaseInfo, GithubReleaseAdder};
use crate::file_auth::release_types::{
    BackendReleaseInfo, ReleaseAdder, ReleaseError, ReleaseIndexWriter, ReleaseUrlError,
};
use forge_release::common::ReleaseInfo;
use forge_release::github::ClientProvidedData;
use forge_url::github::is_github_release_host;
use rest_api_types::errors::ApiError;
use rest_api_types::path_validation::NormalisedPaths;
#[cfg(all(test, feature = "test-utils"))]
use std::net::{IpAddr, Ipv4Addr};
use std::path::PathBuf;
use tokio::fs::File;

#[derive(Debug)]
pub enum ReleaseAdders {
    Github(Box<GithubReleaseAdder>),
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
        client_provided_data: ClientProvidedData,
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
            let github_adder =
                GithubReleaseAdder::new(release_url, client_provided_data, git_repo_path, config)
                    .await?;
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
#[cfg(all(test, feature = "test-utils"))]
mod test_utils_tests {
    use super::*;
    use forge_release::github::ClientProvidedData;
    use rest_api_test_helpers::get_random_port;

    const CLIENT_SENT_INDEX_PLACEHOLDER: &str = "test_client_index";
    const CLIENT_SENT_SIGNATURE_PLACEHOLDER: &str = "test_client_signature";
    const CLIENT_PUB_KEY_PLACEHOLDER: &str = "test_client_pub_key";

    fn client_provided_data(release_url: &url::Url) -> ClientProvidedData {
        ClientProvidedData {
            github_release_url: release_url.to_string(),
            client_pub_key: CLIENT_PUB_KEY_PLACEHOLDER.to_string(),
            client_sent_index: CLIENT_SENT_INDEX_PLACEHOLDER.to_string(),
            client_sent_signature: CLIENT_SENT_SIGNATURE_PLACEHOLDER.to_string(),
        }
    }

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

        match ReleaseAdders::new(
            &release_url,
            client_provided_data(&release_url),
            temp_dir.path().to_path_buf(),
            &mock_config,
        )
        .await
        {
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

        let adder = ReleaseAdders::new(
            &release_url,
            client_provided_data(&release_url),
            git_repo_path.clone(),
            &mock_config,
        )
        .await
        .unwrap();

        let ReleaseAdders::Github(github) = &adder;
        assert_eq!(
            github.client_provided_data.client_sent_index,
            CLIENT_SENT_INDEX_PLACEHOLDER
        );
        assert_eq!(
            github.client_provided_data.client_sent_signature,
            CLIENT_SENT_SIGNATURE_PLACEHOLDER
        );
        assert_eq!(
            github.client_provided_data.client_pub_key,
            CLIENT_PUB_KEY_PLACEHOLDER
        );

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

        let adder = ReleaseAdders::new(
            &release_url,
            client_provided_data(&release_url),
            git_repo_path.clone(),
            &mock_config,
        )
        .await
        .unwrap();

        let result = adder.create_index().await;
        assert!(
            result.is_ok(),
            "create_index should succeed when signers file exists at origin prefix path"
        );
    }

    // The index file written on disk is what consumers read, so its content
    // must match the release data served by the github api. Expected values
    // are pinned to the response returned by the test-utils mock fetcher.
    #[tokio::test]
    async fn test_create_index_writes_expected_index_content() {
        use crate::file_auth::release_types::ReleaseAdder;
        use constants::{SIGNERS_DIR, SIGNERS_FILE};
        use features_lib::{ChecksumSourceFormat, FileChecksum, HashAlgorithm};
        use std::net::{IpAddr, Ipv4Addr};
        use tempfile::TempDir;

        let temp_dir = TempDir::new().unwrap();
        let git_repo_path = temp_dir.path().to_path_buf();

        let signers_dir = git_repo_path
            .join("https/github.com/443/testowner/testrepo")
            .join(SIGNERS_DIR);
        tokio::fs::create_dir_all(&signers_dir).await.unwrap();
        tokio::fs::write(signers_dir.join(SIGNERS_FILE), "{}")
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
            git_repo_path: git_repo_path.clone(),
            log_level: "info".to_string(),
            git_backend,
            git_signing_pub_key_path: test_helpers::git_signing_pub_key_path(),
            github_api_key: None,
            gitlab_api_key: None,
        };

        let adder = ReleaseAdders::new(
            &release_url,
            client_provided_data(&release_url),
            git_repo_path.clone(),
            &mock_config,
        )
        .await
        .unwrap();

        let registration_started_at = chrono::Utc::now();
        let index_path = adder.create_index().await.unwrap();
        let index = rest_api_test_helpers::read_on_disk_index(&index_path.absolute_path()).unwrap();

        assert_eq!(index.version, 1);
        assert_eq!(
            index.published_on,
            "2024-01-01T00:00:00Z"
                .parse::<chrono::DateTime<chrono::Utc>>()
                .unwrap(),
            "published_on must come from the release's published_at timestamp"
        );
        assert!(
            index.mirrored_on >= registration_started_at && index.mirrored_on <= chrono::Utc::now(),
            "mirrored_on must be the registration time, got {}",
            index.mirrored_on
        );
        assert_eq!(
            index.published_files,
            vec![FileChecksum {
                file_name: "test.tar.gz".to_string(),
                algo: HashAlgorithm::Sha256,
                source: "https://api.github.com/repos/testowner/testrepo/releases/123".to_string(),
                source_format: ChecksumSourceFormat::GithubRelease,
                hash: "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890"
                    .to_string(),
            }]
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

        let adder = ReleaseAdders::new(
            &release_url,
            client_provided_data(&release_url),
            git_repo_path.clone(),
            &mock_config,
        )
        .await
        .unwrap();

        let result = adder.create_index().await;
        assert!(
            result.is_err(),
            "create_index should fail when no signers file exists"
        );
    }
}
