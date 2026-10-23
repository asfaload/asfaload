use crate::file_auth::fileserver_release::FileServerReleaseAdder;
use crate::file_auth::github_release::GithubReleaseAdder;
use crate::file_auth::release_types::{ReleaseAdder, ReleaseError, ReleaseIndexWriter};
use forge_release::common::{ClientIndexSources, ClientProvidedData};
use rest_api_types::errors::ApiError;
use rest_api_types::path_validation::NormalisedPaths;
#[cfg(all(test, feature = "test-utils"))]
use std::net::{IpAddr, Ipv4Addr};
use std::path::PathBuf;
use tokio::fs::File;

#[derive(Debug)]
pub enum ReleaseAdders {
    Github(Box<GithubReleaseAdder>),
    Checksums(Box<FileServerReleaseAdder>),
}

impl ReleaseIndexWriter for ReleaseAdders {
    async fn write_index(&self, f: &mut File, content: &[u8]) -> Result<(), ApiError> {
        match self {
            Self::Github(github) => github.as_ref().write_index(f, content).await,
            Self::Checksums(fs) => fs.as_ref().write_index(f, content).await,
        }
    }
}

impl ReleaseAdders {
    /// Build the adder matching the client index source.
    ///
    /// The source variant is the dispatch key: it selects the adder that
    /// handles the client data. The selected adder validates the client
    /// provided data because:
    /// - the adder has access to all data it needs, such as the config to create the release
    ///   fetcher.
    /// - validation of the data depends on the forge we will interact with, and so only a
    ///   specific release adder can do the validation.
    pub async fn new(
        client_provided_data: ClientProvidedData,
        git_repo_path: PathBuf,
        config: &crate::config::AppConfig,
    ) -> Result<Self, ReleaseError> {
        match &client_provided_data.sources {
            ClientIndexSources::Github(_) => {
                let github_adder =
                    GithubReleaseAdder::new(client_provided_data, git_repo_path, config).await?;
                Ok(Self::Github(Box::new(github_adder)))
            }
            ClientIndexSources::FileServer(_) => {
                let adder =
                    FileServerReleaseAdder::new(client_provided_data, git_repo_path, config)
                        .await?;
                Ok(Self::Checksums(Box::new(adder)))
            }
        }
    }
}

impl ReleaseAdder for ReleaseAdders {
    async fn index_content(&self) -> Result<String, ApiError> {
        match self {
            Self::Github(github) => github.as_ref().index_content().await,
            Self::Checksums(adder) => adder.as_ref().index_content().await,
        }
    }

    async fn index_path(&self) -> Result<NormalisedPaths, ApiError> {
        match self {
            Self::Github(github) => github.as_ref().index_path().await,
            Self::Checksums(adder) => adder.as_ref().index_path().await,
        }
    }

    fn pub_key(&self) -> &features_lib::AsfaloadPublicKeys {
        match self {
            Self::Github(github) => github.pub_key(),
            Self::Checksums(adder) => adder.pub_key(),
        }
    }
    fn signature(&self) -> &features_lib::AsfaloadSignatures {
        match self {
            Self::Github(github) => github.signature(),
            Self::Checksums(adder) => adder.signature(),
        }
    }
}

#[cfg(all(test, feature = "test-utils"))]
mod test_utils_tests {
    use super::*;
    use crate::file_auth::release_types::ReleaseUrlError;
    use forge_release::github::GithubReleaseSource;
    use forge_release::github::test_utils::create_mocked_client_provided_data;
    use rest_api_test_helpers::get_random_port;

    // The github rest api serves release info, but a release url must target
    // the project's release pages: the api host is not a repo host.
    #[tokio::test]
    async fn test_release_adders_reject_github_api_url() {
        use tempfile::TempDir;

        let temp_dir = TempDir::new().unwrap();
        let release_url =
            url::Url::parse("https://api.github.com/repos/owner/repo/releases/123").unwrap();

        // The host is validated before any verification of the client
        // data, so only the source url matters here.
        let client_data = ClientProvidedData {
            sources: ClientIndexSources::Github(GithubReleaseSource::new(release_url)),
            client_pub_key: "unused".to_string(),
            client_sent_index: "unused".to_string(),
            client_sent_signature: "unused".to_string(),
        };

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

        match ReleaseAdders::new(client_data, temp_dir.path().to_path_buf(), &mock_config).await {
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
        use features_lib::{AsfaloadPublicKeyTrait, AsfaloadSignatureTrait};
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

        let client_data = create_mocked_client_provided_data();
        // Keep the index bytes the client sent, to compare after verification.
        let sent_index_bytes = common::string_from_base64(&client_data.client_sent_index).unwrap();

        let adder = ReleaseAdders::new(client_data, git_repo_path.clone(), &mock_config)
            .await
            .unwrap();

        let ReleaseAdders::Github(github) = &adder else {
            panic!("We should have a github relese adder here")
        };
        // The data accepted by the adder must be kept unchanged, no re-serialization
        // must happen by the verification process, as the registration process
        // should only use verified client data.
        let verified = &github.verified_client_data;
        assert_eq!(
            verified.sources(),
            &[release_url.clone()][..],
            "the verified data must keep the release url sent by the client"
        );
        assert_eq!(
            verified.index_string(),
            sent_index_bytes,
            "the verified data must keep the bytes of the index sent by the client"
        );
        assert!(
            !verified.signature().to_base64().is_empty(),
            "the verified data must keep the signature sent by the client"
        );
        assert!(
            verified
                .pub_key()
                .to_base64()
                .starts_with(features_lib::ASFALOAD_PUB_PREFIX),
            "the verified data must keep the public key sent by the client"
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
            create_mocked_client_provided_data(),
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

    // The index file written on disk is what consumers read: registration
    // persists the client-provided index unchanged, so the file must contain
    // exactly the bytes the client sent, verified against the mock release.
    // Expected values are pinned to the response returned by the test-utils
    // mock fetcher.
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

        let client_data = create_mocked_client_provided_data();
        // Keep the index bytes the client sent: the persisted file must be
        // byte-identical, as the client signature covers those bytes only.
        let sent_index_bytes = common::string_from_base64(&client_data.client_sent_index).unwrap();

        let adder = ReleaseAdders::new(client_data, git_repo_path.clone(), &mock_config)
            .await
            .unwrap();

        let index_path = adder.create_index().await.unwrap();
        assert_eq!(
            tokio::fs::read_to_string(&index_path.absolute_path())
                .await
                .unwrap(),
            sent_index_bytes,
            "the persisted index must be exactly the bytes the client signed"
        );
        let index = rest_api_test_helpers::read_on_disk_index(&index_path.absolute_path()).unwrap();

        assert_eq!(index.version, 1);
        assert_eq!(
            index.published_on,
            "2024-01-01T00:00:00Z"
                .parse::<chrono::DateTime<chrono::Utc>>()
                .unwrap(),
            "published_on must come from the release's published_at timestamp"
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
            create_mocked_client_provided_data(),
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
