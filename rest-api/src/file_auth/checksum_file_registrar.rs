use crate::constants::INDEX_FILE;
use forge_release::checksums::index_from_shasums_urls;
use rest_api_types::errors::ApiError;
use rest_api_types::path_validation::NormalisedPaths;
use rest_api_types::validate_common_parent;
use std::path::PathBuf;

/// Handles registration of files from checksums files (e.g. SHA256SUMS, SHA512SUMS).
///
/// Instead of downloading each artifact and computing its hash, this registrar
/// downloads text-based checksum files, parses them to extract file names and
/// pre-computed hashes, and writes an index file into the git-backed repository.
pub struct ChecksumFileRegistrar {
    reqwest_client: reqwest::Client,
    directory_path: NormalisedPaths,
    urls: Vec<url::Url>,
}

impl ChecksumFileRegistrar {
    pub async fn new(git_repo_path: PathBuf, urls: Vec<url::Url>) -> Result<Self, ApiError> {
        let base = validate_common_parent(&urls)
            .map_err(|e| ApiError::InvalidRequestBody(e.to_string()))?;

        let dir_path = format!("{}{}", base.prefix, base.parent_path);
        let directory_path = NormalisedPaths::new(git_repo_path, PathBuf::from(&dir_path)).await?;

        Ok(Self {
            reqwest_client: reqwest::Client::new(),
            directory_path,
            urls,
        })
    }

    /// Returns the on-disk directory corresponding to this checksums file directory.
    /// Used to locate the signers file.
    pub fn signers_file_path(&self) -> PathBuf {
        self.directory_path.absolute_path()
    }

    /// Computes the normalised path where the index file should be written.
    pub async fn index_path(&self) -> Result<NormalisedPaths, ApiError> {
        self.directory_path.join(INDEX_FILE).await
    }

    /// Downloads all checksums files in parallel, parses them, and writes the index file.
    /// Fails if the index file already exists.
    pub async fn create_index(&self) -> Result<NormalisedPaths, ApiError> {
        // Verify a signers file exists for this directory
        let dir_on_disk = self.signers_file_path();
        common::fs::names::find_global_signers_for(&dir_on_disk)
            .map_err(|_| ApiError::NoActiveSignersFile)?;

        let index_path = self.index_path().await?;
        let abs_path = index_path.absolute_path();

        if let Some(parent) = abs_path.parent() {
            tokio::fs::create_dir_all(parent).await.map_err(|e| {
                ApiError::FileWriteFailed(format!("Failed to create directory: {}", e))
            })?;
        }
        let index = index_from_shasums_urls(&self.reqwest_client, &self.urls)
            .await
            .map_err(|e| ApiError::ReleaseApiError("ChecksumFile".to_string(), e.to_string()))?;
        let content = common::to_posix_json(&index).map_err(|e| {
            ApiError::InternalServerError(format!("Failed to serialize index: {}", e))
        })?;

        let mut oo = tokio::fs::OpenOptions::new();
        match oo.write(true).create_new(true).open(&abs_path).await {
            Ok(mut f) => {
                use tokio::io::AsyncWriteExt;
                f.write_all(content.as_bytes()).await.map_err(|e| {
                    ApiError::FileWriteFailed(format!("Failed to write index file: {}", e))
                })?;
                // tokio buffers file writes: without an awaited flush the
                // index file can still be empty on disk when this returns.
                // The git actor commits the file right after.
                f.flush().await.map_err(|e| {
                    ApiError::FileWriteFailed(format!("Failed to flush index file: {}", e))
                })?;
                Ok(index_path)
            }
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                Err(ApiError::ReleaseAlreadyRegistered(format!(
                    "Directory already registered: {}",
                    index_path.relative_path().display()
                )))
            }
            Err(e) => Err(ApiError::FileWriteFailed(format!(
                "Failed to create index file: {}",
                e
            ))),
        }
    }
}

#[cfg(all(test, feature = "test-utils"))]
mod test_utils_tests {
    use super::*;
    use constants::{SIGNERS_DIR, SIGNERS_FILE};
    use features_lib::{ChecksumSourceFormat, FileChecksum};
    use forge_url::path_prefix_from_url;

    // The index written on disk is what consumers read: its content must
    // match the entries of the parsed checksums file, and follow the POSIX
    // JSON contract.
    #[tokio::test]
    async fn create_index_writes_expected_content_to_disk() {
        use features_lib::HashAlgorithm;
        let temp_dir = tempfile::tempdir().unwrap();
        let git_repo_path = temp_dir.path().to_path_buf();

        let mock_server = httpmock::MockServer::start();
        let checksum_content =
            "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890  file.tar.gz\n";
        mock_server.mock(|when, then| {
            when.method(httpmock::Method::GET).path("/v1.0/SHA256SUMS");
            then.status(200).body(checksum_content);
        });

        let checksum_url =
            url::Url::parse(&format!("{}/v1.0/SHA256SUMS", mock_server.url(""))).unwrap();

        // Compute the directory path the same way ChecksumFileRegistrar::new does
        let prefix = path_prefix_from_url(&checksum_url).unwrap();
        let relative_dir = format!("{}/v1.0", prefix);
        let signers_dir = git_repo_path.join(&relative_dir).join(SIGNERS_DIR);
        tokio::fs::create_dir_all(&signers_dir).await.unwrap();
        tokio::fs::write(signers_dir.join(SIGNERS_FILE), "{}")
            .await
            .unwrap();

        let registrar =
            ChecksumFileRegistrar::new(git_repo_path.clone(), vec![checksum_url.clone()])
                .await
                .unwrap();

        let before = chrono::Utc::now();
        let index_path_result = registrar.create_index().await;
        assert!(
            index_path_result.is_ok(),
            "create_index should succeed: {:?}",
            index_path_result
        );

        let index_abs = index_path_result.unwrap().absolute_path();
        let index = rest_api_test_helpers::read_on_disk_index(&index_abs).unwrap();

        assert_eq!(index.version, 1);
        // A checksums file carries no upstream publication date: both
        // timestamps are set at registration time.
        assert_eq!(
            index.published_on, index.mirrored_on,
            "published_on must equal mirrored_on when registering from a checksums file"
        );
        assert!(
            index.mirrored_on >= before && index.mirrored_on <= chrono::Utc::now(),
            "mirrored_on must be the registration time, got {}",
            index.mirrored_on
        );
        assert_eq!(
            index.published_files,
            vec![FileChecksum {
                file_name: "file.tar.gz".to_string(),
                algo: HashAlgorithm::Sha256,
                source: checksum_url.to_string(),
                source_format: ChecksumSourceFormat::ShaSum,
                hash: "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890"
                    .to_string(),
            }]
        );
    }
}

#[cfg(all(test, not(feature = "test-utils")))]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[tokio::test]
    async fn test_new_validates_urls() {
        let temp_dir = tempfile::tempdir().unwrap();
        let url = url::Url::parse("https://files.example.com/releases/v1.0/SHA256SUMS").unwrap();
        let result = ChecksumFileRegistrar::new(temp_dir.path().to_path_buf(), vec![url]).await;
        assert!(result.is_ok());
        let registrar = result.unwrap();
        assert_eq!(
            registrar.directory_path.relative_path(),
            PathBuf::from("https/files.example.com/443/releases/v1.0")
        );
        assert_eq!(registrar.urls.len(), 1);
    }

    #[tokio::test]
    async fn test_new_different_hosts_error() {
        let temp_dir = tempfile::tempdir().unwrap();
        let urls = vec![
            url::Url::parse("https://files.example.com/releases/v1.0/SHA256SUMS").unwrap(),
            url::Url::parse("https://other.example.com/releases/v1.0/SHA512SUMS").unwrap(),
        ];
        let result = ChecksumFileRegistrar::new(temp_dir.path().to_path_buf(), urls).await;
        match result {
            Err(ApiError::InvalidRequestBody(msg)) => {
                assert!(msg.contains("files.example.com"));
                assert!(msg.contains("other.example.com"));
            }
            Err(e) => panic!("Expected InvalidRequestBody, got {}", e),
            Ok(_) => panic!("Expected error for different hosts"),
        }
    }

    #[tokio::test]
    async fn test_new_different_parents_error() {
        let temp_dir = tempfile::tempdir().unwrap();
        let urls = vec![
            url::Url::parse("https://files.example.com/releases/v1.0/SHA256SUMS").unwrap(),
            url::Url::parse("https://files.example.com/releases/v2.0/SHA256SUMS").unwrap(),
        ];
        let result = ChecksumFileRegistrar::new(temp_dir.path().to_path_buf(), urls).await;
        match result {
            Err(ApiError::InvalidRequestBody(msg)) => {
                assert!(msg.contains("/releases/v1.0/"));
                assert!(msg.contains("/releases/v2.0/"));
            }
            Err(e) => panic!("Expected InvalidRequestBody, got {}", e),
            Ok(_) => panic!("Expected error for different parents"),
        }
    }

    #[tokio::test]
    async fn test_new_empty_urls_error() {
        let temp_dir = tempfile::tempdir().unwrap();
        let result = ChecksumFileRegistrar::new(temp_dir.path().to_path_buf(), vec![]).await;
        match result {
            Err(ApiError::InvalidRequestBody(msg)) => {
                assert!(msg.contains("At least one URL"));
            }
            Err(e) => panic!("Expected InvalidRequestBody, got {}", e),
            Ok(_) => panic!("Expected error for empty URLs"),
        }
    }

    #[tokio::test]
    async fn test_signers_file_path() {
        let temp_dir = tempfile::tempdir().unwrap();
        let url =
            url::Url::parse("https://files.example.com/projects/myapp/v2.0/SHA256SUMS").unwrap();
        let registrar = ChecksumFileRegistrar::new(temp_dir.path().to_path_buf(), vec![url])
            .await
            .unwrap();
        let expected = temp_dir
            .path()
            .join("https/files.example.com/443/projects/myapp/v2.0");
        assert_eq!(registrar.signers_file_path(), expected);
    }

    #[tokio::test]
    async fn test_index_path() {
        let temp_dir = tempfile::tempdir().unwrap();
        let url = url::Url::parse("https://files.example.com/releases/v1.0/SHA256SUMS").unwrap();
        let registrar = ChecksumFileRegistrar::new(temp_dir.path().to_path_buf(), vec![url])
            .await
            .unwrap();
        let index_path = registrar.index_path().await.unwrap();
        let relative = index_path.relative_path();
        assert_eq!(
            relative,
            PathBuf::from("https/files.example.com/443/releases/v1.0").join(INDEX_FILE)
        );
    }
}
