use std::collections::HashSet;

use common::{into_url::IntoUrl, sha512_for_content, string_from_base64};
use features_lib::{
    AsfaloadIndex, AsfaloadPublicKeyTrait, AsfaloadPublicKeys, AsfaloadSignatureTrait,
    AsfaloadSignatures, FileChecksum,
};
use thiserror::Error;
use url::Url;

use crate::{checksums::ChecksumsReleaseSource, github::GithubReleaseSource};

#[derive(Debug, Error)]
pub enum ReleaseHandlingError {
    #[error("InvalidUrl: {0}")]
    InvalidUrl(String),

    #[error("Fetch error: {0}")]
    FetchError(#[from] common::http::FetchError),

    #[error("Parse error: {0}")]
    ParseError(#[from] serde_json::Error),

    #[error("Url parse error: {0}")]
    UrlParseError(#[from] url::ParseError),

    #[error("Invalid data: {0}")]
    InvalidData(String),

    #[error("An error occured: {0}")]
    Generic(String),
}

pub trait ReleaseFetcher<T> {
    /// Each fetcher decides how to use the urls of the client index source:
    /// the github fetcher uses only the first one, while the file server
    /// fetcher downloads them all.
    fn fetch<U: IntoUrl + Clone + Sync>(
        &self,
        url: &[U],
    ) -> impl Future<Output = Result<T, ReleaseHandlingError>> + Send;
}

pub struct ReleaseAssetInfo {
    pub hash: Option<FileChecksum>,
}

pub trait ReleaseResponseTrait {
    fn generate_index(
        &self,
    ) -> impl Future<Output = Result<AsfaloadIndex, ReleaseHandlingError>> + Send;
}

/// The client index sources, dispatched at runtime.
///
#[derive(Debug, Clone)]
pub enum ClientIndexSources {
    Github(GithubReleaseSource),
    FileServer(ChecksumsReleaseSource),
}

impl ClientIndexSources {
    /// The urls of the sources the client used to build its index.
    pub fn to_urls(&self) -> &[Url] {
        match self {
            Self::Github(s) => std::slice::from_ref(s.url()),
            Self::FileServer(s) => s.urls(),
        }
    }
}

impl std::fmt::Display for ClientIndexSources {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Github(s) => write!(f, "{s}"),
            Self::FileServer(s) => write!(f, "{s}"),
        }
    }
}

pub struct ClientProvidedData {
    pub sources: ClientIndexSources,
    pub client_pub_key: String,
    pub client_sent_index: String,
    pub client_sent_signature: String,
}

pub struct VerifiedClientData {
    client_provided_data: ClientProvidedData,
    pub_key: AsfaloadPublicKeys,
    index_string: String,
    signature: AsfaloadSignatures,
}

/// Indicates with date need to be included in indexes comparison. For forges without publication
/// date, like a self hosted file server, use None, for github releases, use PublicationDate
pub enum IndexDateChecks {
    PublicationDate,
    None,
}
impl VerifiedClientData {
    /// Helper to get explicit message about indexes differences. Returns None if no difference.
    /// We keep it simple and don't try to report detailed differences in the published files found
    /// in each index. Differences are expected to be very rare as client and servers build their
    /// respective indexes from the same source and in a short timespan.
    ///
    pub(crate) fn report_indexes_differences(
        client_provided_index: &AsfaloadIndex,
        server_built_index: &AsfaloadIndex,
        dates_check: IndexDateChecks,
    ) -> Option<String> {
        let mut lines = Vec::new();
        if client_provided_index.published_files.len() != server_built_index.published_files.len() {
            lines.push("Files published differ in number".to_string());
        };

        // To compare the lists of published files of both indexes, we build a HashSet for each,
        // where the item in the set is the FileChecksum itself. This ensures every field,
        // including the file name and the digest algorithm, is compared.
        let expected: HashSet<&FileChecksum> = server_built_index.published_files.iter().collect();

        let provided: HashSet<&FileChecksum> =
            client_provided_index.published_files.iter().collect();
        if expected != provided {
            if expected.len() != provided.len() {
                lines.push("Files published differ in number of distinct entries".to_string());
            } else {
                lines.push("Files published differ.".to_string());
            }
        }
        if matches!(dates_check, IndexDateChecks::PublicationDate)
            && server_built_index.published_on != client_provided_index.published_on
        {
            lines.push(format!(
                "Provided published_on ({}) differs from the one retrieved ({})",
                client_provided_index.published_on, server_built_index.published_on
            ));
        }
        if server_built_index.version != client_provided_index.version {
            lines.push(format!(
                "Provided version ({}) differs from the one retrieved ({})",
                client_provided_index.version, server_built_index.version
            ));
        }

        if lines.is_empty() {
            None
        } else {
            Some(lines.join("\n"))
        }
    }

    /// Verify the data provided by the client and return it wrapped in a
    /// type guaranteeing the data has been checked.
    /// The fetcher must be the fetcher of the forge named in `data.sources`.
    ///
    /// Two checks are done:
    /// - the signature sent by the client verifies with the public key it
    ///   declares, over the exact bytes of the index it sent, and
    /// - the index it sent publishes exactly the files and hashes we find
    ///   in the release we retrieve.
    pub async fn new<F, R>(
        data: ClientProvidedData,
        fetcher: &F,
    ) -> Result<Self, ReleaseHandlingError>
    where
        F: ReleaseFetcher<R>,
        R: ReleaseResponseTrait,
    {
        // Parse the signature sent
        let signature =
            AsfaloadSignatures::from_base64(&data.client_sent_signature).map_err(|e| {
                ReleaseHandlingError::InvalidData(format!(
                    "Could not parse signature sent by client for release {}: {}",
                    data.sources, e
                ))
            })?;

        // Parse the index sent
        let index_string = string_from_base64(&data.client_sent_index).map_err(|e| {
            ReleaseHandlingError::InvalidData(format!(
                "Could not decode index sent by client: {}",
                e
            ))
        })?;

        // Compute digest of client sent index json, for signature validation
        let index_sha512 = sha512_for_content(index_string.as_bytes()).map_err(|e| {
            ReleaseHandlingError::InvalidData(format!(
                "Could not compute sha512 of the index sent by client for release {}: {}",
                data.sources, e
            ))
        })?;

        let pub_key = AsfaloadPublicKeys::from_base64(&data.client_pub_key).map_err(|e| {
            ReleaseHandlingError::InvalidData(format!(
                "Could not parse public key sent by client for release {}: {}",
                data.sources, e
            ))
        })?;

        // Verify the signature sent by client
        pub_key.verify(&signature, &index_sha512).map_err(|e| {
            ReleaseHandlingError::InvalidData(format!(
                "Signature sent by client for release {} does not verify: {}",
                data.sources, e
            ))
        })?;

        // Now we will check that the index we build ourself for the release is equivalent
        let client_provided_index: AsfaloadIndex =
            serde_json::from_str(&index_string).map_err(|e| {
                ReleaseHandlingError::InvalidData(format!(
                    "Could not parse index sent by client for release {}: {}",
                    data.sources, e
                ))
            })?;

        // Retrieve the release and build our own index: the client index
        // must publish exactly the files we find there, with identical hashes.
        let release: R = fetcher.fetch(data.sources.to_urls()).await.map_err(|e| {
            ReleaseHandlingError::Generic(format!("Could not retrieve release: {}", e))
        })?;

        let index = release.generate_index().await?;

        // Checksums files carry no upstream publication date: both the client
        // and the server stamp their index generation time, so the dates can
        // never match. See `report_indexes_differences` for the details.
        let dates_check = if matches!(data.sources, ClientIndexSources::FileServer(_)) {
            IndexDateChecks::None
        } else {
            IndexDateChecks::PublicationDate
        };

        if let Some(msg) =
            Self::report_indexes_differences(&client_provided_index, &index, dates_check)
        {
            return Err(ReleaseHandlingError::InvalidData(format!(
                "Index provided by client is not identical to index generated server side for release at {}: {}",
                data.sources, msg
            )));
        }

        Ok(VerifiedClientData {
            client_provided_data: data,
            pub_key,
            index_string,
            signature,
        })
    }

    pub fn sources(&self) -> &[Url] {
        self.client_provided_data.sources.to_urls()
    }

    pub fn pub_key(&self) -> &AsfaloadPublicKeys {
        &self.pub_key
    }

    pub fn index_string(&self) -> &str {
        &self.index_string
    }

    pub fn signature(&self) -> &AsfaloadSignatures {
        &self.signature
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // The enum exposes the urls of the wrapped source, and displays like it.
    #[test]
    fn github_source_exposes_its_url() {
        let url = url::Url::parse("https://github.com/owner/repo/releases/tag/v1.0.0").unwrap();
        let sources = ClientIndexSources::Github(GithubReleaseSource::new(url.clone()));

        assert_eq!(sources.to_urls(), std::slice::from_ref(&url));
        assert_eq!(sources.to_string(), url.to_string());
    }

    fn index_with_dates(
        published_on: chrono::DateTime<chrono::Utc>,
        published_files: Vec<FileChecksum>,
    ) -> AsfaloadIndex {
        AsfaloadIndex {
            mirrored_on: published_on,
            published_on,
            version: 1,
            published_files,
        }
    }

    fn checksum_file_checksum() -> FileChecksum {
        FileChecksum {
            file_name: "artifact.bin".to_string(),
            algo: features_lib::HashAlgorithm::Sha256,
            source: "http://files.example.com/owner/repo/releases/v1.0/SHA256SUMS".to_string(),
            source_format: features_lib::ChecksumSourceFormat::ShaSum,
            hash: "a".repeat(64),
        }
    }

    // Checksums files carry no publication date: the client and the server
    // stamp their own generation time, and the two values can never match.
    // The dates check requested must not report that difference.
    #[test]
    fn skipped_dates_check_ignores_publication_dates() {
        let client_date: chrono::DateTime<chrono::Utc> = "2026-01-01T00:00:00Z".parse().unwrap();
        let server_date: chrono::DateTime<chrono::Utc> = "2026-01-02T00:00:00Z".parse().unwrap();
        let client_provided_index = index_with_dates(client_date, vec![checksum_file_checksum()]);
        let server_built_index = index_with_dates(server_date, vec![checksum_file_checksum()]);

        let differences = VerifiedClientData::report_indexes_differences(
            &client_provided_index,
            &server_built_index,
            IndexDateChecks::None,
        );

        assert!(
            differences.is_none(),
            "Expected no difference report, got: {:?}",
            differences
        );
    }

    // When the publication date check is requested, differing publication
    // dates must produce a difference report.
    #[test]
    fn dates_check_reports_publication_date_difference() {
        let client_date: chrono::DateTime<chrono::Utc> = "2026-01-01T00:00:00Z".parse().unwrap();
        let server_date: chrono::DateTime<chrono::Utc> = "2026-01-02T00:00:00Z".parse().unwrap();
        let client_provided_index = index_with_dates(client_date, vec![checksum_file_checksum()]);
        let server_built_index = index_with_dates(server_date, vec![checksum_file_checksum()]);

        let differences = VerifiedClientData::report_indexes_differences(
            &client_provided_index,
            &server_built_index,
            IndexDateChecks::PublicationDate,
        );

        assert!(
            differences
                .as_ref()
                .is_some_and(|d| d.contains("Provided published_on")),
            "Expected a publication date difference report, got: {:?}",
            differences
        );
    }
}
