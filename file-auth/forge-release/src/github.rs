use std::{
    collections::HashSet,
    fmt::{self},
};

use crate::common::{ReleaseAssetInfo, ReleaseFetcher, ReleaseHandlingError, ReleaseInfo};
use common::{
    http::fetch_request_with_retry, into_url::IntoUrl, sha512_for_content, string_from_base64,
};
use core::time::Duration;
use features_lib::{
    AsfaloadIndex, AsfaloadPublicKeyTrait, AsfaloadPublicKeys, AsfaloadSignatureTrait,
    AsfaloadSignatures, ChecksumSourceFormat, FileChecksum, HashAlgorithm, IndexValidationError,
    ParsedChecksum,
};
use forge_url::path_prefix_from_url;
use url::Url;

#[cfg(feature = "test-utils")]
pub mod test_utils;

const MAX_RETRIES: u32 = 3;
const REQUEST_TIMEOUT_SEC: u64 = 10;
/// Builds an api url to retrieve the release info. This builds the url based on owner, repo and
/// tag, and the document returned is a json object with all details of the release. The document
/// has a url field, which is of the form
///    https://api.github.com/repos/{owner}/{repo}/releases/252430053
/// This last url does not use the tag but a release id, and is probably the canonical url of the release.
/// It returns the exact same document as the url we build with owner, repo and tag.
pub fn github_release_api_url(release_page_url: &url::Url) -> Result<Url, ReleaseHandlingError> {
    let (_host, owner, repo, tag) =
        forge_url::github::validate_github_release_url(release_page_url)
            .map_err(|e| ReleaseHandlingError::InvalidUrl(e.to_string()))?;
    url::Url::parse(&format!(
        "https://api.github.com/repos/{owner}/{repo}/releases/tags/{tag}"
    ))
    .map_err(|e| {
        ReleaseHandlingError::InvalidUrl(format!(
            "Could not build github api release url from {}: {}",
            release_page_url, e
        ))
    })
}

// Minimal shape of a github release api response ignoring irrelevant fields.
#[derive(serde::Deserialize)]
pub struct GithubReleaseResponse {
    /// The github rest-api url of the release. The index records it as the
    /// digest source of every asset.
    pub url: String,
    /// Absent for a draft release. Index generation falls back to created_at.
    pub published_at: Option<chrono::DateTime<chrono::Utc>>,
    pub created_at: Option<chrono::DateTime<chrono::Utc>>,
    pub assets: Vec<GithubReleaseAsset>,
}

#[derive(serde::Deserialize)]
pub struct GithubReleaseAsset {
    pub name: String,
    pub digest: Option<String>,
}

impl GithubReleaseResponse {
    pub fn extract_assets(&self) -> Vec<ReleaseAssetInfo> {
        self.assets
            .iter()
            .map(|asset| {
                let hash = asset.digest.as_ref().and_then(|d| {
                    d.strip_prefix("sha256:").map(|hash| FileChecksum {
                        file_name: asset.name.clone(),
                        algo: HashAlgorithm::Sha256,
                        // For a github release, the source is the url to get from the GH rest-api
                        // to retrieve the release info, incl. assets and their digest.
                        source: self.url.to_string(),
                        source_format: ChecksumSourceFormat::GithubRelease,
                        hash: hash.to_string(),
                    })
                });
                ReleaseAssetInfo { hash }
            })
            .collect()
    }
    pub fn generate_index(&self) -> Result<AsfaloadIndex, ReleaseHandlingError> {
        let assets = self.extract_assets();
        if assets.is_empty() {
            return Err(ReleaseHandlingError::InvalidData(
                "No assets found in Github release".to_string(),
            ));
        }
        let published_files: Vec<FileChecksum> = self
            .extract_assets()
            .iter()
            .filter_map(|asset| asset.hash.clone())
            .collect();

        let published_on = self.published_at.or(self.created_at).ok_or_else(|| {
            ReleaseHandlingError::InvalidData(
                "No publication timestamp found in release".to_string(),
            )
        })?;
        let mirrored_on = chrono::Utc::now();

        Ok(AsfaloadIndex {
            mirrored_on,
            published_on: published_on.to_utc(),
            version: 1,
            published_files,
        })
    }

    pub fn generate_index_json(&self) -> Result<String, ReleaseHandlingError> {
        let index = self.generate_index()?;
        common::to_posix_json(&index).map_err(|e| {
            ReleaseHandlingError::InvalidData(format!("Failed to serialize index: {}", e))
        })
    }
}
// Extract the digests of a github release api response, skipping assets
// without digest or with an algorithm we cannot record in an index.
pub fn get_checksums_from_github_rest_api_answer(
    body: &str,
) -> Result<Vec<ParsedChecksum>, IndexValidationError> {
    let response: GithubReleaseResponse =
        serde_json::from_str(body).map_err(|e| IndexValidationError::DigestDocumentParseError {
            reason: format!("expected a github release api response: {e}"),
        })?;
    Ok(response
        .assets
        .iter()
        .filter_map(|asset| {
            let (algo, hash) = asset.digest.as_deref()?.split_once(':')?;
            let algo = match algo {
                "sha256" => HashAlgorithm::Sha256,
                "sha512" => HashAlgorithm::Sha512,
                _ => return None,
            };
            Some(ParsedChecksum {
                file_name: asset.name.clone(),
                algo,
                hash: hash.to_string(),
            })
        })
        .collect())
}

// Originally in rest-api, but made available to client to generate index for release registration
// -----------------------------------------------------------------------------------------------

/// Information of a Github release
#[derive(Debug, Clone)]
pub struct GithubReleaseInfo {
    /// The release page URL this info was built from.
    pub url: Url,
    /// scheme/host/port
    pub origin_prefix: String,
    pub owner: String,
    pub repo: String,
    pub tag: String,
}

pub struct ClientProvidedData {
    pub github_release_url: String,
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

impl VerifiedClientData {
    /// Helper to get explicit message about indexes differences. Returns None if no difference.
    /// We keep it simple and don't try to report detailed differences in the published files found
    /// in each index. Differences are expected to be very rare as client and servers build their
    /// respective indexes from the same source and in a short timespan.
    fn report_indexes_differences(
        client_provided_index: &AsfaloadIndex,
        server_built_index: &AsfaloadIndex,
    ) -> Option<String> {
        // To compare the lists of published files of both indexes, we build a HashSet for each,
        // where the item in the set is the FileChecksum itself. This ensures all fields, and so
        // incl. the filename and the digest algorithms are used in the comparison.
        let expected: HashSet<&FileChecksum> = server_built_index.published_files.iter().collect();

        let provided: HashSet<&FileChecksum> =
            client_provided_index.published_files.iter().collect();
        let mut lines = Vec::new();
        if expected != provided {
            if expected.len() != provided.len() {
                lines.push("Files published differ in number".to_string());
            } else {
                lines.push("Files published differ.".to_string());
            }
        }
        if server_built_index.published_on != client_provided_index.published_on {
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
    ///
    /// Two checks are done:
    /// - the signature sent by the client verifies with the public key it
    ///   declares, over the exact bytes of the index it sent, and
    /// - the index it sent publishes exactly the files and hashes we find
    ///   in the release we retrieve from github.
    pub async fn new<F>(data: ClientProvidedData, fetcher: &F) -> Result<Self, ReleaseHandlingError>
    where
        F: ReleaseFetcher<GithubReleaseResponse>,
    {
        // Parse the signature sent
        let signature =
            AsfaloadSignatures::from_base64(&data.client_sent_signature).map_err(|e| {
                ReleaseHandlingError::InvalidData(format!(
                    "Could not parse signature sent by client for github release {}: {}",
                    data.github_release_url, e
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
                "Could not compute sha512 of the index sent by client for github release {}: {}",
                data.github_release_url, e
            ))
        })?;

        let pub_key = AsfaloadPublicKeys::from_base64(&data.client_pub_key).map_err(|e| {
            ReleaseHandlingError::InvalidData(format!(
                "Could not parse public key sent by client for github release {}: {}",
                data.github_release_url, e
            ))
        })?;

        // Verify the signature sent by client
        pub_key.verify(&signature, &index_sha512).map_err(|e| {
            ReleaseHandlingError::InvalidData(format!(
                "Signature sent by client for github release {} does not verify: {}",
                data.github_release_url, e
            ))
        })?;

        // Now we will check that the index we build ourself for the release is equivalent
        let client_provided_index: AsfaloadIndex =
            serde_json::from_str(&index_string).map_err(|e| {
                ReleaseHandlingError::InvalidData(format!(
                    "Could not parse index sent by client for github release {}: {}",
                    data.github_release_url, e
                ))
            })?;

        // Retrieve the release and build our own index: the client index
        // must publish exactly the files we find there, with identical hashes.
        let release: GithubReleaseResponse = fetcher
            .fetch(data.github_release_url.clone())
            .await
            .map_err(|e| {
            ReleaseHandlingError::Generic(format!("Could not retrieve github release: {}", e))
        })?;

        let index = release.generate_index()?;

        if let Some(msg) = Self::report_indexes_differences(&client_provided_index, &index) {
            return Err(ReleaseHandlingError::InvalidData(format!(
                "Index provided by client is not identical to index generated server side for release at {}: {}",
                data.github_release_url, msg
            )));
        }

        Ok(VerifiedClientData {
            client_provided_data: data,
            pub_key,
            index_string,
            signature,
        })
    }

    pub fn github_release_url(&self) -> &str {
        &self.client_provided_data.github_release_url
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

impl GithubReleaseInfo {
    pub fn from_url(url: &url::Url) -> Result<Self, ReleaseHandlingError> {
        let (_host, owner, repo, tag) = forge_url::github::validate_github_release_url(url)
            .map_err(|e| ReleaseHandlingError::InvalidUrl(e.to_string()))?;
        let origin_prefix = path_prefix_from_url(url)
            .map_err(|e| ReleaseHandlingError::InvalidUrl(e.to_string()))?;
        Ok(GithubReleaseInfo {
            url: url.clone(),
            origin_prefix,
            owner,
            repo,
            tag,
        })
    }

    pub fn to_url(&self) -> Result<url::Url, ReleaseHandlingError> {
        Ok(self.url.clone())
    }
}

impl fmt::Display for GithubReleaseInfo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}",
            self.to_url().map(|u| u.to_string()).unwrap_or(format!(
                "GithubReleaseInfo(origin_prefix: {}, repo: {}/{}, tag: {})",
                self.origin_prefix, self.owner, self.repo, self.tag
            ))
        )
    }
}

#[derive(Debug)]
pub struct GithubReleaseFetcher {
    client: reqwest::Client,
    token: Option<String>,
}

impl GithubReleaseFetcher {
    pub fn new(token: Option<String>) -> Self {
        Self {
            client: reqwest::Client::new(),
            token,
        }
    }
    /// Build the request to the github rest api. The bearer token is added when
    /// the caller configured one: without it the api rate limits the requests.
    fn build_request(&self, api_url: &Url) -> reqwest::RequestBuilder {
        let mut request = self
            .client
            .get(api_url.clone())
            .timeout(Duration::from_secs(REQUEST_TIMEOUT_SEC))
            .header(reqwest::header::USER_AGENT, "asfaload");
        if let Some(token) = &self.token {
            request = request.bearer_auth(token);
        }
        request
    }
}

impl ReleaseFetcher<GithubReleaseResponse> for GithubReleaseFetcher {
    /// Builds a GithubReleaseResponse, which can generate the index of the release
    async fn fetch<U: IntoUrl>(
        &self,
        url_in: U,
    ) -> Result<GithubReleaseResponse, ReleaseHandlingError> {
        let url_text = url_in.to_string();
        let url = url_in.into_url().map_err(|e| {
            ReleaseHandlingError::InvalidUrl(format!("Could not parse url {}: {}", url_text, e))
        })?;
        // Build the api url once, so an invalid url fails at once and is not retried.
        let api_url = github_release_api_url(&url)?;
        let body = fetch_request_with_retry(
            api_url.as_str(),
            || self.build_request(&api_url),
            MAX_RETRIES,
        )
        .await?;
        Ok(serde_json::from_str(&body)?)
    }
}

// -----------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // The release adder fetches releases starting from the release html page
    // url. Data must come from the rest-api endpoint: check the conversion.
    #[test]
    fn release_api_url_is_derived_from_release_page_url() {
        let page_url =
            url::Url::parse("https://github.com/testowner/testrepo/releases/tag/v1.0.0").unwrap();
        let api_url = github_release_api_url(&page_url).unwrap();
        assert_eq!(
            api_url.as_str(),
            "https://api.github.com/repos/testowner/testrepo/releases/tags/v1.0.0"
        );
    }

    #[test]
    fn non_release_page_url_rejected_for_api_url_conversion() {
        let bad_url = url::Url::parse("https://github.com/owner/repo").unwrap();
        assert!(github_release_api_url(&bad_url).is_err());
    }

    // Server side generation needs the release url and its timestamps. This
    // test pins the shape of the response struct used for parsing and
    // generation.
    #[test]
    fn release_response_exposes_url_and_timestamps() {
        let body = r#"{
            "url": "https://api.github.com/repos/acme/tool/releases/123",
            "published_at": "2024-01-02T03:04:05Z",
            "created_at": "2024-01-01T00:00:00Z",
            "assets": [
                {"name": "app.bin", "digest": "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}
            ]
        }"#;

        let response: GithubReleaseResponse = serde_json::from_str(body).unwrap();

        assert_eq!(
            response.url,
            "https://api.github.com/repos/acme/tool/releases/123"
        );
        assert_eq!(
            response.published_at,
            Some(
                "2024-01-02T03:04:05Z"
                    .parse::<chrono::DateTime<chrono::Utc>>()
                    .unwrap()
            )
        );
        assert_eq!(
            response.created_at,
            Some(
                "2024-01-01T00:00:00Z"
                    .parse::<chrono::DateTime<chrono::Utc>>()
                    .unwrap()
            )
        );
    }

    #[test]
    fn release_response_allows_absent_published_at() {
        let body = r#"{
            "url": "https://api.github.com/repos/acme/tool/releases/123",
            "published_at": null,
            "created_at": "2024-01-01T00:00:00Z",
            "assets": []
        }"#;

        let response: GithubReleaseResponse = serde_json::from_str(body).unwrap();

        assert_eq!(response.published_at, None);
        assert!(response.created_at.is_some());
    }
}

// Verification needs the mock fetcher, so tests run with the test-utils
// feature enabled.
#[cfg(all(test, feature = "test-utils"))]
mod verified_client_data_tests {
    use super::*;
    use crate::github::test_utils::{
        MockGithubReleaseFetcher, client_provided_data_for_index,
        create_mocked_client_provided_data, mocked_client_provided_data_with_keys,
        mocked_release_index,
    };
    use common::{base64_for_string, string_from_base64};
    use features_lib::{
        AsfaloadKeyPairTrait, AsfaloadKeyPairs, AsfaloadPublicKeyTrait, AsfaloadPublicKeys,
        AsfaloadSecretKeys, AsfaloadSignatureTrait, sha512_for_content,
    };
    use std::sync::OnceLock;

    const TEST_KEY_PASSWORD: &str = "test_password";

    fn keys_with_password() -> (&'static AsfaloadPublicKeys, &'static AsfaloadSecretKeys) {
        static KEYS: OnceLock<(AsfaloadPublicKeys, AsfaloadSecretKeys)> = OnceLock::new();
        let keys = KEYS.get_or_init(|| {
            let key_pair = AsfaloadKeyPairs::new(TEST_KEY_PASSWORD).unwrap();
            (
                key_pair.public_key(),
                key_pair.secret_key(TEST_KEY_PASSWORD).unwrap(),
            )
        });
        (&keys.0, &keys.1)
    }

    /// Unrelated key pair: its signature must be rejected when the client
    /// declares the first pair's public key.
    fn other_keys_with_password() -> (&'static AsfaloadPublicKeys, &'static AsfaloadSecretKeys) {
        static KEYS: OnceLock<(AsfaloadPublicKeys, AsfaloadSecretKeys)> = OnceLock::new();
        let keys = KEYS.get_or_init(|| {
            let key_pair = AsfaloadKeyPairs::new("other_test_password").unwrap();
            (
                key_pair.public_key(),
                key_pair.secret_key("other_test_password").unwrap(),
            )
        });
        (&keys.0, &keys.1)
    }

    async fn verify_rejects_with(data: ClientProvidedData, expected_message: &str) {
        let fetcher = MockGithubReleaseFetcher::new();
        let outcome = VerifiedClientData::new(data, &fetcher).await;
        match outcome {
            Err(ReleaseHandlingError::InvalidData(msg)) => assert!(
                msg.contains(expected_message),
                "Expected message containing '{expected_message}', got: {msg}"
            ),
            Err(e) => panic!("Expected InvalidData but got: {e}"),
            Ok(_) => panic!("Expected client data verification to fail, but it succeeded"),
        }
    }

    // Verifies the client index is rejected as not identical to the server
    // generated index, and that the error reports every expected difference
    // detail. This keeps the differences reporting under test.
    async fn verify_rejects_index_with(data: ClientProvidedData, expected_details: &[&str]) {
        let fetcher = MockGithubReleaseFetcher::new();
        let outcome = VerifiedClientData::new(data, &fetcher).await;
        match outcome {
            Err(ReleaseHandlingError::InvalidData(msg)) => {
                assert!(
                    msg.contains("not identical to index generated server side"),
                    "Expected index mismatch rejection, got: {msg}"
                );
                for detail in expected_details {
                    assert!(
                        msg.contains(detail),
                        "Expected message containing '{detail}', got: {msg}"
                    );
                }
            }
            Err(e) => panic!("Expected InvalidData but got: {e}"),
            Ok(_) => panic!("Expected client data verification to fail, but it succeeded"),
        }
    }

    // The verified data must be exactly what the client sent: the server
    // keeps using it to register the release.
    #[tokio::test]
    async fn accepts_client_index_and_signature_matching_server_index() {
        let data = create_mocked_client_provided_data();
        let expected_url = data.github_release_url.clone();
        let expected_pub_key = data.client_pub_key.clone();
        let expected_index = data.client_sent_index.clone();
        let expected_signature = data.client_sent_signature.clone();

        let fetcher = MockGithubReleaseFetcher::new();
        let outcome = VerifiedClientData::new(data, &fetcher).await;

        match outcome {
            Ok(verified) => {
                // The accessors must expose exactly the data sent by the
                // client, in their parsed form as the server will use it.
                assert_eq!(verified.github_release_url(), expected_url);
                assert_eq!(verified.pub_key().to_base64(), expected_pub_key);
                let expected_index_bytes = string_from_base64(&expected_index).unwrap();
                assert_eq!(verified.index_string(), expected_index_bytes);
                assert_eq!(verified.signature().to_base64(), expected_signature);
            }
            Err(e) => panic!("Expected client data to be verified, but got: {e}"),
        }
    }

    // The client index and the signature must attest the same content: a
    // signature computed over other content must be rejected even if the
    // sent index is exactly the one the server builds itself.
    #[tokio::test]
    async fn rejects_signature_computed_over_other_content() {
        let (pub_key, secret_key) = keys_with_password();
        let tampered_index = format!("{}\ntampered content\n", mocked_release_index());
        let mut data = client_provided_data_for_index(pub_key, secret_key, &tampered_index);
        // Send the genuine index with the signature over the tampered one.
        data.client_sent_index = base64_for_string(mocked_release_index());

        verify_rejects_with(data, "Signature sent by client").await;
    }

    // The signature must be made with the key corresponding to the public
    // key sent by the client.
    #[tokio::test]
    async fn rejects_signature_of_other_key_than_declared_public_key() {
        let (pub_key, _secret_key) = keys_with_password();
        let (_other_pub_key, other_secret_key) = other_keys_with_password();
        // Index over the mocked release, but signed with the unrelated key.
        let data = mocked_client_provided_data_with_keys(pub_key, other_secret_key);

        verify_rejects_with(data, "Signature sent by client").await;
    }

    // Even with a valid signature, the client index must publish exactly the
    // files and hashes found in the release for which it is registered.
    #[tokio::test]
    async fn rejects_index_not_identical_to_server_generated_index() {
        let (pub_key, secret_key) = keys_with_password();
        let mut value: serde_json::Value = serde_json::from_str(&mocked_release_index()).unwrap();
        value["publishedFiles"][0]["hash"] = serde_json::Value::String("f".repeat(64));
        let index_string = serde_json::to_string(&value).unwrap();
        let data = client_provided_data_for_index(pub_key, secret_key, &index_string);

        // The file count is unchanged, so only the content difference is
        // reported.
        verify_rejects_index_with(data, &["Files published differ."]).await;
    }

    // The publication date is part of the index identity: an index published
    // on another date must not pass as the release's own index.
    #[tokio::test]
    async fn rejects_client_index_with_other_published_on() {
        let (pub_key, secret_key) = keys_with_password();
        let data = client_data_with_index(pub_key, secret_key, |value| {
            value["publishedOn"] = serde_json::json!("2000-01-01T00:00:00Z");
        });

        // The provided and the retrieved dates must both be reported.
        verify_rejects_index_with(
            data,
            &["Provided published_on (", "2000-01-01", "2024-01-01"],
        )
        .await;
    }

    // The index version is part of the index identity: an index with another
    // version must not pass as the release's own index.
    #[tokio::test]
    async fn rejects_client_index_with_other_version() {
        let (pub_key, secret_key) = keys_with_password();
        let data = client_data_with_index(pub_key, secret_key, |value| {
            value["version"] = serde_json::json!(2);
        });

        verify_rejects_index_with(
            data,
            &["Provided version (2) differs from the one retrieved (1)"],
        )
        .await;
    }

    #[tokio::test]
    async fn rejects_unparsable_public_key() {
        let (pub_key, secret_key) = keys_with_password();
        let mut data = mocked_client_provided_data_with_keys(pub_key, secret_key);
        data.client_pub_key = "not-a-key".to_string();

        verify_rejects_with(data, "Could not parse public key sent by client").await;
    }

    #[tokio::test]
    async fn rejects_index_encoded_with_invalid_base64() {
        let (pub_key, secret_key) = keys_with_password();
        let mut data = mocked_client_provided_data_with_keys(pub_key, secret_key);
        data.client_sent_index = "!!! not base64 !!!".to_string();

        verify_rejects_with(data, "Could not decode index sent by client").await;
    }

    #[tokio::test]
    async fn rejects_signature_encoded_with_invalid_base64() {
        let (pub_key, secret_key) = keys_with_password();
        let mut data = mocked_client_provided_data_with_keys(pub_key, secret_key);
        data.client_sent_signature = "!!! not base64 !!!".to_string();

        verify_rejects_with(data, "Could not parse signature sent by client").await;
    }

    // The sent index must parse as an index: valid base64 with a signature
    // over it, but content that is not index json, is invalid client data.
    #[tokio::test]
    async fn rejects_index_that_does_not_parse_as_index() {
        let (pub_key, secret_key) = keys_with_password();
        let data = client_provided_data_for_index(pub_key, secret_key, "not index json at all");

        verify_rejects_with(data, "Could not parse index sent by client").await;
    }

    // Signs the json of the mocked release index after applying the given
    // change, so only the comparison against the server-generated index can
    // reject the data: the signature is valid over the sent content.
    fn client_data_with_index(
        pub_key: &AsfaloadPublicKeys,
        secret_key: &AsfaloadSecretKeys,
        change: impl FnOnce(&mut serde_json::Value),
    ) -> ClientProvidedData {
        let mut value: serde_json::Value = serde_json::from_str(&mocked_release_index()).unwrap();
        change(&mut value);
        let index_string = serde_json::to_string(&value).unwrap();
        client_provided_data_for_index(pub_key, secret_key, &index_string)
    }

    // A file missing from the client index means a plausible checksum may
    // be replaced by an unchecked download, so it must be rejected.
    #[tokio::test]
    async fn rejects_client_index_omitting_a_published_file() {
        let (pub_key, secret_key) = keys_with_password();
        let data = client_data_with_index(pub_key, secret_key, |value| {
            value["publishedFiles"].as_array_mut().unwrap().clear();
        });

        verify_rejects_index_with(data, &["Files published differ in number"]).await;
    }

    // A file added to the client index is an injection attempt: it would
    // validate a download the release never published.
    #[tokio::test]
    async fn rejects_client_index_with_extra_published_file() {
        let (pub_key, secret_key) = keys_with_password();
        let data = client_data_with_index(pub_key, secret_key, |value| {
            let extra = serde_json::json!({
                "fileName": "extra.tar.gz",
                "algo": "Sha256",
                "source": "https://api.github.com/repos/testowner/testrepo/releases/123",
                "sourceFormat": "GithubRelease",
                "hash": "a".repeat(64),
            });
            value["publishedFiles"]
                .as_array_mut()
                .unwrap()
                .insert(0, extra);
        });

        verify_rejects_index_with(data, &["Files published differ in number"]).await;
    }

    // A well-formed but empty index would validate downloads of nothing:
    // it must not be accepted as "equal to" the server index.
    #[tokio::test]
    async fn rejects_client_index_with_empty_published_files() {
        let (pub_key, secret_key) = keys_with_password();
        let data = client_data_with_index(pub_key, secret_key, |value| {
            value["publishedFiles"] = serde_json::json!([]);
        });

        verify_rejects_index_with(data, &["Files published differ in number"]).await;
    }

    // The digest algorithm is a trust decision: a hash checked as sha256
    // cannot be published as sha512.
    #[tokio::test]
    async fn rejects_client_index_with_other_digest_algorithm() {
        let (pub_key, secret_key) = keys_with_password();
        let data = client_data_with_index(pub_key, secret_key, |value| {
            value["publishedFiles"][0]["algo"] = serde_json::Value::String("Sha512".to_string());
        });

        verify_rejects_index_with(data, &["Files published differ."]).await;
    }

    // The source tells where the digest comes from; the client index and
    // the server index must publish the same one.
    #[tokio::test]
    async fn rejects_client_index_with_other_source() {
        let (pub_key, secret_key) = keys_with_password();
        let data = client_data_with_index(pub_key, secret_key, |value| {
            value["publishedFiles"][0]["source"] =
                serde_json::Value::String("https://downloads.example.com".to_string());
        });

        verify_rejects_index_with(data, &["Files published differ."]).await;
    }

    // The comparison is on the parsed content, not on the exact bytes: an
    // index equal to the server one but serialized differently (key order,
    // whitespace) validated with the matching signature must be accepted.
    #[tokio::test]
    async fn accepts_semantically_identical_index_with_other_serialization() {
        let (pub_key, secret_key) = keys_with_password();
        let value: serde_json::Value = serde_json::from_str(&mocked_release_index()).unwrap();
        let pretty_index = serde_json::to_string_pretty(&value).unwrap();
        // Serializing differently changes the bytes, so the signature must
        // cover the sent (pretty) content.
        let data = client_provided_data_for_index(pub_key, secret_key, &pretty_index);

        let fetcher = MockGithubReleaseFetcher::new();
        let outcome = VerifiedClientData::new(data, &fetcher).await;
        match outcome {
            Ok(verified) => {
                // The kept data is the exact bytes the client sent, not a
                // re-serialization: the signature must cover the
                // persisted data.
                assert_eq!(verified.index_string(), pretty_index);
            }
            Err(e) => panic!("Expected semantically identical index to be verified, got: {e}"),
        }
    }

    // The accessors must expose consistent parsed data: the signature the
    // client sent verifies over the digest of the index bytes it sent,
    // with the public key it declared.
    #[tokio::test]
    async fn exposes_parsed_client_data() {
        let (pub_key, secret_key) = keys_with_password();
        let index = mocked_release_index();
        let data = client_provided_data_for_index(pub_key, secret_key, &index);

        let fetcher = MockGithubReleaseFetcher::new();
        let outcome = VerifiedClientData::new(data, &fetcher).await;
        match outcome {
            Ok(verified) => {
                assert_eq!(verified.index_string(), index);
                assert_eq!(verified.pub_key().to_base64(), pub_key.to_base64());
                let index_sha512 = sha512_for_content(verified.index_string().as_bytes()).unwrap();
                assert!(
                    verified
                        .pub_key()
                        .verify(verified.signature(), &index_sha512)
                        .is_ok(),
                    "the exposed signature must verify over the exposed index with the exposed key"
                );
            }
            Err(e) => panic!("Expected client data to be verified, but got: {e}"),
        }
    }
}
