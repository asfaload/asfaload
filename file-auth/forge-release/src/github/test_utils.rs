//! Test doubles for the github release fetcher. Available with the
//! `test-utils` feature only, they let tests run without network access
//! to github.

use common::base64_for_string;
use features_lib::{
    AsfaloadKeyPairTrait, AsfaloadKeyPairs, AsfaloadPublicKeyTrait, AsfaloadPublicKeys,
    AsfaloadSecretKeyTrait, AsfaloadSecretKeys, AsfaloadSignatureTrait, sha512_for_content,
};

use super::GithubReleaseResponse;
use crate::common::{ClientProvidedData, ReleaseFetcher, ReleaseHandlingError};
use common::into_url::IntoUrl;

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
    async fn fetch<U: IntoUrl + Clone + Sync>(
        &self,
        _url: &[U],
    ) -> Result<GithubReleaseResponse, ReleaseHandlingError> {
        Ok(create_mock_release_response())
    }
}

// Url of the release page for the mocked release response: verification
// tests must send this url so the mock fetcher is used consistently.
pub const MOCK_RELEASE_PAGE_URL: &str = "https://github.com/testowner/testrepo/releases/tag/v1.0.0";
const TEST_KEY_PASSWORD: &str = "test_password";

/// The index json generated from the mocked release response, as the client
/// would send base64-encoded to the rest-api.
pub fn mocked_release_index() -> String {
    create_mock_release_response()
        .generate_index_json()
        .unwrap()
}

/// Builds a ClientProvidedData signing the sha512 of the given index content
/// with the given keys, mirroring what the rest-api client library builds
/// on release registration. `index` is sent unchanged (base64-encoded).
pub fn client_provided_data_for_index(
    public_key: &AsfaloadPublicKeys,
    secret_key: &AsfaloadSecretKeys,
    index: &str,
) -> ClientProvidedData<url::Url> {
    let hash = sha512_for_content(index.as_bytes()).unwrap();
    let signature = secret_key.sign(&hash).unwrap();
    ClientProvidedData {
        sources: url::Url::parse(MOCK_RELEASE_PAGE_URL).unwrap(),
        client_pub_key: public_key.to_base64(),
        client_sent_index: base64_for_string(index),
        client_sent_signature: signature.to_base64(),
    }
}

/// ClientProvidedData whose index is the one the rest-api builds itself from
/// the mocked release, signed by the provided keys.
pub fn mocked_client_provided_data_with_keys(
    public_key: &AsfaloadPublicKeys,
    secret_key: &AsfaloadSecretKeys,
) -> ClientProvidedData<url::Url> {
    client_provided_data_for_index(public_key, secret_key, &mocked_release_index())
}

/// ClientProvidedData over the mocked release index, signed by a freshly
/// generated key pair. Generation runs argon2, so prefer
/// `mocked_client_provided_data_with_keys` when keys are already available.
pub fn create_mocked_client_provided_data() -> ClientProvidedData<url::Url> {
    let key_pair = AsfaloadKeyPairs::new(TEST_KEY_PASSWORD).unwrap();
    let secret_key = key_pair.secret_key(TEST_KEY_PASSWORD).unwrap();
    mocked_client_provided_data_with_keys(&key_pair.public_key(), &secret_key)
}
