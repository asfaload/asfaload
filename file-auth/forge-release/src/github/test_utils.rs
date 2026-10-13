//! Test doubles for the github release fetcher. Available with the
//! `test-utils` feature only, they let tests run without network access
//! to github.

use super::GithubReleaseResponse;
use crate::common::{ReleaseFetcher, ReleaseHandlingError};
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
    async fn fetch<U: IntoUrl>(
        &self,
        _url: U,
    ) -> Result<GithubReleaseResponse, ReleaseHandlingError> {
        Ok(create_mock_release_response())
    }
}
