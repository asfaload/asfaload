use std::fmt::{self};

use crate::common::{ReleaseFetcher, ReleaseHandlingError, ReleaseInfo};
use common::http::{FetchError, fetch_request};
use features_lib::{HashAlgorithm, IndexValidationError, ParsedChecksum, fetch_with_retry};
use forge_url::path_prefix_from_url;
use url::Url;

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
    pub origin_prefix: String,
    pub owner: String,
    pub repo: String,
    pub tag: String,
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
            origin_prefix,
            owner,
            repo,
            tag,
        })
    }

    pub fn to_url(&self) -> Result<url::Url, ReleaseHandlingError> {
        let s = format!(
            "https://github.com/{}/{}/releases/tag/{}",
            self.owner(),
            self.repo(),
            self.tag()
        );
        url::Url::parse(&s).map_err(|e| {
            ReleaseHandlingError::InvalidUrl(format!(
                "Could not convert GithubReleaseInfo to url: {}",
                e
            ))
        })
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
}

impl ReleaseFetcher<GithubReleaseResponse> for GithubReleaseFetcher {
    async fn fetch(&self, url: Url) -> Result<GithubReleaseResponse, ReleaseHandlingError> {
        let mut request = self
            .client
            .get(url.clone())
            .header(reqwest::header::USER_AGENT, "asfaload");
        if let Some(token) = &self.token {
            request = request.bearer_auth(token);
        }
        let body = fetch_request(request).await.map_err(|e| {
            ReleaseHandlingError::Generic(format!("failed fetching release at {}", e))
        })?;
        Ok(serde_json::from_str(&body)?)
    }
}

// -----------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

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
