use features_lib::{HashAlgorithm, IndexValidationError, ParsedChecksum};

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
pub fn parse_github_rest_api_answer(
    body: &str,
    source_url: &str,
) -> Result<Vec<ParsedChecksum>, IndexValidationError> {
    let response: GithubReleaseResponse =
        serde_json::from_str(body).map_err(|e| IndexValidationError::DigestSourceParseError {
            url: source_url.to_string(),
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
