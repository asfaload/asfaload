use std::{
    collections::{HashMap, hash_map::Entry},
    time::Duration,
};

use reqwest::Client;

/// Error type for HTTP fetch operations.
#[derive(Debug, thiserror::Error)]
pub enum FetchError {
    #[error("Client error: {0}")]
    ClientError(String),
    #[error("Request failed: {0}")]
    RequestFailed(String),
    #[error("HTTP {status}: {url}")]
    HttpError { status: u16, url: String },
    #[error("Rate limit exceeded after {retries} retries: {url}")]
    RateLimitExceeded { retries: u32, url: String },
    #[error("Failed to read response body: {0}")]
    BodyReadError(String),
}

const MAX_RETRIES: u32 = 3;
const INITIAL_BACKOFF_SEC: u64 = 1;
const MAX_BACKOFF_SEC: u64 = 3600;
const REQUEST_TIMEOUT_SEC: u64 = 10;

/// Fetch the content at `url` as a string, retrying on HTTP 429 with
/// exponential backoff. Respects the `Retry-After` header when present.
pub async fn fetch_with_retry(url: &str) -> Result<String, FetchError> {
    let mut retries = 0;
    let mut backoff_sec = INITIAL_BACKOFF_SEC;

    loop {
        let client = Client::builder()
            .timeout(Duration::from_secs(REQUEST_TIMEOUT_SEC))
            .build()
            .map_err(|e| FetchError::ClientError(e.to_string()))?;
        let response = client
            .get(url)
            .send()
            .await
            .map_err(|e| FetchError::RequestFailed(format!("{}: {}", url, e)))?;

        if response.status() == 429 {
            if retries >= MAX_RETRIES {
                return Err(FetchError::RateLimitExceeded {
                    retries: MAX_RETRIES,
                    url: url.to_string(),
                });
            }
            let retry_after = response
                .headers()
                .get("Retry-After")
                .and_then(|h| h.to_str().ok())
                .and_then(|s| s.parse().ok())
                .unwrap_or(backoff_sec)
                .min(MAX_BACKOFF_SEC);

            tokio::time::sleep(Duration::from_secs(retry_after)).await;
            retries += 1;
            backoff_sec = (backoff_sec * 2).min(MAX_BACKOFF_SEC);
            continue;
        }

        if !response.status().is_success() {
            return Err(FetchError::HttpError {
                status: response.status().as_u16(),
                url: url.to_string(),
            });
        }

        return response
            .text()
            .await
            .map_err(|e| FetchError::BodyReadError(format!("{}: {}", url, e)));
    }
}

/// Returns a new empty cache to be used with fetch_sequentially_with_cache.
pub fn new_sequential_cache() -> HashMap<String, String> {
    HashMap::new()
}
/// Fetch url only if it is not found as a key in the cache, as it then returns the value found in
/// the cache. Cache is meant to be used in sequential fetches only.
pub async fn fetch_sequentially_with_cache(
    url: &str,
    cache: &mut HashMap<String, String>,
) -> Result<String, FetchError> {
    match cache.entry(url.into()) {
        Entry::Vacant(entry) => {
            let content = fetch_with_retry(url).await?;
            entry.insert(content.clone());
            Ok(content)
        }
        Entry::Occupied(entry) => Ok(entry.get().clone()),
    }
}
