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
            // user agent is required as Github rest api rejects requests without one set
            .user_agent("asfaload")
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

pub async fn fetch_request(req: reqwest::RequestBuilder) -> Result<String, FetchError> {
    let response = req
        .send()
        .await
        .map_err(|e| FetchError::RequestFailed(format!("fetch_request failed with {}", e)))?;
    if !response.status().is_success() {
        return Err(FetchError::RequestFailed(format!(
            "fetch_request go error status back: {}",
            response.status().as_u16()
        )));
    }

    return response
        .text()
        .await
        .map_err(|e| FetchError::BodyReadError(format!("fetch_request failed with: {}", e)));
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

#[cfg(test)]
mod tests {
    use super::*;

    const BODY: &str = "body served by the mock server";

    #[tokio::test]
    async fn requests_carry_the_asfaload_cli_user_agent() -> anyhow::Result<()> {
        let mut server = mockito::Server::new_async().await;
        let mock = server
            .mock("GET", "/data")
            .match_header("User-Agent", "asfaload")
            .with_status(200)
            .with_body(BODY)
            .expect(1)
            .create_async()
            .await;
        let url = format!("{}/data", server.url());

        let body = fetch_with_retry(&url).await?;

        assert_eq!(body, BODY);
        mock.assert_async().await;
        Ok(())
    }

    #[tokio::test]
    async fn cache_hit_serves_body_without_second_fetch() -> anyhow::Result<()> {
        let mut server = mockito::Server::new_async().await;
        // Panics on assert if hit any other number of times than once.
        let mock = server
            .mock("GET", "/data")
            .with_status(200)
            .with_body(BODY)
            .expect(1)
            .create_async()
            .await;
        let url = format!("{}/data", server.url());
        let mut cache = new_sequential_cache();

        let first = fetch_sequentially_with_cache(&url, &mut cache).await?;
        let second = fetch_sequentially_with_cache(&url, &mut cache).await?;

        assert_eq!(first, BODY);
        assert_eq!(second, BODY);
        mock.assert_async().await;
        Ok(())
    }

    #[tokio::test]
    async fn distinct_urls_are_fetched_once_each() -> anyhow::Result<()> {
        let mut server = mockito::Server::new_async().await;
        let mock_a = server
            .mock("GET", "/a")
            .with_status(200)
            .with_body("body a")
            .expect(1)
            .create_async()
            .await;
        let mock_b = server
            .mock("GET", "/b")
            .with_status(200)
            .with_body("body b")
            .expect(1)
            .create_async()
            .await;
        let url_a = format!("{}/a", server.url());
        let url_b = format!("{}/b", server.url());
        let mut cache = new_sequential_cache();

        let first = fetch_sequentially_with_cache(&url_a, &mut cache).await?;
        let second = fetch_sequentially_with_cache(&url_b, &mut cache).await?;
        // Repeating the first url must be served from the cache.
        let again_a = fetch_sequentially_with_cache(&url_a, &mut cache).await?;

        assert_eq!(first, "body a");
        assert_eq!(second, "body b");
        assert_eq!(again_a, "body a");
        mock_a.assert_async().await;
        mock_b.assert_async().await;
        Ok(())
    }

    #[tokio::test]
    async fn failed_fetch_is_not_cached() -> anyhow::Result<()> {
        let mut server = mockito::Server::new_async().await;
        let failing = server
            .mock("GET", "/flaky")
            .with_status(500)
            .expect(1)
            .create_async()
            .await;
        let url = format!("{}/flaky", server.url());
        let mut cache = new_sequential_cache();

        match fetch_sequentially_with_cache(&url, &mut cache).await {
            Err(FetchError::HttpError {
                status,
                url: err_url,
            }) => {
                assert_eq!(status, 500);
                assert_eq!(err_url, url);
            }
            Err(e) => panic!("Expected FetchError::HttpError but got {}", e),
            Ok(v) => panic!("Expected error, got {v}"),
        }
        assert!(
            cache.is_empty(),
            "a failed fetch must not populate the cache"
        );
        failing.assert_async().await;

        // The failed url can be retried afterwards.
        server.reset();
        let working = server
            .mock("GET", "/flaky")
            .with_status(200)
            .with_body(BODY)
            .expect(1)
            .create_async()
            .await;
        let retried = fetch_sequentially_with_cache(&url, &mut cache).await?;
        assert_eq!(retried, BODY);
        working.assert_async().await;
        Ok(())
    }
}
