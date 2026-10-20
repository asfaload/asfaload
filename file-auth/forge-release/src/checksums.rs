use common::into_url::IntoUrl;
use features_lib::{AsfaloadIndex, ChecksumSourceFormat, FileChecksum, parse_checksums};
use futures_util::{StreamExt, stream};
use url::Url;

use crate::common::ReleaseHandlingError;

pub const MAX_CHECKSUM_FILE_SIZE: u64 = 512 * 1024; // 512KB
pub const MAX_PARALLEL_CSUMS: usize = 8;

/// Downloads the text content of a checksums file, enforcing a size limit.
async fn download_checksum_file(
    client: &reqwest::Client,
    url: &str,
) -> Result<String, ReleaseHandlingError> {
    use futures_util::StreamExt as _;

    let response = client.get(url).send().await.map_err(|e| {
        ReleaseHandlingError::Generic(format!("Failed to download checksums file: {}", e))
    })?;

    if response.status() != reqwest::StatusCode::OK {
        return Err(ReleaseHandlingError::Generic(format!(
            "HTTP error downloading checksums file {}: {}",
            url,
            response.status()
        )));
    }

    if let Some(len) = response.content_length()
        && len > MAX_CHECKSUM_FILE_SIZE
    {
        return Err(ReleaseHandlingError::InvalidData(format!(
            "Checksums file size {} exceeds limit {}",
            len, MAX_CHECKSUM_FILE_SIZE
        )));
    }

    let mut stream = response.bytes_stream();
    let mut body = Vec::new();
    let mut total_bytes = 0u64;

    while let Some(chunk_result) = stream.next().await {
        let chunk = chunk_result.map_err(|e| {
            ReleaseHandlingError::Generic(format!("Error reading checksums stream: {}", e))
        })?;

        total_bytes += chunk.len() as u64;
        if total_bytes > MAX_CHECKSUM_FILE_SIZE {
            return Err(ReleaseHandlingError::InvalidData(format!(
                "Checksums file size exceeded limit during download: {}",
                MAX_CHECKSUM_FILE_SIZE
            )));
        }

        body.extend_from_slice(&chunk);
    }

    String::from_utf8(body).map_err(|e| {
        ReleaseHandlingError::InvalidData(format!("Checksums file is not valid UTF-8: {}", e))
    })
}
pub async fn index_from_shasums_urls<U: IntoUrl + Clone>(
    reqwest_client: &reqwest::Client,
    urls_in: &[U],
) -> Result<AsfaloadIndex, ReleaseHandlingError> {
    let urls = urls_in
        .iter()
        .cloned()
        .map(|u| u.into_url())
        .collect::<Result<Vec<Url>, _>>()?;
    // Download and parse checksums files in parallel
    let results: Vec<Result<Vec<FileChecksum>, ReleaseHandlingError>> =
        stream::iter(urls.iter().cloned())
            .map(|url| {
                let client = reqwest_client.clone();
                async move {
                    let content = download_checksum_file(&client, url.as_str()).await?;
                    let checksums = parse_checksums(&content).map_err(|e| {
                        ReleaseHandlingError::InvalidData(format!(
                            "Failed to parse checksums file {}: {}",
                            url, e
                        ))
                    })?;
                    Ok(checksums
                        .into_iter()
                        .map(|c| FileChecksum {
                            file_name: c.file_name,
                            algo: c.algo,
                            source: url.to_string(),
                            source_format: ChecksumSourceFormat::ShaSum,
                            hash: c.hash,
                        })
                        .collect())
                }
            })
            .buffer_unordered(MAX_PARALLEL_CSUMS)
            .collect()
            .await;

    let published_files: Vec<FileChecksum> = results
        .into_iter()
        .collect::<Result<Vec<_>, _>>()?
        .into_iter()
        .flatten()
        .collect();

    let now = chrono::Utc::now();
    Ok(AsfaloadIndex {
        mirrored_on: now,
        published_on: now,
        version: 1,
        published_files,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use features_lib::HashAlgorithm;

    const SHA256_HEX: &str = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
    const SHA512_HEX: &str = "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e";

    /// Serve a chunked body, so the response carries no content-length header
    /// and only the streaming size limit of `download_checksum_file` applies.
    async fn serve_chunked(
        server: &mut mockito::Server,
        path: &str,
        body: Vec<u8>,
    ) -> mockito::Mock {
        server
            .mock("GET", path)
            .with_status(200)
            .with_chunked_body(move |writer| writer.write_all(&body))
            .create_async()
            .await
    }

    fn urls_for(server: &mockito::Server, paths: &[&str]) -> Vec<Url> {
        paths
            .iter()
            .map(|path| Url::parse(&format!("{}{}", server.url(), path)).unwrap())
            .collect()
    }

    fn expect_invalid_data(result: Result<String, ReleaseHandlingError>, expected_substring: &str) {
        match result {
            Err(ReleaseHandlingError::InvalidData(msg)) => assert!(
                msg.contains(expected_substring),
                "unexpected message: {msg}"
            ),
            other => panic!("expected an InvalidData error, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn download_returns_the_file_content() -> Result<(), ReleaseHandlingError> {
        let mut server = mockito::Server::new_async().await;
        let body = format!("{SHA256_HEX}  app.tar.gz\n");
        let mock = server
            .mock("GET", "/checksums")
            .with_status(200)
            .with_body(body.as_str())
            .create_async()
            .await;
        let url = format!("{}/checksums", server.url());

        let content = download_checksum_file(&reqwest::Client::new(), &url).await?;

        assert_eq!(content, body);
        mock.assert_async().await;
        Ok(())
    }

    #[tokio::test]
    async fn download_reports_http_error_status() {
        let mut server = mockito::Server::new_async().await;
        let mock = server
            .mock("GET", "/missing")
            .with_status(404)
            .create_async()
            .await;
        let url = format!("{}/missing", server.url());

        match download_checksum_file(&reqwest::Client::new(), &url).await {
            Err(ReleaseHandlingError::Generic(msg)) => {
                assert!(
                    msg.contains("HTTP error downloading checksums file"),
                    "unexpected message: {msg}"
                );
                assert!(msg.contains("404"), "unexpected message: {msg}");
            }
            other => panic!("expected a Generic error, got {other:?}"),
        }
        mock.assert_async().await;
    }

    #[tokio::test]
    async fn download_rejects_oversized_file_when_content_length_is_known() {
        let mut server = mockito::Server::new_async().await;
        let oversized = vec![b'a'; (MAX_CHECKSUM_FILE_SIZE + 1) as usize];
        let mock = server
            .mock("GET", "/too-big")
            .with_status(200)
            .with_body(oversized)
            .create_async()
            .await;
        let url = format!("{}/too-big", server.url());

        let result = download_checksum_file(&reqwest::Client::new(), &url).await;

        expect_invalid_data(result, "exceeds limit");
        mock.assert_async().await;
    }

    #[tokio::test]
    async fn download_rejects_oversized_streamed_file() {
        let mut server = mockito::Server::new_async().await;
        // Chunked responses have no content-length, so the limit must be
        // enforced while accumulating the stream.
        let mock = serve_chunked(
            &mut server,
            "/too-big",
            vec![b'a'; (MAX_CHECKSUM_FILE_SIZE + 1) as usize],
        )
        .await;
        let url = format!("{}/too-big", server.url());

        let result = download_checksum_file(&reqwest::Client::new(), &url).await;

        expect_invalid_data(result, "exceeded limit during download");
        mock.assert_async().await;
    }

    #[tokio::test]
    async fn download_accepts_streamed_file_at_the_size_limit() -> Result<(), ReleaseHandlingError>
    {
        let mut server = mockito::Server::new_async().await;
        // A file of exactly MAX_CHECKSUM_FILE_SIZE bytes is accepted.
        let body = vec![b'a'; MAX_CHECKSUM_FILE_SIZE as usize];
        let mock = serve_chunked(&mut server, "/at-limit", body.clone()).await;
        let url = format!("{}/at-limit", server.url());

        let content = download_checksum_file(&reqwest::Client::new(), &url).await?;

        assert_eq!(content.into_bytes(), body);
        mock.assert_async().await;
        Ok(())
    }

    #[tokio::test]
    async fn download_rejects_non_utf8_content() {
        let mut server = mockito::Server::new_async().await;
        let mock = server
            .mock("GET", "/binary")
            .with_status(200)
            .with_body(vec![0xff, 0xfe, 0xfa])
            .create_async()
            .await;
        let url = format!("{}/binary", server.url());

        let result = download_checksum_file(&reqwest::Client::new(), &url).await;

        expect_invalid_data(result, "not valid UTF-8");
        mock.assert_async().await;
    }

    #[tokio::test]
    async fn download_reports_request_errors() {
        // No server is started: nothing listens on this port.
        let url = "http://127.0.0.1:1/checksums";

        match download_checksum_file(&reqwest::Client::new(), url).await {
            Err(ReleaseHandlingError::Generic(msg)) => assert!(
                msg.contains("Failed to download checksums file"),
                "unexpected message: {msg}"
            ),
            other => panic!("expected a Generic error, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn index_collects_checksums_from_all_urls() -> Result<(), ReleaseHandlingError> {
        let mut server = mockito::Server::new_async().await;
        let mock_sha256 = server
            .mock("GET", "/sha256sums.txt")
            .with_status(200)
            .with_body(format!("{SHA256_HEX}  app.tar.gz\n"))
            .create_async()
            .await;
        let mock_sha512 = server
            .mock("GET", "/sha512sums.txt")
            .with_status(200)
            .with_body(format!(
                "{SHA512_HEX}  app.tar.gz.sig\n{SHA256_HEX}  readme.txt\n"
            ))
            .create_async()
            .await;
        let urls = urls_for(&server, &["/sha256sums.txt", "/sha512sums.txt"]);

        let index = index_from_shasums_urls(&reqwest::Client::new(), &urls).await?;

        assert_eq!(index.version, 1);

        // Checksums are downloaded in parallel, so entries are not ordered.
        let mut published = index.published_files;
        published.sort_by(|left, right| left.file_name.cmp(&right.file_name));

        let expected = vec![
            FileChecksum {
                file_name: "app.tar.gz".to_string(),
                algo: HashAlgorithm::Sha256,
                source: urls[0].to_string(),
                source_format: ChecksumSourceFormat::ShaSum,
                hash: SHA256_HEX.to_string(),
            },
            FileChecksum {
                file_name: "app.tar.gz.sig".to_string(),
                algo: HashAlgorithm::Sha512,
                source: urls[1].to_string(),
                source_format: ChecksumSourceFormat::ShaSum,
                hash: SHA512_HEX.to_string(),
            },
            FileChecksum {
                file_name: "readme.txt".to_string(),
                algo: HashAlgorithm::Sha256,
                source: urls[1].to_string(),
                source_format: ChecksumSourceFormat::ShaSum,
                hash: SHA256_HEX.to_string(),
            },
        ];
        assert_eq!(published, expected);

        mock_sha256.assert_async().await;
        mock_sha512.assert_async().await;
        Ok(())
    }

    #[tokio::test]
    async fn index_without_urls_is_empty() -> Result<(), ReleaseHandlingError> {
        let index = index_from_shasums_urls(&reqwest::Client::new(), &Vec::<Url>::new()).await?;

        assert!(index.published_files.is_empty());
        assert_eq!(index.version, 1);
        Ok(())
    }

    #[tokio::test]
    async fn index_accepts_string_urls() -> Result<(), ReleaseHandlingError> {
        let mut server = mockito::Server::new_async().await;
        let mock = server
            .mock("GET", "/sha256sums.txt")
            .with_status(200)
            .with_body(format!("{SHA256_HEX}  app.tar.gz\n"))
            .create_async()
            .await;
        let url = format!("{}/sha256sums.txt", server.url());
        let urls = [url.as_str()];

        let index = index_from_shasums_urls(&reqwest::Client::new(), &urls).await?;

        let expected = vec![FileChecksum {
            file_name: "app.tar.gz".to_string(),
            algo: HashAlgorithm::Sha256,
            source: url.clone(),
            source_format: ChecksumSourceFormat::ShaSum,
            hash: SHA256_HEX.to_string(),
        }];
        assert_eq!(index.published_files, expected);

        mock.assert_async().await;
        Ok(())
    }

    #[tokio::test]
    async fn index_fails_when_a_string_url_is_invalid() {
        let urls = [String::from("not a url")];

        match index_from_shasums_urls(&reqwest::Client::new(), &urls).await {
            Err(ReleaseHandlingError::UrlParseError(_)) => {}
            Err(other) => panic!("expected a UrlParseError, got {other:?}"),
            Ok(index) => panic!(
                "expected a UrlParseError, got a successful index with {} published files",
                index.published_files.len()
            ),
        }
    }

    #[tokio::test]
    async fn index_fails_when_a_checksum_file_cannot_be_downloaded() {
        let mut server = mockito::Server::new_async().await;
        server
            .mock("GET", "/good")
            .with_status(200)
            .with_body(format!("{SHA256_HEX}  app.tar.gz\n"))
            .create_async()
            .await;
        server
            .mock("GET", "/missing")
            .with_status(404)
            .create_async()
            .await;
        let urls = urls_for(&server, &["/good", "/missing"]);

        match index_from_shasums_urls(&reqwest::Client::new(), &urls).await {
            Err(ReleaseHandlingError::Generic(msg)) => assert!(
                msg.contains("HTTP error downloading checksums file"),
                "unexpected message: {msg}"
            ),
            Err(other) => panic!("expected a Generic error, got {other:?}"),
            Ok(index) => panic!(
                "expected a Generic error, got a successful index with {} published files",
                index.published_files.len()
            ),
        }
    }

    #[tokio::test]
    async fn index_fails_when_a_checksum_file_cannot_be_parsed() {
        let mut server = mockito::Server::new_async().await;
        server
            .mock("GET", "/bad")
            .with_status(200)
            .with_body("this is not a checksum line")
            .create_async()
            .await;
        let urls = urls_for(&server, &["/bad"]);

        match index_from_shasums_urls(&reqwest::Client::new(), &urls).await {
            Err(ReleaseHandlingError::InvalidData(msg)) => assert!(
                msg.contains("Failed to parse checksums file"),
                "unexpected message: {msg}"
            ),
            Err(other) => panic!("expected an InvalidData error, got {other:?}"),
            Ok(index) => panic!(
                "expected an InvalidData error, got a successful index with {} published files",
                index.published_files.len()
            ),
        }
    }
}
