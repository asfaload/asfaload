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
pub async fn index_from_shasums_urls(
    reqwest_client: &reqwest::Client,
    urls: &[Url],
) -> Result<AsfaloadIndex, ReleaseHandlingError> {
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
