use features_lib::{
    AsfaloadIndex, ChecksumSourceFormat, HashAlgorithm, IndexValidationError, ParsedChecksum,
    fetch_sequentially_with_cache, new_sequential_cache, parse_checksums as parse_shasum_content,
};

// Minimal shape of a github release api response ignoring irrelevant fields.
#[derive(serde::Deserialize)]
struct GithubReleaseResponse {
    assets: Vec<GithubReleaseAsset>,
}

#[derive(serde::Deserialize)]
struct GithubReleaseAsset {
    name: String,
    digest: Option<String>,
}

// Extract the digests of a github release api response, skipping assets
// without digest or with an algorithm we cannot record in an index.
fn parse_github_rest_api_answer(
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

pub async fn parse_checksums(
    index: AsfaloadIndex,
) -> Result<Vec<ParsedChecksum>, IndexValidationError> {
    let mut checksums = Vec::new();
    let mut cache = new_sequential_cache();
    for published_file in index.published_files {
        // A byte order mark is not whitespace: strip it before parsing,
        // or it corrupts the first parsed line.
        let body = fetch_sequentially_with_cache(&published_file.source, &mut cache).await?;
        let content = body.trim_start_matches('\u{feff}');
        match published_file.source_format {
            ChecksumSourceFormat::ShaSum => {
                checksums.extend(
                    parse_shasum_content(content)
                        .map_err(|e| IndexValidationError::DigestSourceParseError {
                            url: published_file.source.clone(),
                            reason: e.to_string(),
                        })?
                        .into_iter()
                        .filter(|checksum| {
                            checksum.file_name == published_file.file_name
                                && checksum.algo == published_file.algo
                        }),
                );
            }
            ChecksumSourceFormat::GithubRelease => {
                let source_digests = parse_github_rest_api_answer(content, &published_file.source)?;
                checksums.extend(source_digests.into_iter().filter(|checksum| {
                    checksum.file_name == published_file.file_name
                        && checksum.algo == published_file.algo
                }));
            }
        }
    }
    Ok(checksums)
}

#[cfg(test)]
mod tests {
    use super::*;
    use features_lib::{FileChecksum, HashAlgorithm, IndexValidationError};

    const SHA256_A: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const SHA256_B: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

    // An index with one published file whose digest source is served by the
    // mockito server. The recorded hash is irrelevant to parsing.
    fn index_with_source_format(
        source_format: ChecksumSourceFormat,
        source_url: String,
    ) -> AsfaloadIndex {
        AsfaloadIndex {
            mirrored_on: chrono::Utc::now(),
            published_on: chrono::Utc::now(),
            version: 1,
            published_files: vec![FileChecksum {
                file_name: "app.bin".to_string(),
                algo: HashAlgorithm::Sha256,
                source: source_url,
                source_format,
                hash: SHA256_A.to_string(),
            }],
        }
    }

    #[tokio::test]
    async fn shasum_source_parses_entry_matching_published_file() {
        let mut server = mockito::Server::new_async().await;
        let _m = server
            .mock("GET", "/checksums.txt")
            .with_status(200)
            .with_body(format!("{SHA256_A}  app.bin\n{SHA256_B}  other.bin"))
            .create_async()
            .await;
        let index = index_with_source_format(
            ChecksumSourceFormat::ShaSum,
            format!("{}/checksums.txt", server.url()),
        );

        let parsed = parse_checksums(index).await.unwrap();

        // Only the published file's own entry is kept, not the whole source.
        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed[0].file_name, "app.bin");
        assert_eq!(parsed[0].algo, HashAlgorithm::Sha256);
        assert_eq!(parsed[0].hash, SHA256_A);
    }

    #[tokio::test]
    async fn shasum_source_with_leading_bom_parses() {
        let mut server = mockito::Server::new_async().await;
        let _m = server
            .mock("GET", "/checksums.txt")
            .with_status(200)
            .with_body(format!("\u{feff}{SHA256_A}  app.bin"))
            .create_async()
            .await;
        let index = index_with_source_format(
            ChecksumSourceFormat::ShaSum,
            format!("{}/checksums.txt", server.url()),
        );

        let parsed = parse_checksums(index).await.unwrap();

        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed[0].hash, SHA256_A);
    }

    #[tokio::test]
    async fn shasum_source_fetch_error_propagates() {
        let mut server = mockito::Server::new_async().await;
        let _m = server
            .mock("GET", "/checksums.txt")
            .with_status(404)
            .create_async()
            .await;
        let index = index_with_source_format(
            ChecksumSourceFormat::ShaSum,
            format!("{}/checksums.txt", server.url()),
        );

        match parse_checksums(index).await {
            Err(IndexValidationError::FetchError(_)) => {}
            other => panic!("Expected FetchError, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn shasum_source_parse_error_propagates() {
        let mut server = mockito::Server::new_async().await;
        let _m = server
            .mock("GET", "/checksums.txt")
            .with_status(200)
            .with_body("not-a-valid-checksum-line")
            .create_async()
            .await;
        let index = index_with_source_format(
            ChecksumSourceFormat::ShaSum,
            format!("{}/checksums.txt", server.url()),
        );

        match parse_checksums(index).await {
            Err(IndexValidationError::ChecksumParseError(_)) => {}
            other => panic!("Expected ChecksumParseError, got {other:?}"),
        }
    }
}
