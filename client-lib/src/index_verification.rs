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

pub async fn extract_parsed_checksums_from_index(
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

        let parsed = extract_parsed_checksums_from_index(index).await.unwrap();

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

        let parsed = extract_parsed_checksums_from_index(index).await.unwrap();

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

        match extract_parsed_checksums_from_index(index).await {
            Err(IndexValidationError::FetchError(_)) => {}
            other => panic!("Expected FetchError, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn shasum_source_parse_error_names_source_url() {
        let mut server = mockito::Server::new_async().await;
        let _m = server
            .mock("GET", "/checksums.txt")
            .with_status(200)
            .with_body("not-a-valid-checksum-line")
            .create_async()
            .await;
        let source_url = format!("{}/checksums.txt", server.url());
        let index = index_with_source_format(ChecksumSourceFormat::ShaSum, source_url.clone());

        match extract_parsed_checksums_from_index(index).await {
            Err(IndexValidationError::DigestSourceParseError { url, .. }) => {
                assert_eq!(url, source_url);
            }
            other => panic!("Expected DigestSourceParseError, got {other:?}"),
        }
    }

    // A github release API url serves one json document listing every asset
    // with its digest, as "<algo>:<hex>".
    const RELEASE_URL_PATH: &str = "/repos/acme/tool/releases/123";

    fn release_body(entries: &[(&str, Option<&str>)]) -> String {
        let assets: Vec<String> = entries
            .iter()
            .map(|(name, digest)| match digest {
                Some(d) => format!(r#"{{"name":"{name}","digest":"{d}"}}"#),
                None => format!(r#"{{"name":"{name}","digest":null}}"#),
            })
            .collect();
        format!(
            r#"{{"url":"the-release-url","assets":[{}]}}"#,
            assets.join(",")
        )
    }

    fn index_with_files(
        source_format: ChecksumSourceFormat,
        source_url: String,
        files: &[(&str, HashAlgorithm, &str)],
    ) -> AsfaloadIndex {
        AsfaloadIndex {
            mirrored_on: chrono::Utc::now(),
            published_on: chrono::Utc::now(),
            version: 1,
            published_files: files
                .iter()
                .map(|(file_name, algo, hash)| FileChecksum {
                    file_name: file_name.to_string(),
                    algo: algo.clone(),
                    source: source_url.clone(),
                    source_format: source_format.clone(),
                    hash: hash.to_string(),
                })
                .collect(),
        }
    }

    #[tokio::test]
    async fn release_source_parses_entry_of_matching_published_file() {
        let mut server = mockito::Server::new_async().await;
        let _m = server
            .mock("GET", RELEASE_URL_PATH)
            .with_status(200)
            .with_body(release_body(&[
                ("app.bin", Some("sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")),
                ("lib.tar", Some("sha512:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")),
                ("unsigned.bin", None),
            ]))
            .create_async()
            .await;
        let index = index_with_files(
            ChecksumSourceFormat::GithubRelease,
            format!("{}{RELEASE_URL_PATH}", server.url()),
            &[("app.bin", HashAlgorithm::Sha256, SHA256_A)],
        );

        let parsed = extract_parsed_checksums_from_index(index).await.unwrap();

        // Only the published file's own sha256 entry is kept: assets with
        // other algorithms or without digest are not part of this index.
        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed[0].file_name, "app.bin");
        assert_eq!(parsed[0].algo, HashAlgorithm::Sha256);
        assert_eq!(parsed[0].hash, SHA256_A);
    }

    #[tokio::test]
    async fn release_source_with_leading_bom_parses() {
        let mut server = mockito::Server::new_async().await;
        let _m = server
            .mock("GET", RELEASE_URL_PATH)
            .with_status(200)
            .with_body(format!(
                "\u{feff}{}",
                release_body(&[(
                    "app.bin",
                    Some("sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
                )])
            ))
            .create_async()
            .await;
        let index = index_with_files(
            ChecksumSourceFormat::GithubRelease,
            format!("{}{RELEASE_URL_PATH}", server.url()),
            &[("app.bin", HashAlgorithm::Sha256, SHA256_A)],
        );

        let parsed = extract_parsed_checksums_from_index(index).await.unwrap();

        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed[0].hash, SHA256_A);
    }

    #[tokio::test]
    async fn release_source_malformed_json_names_source_url() {
        let mut server = mockito::Server::new_async().await;
        let _m = server
            .mock("GET", RELEASE_URL_PATH)
            .with_status(200)
            .with_body("not a release response")
            .create_async()
            .await;
        let source_url = format!("{}{RELEASE_URL_PATH}", server.url());
        let index = index_with_files(
            ChecksumSourceFormat::GithubRelease,
            source_url.clone(),
            &[("app.bin", HashAlgorithm::Sha256, SHA256_A)],
        );

        match extract_parsed_checksums_from_index(index).await {
            Err(IndexValidationError::DigestSourceParseError { url, .. }) => {
                assert_eq!(url, source_url);
            }
            other => panic!("Expected DigestSourceParseError, got {other:?}"),
        }
    }

    // All files of a github release share the release api url, so it must be
    // fetched once for the whole index, not once per published file.
    #[tokio::test]
    async fn release_source_shared_by_files_is_fetched_once() {
        let mut server = mockito::Server::new_async().await;
        // Panics on assert if hit any other number of times than once.
        let mock = server
            .mock("GET", RELEASE_URL_PATH)
            .with_status(200)
            .with_body(release_body(&[
                (
                    "app.bin",
                    Some("sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
                ),
                (
                    "lib.tar",
                    Some("sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"),
                ),
            ]))
            .expect(1)
            .create_async()
            .await;
        let index = index_with_files(
            ChecksumSourceFormat::GithubRelease,
            format!("{}{RELEASE_URL_PATH}", server.url()),
            &[
                ("app.bin", HashAlgorithm::Sha256, SHA256_A),
                ("lib.tar", HashAlgorithm::Sha256, SHA256_B),
            ],
        );

        let parsed = extract_parsed_checksums_from_index(index).await.unwrap();

        assert_eq!(parsed.len(), 2);
        mock.assert_async().await;
    }
}
