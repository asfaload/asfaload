use std::collections::HashMap;
use std::collections::hash_map::Entry;

use features_lib::{
    AsfaloadIndex, ChecksumSourceFormat, IndexValidationError, ParsedChecksum,
    fetch_sequentially_with_cache, new_sequential_cache, parse_checksums as parse_shasum_content,
};
use forge_release::github::get_checksums_from_github_rest_api_answer;

/// Fetch and parse every digest source of the index, once per distinct url.
/// The returned map is keyed by the source url and holds every entry the
/// source provides: keeping only the entries of each published file is
/// validate_index_against_digests' job.
pub async fn extract_parsed_checksums_from_index(
    index: &AsfaloadIndex,
) -> Result<HashMap<String, Vec<ParsedChecksum>>, IndexValidationError> {
    let mut parsed_checksums: HashMap<String, Vec<ParsedChecksum>> = HashMap::new();
    let mut cache = new_sequential_cache();
    for published_file in &index.published_files {
        if let Entry::Vacant(entry) = parsed_checksums.entry(published_file.source.clone()) {
            let body = fetch_sequentially_with_cache(&published_file.source, &mut cache).await?;
            // A byte order mark is not whitespace: strip it before parsing,
            // or it corrupts the first parsed line.
            let content = body.trim_start_matches('\u{feff}');
            // The first occurrence of an url decides the format its content
            // is parsed with.
            let parsed = match published_file.source_format {
                ChecksumSourceFormat::ShaSum => parse_shasum_content(content).map_err(|e| {
                    IndexValidationError::DigestSourceError {
                        url: published_file.source.clone(),
                        reason: e.to_string(),
                    }
                })?,
                ChecksumSourceFormat::GithubRelease => {
                    get_checksums_from_github_rest_api_answer(content).map_err(|e| {
                        IndexValidationError::DigestSourceError {
                            url: published_file.source.clone(),
                            reason: e.to_string(),
                        }
                    })?
                }
            };
            entry.insert(parsed);
        }
    }
    Ok(parsed_checksums)
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

        let parsed = extract_parsed_checksums_from_index(&index).await.unwrap();

        // The whole source content is extracted: keeping only the published
        // file's own entry is validate_index_against_digests' job.
        assert_eq!(parsed.len(), 1);
        let entries = parsed
            .get(&format!("{}/checksums.txt", server.url()))
            .unwrap();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].file_name, "app.bin");
        assert_eq!(entries[0].algo, HashAlgorithm::Sha256);
        assert_eq!(entries[0].hash, SHA256_A);
        assert_eq!(entries[1].file_name, "other.bin");
        assert_eq!(entries[1].hash, SHA256_B);
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

        let parsed = extract_parsed_checksums_from_index(&index).await.unwrap();

        let entries = parsed
            .get(&format!("{}/checksums.txt", server.url()))
            .unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].hash, SHA256_A);
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

        match extract_parsed_checksums_from_index(&index).await {
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

        match extract_parsed_checksums_from_index(&index).await {
            Err(IndexValidationError::DigestDocumentParseError { url, .. }) => {
                assert_eq!(url, source_url);
            }
            other => panic!("Expected DigestSourceParseError, got {other:?}"),
        }
    }

    // A github release API url serves one json document listing every asset
    // with its digest, as "<algo>:<hex>".
    const RELEASE_URL_PATH: &str = "/repos/acme/tool/releases/123";

    // The api mocks listen on 127.0.0.2: with the forge-url test-utils feature
    // it is the github api test host, while 127.0.0.1 stands for repo urls.
    async fn api_server() -> mockito::Server {
        mockito::Server::new_with_opts_async(mockito::ServerOpts {
            host: "127.0.0.2",
            ..Default::default()
        })
        .await
    }

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
        let mut server = api_server().await;
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

        let parsed = extract_parsed_checksums_from_index(&index).await.unwrap();

        // The whole release content is extracted: assets without digest or
        // with an unsupported algorithm are skipped, but keeping only the
        // published file's own entry is validate_index_against_digests' job.
        assert_eq!(parsed.len(), 1);
        let entries = parsed
            .get(&format!("{}{RELEASE_URL_PATH}", server.url()))
            .unwrap();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].file_name, "app.bin");
        assert_eq!(entries[0].algo, HashAlgorithm::Sha256);
        assert_eq!(entries[0].hash, SHA256_A);
        assert_eq!(entries[1].file_name, "lib.tar");
        assert_eq!(entries[1].algo, HashAlgorithm::Sha512);
    }

    #[tokio::test]
    async fn release_source_with_leading_bom_parses() {
        let mut server = api_server().await;
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

        let parsed = extract_parsed_checksums_from_index(&index).await.unwrap();

        let entries = parsed
            .get(&format!("{}{RELEASE_URL_PATH}", server.url()))
            .unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].hash, SHA256_A);
    }

    #[tokio::test]
    async fn release_source_malformed_json_names_source_url() {
        let mut server = api_server().await;
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

        match extract_parsed_checksums_from_index(&index).await {
            Err(IndexValidationError::DigestDocumentParseError { url, .. }) => {
                assert_eq!(url, source_url);
            }
            other => panic!("Expected DigestSourceParseError, got {other:?}"),
        }
    }

    // All files of a github release share the release api url, so it must be
    // fetched once for the whole index, not once per published file.
    #[tokio::test]
    async fn release_source_shared_by_files_is_fetched_once() {
        let mut server = api_server().await;
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

        let parsed = extract_parsed_checksums_from_index(&index).await.unwrap();

        // One source url in the map, holding every asset of the release.
        assert_eq!(parsed.len(), 1);
        assert_eq!(
            parsed
                .get(&format!("{}{RELEASE_URL_PATH}", server.url()))
                .unwrap()
                .len(),
            2
        );
        mock.assert_async().await;
    }
}
