use features_lib::{
    AsfaloadIndex, ChecksumSourceFormat, IndexValidationError, ParsedChecksum,
    fetch_sequentially_with_cache, new_sequential_cache, parse_checksums as parse_shasum_content,
};

pub async fn parse_checksums(
    index: AsfaloadIndex,
) -> Result<Vec<ParsedChecksum>, IndexValidationError> {
    let mut checksums = Vec::new();
    let mut cache = new_sequential_cache();
    for published_file in index.published_files {
        match published_file.source_format {
            ChecksumSourceFormat::ShaSum => {
                // A byte order mark is not whitespace: strip it before parsing,
                // or it corrupts the first parsed line.
                let body =
                    fetch_sequentially_with_cache(&published_file.source, &mut cache).await?;
                let content = body.trim_start_matches('\u{feff}');
                checksums.extend(
                    parse_shasum_content(content)?
                        .into_iter()
                        .filter(|checksum| {
                            checksum.file_name == published_file.file_name
                                && checksum.algo == published_file.algo
                        }),
                );
            }
            ChecksumSourceFormat::GithubRelease => {}
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
