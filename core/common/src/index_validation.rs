use crate::{checksums_parser::ChecksumParseError, http::FetchError};

#[derive(Debug, thiserror::Error)]
pub enum IndexValidationError {
    #[error("The source of the digest was invalid ({0})")]
    InvalidSource(String),
    #[error("Couldn't retrieve file: {0}")]
    FetchError(#[from] FetchError),
    #[error("Couldn't parse checksum: {0}")]
    ChecksumParseError(#[from] ChecksumParseError),
    #[error(
        "A digest mismatch was found: Index has value {in_index} but source has {in_source}. Source was found at {origin}"
    )]
    DigestMismatch {
        in_index: String,
        in_source: String,
        origin: String,
    },
}

// This module covers usage of Asfaload for file downloads authentication.
pub mod file_auth {
    use std::collections::HashMap;
    use std::collections::hash_map::Entry;

    use crate::{
        checksums_parser::{ParsedChecksum, parse_checksums},
        http::fetch_with_retry,
        index_types::AsfaloadIndex,
        index_validation::IndexValidationError,
    };

    // Validates that all digests present in the AsfaloadIndex can be found in the digests passed.
    // It does not ensure that all digests found in sources are present in the index.
    // The key of the digests HashMap is the url where the digests file can be found.
    pub(crate) async fn validate_index_against_digests(
        index: AsfaloadIndex,
        digests: HashMap<String, Vec<ParsedChecksum>>,
    ) -> Result<(), IndexValidationError> {
        for published_file in index.published_files {
            let source_url = published_file.source;
            let source = digests
                .get(&source_url)
                .ok_or(IndexValidationError::InvalidSource(format!(
                    "Source {} was not retrieved",
                    source_url
                )))?;
            // Only keep entry matching filename and digest computation algorithm
            let checksums: Vec<ParsedChecksum> = source
                .iter()
                .filter(|line| {
                    line.file_name == published_file.file_name && line.algo == published_file.algo
                })
                .cloned()
                .collect();
            // Files produced by sha256sum et al are not expected to contain duplicates
            match &checksums[..] {
                [checksum] => {
                    if published_file.hash != checksum.hash {
                        // If we detect a digest mismatch, we report it as an error
                        return Err(IndexValidationError::DigestMismatch {
                            in_index: published_file.hash,
                            in_source: checksum.hash.clone(),
                            origin: source_url,
                        });
                    }
                }
                _ => {
                    return Err(IndexValidationError::InvalidSource(format!(
                        "Found {} checksums for {}, expected exactly 1",
                        checksums.len(),
                        published_file.file_name
                    )));
                }
            }
        }
        Ok(())
    }
    /// Validates all digests in the asfaload index against their original source.
    // Could be improved as we download all sources before validating. This is not
    // a big problem as most indexes will have one source.
    pub async fn validate_index_hash_files(
        index: AsfaloadIndex,
    ) -> Result<(), IndexValidationError> {
        let mut cached_checksums: HashMap<String, Vec<ParsedChecksum>> = HashMap::new();
        for published_file in &index.published_files {
            // get the digest values found in the source for this published_file
            let source_url = &published_file.source;
            if let Entry::Vacant(entry) = cached_checksums.entry(source_url.into()) {
                let parsed = parse_checksums(&fetch_with_retry(source_url).await?)?;
                entry.insert(parsed);
            }
        }
        validate_index_against_digests(index, cached_checksums).await
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use anyhow::Result;
    use chrono::Utc;

    use super::{
        IndexValidationError,
        file_auth::{validate_index_against_digests, validate_index_hash_files},
    };
    use crate::{
        checksums_parser::ParsedChecksum,
        index_types::{AsfaloadIndex, FileChecksum, HashAlgorithm},
    };

    // Two distinct, valid SHA-256 hex digests so a mismatch is detectable.
    const SHA256_A: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const SHA256_B: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    const URL_A: &str = "https://example.test/checksums-a.txt";
    const URL_B: &str = "https://example.test/checksums-b.txt";

    fn file_checksum(
        file_name: &str,
        algo: HashAlgorithm,
        source: &str,
        hash: &str,
    ) -> FileChecksum {
        FileChecksum {
            file_name: file_name.to_string(),
            algo,
            source: source.to_string(),
            hash: hash.to_string(),
        }
    }

    fn index_with(files: Vec<FileChecksum>) -> AsfaloadIndex {
        AsfaloadIndex {
            mirrored_on: Utc::now(),
            published_on: Utc::now(),
            version: 1,
            published_files: files,
        }
    }

    fn parsed(file_name: &str, algo: HashAlgorithm, hash: &str) -> ParsedChecksum {
        ParsedChecksum {
            file_name: file_name.to_string(),
            algo,
            hash: hash.to_string(),
        }
    }

    fn digests_of(
        entries: Vec<(&str, Vec<ParsedChecksum>)>,
    ) -> HashMap<String, Vec<ParsedChecksum>> {
        entries
            .into_iter()
            .map(|(url, checksums)| (url.to_string(), checksums))
            .collect()
    }

    #[tokio::test]
    async fn validates_matching_digest() -> Result<()> {
        let index = index_with(vec![file_checksum(
            "app.bin",
            HashAlgorithm::Sha256,
            URL_A,
            SHA256_A,
        )]);
        let digests = digests_of(vec![(
            URL_A,
            vec![parsed("app.bin", HashAlgorithm::Sha256, SHA256_A)],
        )]);

        validate_index_against_digests(index, digests).await?;
        Ok(())
    }

    #[tokio::test]
    async fn reports_digest_mismatch_with_location() {
        let index = index_with(vec![file_checksum(
            "app.bin",
            HashAlgorithm::Sha256,
            URL_A,
            SHA256_A,
        )]);
        let digests = digests_of(vec![(
            URL_A,
            vec![parsed("app.bin", HashAlgorithm::Sha256, SHA256_B)],
        )]);

        match validate_index_against_digests(index, digests).await {
            Err(IndexValidationError::DigestMismatch {
                in_index,
                in_source,
                origin,
            }) => {
                assert_eq!(in_index, SHA256_A);
                assert_eq!(in_source, SHA256_B);
                assert_eq!(origin, URL_A);
            }
            Err(e) => panic!("Expected DigestMismatch but got {}", e),
            Ok(_) => panic!("Expected DigestMismatch error, got Ok value!"),
        }
    }

    #[tokio::test]
    async fn reports_missing_source_with_its_url() {
        let index = index_with(vec![file_checksum(
            "app.bin",
            HashAlgorithm::Sha256,
            URL_A,
            SHA256_A,
        )]);
        // The digests map contains another source, not URL_A
        let digests = digests_of(vec![(
            URL_B,
            vec![parsed("app.bin", HashAlgorithm::Sha256, SHA256_A)],
        )]);

        match validate_index_against_digests(index, digests).await {
            Err(IndexValidationError::InvalidSource(msg)) => {
                assert!(
                    msg.contains(URL_A),
                    "error should name the missing URL, got: {}",
                    msg
                );
            }
            Err(e) => panic!("Expected InvalidSource but got {}", e),
            Ok(_) => panic!("Expected InvalidSource error, got Ok value!"),
        }
    }

    #[tokio::test]
    async fn reports_zero_checksums_when_file_absent_from_source() {
        let index = index_with(vec![file_checksum(
            "app.bin",
            HashAlgorithm::Sha256,
            URL_A,
            SHA256_A,
        )]);
        // Source lists only an unrelated file
        let digests = digests_of(vec![(
            URL_A,
            vec![parsed("other.bin", HashAlgorithm::Sha256, SHA256_A)],
        )]);

        match validate_index_against_digests(index, digests).await {
            Err(IndexValidationError::InvalidSource(msg)) => {
                assert!(
                    msg.contains("Found 0 checksums"),
                    "expected zero-matches message, got: {}",
                    msg
                );
                assert!(msg.contains("app.bin"));
            }
            Err(e) => panic!("Expected InvalidSource but got {}", e),
            Ok(_) => panic!("Expected InvalidSource error, got Ok value!"),
        }
    }

    #[tokio::test]
    async fn reports_zero_checksums_when_algorithm_differs() {
        // Same filename and hash, but the source checksum was computed with
        // sha512 while the index declares sha256: the algo filter must reject
        // the match.
        let sha512_hash = "cc".repeat(64);
        let index = index_with(vec![file_checksum(
            "app.bin",
            HashAlgorithm::Sha256,
            URL_A,
            &sha512_hash,
        )]);
        let digests = digests_of(vec![(
            URL_A,
            vec![parsed("app.bin", HashAlgorithm::Sha512, &sha512_hash)],
        )]);

        match validate_index_against_digests(index, digests).await {
            Err(IndexValidationError::InvalidSource(msg)) => {
                assert!(
                    msg.contains("Found 0 checksums"),
                    "expected zero-matches message, got: {}",
                    msg
                );
            }
            Err(e) => panic!("Expected InvalidSource but got {}", e),
            Ok(_) => panic!("Expected InvalidSource error, got Ok value!"),
        }
    }

    #[tokio::test]
    async fn reports_duplicate_checksums_in_source() {
        let index = index_with(vec![file_checksum(
            "app.bin",
            HashAlgorithm::Sha256,
            URL_A,
            SHA256_A,
        )]);
        // sha256sum output is not expected to contain duplicate entries;
        // two matching lines must be reported, not silently consumed.
        let digests = digests_of(vec![(
            URL_A,
            vec![
                parsed("app.bin", HashAlgorithm::Sha256, SHA256_A),
                parsed("app.bin", HashAlgorithm::Sha256, SHA256_A),
            ],
        )]);

        match validate_index_against_digests(index, digests).await {
            Err(IndexValidationError::InvalidSource(msg)) => {
                assert!(
                    msg.contains("Found 2 checksums"),
                    "expected duplicates message, got: {}",
                    msg
                );
            }
            Err(e) => panic!("Expected InvalidSource but got {}", e),
            Ok(_) => panic!("Expected InvalidSource error, got Ok value!"),
        }
    }

    #[tokio::test]
    async fn validates_multiple_files_across_sources() -> Result<()> {
        let index = index_with(vec![
            file_checksum("app.bin", HashAlgorithm::Sha256, URL_A, SHA256_A),
            file_checksum("lib.tar", HashAlgorithm::Sha256, URL_B, SHA256_B),
        ]);
        let digests = digests_of(vec![
            (
                URL_A,
                vec![
                    parsed("app.bin", HashAlgorithm::Sha256, SHA256_A),
                    // extra entries in sources are tolerated
                    parsed("unrelated.bin", HashAlgorithm::Sha256, SHA256_B),
                ],
            ),
            (
                URL_B,
                vec![parsed("lib.tar", HashAlgorithm::Sha256, SHA256_B)],
            ),
        ]);

        validate_index_against_digests(index, digests).await?;
        Ok(())
    }

    // Builds the body of a sha256sum-format checksums file.
    fn checksums_body(pairs: &[(&str, &str)]) -> String {
        pairs
            .iter()
            .map(|(hash, file_name)| format!("{}  {}", hash, file_name))
            .collect::<Vec<_>>()
            .join("\n")
    }

    #[tokio::test]
    async fn fetched_source_validates_matching_digest() -> Result<()> {
        let mut server = mockito::Server::new_async().await;
        let _m = server
            .mock("GET", "/checksums.txt")
            .with_status(200)
            .with_body(checksums_body(&[(SHA256_A, "app.bin")]))
            .create_async()
            .await;

        let source = format!("{}/checksums.txt", server.url());
        let index = index_with(vec![file_checksum(
            "app.bin",
            HashAlgorithm::Sha256,
            &source,
            SHA256_A,
        )]);

        validate_index_hash_files(index).await?;
        Ok(())
    }

    #[tokio::test]
    async fn each_file_is_validated_against_its_own_source() -> Result<()> {
        let mut server = mockito::Server::new_async().await;
        let _m1 = server
            .mock("GET", "/checksums-a.txt")
            .with_status(200)
            .with_body(checksums_body(&[(SHA256_A, "app.bin")]))
            .create_async()
            .await;
        let _m2 = server
            .mock("GET", "/checksums-b.txt")
            .with_status(200)
            .with_body(checksums_body(&[(SHA256_B, "lib.tar")]))
            .create_async()
            .await;

        let index = index_with(vec![
            file_checksum(
                "app.bin",
                HashAlgorithm::Sha256,
                &format!("{}/checksums-a.txt", server.url()),
                SHA256_A,
            ),
            file_checksum(
                "lib.tar",
                HashAlgorithm::Sha256,
                &format!("{}/checksums-b.txt", server.url()),
                SHA256_B,
            ),
        ]);

        validate_index_hash_files(index).await?;
        Ok(())
    }
}
