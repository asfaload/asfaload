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
