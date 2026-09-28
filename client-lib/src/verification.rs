use crate::types::ComputedHash;
use crate::{AsfaloadLibResult, ClientLibError};
use features_lib::{
    AsfaloadHashes, AsfaloadIndex, AsfaloadPublicKeyTrait, AsfaloadPublicKeys, AsfaloadSignatures,
    SignersConfig,
    aggregate_signature_helpers::{check_groups, get_individual_signatures_from_bytes},
};
use std::collections::HashMap;

pub fn verify_signatures(
    signatures_content: &[u8],
    signers_config: &SignersConfig,
    data: &AsfaloadHashes,
) -> AsfaloadLibResult<(usize, usize)> {
    let artifact_groups = signers_config.artifact_signers();
    if artifact_groups.is_empty() {
        return Err(ClientLibError::MissingArtifactSigners);
    }

    let (typed_signatures, invalid_count) = collect_valid_signatures(signatures_content, data)?;

    let is_complete = check_groups(artifact_groups, &typed_signatures, data);

    if !is_complete {
        return Err(ClientLibError::SignatureThresholdNotMet {
            required: artifact_groups.len(),
            found: typed_signatures.len(),
        });
    }

    let valid_count = typed_signatures.len();
    Ok((valid_count, invalid_count))
}

/// Parse a signatures envelope and verify each signature over `data`.
/// Returns the valid signatures keyed by public key, plus the count of
/// signatures that failed verification.
pub(crate) fn collect_valid_signatures(
    signatures_content: &[u8],
    data: &AsfaloadHashes,
) -> AsfaloadLibResult<(HashMap<AsfaloadPublicKeys, AsfaloadSignatures>, usize)> {
    let mut typed_signatures: HashMap<AsfaloadPublicKeys, AsfaloadSignatures> = HashMap::new();
    let mut invalid_count = 0;

    let parsed_signatures = get_individual_signatures_from_bytes(signatures_content)
        .map_err(|e| ClientLibError::SignaturesParseError(e.to_string()))?;

    for (pubkey, signature) in parsed_signatures {
        if pubkey.verify(&signature, data).is_err() {
            invalid_count += 1;
            continue;
        }

        typed_signatures.insert(pubkey, signature);
    }

    Ok((typed_signatures, invalid_count))
}

/// Get expected hash for a file from the index as a `ComputedHash`.
/// Returns an error if the algorithm is unsupported (Sha1, Md5).
pub fn get_file_hash_info(
    index: &AsfaloadIndex,
    filename: &str,
) -> AsfaloadLibResult<ComputedHash> {
    let file_entry = index
        .published_files
        .iter()
        .find(|f| f.file_name == filename)
        .ok_or_else(|| ClientLibError::FileNotInIndex(filename.to_string()))?;

    ComputedHash::from_algorithm_and_hex(file_entry.algo.clone(), file_entry.hash.clone())
}

pub fn verify_file_hash(expected: &ComputedHash, computed: &ComputedHash) -> AsfaloadLibResult<()> {
    if expected.algorithm() != computed.algorithm() {
        return Err(ClientLibError::HashAlgorithmMismatch {
            expected: expected.algorithm(),
            computed: computed.algorithm(),
        });
    }

    if expected != computed {
        return Err(ClientLibError::HashMismatch {
            expected: expected.hex_value().to_lowercase(),
            computed: computed.hex_value().to_lowercase(),
        });
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use features_lib::HashAlgorithm;

    // --- verify_file_hash tests ---

    #[test]
    fn verify_file_hash_sha256_matching() {
        let hash = ComputedHash::Sha256("abc123def456".to_string());
        let result = verify_file_hash(&hash, &hash);
        assert!(result.is_ok());
    }

    #[test]
    fn verify_file_hash_sha512_matching() {
        let hash = ComputedHash::Sha512("abc123def456".to_string());
        let result = verify_file_hash(&hash, &hash);
        assert!(result.is_ok());
    }

    #[test]
    fn verify_file_hash_case_insensitive() {
        let a = ComputedHash::Sha256("ABC123DEF".to_string());
        let b = ComputedHash::Sha256("abc123def".to_string());
        let result = verify_file_hash(&a, &b);
        assert!(result.is_ok());
    }

    #[test]
    fn verify_file_hash_mismatch() {
        let a = ComputedHash::Sha256("abc123".to_string());
        let b = ComputedHash::Sha256("def456".to_string());
        match verify_file_hash(&a, &b) {
            Err(ClientLibError::HashMismatch { expected, computed }) => {
                assert_eq!(expected, "abc123");
                assert_eq!(computed, "def456");
            }
            Err(e) => panic!("Expected HashMismatch, got: {e:?}"),
            Ok(_) => panic!("Expected HashMismatch error, got Ok"),
        }
    }

    #[test]
    fn verify_file_hash_algorithm_mismatch() {
        let expected = ComputedHash::Sha256("abc123".to_string());
        let computed = ComputedHash::Sha512("abc123".to_string());
        match verify_file_hash(&expected, &computed) {
            Err(ClientLibError::HashAlgorithmMismatch { .. }) => {}
            Err(e) => panic!("Expected HashAlgorithmMismatch, got: {e:?}"),
            Ok(_) => panic!("Expected HashAlgorithmMismatch error, got Ok"),
        }
    }

    // --- get_file_hash_info tests ---

    #[test]
    fn get_file_hash_info_sha256() {
        use chrono::Utc;
        use features_lib::{AsfaloadIndex, ChecksumSourceFormat, FileChecksum};

        let index = AsfaloadIndex {
            mirrored_on: Utc::now(),
            published_on: Utc::now(),
            version: 1,
            published_files: vec![FileChecksum {
                file_name: "test.txt".to_string(),
                algo: HashAlgorithm::Sha256,
                source: "http://example.com/test.txt".to_string(),
                source_format: ChecksumSourceFormat::ShaSum,
                hash: "abc123def456".to_string(),
            }],
        };

        match get_file_hash_info(&index, "test.txt") {
            Ok(ComputedHash::Sha256(hex)) => assert_eq!(hex, "abc123def456"),
            Ok(other) => panic!("Expected Sha256 variant, got: {other}"),
            Err(e) => panic!("Expected Ok, got: {e:?}"),
        }
    }

    #[test]
    fn get_file_hash_info_unsupported_algo() {
        use chrono::Utc;
        use features_lib::{AsfaloadIndex, ChecksumSourceFormat, FileChecksum};

        let index = AsfaloadIndex {
            mirrored_on: Utc::now(),
            published_on: Utc::now(),
            version: 1,
            published_files: vec![FileChecksum {
                file_name: "test.txt".to_string(),
                algo: HashAlgorithm::Sha1,
                source: "http://example.com/test.txt".to_string(),
                source_format: ChecksumSourceFormat::ShaSum,
                hash: "old_hash".to_string(),
            }],
        };

        match get_file_hash_info(&index, "test.txt") {
            Err(ClientLibError::UnsupportedHashAlgorithm(HashAlgorithm::Sha1)) => {}
            Err(e) => panic!("Expected UnsupportedHashAlgorithm(Sha1), got: {e:?}"),
            Ok(v) => panic!("Expected error, got: {v}"),
        }
    }
}
