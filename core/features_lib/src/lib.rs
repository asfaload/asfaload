use std::path::{Path, PathBuf};

pub use common::errors;
use common::fs::names::{find_global_signers_for, pending_signers_file_in_dir};
pub use common::fs::names::{local_signers_path_for, signatures_path_for};
pub use common::{
    ArtifactMarker, FileType, InitialSignersFileMarker, SignedFile, SignersFileMarker,
    errors::SignedFileError,
};
use common::{MetadataFileMarker, RevocationMarker, RevokedArtifactMarker};
pub use common::{SignedFileLoader, SignedFileWithKind};

pub use common::{AsfaloadHashes, sha512_for_content, sha512_for_file, to_posix_json};

pub use common::checksums_parser::ParsedChecksum;
pub use common::checksums_parser::parse_checksums;
pub use common::http::{fetch_sequentially_with_cache, fetch_with_retry, new_sequential_cache};
pub use common::index_types::{AsfaloadIndex, ChecksumSourceFormat, FileChecksum, HashAlgorithm};
pub use common::index_validation::IndexValidationError;
pub use common::index_validation::file_auth::validate_index_against_digests;

use ::constants::PENDING_SUFFIX;
// Re-export traits for users
pub use signatures::keys::AsfaloadKeyPairTrait;
pub use signatures::keys::AsfaloadPublicKeyTrait;
pub use signatures::keys::AsfaloadSecretKeyTrait;
pub use signatures::keys::AsfaloadSignatureTrait;
pub use signatures::keys::KeyFormat;
pub use signatures::keys::asfaload::ASFALOAD_PRIV_PREFIX;
pub use signatures::keys::asfaload::ASFALOAD_PUB_PREFIX;

// Re-export the types directly
pub use signatures::signatures_file::{SignaturesFile, TaggedSignature};
pub use signatures::types::AsfaloadKeyPairs;
pub use signatures::types::AsfaloadPublicKeys;
pub use signatures::types::AsfaloadSecretKeys;
pub use signatures::types::AsfaloadSignatures;

pub use signers_file::activate_signers_file;
pub use signers_file::sign_signers_and_metadata_file;
pub use signers_file::validate_signers_chain_on_disk;
pub use signers_file::{validate_chain, validate_history_transitions};
pub use signers_file_types::revocation::RevocationInfo;
pub use signers_file_types::{
    CurrentSignersInfo, Forge, ForgeOrigin, HistoryEntry, HistoryFile, SignersChain,
    SignersChainEntry, SignersConfigMetadata, SignersConfigOrigin, SignersInfoTrait,
    VerifiedForgeContent,
};
pub use signers_file_types::{SignersConfig, parse_signers_config};

// In this type argument we use AsfaloadPublicKeys and AsfaloadSignatures directly.
// This allows the user of this type to not specify any type arguments.
pub type SignatureWithState = aggregate_signature::SignatureWithState;
pub use aggregate_signature::can_revoke;
pub use aggregate_signature::can_signer_add_signature;

// We define and implement this trait in the user_lib as it depends on traits defined in other crates,
// which we want to avoid in common.
pub trait SignedFileTrait
where
    AsfaloadPublicKeys: AsfaloadPublicKeyTrait<Signature = AsfaloadSignatures>,
    AsfaloadSignatures: AsfaloadSignatureTrait,
{
    fn add_signature(
        &self,
        sig: AsfaloadSignatures,
        pubkey: AsfaloadPublicKeys,
    ) -> Result<SignatureWithState, SignedFileError>;
    fn is_signed(&self) -> Result<bool, SignedFileError>;
}

//SignedFileTrait implementation for initial signers file and signers file updates
//are identical. The way to avoid duplicated code is to:
//* define an empty helper trait implemented by both marker types that lead to
//  the same implementation.
//* implement the SignefFileTrait once for all markers implementing that helper trait.
pub trait SignableFileMarker {}
impl SignableFileMarker for InitialSignersFileMarker {}
impl SignableFileMarker for SignersFileMarker {}

impl<T> SignedFileTrait for SignedFile<T>
where
    T: SignableFileMarker,
    AsfaloadPublicKeys: AsfaloadPublicKeyTrait<Signature = AsfaloadSignatures>,
    AsfaloadSignatures: AsfaloadSignatureTrait,
{
    fn add_signature(
        &self,
        sig: AsfaloadSignatures,
        pubkey: AsfaloadPublicKeys,
    ) -> Result<SignatureWithState, SignedFileError> {
        let agg_sig_with_state = SignatureWithState::load_for_file(&self.location)?;
        if let Some(pending_sig) = agg_sig_with_state.get_pending() {
            pending_sig
                .add_individual_signature(&sig, &pubkey)
                .map_err(|e| e.into())
        } else {
            Err(SignedFileError::AggregateSignatureError(
                common::errors::AggregateSignatureError::SignatureAlreadyComplete,
            ))
        }
    }

    fn is_signed(&self) -> Result<bool, SignedFileError> {
        let r = SignatureWithState::load_for_file(&self.location)?
            .get_complete()
            .is_some();
        Ok(r)
    }
}

impl SignedFileTrait for SignedFile<ArtifactMarker>
where
    AsfaloadPublicKeys: AsfaloadPublicKeyTrait<Signature = AsfaloadSignatures>,
    AsfaloadSignatures: AsfaloadSignatureTrait,
{
    fn add_signature(
        &self,
        sig: AsfaloadSignatures,
        pubkey: AsfaloadPublicKeys,
    ) -> Result<SignatureWithState, SignedFileError> {
        let agg_sig_with_state = SignatureWithState::load_for_file(&self.location)?;
        if let Some(pending_sig) = agg_sig_with_state.get_pending() {
            pending_sig
                .add_individual_signature(&sig, &pubkey)
                .map_err(|e| e.into())
        } else {
            Err(SignedFileError::AggregateSignatureError(
                common::errors::AggregateSignatureError::LogicError(
                    "Signature is already complete; cannot add another signature.".to_string(),
                ),
            ))
        }
    }

    fn is_signed(&self) -> Result<bool, SignedFileError> {
        let r = SignatureWithState::load_for_file(&self.location)?
            .get_complete()
            .is_some();
        Ok(r)
    }
}

impl SignedFileTrait for SignedFile<RevocationMarker>
where
    AsfaloadPublicKeys: AsfaloadPublicKeyTrait<Signature = AsfaloadSignatures>,
    AsfaloadSignatures: AsfaloadSignatureTrait,
{
    fn add_signature(
        &self,
        sig: AsfaloadSignatures,
        pubkey: AsfaloadPublicKeys,
    ) -> Result<SignatureWithState, SignedFileError> {
        // If it is not found, it might be that the revocation was completed and the pending
        // revocation file was moved to its final location for artivation
        let path = PathBuf::from(&self.location);
        // Check if it was completed and moved. This applies to revocation files
        if !path.exists() {
            if let Some(location_str) = self.location.strip_suffix(&format!(".{}", PENDING_SUFFIX))
                && Path::new(location_str).exists()
            {
                return Err(SignedFileError::AggregateSignatureError(
                    common::errors::AggregateSignatureError::SignatureAlreadyComplete,
                ));
            } else {
                return Err(SignedFileError::NotFound(self.location.clone()));
            }
        }
        let agg_sig_with_state = SignatureWithState::load_for_file(&self.location)?;
        if let Some(pending_sig) = agg_sig_with_state.get_pending() {
            pending_sig
                .add_individual_signature(&sig, &pubkey)
                .map_err(|e| e.into())
        } else {
            // This should never happend for a revocation, as the signature subject is moved once
            // the signature is complete.
            Err(SignedFileError::AggregateSignatureError(
                common::errors::AggregateSignatureError::LogicError(
                    "Signature is already complete; cannot add another signature.".to_string(),
                ),
            ))
        }
    }

    fn is_signed(&self) -> Result<bool, SignedFileError> {
        let r = SignatureWithState::load_for_file(&self.location)?
            .get_complete()
            .is_some();
        Ok(r)
    }
}

impl SignedFileTrait for SignedFile<RevokedArtifactMarker>
where
    AsfaloadPublicKeys: AsfaloadPublicKeyTrait<Signature = AsfaloadSignatures>,
    AsfaloadSignatures: AsfaloadSignatureTrait,
{
    fn add_signature(
        &self,
        _sig: AsfaloadSignatures,
        _pubkey: AsfaloadPublicKeys,
    ) -> Result<SignatureWithState, SignedFileError> {
        Err(SignedFileError::Revoked())
    }

    fn is_signed(&self) -> Result<bool, SignedFileError> {
        Ok(false)
    }
}

impl SignedFileTrait for SignedFile<MetadataFileMarker>
where
    AsfaloadPublicKeys: AsfaloadPublicKeyTrait<Signature = AsfaloadSignatures>,
    AsfaloadSignatures: AsfaloadSignatureTrait,
{
    fn add_signature(
        &self,
        sig: AsfaloadSignatures,
        pubkey: AsfaloadPublicKeys,
    ) -> Result<SignatureWithState, SignedFileError> {
        let agg_sig_with_state = SignatureWithState::load_for_file(&self.location)?;
        if let Some(pending_sig) = agg_sig_with_state.get_pending() {
            pending_sig
                .add_individual_signature(&sig, &pubkey)
                .map_err(|e| e.into())
        } else {
            Err(SignedFileError::AggregateSignatureError(
                common::errors::AggregateSignatureError::SignatureAlreadyComplete,
            ))
        }
    }

    fn is_signed(&self) -> Result<bool, SignedFileError> {
        let r = SignatureWithState::load_for_file(&self.location)?
            .get_complete()
            .is_some();
        Ok(r)
    }
}

pub trait SignedFileWithKindTrait
where
    AsfaloadPublicKeys: AsfaloadPublicKeyTrait<Signature = AsfaloadSignatures>,
    AsfaloadSignatures: AsfaloadSignatureTrait,
{
    fn add_signature(
        &self,
        sig: AsfaloadSignatures,
        pubkey: AsfaloadPublicKeys,
    ) -> Result<SignatureWithState, SignedFileError>;
    fn is_signed(&self) -> Result<bool, SignedFileError>;
}

impl SignedFileWithKindTrait for SignedFileWithKind
where
    AsfaloadPublicKeys: AsfaloadPublicKeyTrait<Signature = AsfaloadSignatures>,
    AsfaloadSignatures: AsfaloadSignatureTrait,
{
    fn add_signature(
        &self,
        sig: AsfaloadSignatures,
        pubkey: AsfaloadPublicKeys,
    ) -> Result<SignatureWithState, SignedFileError> {
        match self {
            SignedFileWithKind::InitialSignersFile(sf) => sf.add_signature(sig, pubkey),
            SignedFileWithKind::SignersFile(sf) => sf.add_signature(sig, pubkey),
            SignedFileWithKind::Artifact(sf) => sf.add_signature(sig, pubkey),
            SignedFileWithKind::Revocation(sf) => sf.add_signature(sig, pubkey),
            SignedFileWithKind::RevokedArtifact(sf) => sf.add_signature(sig, pubkey),
            SignedFileWithKind::Metadata(sf) => sf.add_signature(sig, pubkey),
        }
    }

    fn is_signed(&self) -> Result<bool, SignedFileError> {
        match self {
            SignedFileWithKind::InitialSignersFile(sf) => sf.is_signed(),
            SignedFileWithKind::SignersFile(sf) => sf.is_signed(),
            SignedFileWithKind::Artifact(sf) => sf.is_signed(),
            SignedFileWithKind::Revocation(sf) => sf.is_signed(),
            SignedFileWithKind::RevokedArtifact(sf) => sf.is_signed(),
            SignedFileWithKind::Metadata(sf) => sf.is_signed(),
        }
    }
}

pub trait SignersFileTrait {
    fn find_for_path<P: AsRef<Path>>(path_in: P) -> Result<PathBuf, std::io::Error>;
    fn find_pending_in_dir<P: AsRef<Path>>(path_in: P) -> Result<PathBuf, std::io::Error>;
}

pub struct SignersFile;
impl SignersFileTrait for SignersFile {
    fn find_for_path<P: AsRef<Path>>(path_in: P) -> Result<PathBuf, std::io::Error> {
        find_global_signers_for(path_in.as_ref())
    }
    fn find_pending_in_dir<P: AsRef<Path>>(path_in: P) -> Result<PathBuf, std::io::Error> {
        pending_signers_file_in_dir(path_in)
    }
}

pub mod aggregate_signature_helpers {
    use std::{collections::HashMap, path::Path};

    pub use aggregate_signature::{
        check_all_signers, check_groups, get_authorized_signers_for_file, get_missing_signers,
        load_signers_config, verify_all_signers_signed,
    };
    use aggregate_signature::{
        get_individual_signatures_from_bytes as get_individual_signatures_from_bytes_ori,
        get_individual_signatures_from_file as get_individual_signatures_ori,
        parse_tagged_signatures as parse_tagged_signatures_ori,
    };
    use common::errors::AggregateSignatureError;
    use signatures::keys::{AsfaloadPublicKeyTrait, AsfaloadSignatureTrait};
    use signatures::signatures_file::TaggedSignature;
    use signatures::types::{AsfaloadPublicKeys, AsfaloadSignatures};

    pub fn get_individual_signatures<P: AsRef<Path>>(
        sig_file_path: P,
    ) -> Result<HashMap<AsfaloadPublicKeys, AsfaloadSignatures>, AggregateSignatureError>
    where
        AsfaloadPublicKeys: AsfaloadPublicKeyTrait<Signature = AsfaloadSignatures>,
        AsfaloadSignatures: AsfaloadSignatureTrait,
    {
        get_individual_signatures_ori::<AsfaloadPublicKeys, AsfaloadSignatures, _>(sig_file_path)
    }

    pub fn get_individual_signatures_from_bytes<T: std::borrow::Borrow<[u8]>>(
        signatures_content_in: T,
    ) -> Result<HashMap<AsfaloadPublicKeys, AsfaloadSignatures>, AggregateSignatureError>
    where
        AsfaloadPublicKeys: AsfaloadPublicKeyTrait<Signature = AsfaloadSignatures>,
        AsfaloadSignatures: AsfaloadSignatureTrait,
    {
        get_individual_signatures_from_bytes_ori::<AsfaloadPublicKeys, AsfaloadSignatures, _>(
            signatures_content_in.borrow(),
        )
    }

    pub fn parse_tagged_signatures(
        entries: &HashMap<String, TaggedSignature>,
    ) -> Result<HashMap<AsfaloadPublicKeys, AsfaloadSignatures>, AggregateSignatureError>
    where
        AsfaloadPublicKeys: AsfaloadPublicKeyTrait<Signature = AsfaloadSignatures>,
        AsfaloadSignatures: AsfaloadSignatureTrait,
    {
        parse_tagged_signatures_ori::<AsfaloadPublicKeys, AsfaloadSignatures>(entries)
    }
}

pub mod constants {
    pub use constants::*;
}
pub mod rest_api {
    pub use rest_api_types::{
        ListPendingResponse, SubmitSignatureRequest, SubmitSignatureResponse,
    };
}

#[cfg(test)]
mod tests_signed_file_revocation {
    use super::*;
    use ::constants::{PENDING_REVOCATION_SUFFIX, SIGNERS_DIR, SIGNERS_FILE};
    use chrono::Utc;
    use common::errors::AggregateSignatureError;
    use common::fs::names::revocation_path_for;
    use common::{sha512_for_content, sha512_for_file};
    use signatures::keys::AsfaloadSecretKeyTrait;
    use signers_file_types::SignersConfig;
    use std::fs;
    use tempfile::TempDir;
    use test_helpers::TestKeys;

    /// Set up a temp directory with:
    /// - An active signers config containing explicit revocation_keys
    /// - A revocation JSON file for a dummy artifact
    /// - A local signers copy for the revocation file (needed after completion)
    ///
    /// Returns the path to the revocation file.
    fn setup_revocation_test(
        temp_dir: &TempDir,
        test_keys: &TestKeys,
        revocation_key_indices: &[usize],
        revocation_threshold: u32,
    ) -> anyhow::Result<std::path::PathBuf> {
        let root = temp_dir.path();

        // Create active signers config with explicit revocation_keys
        let signers_dir = root.join(SIGNERS_DIR);
        fs::create_dir_all(&signers_dir)?;
        let signers_file = signers_dir.join(SIGNERS_FILE);

        let revocation_keys: Vec<_> = revocation_key_indices
            .iter()
            .map(|&i| test_keys.pub_key(i).unwrap().clone())
            .collect();

        let signers_config = SignersConfig::with_keys(
            1,
            (vec![test_keys.pub_key(0).unwrap().clone()], 1),
            None,
            None,
            Some((revocation_keys, revocation_threshold)),
        )?;

        let config_json = serde_json::to_string_pretty(&signers_config)?;
        fs::write(&signers_file, &config_json)?;

        // Create subdirectory for artifact and revocation files
        let sub_dir = root.join("releases");
        fs::create_dir_all(&sub_dir)?;

        // Create revocation JSON file
        let revocation_info = signers_file_types::revocation::RevocationInfo {
            timestamp: Utc::now(),
            subject_digest: sha512_for_content(b"artifact content".to_vec())?,
            initiator: test_keys
                .pub_key(revocation_key_indices[0])
                .unwrap()
                .clone(),
        };
        let revocation_json = serde_json::to_string_pretty(&revocation_info)?;
        let revocation_path = sub_dir.join(format!("artifact.bin.{}", PENDING_REVOCATION_SUFFIX));
        fs::write(&revocation_path, &revocation_json)?;

        Ok(revocation_path)
    }

    #[test]
    fn test_add_signature_stays_pending_when_threshold_not_met() -> anyhow::Result<()> {
        let temp_dir = TempDir::new()?;
        let test_keys = TestKeys::new(2);
        let revocation_path = setup_revocation_test(&temp_dir, &test_keys, &[0, 1], 2)?;

        let signed_file = SignedFile::<common::RevocationMarker>::new(
            revocation_path.to_string_lossy().to_string(),
            None,
        );

        // Sign with first key only (threshold=2, so stays pending)
        let file_hash = sha512_for_file(&revocation_path)?;
        let sig = test_keys.sec_key(0).unwrap().sign(&file_hash)?;
        let result = signed_file.add_signature(sig, test_keys.pub_key(0).unwrap().clone())?;

        assert!(
            matches!(result, SignatureWithState::Pending(_)),
            "Expected Pending after 1 of 2 required signatures"
        );

        Ok(())
    }

    #[test]
    fn test_add_signature_completes_when_threshold_met() -> anyhow::Result<()> {
        let temp_dir = TempDir::new()?;
        let test_keys = TestKeys::new(3);
        let revocation_path = setup_revocation_test(&temp_dir, &test_keys, &[0, 1, 2], 2)?;

        let file_hash = sha512_for_file(&revocation_path)?;

        // Add first signature
        let sf = SignedFile::<common::RevocationMarker>::new(
            revocation_path.to_string_lossy().to_string(),
            None,
        );
        let sig0 = test_keys.sec_key(0).unwrap().sign(&file_hash)?;
        let intermediate = sf.add_signature(sig0, test_keys.pub_key(0).unwrap().clone())?;

        assert!(
            matches!(intermediate, SignatureWithState::Pending(_)),
            "Expected Pending after only one signatures"
        );

        // Add second signature (should complete)
        let sf = SignedFile::<common::RevocationMarker>::new(
            revocation_path.to_string_lossy().to_string(),
            None,
        );
        let sig1 = test_keys.sec_key(1).unwrap().sign(&file_hash)?;
        let result = sf.add_signature(sig1, test_keys.pub_key(1).unwrap().clone())?;

        assert!(
            matches!(result, SignatureWithState::Complete(_)),
            "Expected Complete after both required signatures"
        );

        Ok(())
    }

    #[test]
    fn test_add_signature_does_not_reject_non_member() -> anyhow::Result<()> {
        let temp_dir = TempDir::new()?;
        let test_keys = TestKeys::new(3);
        let revocation_path = setup_revocation_test(&temp_dir, &test_keys, &[0, 1], 2)?;

        let file_hash = sha512_for_file(&revocation_path)?;

        // Add first signature
        let sf = SignedFile::<common::RevocationMarker>::new(
            revocation_path.to_string_lossy().to_string(),
            None,
        );
        let sig0 = test_keys.sec_key(2).unwrap().sign(&file_hash)?;
        let result = sf.add_signature(sig0, test_keys.pub_key(2).unwrap().clone());

        match result {
            Ok(_) => {}
            Err(e) => panic!(
                "Expected success as the signature from group membership is not validated by SignedFile::add_signature, but got {}",
                e
            ),
        }

        Ok(())
    }
    #[test]
    fn test_add_signature_errors_when_already_complete() -> anyhow::Result<()> {
        let temp_dir = TempDir::new()?;
        let test_keys = TestKeys::new(3);
        let revocation_path = setup_revocation_test(&temp_dir, &test_keys, &[0, 1, 2], 2)?;

        let file_hash = sha512_for_file(&revocation_path)?;

        // Complete the signatures with keys 0 and 1
        let sf = SignedFile::<common::RevocationMarker>::new(
            revocation_path.to_string_lossy().to_string(),
            None,
        );
        let sig0 = test_keys.sec_key(0).unwrap().sign(&file_hash)?;
        sf.add_signature(sig0, test_keys.pub_key(0).unwrap().clone())?;

        let sf = SignedFile::<common::RevocationMarker>::new(
            revocation_path.to_string_lossy().to_string(),
            None,
        );
        let sig1 = test_keys.sec_key(1).unwrap().sign(&file_hash)?;
        sf.add_signature(sig1, test_keys.pub_key(1).unwrap().clone())?;

        // Try to add a third signature — should error
        let sf = SignedFile::<common::RevocationMarker>::new(
            revocation_path.to_string_lossy().to_string(),
            None,
        );
        let sig2 = test_keys.sec_key(2).unwrap().sign(&file_hash)?;
        let result = sf.add_signature(sig2, test_keys.pub_key(2).unwrap().clone());

        match result {
            Err(e) => match e {
                SignedFileError::AggregateSignatureError(
                    AggregateSignatureError::SignatureAlreadyComplete,
                ) => {}
                other => panic!("Expected 'already complete' error, got {}", other),
            },
            Ok(_) => panic!(
                "Expected error when adding signature to already complete revocation as file shuld have been moved"
            ),
        }

        Ok(())
    }

    #[test]
    fn test_is_signed_false_when_pending() -> anyhow::Result<()> {
        let temp_dir = TempDir::new()?;
        let test_keys = TestKeys::new(2);
        let revocation_path = setup_revocation_test(&temp_dir, &test_keys, &[0, 1], 2)?;

        // No signatures yet
        let sf = SignedFile::<common::RevocationMarker>::new(
            revocation_path.to_string_lossy().to_string(),
            None,
        );
        assert!(!sf.is_signed()?);

        // Add one signature (still not complete)
        let file_hash = sha512_for_file(&revocation_path)?;
        let sig0 = test_keys.sec_key(0).unwrap().sign(&file_hash)?;
        sf.add_signature(sig0, test_keys.pub_key(0).unwrap().clone())?;

        let sf = SignedFile::<common::RevocationMarker>::new(
            revocation_path.to_string_lossy().to_string(),
            None,
        );
        assert!(
            !sf.is_signed()?,
            "Expected is_signed=false after 1 of 2 required signatures"
        );

        Ok(())
    }

    #[test]
    fn test_is_signed_true_when_complete() -> anyhow::Result<()> {
        let temp_dir = TempDir::new()?;
        let test_keys = TestKeys::new(2);
        let pending_revocation_path = setup_revocation_test(&temp_dir, &test_keys, &[0, 1], 2)?;

        let file_hash = sha512_for_file(&pending_revocation_path)?;

        // Add both signatures
        let sf = SignedFile::<common::RevocationMarker>::new(
            pending_revocation_path.to_string_lossy().to_string(),
            None,
        );
        let sig0 = test_keys.sec_key(0).unwrap().sign(&file_hash)?;
        sf.add_signature(sig0, test_keys.pub_key(0).unwrap().clone())?;

        let sf = SignedFile::<common::RevocationMarker>::new(
            pending_revocation_path.to_string_lossy().to_string(),
            None,
        );
        let sig1 = test_keys.sec_key(1).unwrap().sign(&file_hash)?;
        let signed = sf.add_signature(sig1, test_keys.pub_key(1).unwrap().clone())?;
        // Check the returned SignatureWithState is complete
        assert!(signed.is_complete());

        // Load the renamed complete revocation and check is_signed
        let artifact_path = temp_dir.path().join("releases").join("artifact.bin");
        let revocation_path = revocation_path_for(artifact_path)?;
        let sf = SignedFile::<common::RevocationMarker>::new(
            revocation_path.to_string_lossy().to_string(),
            None,
        );
        assert!(
            sf.is_signed()?,
            "Expected is_signed=true after both required signatures"
        );

        Ok(())
    }

    #[test]
    fn test_add_signature_rejected_for_revoked_artifact() -> anyhow::Result<()> {
        let temp_dir = TempDir::new()?;
        let test_keys = TestKeys::new(1);

        let artifact_path = temp_dir.path().join("artifact.bin");
        fs::write(&artifact_path, "artifact content")?;

        let revocation_path = revocation_path_for(&artifact_path)?;
        fs::write(&revocation_path, r#"{"revoked": true}"#)?;

        let signed_file = SignedFile::<RevokedArtifactMarker>::new(
            artifact_path.to_string_lossy().to_string(),
            None,
        );

        let file_hash = sha512_for_file(&artifact_path)?;
        let sig = test_keys.sec_key(0).unwrap().sign(&file_hash)?;

        let result = signed_file.add_signature(sig, test_keys.pub_key(0).unwrap().clone());

        match result {
            Err(SignedFileError::Revoked()) => {}
            Ok(_) => panic!("Expected SignedFileError::Revoked(), got Ok"),
            Err(e) => panic!("Expected SignedFileError::Revoked(), got: {}", e),
        }

        Ok(())
    }

    #[test]
    fn test_is_signed_returns_false_for_revoked_artifact() -> anyhow::Result<()> {
        let temp_dir = TempDir::new()?;
        let artifact_path = temp_dir.path().join("artifact.bin");

        let signed_file = SignedFile::<RevokedArtifactMarker>::new(
            artifact_path.to_string_lossy().to_string(),
            None,
        );

        let result = signed_file.is_signed()?;
        assert!(
            !result,
            "Expected is_signed() to return false for revoked artifact"
        );

        Ok(())
    }

    #[test]
    fn test_signed_file_with_kind_rejects_revoked_artifact() -> anyhow::Result<()> {
        let temp_dir = TempDir::new()?;
        let test_keys = TestKeys::new(1);

        let signers_dir = temp_dir.path().join(SIGNERS_DIR);
        fs::create_dir_all(&signers_dir)?;
        let signers_file = signers_dir.join(SIGNERS_FILE);

        let signers_config = SignersConfig::with_keys(
            1,
            (vec![test_keys.pub_key(0).unwrap().clone()], 1),
            None,
            None,
            None,
        )?;
        fs::write(&signers_file, serde_json::to_string(&signers_config)?)?;

        let artifact_path = temp_dir.path().join("artifact.bin");
        fs::write(&artifact_path, "artifact content")?;

        let revocation_path = revocation_path_for(&artifact_path)?;
        fs::write(&revocation_path, r#"{"revoked": true}"#)?;

        let signed_file = SignedFileLoader::load(&artifact_path)?;

        match &signed_file {
            SignedFileWithKind::RevokedArtifact(_) => {}
            _ => panic!("Expected RevokedArtifact variant"),
        }

        let file_hash = sha512_for_file(&artifact_path)?;
        let sig = test_keys.sec_key(0).unwrap().sign(&file_hash)?;

        use crate::SignedFileWithKindTrait;
        let result = signed_file.add_signature(sig, test_keys.pub_key(0).unwrap().clone());

        match result {
            Err(SignedFileError::Revoked()) => {}
            Ok(_) => panic!("Expected SignedFileError::Revoked(), got Ok"),
            Err(e) => panic!("Expected SignedFileError::Revoked(), got: {}", e),
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests_signers_add_signature {
    use super::*;
    use ::constants::{PENDING_SIGNERS_DIR, SIGNERS_DIR, SIGNERS_FILE};
    use common::errors::AggregateSignatureError;
    use common::sha512_for_content;
    use signatures::keys::AsfaloadSecretKeyTrait;
    use signers_file::sign_signers_and_metadata_file;
    use signers_file_types::SignersConfig;
    use tempfile::TempDir;
    use test_helpers::{TestKeys, test_metadata};

    #[test]
    fn test_signers_add_signature_adds_pending_signature() -> anyhow::Result<()> {
        let temp_dir = TempDir::new()?;
        let dir_path = temp_dir.path();
        let test_keys = TestKeys::new(2);

        // Create a 2-signer config with threshold 2
        let signers_config = SignersConfig::with_artifact_signers_only(
            1,
            (
                vec![
                    test_keys.pub_key(0).unwrap().clone(),
                    test_keys.pub_key(1).unwrap().clone(),
                ],
                2,
            ),
        )?;
        let json_content = signers_config.to_json()?;

        // Initialize the signers file (no longer signs)
        signers_file::initialize_signers_file(
            dir_path,
            &json_content,
            test_metadata(),
            test_keys.pub_key(0).unwrap(),
        )?;

        // Load the pending signers file through SignedFileLoader
        let pending_signers_path = dir_path.join(PENDING_SIGNERS_DIR).join(SIGNERS_FILE);
        let signed_file = SignedFileLoader::load(&pending_signers_path)?;

        let hash_value = sha512_for_content(json_content.as_bytes().to_vec())?;
        let sig1 = test_keys.sec_key(1).unwrap().sign(&hash_value)?;
        let result = signed_file.add_signature(sig1, test_keys.pub_key(1).unwrap().clone());

        assert!(result.is_ok(), "Expected success, got: {:?}", result.err());

        Ok(())
    }

    #[test]
    fn test_signers_add_signature_errors_when_already_complete() -> anyhow::Result<()> {
        let temp_dir = TempDir::new()?;
        let dir_path = temp_dir.path();
        let test_keys = TestKeys::new(2);

        // Create a 1-signer config (threshold 1)
        let signers_config = SignersConfig::with_artifact_signers_only(
            1,
            (vec![test_keys.pub_key(0).unwrap().clone()], 1),
        )?;
        let json_content = signers_config.to_json()?;

        // Initialize the signers file (stays pending, init no longer signs)
        signers_file::initialize_signers_file(
            dir_path,
            &json_content,
            test_metadata(),
            test_keys.pub_key(0).unwrap(),
        )?;

        // Sign to complete and activate via sign_signers_and_metadata_file
        let pending_signers_path = dir_path.join(PENDING_SIGNERS_DIR).join(SIGNERS_FILE);
        let hash_value = common::sha512_for_file(&pending_signers_path)?;
        let sig0 = test_keys.sec_key(0).unwrap().sign(&hash_value)?;
        let metadata_path = common::fs::names::metadata_path_for(&pending_signers_path)?;
        let metadata_hash = common::sha512_for_file(&metadata_path)?;
        let meta_sig0 = test_keys.sec_key(0).unwrap().sign(&metadata_hash)?;
        sign_signers_and_metadata_file(
            &pending_signers_path,
            &sig0,
            test_keys.pub_key(0).unwrap(),
            &meta_sig0,
        )?;

        // Load the now-active signers file through SignedFileLoader
        let active_signers_path = dir_path.join(SIGNERS_DIR).join(SIGNERS_FILE);
        let signed_file = SignedFileLoader::load(&active_signers_path)?;

        // Try to add another signature -- should fail with SignatureAlreadyComplete
        let active_hash = common::sha512_for_file(&active_signers_path)?;
        let sig1 = test_keys.sec_key(1).unwrap().sign(&active_hash)?;
        let result = signed_file.add_signature(sig1, test_keys.pub_key(1).unwrap().clone());

        match result {
            Err(SignedFileError::AggregateSignatureError(
                AggregateSignatureError::SignatureAlreadyComplete,
            )) => {}
            Err(other) => panic!("Expected SignatureAlreadyComplete error, got: {}", other),
            Ok(_) => {
                panic!("Expected error when adding signature to already complete signers file")
            }
        }

        Ok(())
    }
}
