// aggregate_signature/src/revocation.rs

use common::{
    errors::RevocationError,
    fs::names::{
        find_global_signers_for, pending_revocation_path_for, pending_signatures_path_for,
        revocation_path_for, revocation_signatures_path_for, revocation_signers_path_for,
        revoked_pending_signatures_path_for, revoked_signatures_path_for, signatures_path_for,
    },
};
use signatures::{
    keys::AsfaloadPublicKeyTrait,
    types::{AsfaloadPublicKeys, AsfaloadSignatures},
};
use signers_file_types::SignersConfig;
use std::fs;
use std::path::Path;

use crate::{SignatureWithState, can_revoke};

/// Revoke a signed file by creating a revocation file.
///
/// This function validates that the provided public key can revoke the signed file
/// (using the `can_revoke` function), verifies the signature against the revocation
/// JSON content, and creates the necessary revocation files.
///
/// # Arguments
/// * `signed_file_path` - The path to the signed file being revoked
/// * `json_content` - The revocation file as JSON string
/// * `signature` - Signature of the revocation JSON content
/// * `pubkey` - Public key of the revoker
///
/// # Returns
/// * `Ok(SignatureWithState)` with the aggregate signature of the revocation:
///   `Complete` when the initiator signature met the threshold and the
///   revocation is final, `Pending` when other revocation signers must sign
/// * `Err(RevocationError)` if there was an error validating, signing, or writing files
pub fn revoke_signed_file<P>(
    signed_file_path: P,
    json_content: &str,
    signature: &AsfaloadSignatures,
    pubkey: &AsfaloadPublicKeys,
) -> Result<SignatureWithState, RevocationError>
where
    P: AsRef<Path>,
{
    let signed_file_path = signed_file_path.as_ref();

    // 1. Validate the signed file exists and is a file
    if !signed_file_path.exists() {
        return Err(RevocationError::Io(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            format!("Signed file not found: {}", signed_file_path.display()),
        )));
    }

    if signed_file_path.is_dir() {
        return Err(RevocationError::Io(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "Cannot revoke a directory",
        )));
    }

    //  Load the active signers configuration (not the local one copied at time of
    //  signing the signed file we want to revoke)
    let signers_file_path = find_global_signers_for(signed_file_path)?;
    let signers_config = SignersConfig::from_file(&signers_file_path)?;

    // Check if the public key can revoke
    if !can_revoke(pubkey, &signers_config) {
        return Err(RevocationError::Signature(
            "Public key is not authorized to revoke this file".to_string(),
        ));
    }

    //Validate the revocation JSON by parsing it
    let _revocation_info: signers_file_types::revocation::RevocationInfo =
        serde_json::from_str(json_content)?;

    // Compute hash and verify signature
    let hash = common::sha512_for_content(json_content.as_bytes().to_vec())?;
    pubkey
        .verify(signature, &hash)
        .map_err(|e| RevocationError::Signature(format!("Signature verification failed: {}", e)))?;

    //  Create revocation file paths
    let revocation_file_path = revocation_path_for(signed_file_path)?;
    let pending_revocation_file_path = pending_revocation_path_for(signed_file_path)?;
    let revocation_sig_path = revocation_signatures_path_for(signed_file_path)?;
    let revoked_sig_path = revoked_signatures_path_for(signed_file_path)?;

    // 7. Check for existing files to avoid overwriting
    check_existing_files(
        &revocation_file_path,
        &revocation_sig_path,
        &revoked_sig_path,
    )?;

    // If a pending revocation already exists, error out.
    // The `revoke` command is initiation-only. Additional signatures
    // should go through the normal `sign-pending` flow.
    if pending_revocation_file_path.exists() {
        return Err(RevocationError::Io(std::io::Error::new(
            std::io::ErrorKind::AlreadyExists,
            format!(
                "A pending revocation already exists: {}. Should be signed instead.",
                pending_revocation_file_path.display()
            ),
        )));
    }

    // First revocation: write pending revocation JSON file
    fs::write(&pending_revocation_file_path, json_content)?;

    let load_error_to_revocation_error = |e| {
        RevocationError::Signature(format!(
            "Could not load signature with state for {}: {}",
            signed_file_path.display(),
            e
        ))
    };
    let signature_with_state = SignatureWithState::load_for_file(&pending_revocation_file_path)
        .map_err(load_error_to_revocation_error)?;
    let pending_signature =
        signature_with_state
            .get_pending()
            .ok_or(RevocationError::Signature(
                "Could not get pending signature for new revocation.".into(),
            ))?;
    let signature_with_state = pending_signature
        .add_individual_signature(signature, pubkey)
        .map_err(load_error_to_revocation_error)?;

    Ok(signature_with_state)
}

pub fn finalise_revocation_for<P: AsRef<Path>>(
    signed_file_path_in: P,
) -> Result<(), RevocationError> {
    let signed_file_path = signed_file_path_in.as_ref();
    let signers_file_path = find_global_signers_for(signed_file_path)?;
    let revocation_signers_path = revocation_signers_path_for(signed_file_path)?;
    let revoked_pending_sig_path = revoked_pending_signatures_path_for(signed_file_path)?;
    let revoked_sig_path = revoked_signatures_path_for(signed_file_path)?;

    // Move the pending revocation file to the final location
    let pending_revocation_file_path = pending_revocation_path_for(signed_file_path)?;
    let revocation_file_path = revocation_path_for(signed_file_path)?;
    if pending_revocation_file_path.exists() {
        fs::rename(&pending_revocation_file_path, &revocation_file_path)?;
    }

    // Move the pending revocation signatures file to the final location
    let pending_revocation_sig_path = pending_signatures_path_for(&pending_revocation_file_path)?;
    let revocation_sig_path = revocation_signatures_path_for(signed_file_path)?;
    if pending_revocation_sig_path.exists() {
        fs::rename(&pending_revocation_sig_path, &revocation_sig_path)?;
    }

    // Copy current signers file for reference (keep trace of which
    // signers file was used)
    fs::copy(&signers_file_path, &revocation_signers_path)?;

    // Move the original signatures file to .revoked if it exists
    let original_sig_path = signatures_path_for(signed_file_path)?;
    if original_sig_path.exists() && original_sig_path.is_file() {
        fs::rename(&original_sig_path, &revoked_sig_path)?;
    }

    // Move the pending signatures file to .revoked if it exists
    let original_pending_sig_path = pending_signatures_path_for(signed_file_path)?;
    if original_pending_sig_path.exists() && original_pending_sig_path.is_file() {
        fs::rename(&original_pending_sig_path, &revoked_pending_sig_path)?;
    }
    Ok(())
}

/// Check for existing files to avoid overwriting
fn check_existing_files(
    revocation_file_path: &Path,
    revocation_sig_path: &Path,
    revoked_sig_path: &Path,
) -> Result<(), RevocationError> {
    if revocation_file_path.exists() {
        return Err(RevocationError::Io(std::io::Error::new(
            std::io::ErrorKind::AlreadyExists,
            format!(
                "Revocation file already exists: {}",
                revocation_file_path.display()
            ),
        )));
    }

    if revocation_sig_path.exists() {
        return Err(RevocationError::Io(std::io::Error::new(
            std::io::ErrorKind::AlreadyExists,
            format!(
                "Revocation signature file already exists: {}",
                revocation_sig_path.display()
            ),
        )));
    }

    if revoked_sig_path.exists() {
        return Err(RevocationError::Io(std::io::Error::new(
            std::io::ErrorKind::AlreadyExists,
            format!(
                "Revoked signatures file already exists: {}",
                revoked_sig_path.display()
            ),
        )));
    }

    Ok(())
}

// aggregate_signature/src/revocation.rs (additional tests section)

#[cfg(test)]
mod tests {
    use crate::SignatureWithState;

    use super::*;
    use common::{
        FileType, SignedFileLoader,
        fs::names::{
            local_signers_path_for, pending_revocation_pending_signatures_path_for,
            revocation_path_for, revocation_signatures_path_for, revocation_signers_path_for,
            revoked_signatures_path_for, signatures_path_for,
        },
    };
    use constants::SIGNERS_SUFFIX;
    use signatures::{keys::AsfaloadSignatureTrait, types::AsfaloadPublicKeys};
    use std::path::PathBuf;

    #[test]
    fn test_check_existing_files() {
        use tempfile::TempDir;

        let temp_dir = TempDir::new().unwrap();

        // Create test files
        let revocation_file_path = temp_dir.path().join("test.revocation.json");
        let revocation_sig_path = temp_dir.path().join("test.revocation.json.signatures.json");
        let revoked_sig_path = temp_dir.path().join("test.signatures.json.revoked");

        // Initially, all files don't exist, so check should pass
        let result = check_existing_files(
            &revocation_file_path,
            &revocation_sig_path,
            &revoked_sig_path,
        );
        assert!(result.is_ok());

        // Create one of the files and test
        std::fs::write(&revocation_file_path, "test content").unwrap();
        let result = check_existing_files(
            &revocation_file_path,
            &revocation_sig_path,
            &revoked_sig_path,
        );
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("already exists"));

        // Clean up and test another file
        std::fs::remove_file(&revocation_file_path).unwrap();
        std::fs::write(&revocation_sig_path, "test content").unwrap();
        let result = check_existing_files(
            &revocation_file_path,
            &revocation_sig_path,
            &revoked_sig_path,
        );
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("already exists"));

        // Clean up and test the third file
        std::fs::remove_file(&revocation_sig_path).unwrap();
        std::fs::write(&revoked_sig_path, "test content").unwrap();
        let result = check_existing_files(
            &revocation_file_path,
            &revocation_sig_path,
            &revoked_sig_path,
        );
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("already exists"));
    }

    #[test]
    fn test_check_existing_files_with_directories() {
        use tempfile::TempDir;

        let temp_dir = TempDir::new().unwrap();

        // Create test directories instead of files
        let revocation_file_path = temp_dir.path().join("test.revocation.json");
        let revocation_sig_path = temp_dir.path().join("test.revocation.json.signatures.json");
        let revoked_sig_path = temp_dir.path().join("test.signatures.json.revoked");

        std::fs::create_dir(&revocation_file_path).unwrap();

        let result = check_existing_files(
            &revocation_file_path,
            &revocation_sig_path,
            &revoked_sig_path,
        );
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("already exists"));
    }

    //--------------------
    // Revocation tests
    //--------------------

    use chrono::Utc;
    use common::{AsfaloadHashes, fs::names::find_global_signers_for};
    use signatures::keys::AsfaloadSecretKeyTrait;
    use std::collections::HashMap;
    use std::fs;
    use tempfile::TempDir;
    use test_helpers::{TestKeys, create_complete_signers_setup};
    // ----------------
    // Helper functions
    // ----------------

    // Helper to create a signed artifact file with complete aggregate signature
    fn create_signed_artifact_file(
        temp_dir: &TempDir,
        test_keys: &TestKeys,
        artifact_content: &[u8],
    ) -> Result<PathBuf, Box<dyn std::error::Error>> {
        let root = temp_dir.path();

        // Create a test artifact file
        let artifact_path = root.join("artifact.bin");
        fs::write(&artifact_path, artifact_content)?;

        // Create complete aggregate signature for the artifact
        let hash = common::sha512_for_file(&artifact_path)?;

        let mut signatures = HashMap::new();

        let mut agg_sig = SignatureWithState::load_for_file(&artifact_path)?;
        // Sign with both required artifact signers (threshold 2)
        for i in 0..2 {
            // We reload the agg_sig bevause .get_pending() moves it.
            // This is slow but ensure we have the latest version.
            let pubkey = test_keys.pub_key(i).unwrap();
            let seckey = test_keys.sec_key(i).unwrap();
            let signature = seckey.sign(&hash)?;
            signatures.insert(pubkey.to_base64(), signature.to_base64());
            // We get the new, updated agg_sig back, to be used in next iteration.
            agg_sig = agg_sig
                .get_pending()
                .unwrap()
                .add_individual_signature(&signature, pubkey)?;
        }

        // Create local copy of signers file (as done when signature becomes complete)
        let global_signers = find_global_signers_for(&artifact_path)?;
        let local_signers_file = artifact_path.with_file_name(format!(
            "{}.{}",
            artifact_path.file_name().unwrap().to_string_lossy(),
            SIGNERS_SUFFIX
        ));
        fs::copy(&global_signers, &local_signers_file)?;

        Ok(artifact_path)
    }

    // Helper to create revocation JSON content
    fn create_revocation_json(
        timestamp: chrono::DateTime<Utc>,
        subject_digest: &AsfaloadHashes,
        initiator_pubkey: &AsfaloadPublicKeys,
    ) -> Result<String, Box<dyn std::error::Error>> {
        let revocation_info = signers_file_types::revocation::RevocationInfo {
            timestamp,
            subject_digest: subject_digest.clone(),
            initiator: initiator_pubkey.clone(),
        };

        Ok(serde_json::to_string_pretty(&revocation_info)?)
    }
    #[test]
    fn test_revoke_signed_file_with_revocation_key() -> Result<(), Box<dyn std::error::Error>> {
        // -----------------------------------------------------------------
        // Main test logic
        // -----------------------------------------------------------------

        // Create temporary directory
        let temp_dir = TempDir::new()?;

        // Generate test keys: 0,1 for artifact signing, 2 for master, 3 for revocation
        let test_keys = TestKeys::new(4);

        // Create signers setup with master keys (key 2) and revocation keys (key 3)
        create_complete_signers_setup(&temp_dir, &test_keys, None, Some(vec![2]), Some(vec![3]))?;

        // Create signed artifact file
        let artifact_content = b"This is an artifact that will be revoked";
        let artifact_path = create_signed_artifact_file(&temp_dir, &test_keys, artifact_content)?;

        let signatures_file = signatures_path_for(&artifact_path)?;
        let local_signers_file = local_signers_path_for(&artifact_path)?;

        // Verify files exist before revocation
        assert!(artifact_path.exists());
        assert!(signatures_file.exists());
        assert!(local_signers_file.exists());

        // Prepare revocation with revocation key (key 3)
        let timestamp = Utc::now();
        let subject_digest = common::sha512_for_file(&artifact_path)?;
        let initiator_pubkey = test_keys.pub_key(3).unwrap(); // Revocation key
        let revocation_json = create_revocation_json(timestamp, &subject_digest, initiator_pubkey)?;

        // Sign the revocation JSON
        let revocation_hash = common::sha512_for_content(revocation_json.as_bytes().to_vec())?;
        let initiator_seckey = test_keys.sec_key(3).unwrap();
        let revocation_signature = initiator_seckey.sign(&revocation_hash)?;

        // Perform revocation
        let result = revoke_signed_file(
            &artifact_path,
            &revocation_json,
            &revocation_signature,
            initiator_pubkey,
        )?;

        // Single revocation key → threshold 1 → should complete immediately
        assert!(
            result.is_complete(),
            "Single-signer revocation should return Complete, got Pending"
        );

        // Verify revocation files were created
        let revocation_file_path = revocation_path_for(&artifact_path)?;
        assert!(revocation_file_path.exists());

        let revocation_sig_path = revocation_signatures_path_for(&artifact_path)?;
        assert!(revocation_sig_path.exists());

        let revocation_signers_path = revocation_signers_path_for(&artifact_path)?;
        assert!(revocation_signers_path.exists());

        let revoked_sig_path = revoked_signatures_path_for(&artifact_path)?;
        assert!(revoked_sig_path.exists());

        // Verify original signatures file was moved
        assert!(!signatures_file.exists());

        // Verify revocation file content
        let parsed_revocation =
            signers_file_types::revocation::RevocationInfo::from_file(revocation_file_path)?;

        assert_eq!(parsed_revocation.timestamp, timestamp);
        assert_eq!(parsed_revocation.subject_digest, subject_digest);
        assert_eq!(
            parsed_revocation.initiator.to_base64(),
            initiator_pubkey.to_base64()
        );

        // Verify revocation signature file content
        let revocation_sig_content = fs::read_to_string(&revocation_sig_path)?;
        let revocation_sig_file: signatures::signatures_file::SignaturesFile =
            serde_json::from_str(&revocation_sig_content)?;
        assert_eq!(revocation_sig_file.entries.len(), 1);
        assert!(
            revocation_sig_file
                .entries
                .contains_key(&initiator_pubkey.to_base64())
        );
        assert_eq!(
            revocation_sig_file
                .entries
                .get(&initiator_pubkey.to_base64())
                .unwrap()
                .signature,
            revocation_signature.to_base64()
        );

        // Verify revocation signers file matches global signers
        let global_signers = find_global_signers_for(&artifact_path)?;
        let global_signers_content = fs::read_to_string(&global_signers)?;
        let revocation_signers_content = fs::read_to_string(&revocation_signers_path)?;
        assert_eq!(global_signers_content, revocation_signers_content);

        // Verify revoked signatures file content matches original
        let original_sig_content = fs::read_to_string(&revoked_sig_path)?;
        let original_sig_file: signatures::signatures_file::SignaturesFile =
            serde_json::from_str(&original_sig_content)?;
        assert_eq!(original_sig_file.entries.len(), 2); // Should have both artifact signers

        Ok(())
    }
    #[test]
    fn test_revoke_signed_file_with_artifact_fail_when_master_present()
    -> Result<(), Box<dyn std::error::Error>> {
        // Generate test keys (we need at least 3: 2 for artifact signing, 1 for master/revocation)
        let test_keys = TestKeys::new(4);

        // Create new temp dir for clean test
        let temp_dir2 = TempDir::new()?;

        // Create signers setup with master keys and explicit revocation keys (key 2)
        create_complete_signers_setup(&temp_dir2, &test_keys, None, Some(vec![2]), Some(vec![3]))?;

        // Create signed artifact file
        let artifact_path =
            create_signed_artifact_file(&temp_dir2, &test_keys, b"Another artifact")?;

        // Prepare revocation with artifact signer (key 0)
        let timestamp = Utc::now();
        let subject_digest = common::sha512_for_file(&artifact_path)?;
        let initiator_pubkey = test_keys.pub_key(0).unwrap(); // Artifact signer
        let revocation_json = create_revocation_json(timestamp, &subject_digest, initiator_pubkey)?;

        // Sign the revocation JSON
        let revocation_hash = common::sha512_for_content(revocation_json.as_bytes().to_vec())?;
        let initiator_seckey = test_keys.sec_key(0).unwrap();
        let revocation_signature = initiator_seckey.sign(&revocation_hash)?;

        // Perform revocation
        let result = revoke_signed_file(
            &artifact_path,
            &revocation_json,
            &revocation_signature,
            initiator_pubkey,
        );

        assert!(result.is_err());
        match result {
            Err(e) => {
                let err_str = e.to_string();
                assert!(
                    err_str.contains("Public key is not authorized to revoke this file")
                        || err_str.contains("Signature verification failed"),
                    "Unexpected error: {}",
                    err_str
                );
            }
            Ok(_) => panic!("Expected revocation to fail for unauthorized key"),
        }

        // Verify no revocation file was create
        let revocation_file_path = revocation_path_for(&artifact_path)?;
        assert!(!revocation_file_path.exists());
        let revocation_sig_path = revocation_signatures_path_for(&artifact_path)?;
        assert!(!revocation_sig_path.exists());
        let revocation_signers_path = revocation_signers_path_for(&artifact_path)?;
        assert!(!revocation_signers_path.exists());
        let revoked_sig_path = revoked_signatures_path_for(&artifact_path)?;
        assert!(!revoked_sig_path.exists());

        Ok(())
    }
    #[test]
    fn test_revoke_signed_file_with_artifact_fail_when_admin_present()
    -> Result<(), Box<dyn std::error::Error>> {
        // Generate test keys (we need at least 3: 2 for artifact signing, 1 for master/revocation)
        let test_keys = TestKeys::new(3);

        // Create new temp dir for clean test
        let temp_dir2 = TempDir::new()?;

        // Create signers setup with admin keys (key 2), no master, no explicit revocation
        create_complete_signers_setup(&temp_dir2, &test_keys, Some(vec![2]), None, None)?;

        // Create signed artifact file
        let artifact_path =
            create_signed_artifact_file(&temp_dir2, &test_keys, b"Another artifact")?;

        // Prepare revocation with artifact signer (key 0)
        let timestamp = Utc::now();
        let subject_digest = common::sha512_for_file(&artifact_path)?;
        let initiator_pubkey = test_keys.pub_key(0).unwrap(); // Artifact signer
        let revocation_json = create_revocation_json(timestamp, &subject_digest, initiator_pubkey)?;

        // Sign the revocation JSON
        let revocation_hash = common::sha512_for_content(revocation_json.as_bytes().to_vec())?;
        let initiator_seckey = test_keys.sec_key(0).unwrap();
        let revocation_signature = initiator_seckey.sign(&revocation_hash)?;

        // Perform revocation
        let result = revoke_signed_file(
            &artifact_path,
            &revocation_json,
            &revocation_signature,
            initiator_pubkey,
        );

        assert!(result.is_err());
        match result {
            Err(e) => {
                let err_str = e.to_string();
                assert!(
                    err_str.contains("Public key is not authorized to revoke this file")
                        || err_str.contains("Signature verification failed"),
                    "Unexpected error: {}",
                    err_str
                );
            }
            Ok(_) => panic!("Expected revocation to fail for unauthorized key"),
        }

        // Verify no revocation file was create
        let revocation_file_path = revocation_path_for(&artifact_path)?;
        assert!(!revocation_file_path.exists());
        let revocation_sig_path = revocation_signatures_path_for(&artifact_path)?;
        assert!(!revocation_sig_path.exists());
        let revocation_signers_path = revocation_signers_path_for(&artifact_path)?;
        assert!(!revocation_signers_path.exists());
        let revoked_sig_path = revoked_signatures_path_for(&artifact_path)?;
        assert!(!revoked_sig_path.exists());

        Ok(())
    }
    #[test]
    fn test_revoke_signed_file_with_admin_fail_when_master_present()
    -> Result<(), Box<dyn std::error::Error>> {
        // Generate test keys (we need at least 3: 2 for artifact signing, 1 for master/revocation)
        let test_keys = TestKeys::new(5);

        // Create new temp dir for clean test
        let temp_dir2 = TempDir::new()?;

        // Create signers setup with admin (key 2), master (key 3), and explicit revocation
        create_complete_signers_setup(
            &temp_dir2,
            &test_keys,
            Some(vec![2]),
            Some(vec![3]),
            Some(vec![4]),
        )?;

        // Create signed artifact file
        let artifact_path =
            create_signed_artifact_file(&temp_dir2, &test_keys, b"Another artifact")?;

        // Prepare revocation with artifact signer (key 0)
        let timestamp = Utc::now();
        let subject_digest = common::sha512_for_file(&artifact_path)?;
        let initiator_pubkey = test_keys.pub_key(2).unwrap(); // Admin signer
        let revocation_json = create_revocation_json(timestamp, &subject_digest, initiator_pubkey)?;

        // Sign the revocation JSON
        let revocation_hash = common::sha512_for_content(revocation_json.as_bytes().to_vec())?;
        let initiator_seckey = test_keys.sec_key(2).unwrap();
        let revocation_signature = initiator_seckey.sign(&revocation_hash)?;

        // Perform revocation
        let result = revoke_signed_file(
            &artifact_path,
            &revocation_json,
            &revocation_signature,
            initiator_pubkey,
        );

        assert!(result.is_err());
        match result {
            Err(e) => {
                let err_str = e.to_string();
                assert!(
                    err_str.contains("Public key is not authorized to revoke this file")
                        || err_str.contains("Signature verification failed"),
                    "Unexpected error: {}",
                    err_str
                );
            }
            Ok(_) => panic!("Expected revocation to fail for unauthorized key"),
        }

        // Verify no revocation file was create
        let revocation_file_path = revocation_path_for(&artifact_path)?;
        assert!(!revocation_file_path.exists());
        let revocation_sig_path = revocation_signatures_path_for(&artifact_path)?;
        assert!(!revocation_sig_path.exists());
        let revocation_signers_path = revocation_signers_path_for(&artifact_path)?;
        assert!(!revocation_signers_path.exists());
        let revoked_sig_path = revoked_signatures_path_for(&artifact_path)?;
        assert!(!revoked_sig_path.exists());

        Ok(())
    }

    #[test]
    fn test_revoke_signed_file_with_artifact_ok() -> Result<(), Box<dyn std::error::Error>> {
        // Generate test keys (we need at least 3: 2 for artifact signing, 1 for master/revocation)
        let test_keys = TestKeys::new(3);

        // Create new temp dir for clean test
        let temp_dir2 = TempDir::new()?;

        // Create signers setup without admin or master keys
        create_complete_signers_setup(&temp_dir2, &test_keys, None, None, None)?;

        // Create signed artifact file
        let artifact_path =
            create_signed_artifact_file(&temp_dir2, &test_keys, b"Another artifact")?;
        let signatures_file = signatures_path_for(&artifact_path)?;

        // Prepare revocation with artifact signer (key 0)
        let timestamp = Utc::now();
        let subject_digest = common::sha512_for_file(&artifact_path)?;
        let initiator_pubkey = test_keys.pub_key(0).unwrap(); // Artifact signer
        let revocation_json = create_revocation_json(timestamp, &subject_digest, initiator_pubkey)?;

        // Sign the revocation JSON
        let revocation_hash = common::sha512_for_content(revocation_json.as_bytes().to_vec())?;
        let initiator_seckey = test_keys.sec_key(0).unwrap();
        let revocation_signature = initiator_seckey.sign(&revocation_hash)?;

        // Perform revocation
        let result = revoke_signed_file(
            &artifact_path,
            &revocation_json,
            &revocation_signature,
            initiator_pubkey,
        )?;

        let second_pubkey = test_keys.pub_key(1).unwrap();
        let second_seckey = test_keys.sec_key(1).unwrap();
        let second_signature = second_seckey.sign(&revocation_hash)?;

        let revocation_file_path = revocation_path_for(&artifact_path)?;
        let revocation_sig_path = revocation_signatures_path_for(&artifact_path)?;
        let revocation_signers_path = revocation_signers_path_for(&artifact_path)?;
        let revoked_sig_path = revoked_signatures_path_for(&artifact_path)?;

        let pending_revocation_file_path = pending_revocation_path_for(&artifact_path)?;
        let pending_revocation_sig_path =
            pending_signatures_path_for(&pending_revocation_file_path)?;

        let pending = result
            .get_pending()
            .expect("Should be pending after first signature");

        assert!(pending_revocation_file_path.exists());
        assert!(pending_revocation_sig_path.exists());
        assert!(!revocation_file_path.exists());
        assert!(!revocation_sig_path.exists());
        assert!(!revocation_signers_path.exists());
        assert!(!revoked_sig_path.exists());

        let _complete = pending
            .add_individual_signature(&second_signature, second_pubkey)?
            .get_complete()
            .expect("Should be complete after both artifact signers");

        assert!(!pending_revocation_file_path.exists());
        assert!(!pending_revocation_sig_path.exists());
        assert!(revocation_file_path.exists());
        assert!(revocation_sig_path.exists());
        assert!(revocation_signers_path.exists());
        assert!(revoked_sig_path.exists());
        // Verify original signatures file was moved
        assert!(!signatures_file.exists());

        let signed_file = SignedFileLoader::load(artifact_path)?;
        assert_eq!(signed_file.kind(), FileType::RevokedArtifact);

        Ok(())
    }

    #[test]
    fn test_revoke_signed_file_with_unauthorized() -> Result<(), Box<dyn std::error::Error>> {
        // Generate test keys (we need at least 3: 2 for artifact signing, 1 for master/revocation)
        let test_keys = TestKeys::new(4);
        let temp_dir = TempDir::new()?;

        // Create signers setup with master keys and explicit revocation keys (key 2)
        create_complete_signers_setup(&temp_dir, &test_keys, None, Some(vec![2]), Some(vec![3]))?;

        // Create signed artifact file
        let artifact_path =
            create_signed_artifact_file(&temp_dir, &test_keys, b"Protected artifact")?;

        // Prepare revocation with non-master key (key 1 - artifact signer, not master)
        let timestamp = Utc::now();
        let subject_digest = common::sha512_for_file(&artifact_path)?;
        let unauthorized_pubkey = test_keys.pub_key(1).unwrap(); // Not a master key
        let revocation_json =
            create_revocation_json(timestamp, &subject_digest, unauthorized_pubkey)?;

        // Sign the revocation JSON
        let revocation_hash = common::sha512_for_content(revocation_json.as_bytes().to_vec())?;
        let unauthorized_seckey = test_keys.sec_key(1).unwrap();
        let revocation_signature = unauthorized_seckey.sign(&revocation_hash)?;

        // Attempt revocation - should fail
        let result = revoke_signed_file(
            &artifact_path,
            &revocation_json,
            &revocation_signature,
            unauthorized_pubkey,
        );

        assert!(result.is_err());
        match result {
            Err(e) => {
                let err_str = e.to_string();
                assert!(
                    err_str.contains("Public key is not authorized to revoke this file")
                        || err_str.contains("Signature verification failed"),
                    "Unexpected error: {}",
                    err_str
                );
            }
            Ok(_) => panic!("Expected revocation to fail for unauthorized key"),
        }

        // Verify no revocation file was create
        let revocation_file_path = revocation_path_for(&artifact_path)?;
        assert!(!revocation_file_path.exists());
        let revocation_sig_path = revocation_signatures_path_for(&artifact_path)?;
        assert!(!revocation_sig_path.exists());
        let revocation_signers_path = revocation_signers_path_for(&artifact_path)?;
        assert!(!revocation_signers_path.exists());
        let revoked_sig_path = revoked_signatures_path_for(&artifact_path)?;
        assert!(!revoked_sig_path.exists());

        Ok(())
    }
    #[test]
    fn test_revoke_signed_file_with_invalid_signature() -> Result<(), Box<dyn std::error::Error>> {
        let temp_dir4 = TempDir::new()?;
        // Generate test keys (we need at least 3: 2 for artifact signing, 1 for master/revocation)
        let test_keys = TestKeys::new(4);

        // Create signers setup with master keys and explicit revocation keys (key 2)
        create_complete_signers_setup(&temp_dir4, &test_keys, None, Some(vec![2]), Some(vec![3]))?;

        // Create signed artifact file
        let artifact_path =
            create_signed_artifact_file(&temp_dir4, &test_keys, b"Another artifact")?;

        // Prepare revocation with revocation key (key 3) but sign wrong data
        let timestamp = Utc::now();
        let subject_digest = common::sha512_for_file(&artifact_path)?;
        let revocation_pubkey = test_keys.pub_key(3).unwrap();
        let revocation_json =
            create_revocation_json(timestamp, &subject_digest, revocation_pubkey)?;

        // Sign WRONG data (different hash)
        let wrong_hash = common::sha512_for_content(b"wrong data".to_vec())?;
        let revocation_seckey = test_keys.sec_key(3).unwrap();
        let wrong_signature = revocation_seckey.sign(&wrong_hash)?;

        // Attempt revocation - should fail due to invalid signature
        let result = revoke_signed_file(
            &artifact_path,
            &revocation_json,
            &wrong_signature,
            revocation_pubkey,
        );

        assert!(result.is_err());
        match result {
            Err(e) => {
                let err_str = e.to_string();
                assert!(
                    err_str.contains("Signature verification failed"),
                    "Expected signature verification error, got: {}",
                    err_str
                );
            }
            Ok(_) => panic!("Expected revocation to fail with invalid signature"),
        }

        // Verify no revocation file was create
        let revocation_file_path = revocation_path_for(&artifact_path)?;
        assert!(!revocation_file_path.exists());
        let revocation_sig_path = revocation_signatures_path_for(&artifact_path)?;
        assert!(!revocation_sig_path.exists());
        let revocation_signers_path = revocation_signers_path_for(&artifact_path)?;
        assert!(!revocation_signers_path.exists());
        let revoked_sig_path = revoked_signatures_path_for(&artifact_path)?;
        assert!(!revoked_sig_path.exists());

        Ok(())
    }

    #[test]
    fn test_revoke_inexisting_signed_file() -> Result<(), Box<dyn std::error::Error>> {
        // Generate test keys (we need at least 3: 2 for artifact signing, 1 for master/revocation)
        let test_keys = TestKeys::new(4);
        let temp_dir = TempDir::new()?;
        create_complete_signers_setup(&temp_dir, &test_keys, None, Some(vec![2]), Some(vec![3]))?;

        let non_existent_path = temp_dir.path().join("nonexistent.bin");
        let master_pubkey = test_keys.pub_key(2).unwrap();
        let master_seckey = test_keys.sec_key(2).unwrap();

        let timestamp = Utc::now();
        let dummy_digest = common::sha512_for_content(b"dummy".to_vec())?;
        let revocation_json = create_revocation_json(timestamp, &dummy_digest, master_pubkey)?;
        let revocation_hash = common::sha512_for_content(revocation_json.as_bytes().to_vec())?;
        let signature = master_seckey.sign(&revocation_hash)?;

        let result = revoke_signed_file(
            &non_existent_path,
            &revocation_json,
            &signature,
            master_pubkey,
        );

        assert!(result.is_err());
        match result {
            Err(e) => {
                let err_str = e.to_string();
                assert!(
                    err_str.contains("Signed file not found"),
                    "Expected file not found error, got: {}",
                    err_str
                );
            }
            Ok(_) => panic!("Expected revocation to fail for non-existent file"),
        }

        // Verify no revocation file was create
        let revocation_file_path = revocation_path_for(&non_existent_path)?;
        assert!(!revocation_file_path.exists());
        let revocation_sig_path = revocation_signatures_path_for(&non_existent_path)?;
        assert!(!revocation_sig_path.exists());
        let revocation_signers_path = revocation_signers_path_for(&non_existent_path)?;
        assert!(!revocation_signers_path.exists());
        let revoked_sig_path = revoked_signatures_path_for(&non_existent_path)?;
        assert!(!revoked_sig_path.exists());

        Ok(())
    }

    #[test]
    fn test_revoke_directory_should_fail() -> Result<(), Box<dyn std::error::Error>> {
        // Generate test keys (we need at least 3: 2 for artifact signing, 1 for master/revocation)
        let test_keys = TestKeys::new(4);

        let temp_dir = TempDir::new()?;
        create_complete_signers_setup(&temp_dir, &test_keys, None, Some(vec![2]), Some(vec![3]))?;

        let dir_path = temp_dir.path().join("subdir");
        fs::create_dir(&dir_path)?;

        let master_pubkey = test_keys.pub_key(2).unwrap();
        let master_seckey = test_keys.sec_key(2).unwrap();

        let timestamp = Utc::now();
        let dummy_digest = common::sha512_for_content(b"dummy".to_vec())?;
        let revocation_json = create_revocation_json(timestamp, &dummy_digest, master_pubkey)?;
        let revocation_hash = common::sha512_for_content(revocation_json.as_bytes().to_vec())?;
        let signature = master_seckey.sign(&revocation_hash)?;

        let result = revoke_signed_file(&dir_path, &revocation_json, &signature, master_pubkey);

        assert!(result.is_err());
        match result {
            Err(e) => {
                let err_str = e.to_string();
                assert!(
                    err_str.contains("Cannot revoke a directory"),
                    "Expected directory error, got: {}",
                    err_str
                );
            }
            Ok(_) => panic!("Expected revocation to fail for directory"),
        }

        Ok(())
    }

    #[test]
    fn test_revoke_signed_file_master_fails_with_explicit_revocation_group()
    -> Result<(), Box<dyn std::error::Error>> {
        // When explicit revocation keys exist, master key should NOT be able to revoke
        let test_keys = TestKeys::new(4);
        let temp_dir = TempDir::new()?;

        // master=key 2, revocation=key 3
        create_complete_signers_setup(&temp_dir, &test_keys, None, Some(vec![2]), Some(vec![3]))?;

        let artifact_path =
            create_signed_artifact_file(&temp_dir, &test_keys, b"Protected artifact")?;

        // Try to revoke with master key (key 2) — should fail
        let timestamp = Utc::now();
        let subject_digest = common::sha512_for_file(&artifact_path)?;
        let master_pubkey = test_keys.pub_key(2).unwrap();
        let revocation_json = create_revocation_json(timestamp, &subject_digest, master_pubkey)?;

        let revocation_hash = common::sha512_for_content(revocation_json.as_bytes().to_vec())?;
        let master_seckey = test_keys.sec_key(2).unwrap();
        let revocation_signature = master_seckey.sign(&revocation_hash)?;

        let result = revoke_signed_file(
            &artifact_path,
            &revocation_json,
            &revocation_signature,
            master_pubkey,
        );

        assert!(result.is_err());
        match result {
            Err(e) => {
                let err_str = e.to_string();
                assert!(
                    err_str.contains("Public key is not authorized to revoke this file"),
                    "Expected authorization error, got: {}",
                    err_str
                );
            }
            Ok(_) => {
                panic!("Expected revocation to fail for master key when revocation group exists")
            }
        }

        // Verify no revocation files were created
        let revocation_file_path = revocation_path_for(&artifact_path)?;
        assert!(!revocation_file_path.exists());

        Ok(())
    }

    #[test]
    fn test_revoke_signed_file_with_admin_ok() -> Result<(), Box<dyn std::error::Error>> {
        // When no master and no explicit revocation keys, admin is the revocation fallback
        let test_keys = TestKeys::new(3);
        let temp_dir = TempDir::new()?;

        // admin=key 2, no master, no revocation
        create_complete_signers_setup(&temp_dir, &test_keys, Some(vec![2]), None, None)?;

        let artifact_path =
            create_signed_artifact_file(&temp_dir, &test_keys, b"Admin revocable artifact")?;
        let signatures_file = signatures_path_for(&artifact_path)?;

        // Revoke with admin key (key 2) — should succeed via revocation_keys() fallback
        let timestamp = Utc::now();
        let subject_digest = common::sha512_for_file(&artifact_path)?;
        let admin_pubkey = test_keys.pub_key(2).unwrap();
        let revocation_json = create_revocation_json(timestamp, &subject_digest, admin_pubkey)?;

        let revocation_hash = common::sha512_for_content(revocation_json.as_bytes().to_vec())?;
        let admin_seckey = test_keys.sec_key(2).unwrap();
        let revocation_signature = admin_seckey.sign(&revocation_hash)?;

        let result = revoke_signed_file(
            &artifact_path,
            &revocation_json,
            &revocation_signature,
            admin_pubkey,
        )?;

        // Single admin key as revocation fallback → threshold 1 → should complete immediately
        assert!(
            result.is_complete(),
            "Single-signer revocation should return Complete, got Pending"
        );

        // Verify revocation succeeded
        let revocation_file_path = revocation_path_for(&artifact_path)?;
        assert!(revocation_file_path.exists());
        let revocation_sig_path = revocation_signatures_path_for(&artifact_path)?;
        assert!(revocation_sig_path.exists());
        let revocation_signers_path = revocation_signers_path_for(&artifact_path)?;
        assert!(revocation_signers_path.exists());
        let revoked_sig_path = revoked_signatures_path_for(&artifact_path)?;
        assert!(revoked_sig_path.exists());
        // Original signatures file was moved
        assert!(!signatures_file.exists());

        Ok(())
    }

    #[test]
    fn test_revoke_signed_file_with_revocation_threshold_gt_1()
    -> Result<(), Box<dyn std::error::Error>> {
        let test_keys = TestKeys::new(5);

        let temp_dir = TempDir::new()?;

        // Create signers setup with 2 revocation keys (keys 3, 4) -> threshold will be 2
        create_complete_signers_setup(
            &temp_dir,
            &test_keys,
            None,
            Some(vec![2]),
            Some(vec![3, 4]),
        )?;

        let artifact_path =
            create_signed_artifact_file(&temp_dir, &test_keys, b"Multi-sig revocation artifact")?;

        let timestamp = Utc::now();
        let subject_digest = common::sha512_for_file(&artifact_path)?;
        let initiator_pubkey = test_keys.pub_key(3).unwrap();
        let revocation_json = create_revocation_json(timestamp, &subject_digest, initiator_pubkey)?;

        let revocation_hash = common::sha512_for_content(revocation_json.as_bytes().to_vec())?;

        // First signature from key 3
        let initiator_seckey = test_keys.sec_key(3).unwrap();
        let first_signature = initiator_seckey.sign(&revocation_hash)?;

        // After first signature, revocation should be pending (threshold is 2)
        let result = revoke_signed_file(
            &artifact_path,
            &revocation_json,
            &first_signature,
            initiator_pubkey,
        )?;
        assert!(
            result.is_pending(),
            "Revocation should be pending after first signature"
        );

        // Verify pending revocation file exists
        let pending_revocation_path = pending_revocation_path_for(&artifact_path)?;
        assert!(pending_revocation_path.exists());

        // Verify final revocation file does NOT exist yet
        let revocation_file_path = revocation_path_for(&artifact_path)?;
        assert!(!revocation_file_path.exists());

        // Add second signature from key 4
        let second_pubkey = test_keys.pub_key(4).unwrap();
        let second_seckey = test_keys.sec_key(4).unwrap();
        let second_signature = second_seckey.sign(&revocation_hash)?;

        let pending = result.get_pending().expect("Should have pending signature");
        let _complete = pending
            .add_individual_signature(&second_signature, second_pubkey)?
            .get_complete()
            .expect("Should be complete after both revocation signatures");

        // Now verify revocation files exist
        assert!(revocation_file_path.exists());
        let revocation_sig_path = revocation_signatures_path_for(&artifact_path)?;
        assert!(revocation_sig_path.exists());
        let revocation_signers_path = revocation_signers_path_for(&artifact_path)?;
        assert!(revocation_signers_path.exists());
        let revoked_sig_path = revoked_signatures_path_for(&artifact_path)?;
        assert!(revoked_sig_path.exists());

        // Verify the signatures file was moved
        let signatures_file = signatures_path_for(&artifact_path)?;
        assert!(!signatures_file.exists());

        // Verify both signatures are in the revocation signature file
        let revocation_sig_content = fs::read_to_string(&revocation_sig_path)?;
        let revocation_sig_file: signatures::signatures_file::SignaturesFile =
            serde_json::from_str(&revocation_sig_content)?;
        assert_eq!(revocation_sig_file.entries.len(), 2);
        assert!(
            revocation_sig_file
                .entries
                .contains_key(&initiator_pubkey.to_base64())
        );
        assert!(
            revocation_sig_file
                .entries
                .contains_key(&second_pubkey.to_base64())
        );

        Ok(())
    }

    #[test]
    fn test_revoke_signed_file_second_call_errors_when_pending_exists()
    -> Result<(), Box<dyn std::error::Error>> {
        // Bug: revoke_signed_file overwrites the pending signatures file each time,
        // so calling it with a second signer loses the first signer's signature.
        let test_keys = TestKeys::new(5);
        let temp_dir = TempDir::new()?;

        // 2 revocation keys (keys 3, 4) → threshold 2
        create_complete_signers_setup(
            &temp_dir,
            &test_keys,
            None,
            Some(vec![2]),
            Some(vec![3, 4]),
        )?;

        let artifact_path =
            create_signed_artifact_file(&temp_dir, &test_keys, b"Multi-sig revocation artifact")?;

        let pending_sig_path = pending_revocation_pending_signatures_path_for(&artifact_path)?;
        let revocation_sig_path = revocation_signatures_path_for(&artifact_path)?;

        let timestamp = Utc::now();
        let subject_digest = common::sha512_for_file(&artifact_path)?;
        let first_pubkey = test_keys.pub_key(3).unwrap();
        let revocation_json = create_revocation_json(timestamp, &subject_digest, first_pubkey)?;
        let revocation_hash = common::sha512_for_content(revocation_json.as_bytes().to_vec())?;

        // First revocation call with key 3
        let first_seckey = test_keys.sec_key(3).unwrap();
        let first_signature = first_seckey.sign(&revocation_hash)?;

        let result = revoke_signed_file(
            &artifact_path,
            &revocation_json,
            &first_signature,
            first_pubkey,
        )?;
        assert!(
            result.is_pending(),
            "Should be pending after first signature"
        );
        assert!(
            pending_sig_path.exists(),
            "Pending revocation signatures file should exist"
        );
        assert!(
            !revocation_sig_path.exists(),
            "Final revocation signatures file should not exist"
        );

        // Read the pending signatures file and verify key 3's signature is present
        let pending_revocation_file_path = pending_revocation_path_for(&artifact_path)?;
        let pending_sig_path = pending_signatures_path_for(&pending_revocation_file_path)?;
        let sig_content = fs::read_to_string(&pending_sig_path)?;
        let sig_file: signatures::signatures_file::SignaturesFile =
            serde_json::from_str(&sig_content)?;
        assert_eq!(
            sig_file.entries.len(),
            1,
            "Should have 1 signature after first call"
        );
        assert!(sig_file.entries.contains_key(&first_pubkey.to_base64()));

        // Second revocation call with key 4 — should now ERROR because
        // pending revocation already exists. Additional signatures go
        // through sign-pending, not revoke.
        let second_pubkey = test_keys.pub_key(4).unwrap();
        let second_seckey = test_keys.sec_key(4).unwrap();
        let second_signature = second_seckey.sign(&revocation_hash)?;

        let result = revoke_signed_file(
            &artifact_path,
            &revocation_json,
            &second_signature,
            second_pubkey,
        );

        assert!(
            result.is_err(),
            "Second revoke call should error when pending exists"
        );
        let err = match result {
            Err(e) => e.to_string(),
            Ok(_) => panic!("Expected error but got Ok"),
        };
        assert!(
            err.contains("pending revocation already exists"),
            "Error should mention existing pending revocation, got: {}",
            err
        );
        // Signatures of the revocation should not have changed
        assert!(
            pending_sig_path.exists(),
            "Pending revocation signatures file should exist"
        );
        assert!(
            !revocation_sig_path.exists(),
            "Final revocation signatures file should not exist"
        );

        // Verify first signature is still intact
        let sig_content = fs::read_to_string(&pending_sig_path)?;
        let sig_file: signatures::signatures_file::SignaturesFile =
            serde_json::from_str(&sig_content)?;
        assert_eq!(
            sig_file.entries.len(),
            1,
            "Should still have exactly 1 signature"
        );
        assert!(sig_file.entries.contains_key(&first_pubkey.to_base64()));

        let pending_revocation = SignatureWithState::load_for_file(pending_revocation_file_path)?;
        let final_sig = pending_revocation
            .get_pending()
            .unwrap()
            .add_individual_signature(&second_signature, second_pubkey)?;

        assert!(final_sig.is_complete());

        assert!(
            !pending_sig_path.exists(),
            "Pending revocation signatures file should not exist after both signers called revoke_signed_file"
        );
        assert!(
            revocation_sig_path.exists(),
            "Final revocation signatures file should exist after both signers called revoke_signed_file"
        );

        let signed_file = SignedFileLoader::load(artifact_path)?;
        assert_eq!(signed_file.kind(), FileType::RevokedArtifact);

        Ok(())
    }
}
