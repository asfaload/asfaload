#[cfg(test)]
mod validate_history_rotation_tests;

use aggregate_signature::{AggregateSignature, CompleteSignature, SignatureWithState};
use common::{
    SignedFileLoader,
    errors::{AggregateSignatureError, SignersChainError, SignersFileError},
    fs::{
        names::{
            find_global_signers_for, history_file_path_for, metadata_path_for,
            metadata_signatures_path_for, pending_signatures_path_for, signatures_path_for,
        },
        open_new_file,
    },
};
use constants::{PENDING_SIGNERS_DIR, SIGNERS_DIR, SIGNERS_FILE, SIGNERS_HISTORY_FILE};
use signatures::{
    signatures_file::SignaturesFile,
    types::{AsfaloadPublicKeys, AsfaloadSignatures},
};
use signers_file_types::{
    CurrentSignersInfo, HistoryEntry, HistoryFile, SignersChain, SignersConfig,
    SignersConfigMetadata, SignersConfigProposal, parse_signers_config,
    parse_signers_config_proposal,
};
use std::{borrow::Borrow, convert::identity, ffi::OsStr, fs, io::Write, path::Path};
//

/// Validate that the pubkey is authorized to initialize a signers file.
/// For initial signers, the pubkey must be in the admin_keys group (if present)
/// or in the artifact_signers group (if admin_keys is not present).
fn is_valid_signer_for_signer_init(
    pubkey: &AsfaloadPublicKeys,
    config: &SignersConfig,
) -> Result<(), SignersFileError> {
    let is_valid = config.admin_keys().iter().any(|group| {
        group
            .signers
            .iter()
            .any(|signer| signer.data.pubkey == *pubkey)
    });
    if is_valid {
        Ok(())
    } else {
        Err(SignersFileError::InvalidSigner(
            "The provided public key is not in the required groups for signers init".to_string(),
        ))
    }
}

/// Validate that the pubkey is authorized to propose a signers file update.
/// For updates, the pubkey must be in the admin_keys or master_keys group
/// of the currently active signers file.
fn is_valid_signer_for_update_of(
    pubkey: &AsfaloadPublicKeys,
    active_config: &SignersConfig,
) -> Result<(), SignersFileError> {
    let is_valid = active_config.admin_keys().iter().any(|group| {
        group
            .signers
            .iter()
            .any(|signer| signer.data.pubkey == *pubkey)
    }) || active_config
        .master_keys()
        .unwrap_or_default()
        .iter()
        .any(|group| {
            group
                .signers
                .iter()
                .any(|signer| signer.data.pubkey == *pubkey)
        });
    if is_valid {
        Ok(())
    } else {
        Err(SignersFileError::InvalidSigner(
            "The provided public key is not in the required groups of current config for signers update".to_string(),
        ))
    }
}

pub fn sign_signers_and_metadata_file<P>(
    signers_file_path: P,
    signature: &AsfaloadSignatures,
    pubkey: &AsfaloadPublicKeys,
    metadata_signature: &AsfaloadSignatures,
) -> Result<SignatureWithState, SignersFileError>
where
    P: AsRef<Path>,
{
    let signed_file = SignedFileLoader::load(&signers_file_path)?;
    if !(signed_file.is_initial_signers() || signed_file.is_signers()) {
        return Err(SignersFileError::FileSystemHierarchyError(format!(
            "Trying to sign a file as signers file, which it is not: {}",
            signers_file_path.as_ref().to_string_lossy()
        )));
    }

    // Sign the metadata file first
    let metadata_file_path = metadata_path_for(&signers_file_path)?;
    let metadata_agg_sig = SignatureWithState::load_for_file(&metadata_file_path)?;
    match metadata_agg_sig {
        SignatureWithState::Pending(pending) => {
            pending
                .add_individual_signature(metadata_signature, pubkey)
                .map_err(SignersFileError::from)?;
        }
        SignatureWithState::Complete(_) => {
            // Metadata signature already complete, nothing to do
        }
    }

    // Now sign the signers file itself
    let agg_sig = SignatureWithState::load_for_file(&signers_file_path)?;
    let pending_sig = agg_sig
        .get_pending()
        .ok_or(SignersFileError::AggregateSignatureError(
            AggregateSignatureError::SignatureAlreadyComplete,
        ))?;
    let new_state = pending_sig
        .add_individual_signature(signature, pubkey)
        .map_err(SignersFileError::from)?;

    // If the signature completed, activate the signers file.
    if let SignatureWithState::Complete(ref complete) = new_state {
        activate_signers_file(complete)?;
    }

    Ok(new_state)
}

/// Write a validated signers file to a pending directory.
///
/// This function validates the provided JSON content by deserializing it into a SignersConfig,
/// then creates the pending signers file, its metadata file, and an empty pending signatures file.
/// Signing happens separately via sign-pending.
///
/// # Arguments
/// * `dir_path_in` - The directory where the pending signers file should be placed. If it is not the
///   path to a directory named ${PENDING_SIGNERS_DIR}, a subdirectory with name ${PENDING_SIGNERS_DIR} is created.
/// * `json_content` - The JSON content of the signers configuration
/// * `metadata` - The metadata for the signers configuration
///
/// # Returns
/// * `Ok(())` if the pending file was successfully created
/// * `Err(SignersFileError)` if there was an error validating the JSON or writing the file
pub fn write_valid_signers_file<P: AsRef<Path>>(
    dir_path_in: P,
    json_content: &str,
    metadata_json: &str,
) -> Result<(), SignersFileError> {
    // Ensure we work in the right directory

    let dir_path = {
        if dir_path_in.as_ref().ends_with(PENDING_SIGNERS_DIR) {
            dir_path_in.as_ref().to_path_buf()
        } else {
            dir_path_in.as_ref().join(PENDING_SIGNERS_DIR)
        }
    };

    // If a signers file exists, we refuse to overwrite it
    let signers_file_path = dir_path.join(SIGNERS_FILE);
    if signers_file_path.exists() {
        return Err(SignersFileError::InitialisationError(format!(
            "Signers file exists: {}",
            signers_file_path.to_string_lossy()
        )));
    }

    // If a metadata file exists, we refuse to overwrite it
    let metadata_file_path = metadata_path_for(&signers_file_path)?;
    if metadata_file_path.exists() {
        return Err(SignersFileError::InitialisationError(format!(
            "Metadata file exists: {}",
            metadata_file_path.to_string_lossy()
        )));
    }
    // If a pending signatures file already exists, we refuse to create a pending signers file.
    // We use the function not looking to disk content here, and check on disk ourselves.
    let pending_signature_file_path = pending_signatures_path_for(signers_file_path.clone())?;

    if pending_signature_file_path.exists() {
        return Err(SignersFileError::InitialisationError(format!(
            "Pending signature file exists, refusing to initialise over it: {}",
            pending_signature_file_path.to_string_lossy()
        )));
    }
    // If a complete signatures file already exists, we refuse to create a pending signers file.
    // We use the function not looking to disk content here, and check on disk ourselves.
    let complete_signature_file_path = signatures_path_for(&signers_file_path)?;

    if complete_signature_file_path.exists() {
        return Err(SignersFileError::InitialisationError(format!(
            "Complete signature file exists: {}",
            complete_signature_file_path.to_string_lossy()
        )));
    }
    // First, validate the JSON by parsing it
    let _signers_config: SignersConfig = parse_signers_config(json_content)?;
    let _metadata_content: SignersConfigMetadata = serde_json::from_str(metadata_json)?;

    // Now that all validation have taken place, we can ensure directory exists
    // and create it if not.
    std::fs::create_dir_all(&dir_path)?;

    let result = (|| -> Result<(), SignersFileError> {
        // Write the metadata file (self-authored: canonical trailing newline)
        let mut metadata_file = open_new_file(&metadata_file_path)?;
        metadata_file.write_all(metadata_json.as_bytes())?;
        // Write the JSON content to the pending signers file
        let mut signers_file = open_new_file(&signers_file_path)?;
        signers_file.write_all(json_content.as_bytes())?;
        Ok(())
    })();

    if result.is_err() {
        let _ = std::fs::remove_dir_all(&dir_path);
    }

    result
}
pub fn initialize_signers_file<P: AsRef<Path>>(
    dir_path_in: P,
    json_content_in: impl AsRef<str>,
    metadata: impl AsRef<str>,
    pubkey: &AsfaloadPublicKeys,
) -> Result<(), SignersFileError> {
    let json_content = json_content_in.as_ref();
    let metadata_json_content = metadata.as_ref();
    if dir_path_in.as_ref().join(SIGNERS_DIR).exists()
        || dir_path_in.as_ref().join(PENDING_SIGNERS_DIR).exists()
    {
        return Err(SignersFileError::InitialisationError(format!(
            "Cannot initialise a signers dir in a directory with an existing signers dir: {}",
            dir_path_in.as_ref().to_string_lossy(),
        )));
    }
    let signers_config: SignersConfig = parse_signers_config(json_content)?;
    is_valid_signer_for_signer_init(pubkey, &signers_config)?;
    write_valid_signers_file(dir_path_in.as_ref(), json_content, metadata_json_content)
}

/// Propose an update to an existing signers file.
///
/// This function validates the proposed update's timestamp against the active signers file,
/// then creates a new pending signers file with an empty pending signatures file.
/// Signing happens separately via sign-pending.
///
/// # Arguments
/// * `dir_path` - The directory where the pending signers file should be placed
/// * `json_content` - The JSON content of the new signers configuration
/// * `metadata` - The metadata for the signers configuration
///
/// # Returns
/// * `Ok(())` if the pending file was successfully created
/// * `Err(SignersFileError)` if there was an error validating or creating the file
pub fn propose_signers_file<P: AsRef<Path>>(
    dir_path: P,
    json_content: &str,
    metadata_json: &str,
    pubkey: &AsfaloadPublicKeys,
) -> Result<(), SignersFileError> {
    // Determine the path to the active signers file
    let active_signers_file = find_global_signers_for(dir_path.as_ref()).map_err(|e| {
        SignersFileError::InitialisationError(format!(
            "Active signers file not found for {}: {}",
            dir_path.as_ref().to_string_lossy(),
            e
        ))
    })?;

    // Check if the active signers file exists
    if !active_signers_file.exists() {
        return Err(SignersFileError::InitialisationError(format!(
            "Active signers file does not exist: {}",
            active_signers_file.to_string_lossy()
        )));
    }

    // Parse the active signers file
    let active_config = SignersConfig::from_file(&active_signers_file)?;

    let proposed_update: SignersConfigProposal = parse_signers_config_proposal(json_content)?;
    if proposed_update.timestamp <= active_config.timestamp() {
        return Err(SignersFileError::InvalidData(format!(
            "Timestamp of update is smaller than active signers file's: update:{} <= active:{}",
            proposed_update.timestamp,
            active_config.timestamp()
        )));
    }

    // Check if the provided pubkey is in the admin_keys or master_keys groups
    is_valid_signer_for_update_of(pubkey, &active_config)?;

    write_valid_signers_file(dir_path, json_content, metadata_json)
}

fn move_current_signers_to_history<Pa: AsRef<Path>>(dir: Pa) -> Result<(), SignersFileError> {
    let root_dir = dir.as_ref();
    let active_signers_dir = root_dir.join(SIGNERS_DIR);
    let active_signers_file = active_signers_dir.join(SIGNERS_FILE);
    let history_file_path = root_dir.join(SIGNERS_HISTORY_FILE);

    // Read existing active signers configuration. This is the content that is signed
    // and must be kept intact when moved to the history file
    let existing_content = fs::read_to_string(&active_signers_file)?;

    // Read the signatures file for the active signers
    let signatures_file_path = signatures_path_for(&active_signers_file)?;
    let signatures_content = fs::read_to_string(&signatures_file_path)?;
    let signatures: SignaturesFile = serde_json::from_str(&signatures_content)?;

    // Read the metadata file for the active signers (keep as raw string to preserve exact bytes)
    let metadata_file_path = metadata_path_for(&active_signers_file)?;
    let metadata_content = fs::read_to_string(&metadata_file_path)?;

    // Read the metadata signatures file for the active signers
    let metadata_signatures_file_path = metadata_signatures_path_for(&active_signers_file)?;
    let metadata_signatures_content = fs::read_to_string(&metadata_signatures_file_path)?;
    let metadata_signatures: SignaturesFile = serde_json::from_str(&metadata_signatures_content)?;

    // Get current UTC time as ISO8601 string
    let obsoleted_at = chrono::Utc::now();

    // Validate that the existing content is a valid SignersConfig
    let _existing_config: SignersConfig = parse_signers_config(&existing_content)?;

    // Create the history entry using the raw JSON content (preserves original formatting)
    let history_entry = HistoryEntry {
        obsoleted_at,
        signers_file: existing_content,
        signatures,
        metadata: metadata_content,
        metadata_signatures,
    };

    // Read or create history file
    let mut history_file: HistoryFile = if history_file_path.exists() {
        let history_content = fs::read_to_string(&history_file_path)?;
        if history_content.trim().is_empty() {
            HistoryFile::new()
        } else {
            HistoryFile::from_json(&history_content)?
        }
    } else {
        HistoryFile::new()
    };

    // Append the new entry
    history_file.add_entry(history_entry);

    // Write updated history
    history_file.save_to_file(&history_file_path)?;

    // Remove existing active signers directory
    fs::remove_dir_all(&active_signers_dir)?;
    Ok(())
}

pub fn activate_signers_file<A>(agg_sig: A) -> Result<(), SignersFileError>
where
    A: Borrow<AggregateSignature<CompleteSignature>>,
{
    let agg_sig = agg_sig.borrow();
    if agg_sig.subject().is_artifact() {
        return Err(SignersFileError::FileSystemHierarchyError(format!(
            "Cannot activate a signers file for file of type {}",
            agg_sig.subject().kind()
        )));
    }
    let location = &agg_sig.subject().location();
    let signers_file_path = Path::new(location);

    // Verify the signers file is in a pending directory
    let pending_dir = signers_file_path.parent().ok_or_else(|| {
        SignersFileError::FileSystemHierarchyError(signers_file_path.to_string_lossy().to_string())
    })?;

    if pending_dir.file_name() != Some(OsStr::new(PENDING_SIGNERS_DIR)) {
        return Err(SignersFileError::NotInPendingDir(
            pending_dir.to_string_lossy().to_string(),
        ));
    }

    let root_dir = pending_dir.parent().ok_or_else(|| {
        SignersFileError::FileSystemHierarchyError(pending_dir.to_string_lossy().to_string())
    })?;

    // Handle existing active signers file and history
    let active_signers_dir = root_dir.join(SIGNERS_DIR);
    let active_signers_file = active_signers_dir.join(SIGNERS_FILE);

    if active_signers_file.exists() {
        move_current_signers_to_history(root_dir)?;
    }

    // Rename pending directory to active directory
    fs::rename(pending_dir, &active_signers_dir)?;

    Ok(())
}

/// Verify that every signer listed in `signers_file`'s parsed config has signed
/// both the `signers_file` bytes and the `metadata` bytes. This is the
/// trust-anchor check applied to the genesis entry of a chain — whichever
/// entry that is.
fn validate_full_signatures(
    signers_file: &str,
    signatures: &SignaturesFile,
    metadata: &str,
    metadata_signatures: &SignaturesFile,
) -> bool {
    let signers = match parse_signers_config(signers_file) {
        Ok(c) => c,
        Err(_) => return false,
    };
    aggregate_signature::verify_all_signers_signed(signers_file.as_bytes(), signatures, &signers)
        .is_ok_and(identity)
        && aggregate_signature::verify_all_signers_signed(
            metadata.as_bytes(),
            metadata_signatures,
            &signers,
        )
        .is_ok_and(identity)
}

/// Validate that every transition between consecutive entries in a signers
/// history is properly authorized.
///
/// For each adjacent pair, verifies that the newer entry's signatures
/// satisfy `validate_signers_update` against the older entry's config. Also
/// enforces strict monotonic ordering of `obsoleted_at`. The genesis entry
/// itself is NOT checked here, see validate_chain
///
/// An empty or single-entry history is considered valid (vacuously, as there
/// are no transitions to verify).
pub fn validate_history_transitions(history: &SignersChain) -> Result<(), SignersChainError> {
    // Strict ordering: equal `obsoleted_at` timestamps are rejected. In
    // practice two entries should never share an obsolescence instant, and
    // accepting it would weaken chain auditability. Only history entries
    // carry an `obsoleted_at` — the current entry is the still-active one.
    if !history
        .history_entries()
        .windows(2)
        .all(|p| p[0].obsoleted_at < p[1].obsoleted_at)
    {
        return Err(SignersChainError::ChainOrderingError(
            "entries are not ordered chronologically".into(),
        ));
    }

    history.entries().windows(2).try_for_each(|pair| {
        let parent = &pair[0];
        let updated = &pair[1];

        let parent_signers = parent.signers_config().map_err(|e| {
            SignersChainError::GenericError(format!(
                "Problem getting parent signers of transition: {e}"
            ))
        })?;
        let updated_signers = updated.signers_config().map_err(|e| {
            SignersChainError::GenericError(format!(
                "Problem getting updated signers of transition: {e}"
            ))
        })?;

        // Hash the raw JSON bytes (exactly what was originally signed)
        let file_hash = common::sha512_for_content(updated.signers_file().as_bytes().to_vec())
            .map_err(|e| {
                SignersChainError::GenericError(format!(
                    "Problem computing sha512 of signers file content: {e}"
                ))
            })?;

        let signatures = aggregate_signature::parse_tagged_signatures(
            &updated.signatures().entries,
        )
        .map_err(|e| {
            SignersChainError::GenericError(format!("Problem parsing tagged signatures: {e}"))
        })?;

        aggregate_signature::validate_signers_update(
            &updated_signers,
            &parent_signers,
            &signatures,
            &file_hash,
        )
        .then_some(())
        .ok_or(SignersChainError::GenericError(
            "Signatures criteria for signers update not respected".into(),
        ))
    })
}

/// Full cryptographic validation of a signers chain: genesis entry plus all
/// transitions. Callers that want "validate the whole chain" should use this.
///
/// An empty chain is considered invalid: a current signers entry is required.
pub fn validate_chain(chain: &SignersChain) -> Result<(), SignersChainError> {
    let current = match chain.current_signers_info() {
        // No current signers: we need at least a current signers file in the chain
        None => return Err(SignersChainError::CurrentNotFound),
        Some(c) => c,
    };

    // Genesis is the oldest entry in the chain — the first history entry if any,
    // otherwise the current entry. The genesis must be fully signed (every key
    // in its config signed both file and metadata).
    match chain.history_entries().first() {
        Some(h) => validate_full_signatures(
            &h.signers_file,
            &h.signatures,
            &h.metadata,
            &h.metadata_signatures,
        )
        .then_some(())
        .ok_or(SignersChainError::GenesisEntryError(
            "Full signatures not validated".into(),
        )),
        None => validate_full_signatures(
            &current.signers_file,
            &current.signatures,
            &current.metadata,
            &current.metadata_signatures,
        )
        .then_some(())
        .ok_or(SignersChainError::GenesisEntryError(
            "Genesis entry is current entry, but full signatures not validated".into(),
        )),
    }?;
    validate_history_transitions(chain)
}

/// Build a HistoryFile representing the signers chain applicable to an artifact.
///
/// Filters history entries to those with `obsoleted_at <= cutoff`, then appends
/// the active signers configuration (the one in effect when the artifact was signed)
/// as the final entry with `obsoleted_at` set to the cutoff timestamp.
pub fn signers_chain_for_artifact(
    history: &HistoryFile,
    active_signers_content: &str,
    active_signatures: &SignaturesFile,
    active_metadata_content: &str,
    active_metadata_signatures: &SignaturesFile,
    cutoff: chrono::DateTime<chrono::Utc>,
) -> Result<SignersChain, SignersFileError> {
    //
    // Create empty chain
    let mut chain = SignersChain::default();

    // Collect relevant history entries
    for entry in history.entries() {
        if entry.obsoleted_at <= cutoff {
            chain.add_entry(entry.clone());
        }
    }

    // Set the active-at-that-time signers config
    chain.set_current_info(CurrentSignersInfo {
        signers_file: active_signers_content.to_string(),
        signatures: active_signatures.clone(),
        metadata: active_metadata_content.to_string(),
        metadata_signatures: active_metadata_signatures.clone(),
    });

    Ok(chain)
}

/// Validate the cryptographic chain for a signers file found on disk.
///
/// Reads the signers file and its sidecars, builds a single-entry
/// `HistoryFile`, and validates it via `validate_chain`.
pub fn validate_signers_chain_on_disk(signers_file_path: &Path) -> Result<(), SignersFileError> {
    let chain_err =
        |msg: String| -> SignersFileError { SignersFileError::ChainValidationFailed(msg) };

    let signers_dir = signers_file_path.parent().ok_or_else(|| {
        chain_err(format!(
            "signers file has no parent directory: {}",
            signers_file_path.display()
        ))
    })?;
    let history_file_path = history_file_path_for(signers_dir);
    let history = if history_file_path.exists() {
        HistoryFile::load_from_file(&history_file_path).map_err(|e| {
            chain_err(format!(
                "load history file {}: {e}",
                history_file_path.display()
            ))
        })?
    } else {
        HistoryFile::new()
    };

    let mut chain = SignersChain::default();
    chain.set_entries_from_history(history);

    let entry = CurrentSignersInfo::for_path(signers_file_path)?;
    chain.set_current_info(entry);
    validate_chain(&chain).map_err(|e| {
        SignersFileError::ChainValidationFailed(format!("signers chain validation failed: {e}"))
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use anyhow::Result;
    use common::fs::names::local_signers_path_for;
    use common::fs::names::metadata_path_for;
    use common::fs::names::metadata_signatures_path_for;
    use common::sha512_for_file;
    use constants::{PENDING_SIGNATURES_SUFFIX, SIGNATURES_SUFFIX, SIGNERS_SUFFIX};
    use signatures::keys::AsfaloadPublicKeyTrait;
    use signatures::keys::AsfaloadSecretKeyTrait;
    use signatures::keys::AsfaloadSignatureTrait;
    use signatures::signatures_file::TaggedSignature;
    use signers_file_types::SignerKind;
    use signers_file_types::SignersConfigMetadata;
    use signers_file_types::SignersInfoTrait;
    use signers_file_types::parse_history_file;
    use std::path::PathBuf;
    use tempfile::TempDir;
    use test_helpers::TestKeys;
    use test_helpers::history_helpers::{
        create_test_history_entry, create_test_signers_config, sign_config, sign_metadata,
    };
    use test_helpers::test_metadata;

    /// The test metadata, serialised the way a client would send it. The
    /// metadata functions store this string on disk verbatim.
    fn test_metadata_json() -> String {
        common::to_posix_json(&test_metadata()).unwrap()
    }

    fn assert_metadata_file_valid(root_dir: &Path, is_active: bool) {
        let dir_name = if is_active {
            SIGNERS_DIR
        } else {
            PENDING_SIGNERS_DIR
        };
        let signers_file = root_dir.join(dir_name).join(SIGNERS_FILE);
        let metadata_path = metadata_path_for(&signers_file)
            .unwrap_or_else(|e| panic!("Failed to build metadata path: {}", e));
        assert!(
            metadata_path.exists(),
            "metadata file should exist in {}",
            dir_name
        );
        let content = fs::read_to_string(&metadata_path)
            .unwrap_or_else(|e| panic!("Failed to read metadata file: {}", e));
        let _: SignersConfigMetadata = serde_json::from_str(&content)
            .unwrap_or_else(|e| panic!("Failed to deserialize metadata file: {}", e));
    }

    /// Substitute the known placeholders in fixture templates and insert a timestamp.
    fn render_fixture_template(template: &str, keys: &TestKeys) -> String {
        let timestamp = chrono::Utc::now().to_string();
        render_fixture_template_with_timestamp(template, keys, &timestamp)
    }

    /// Like `render_fixture_template`, but reuses the provided timestamp string.
    fn render_fixture_template_with_timestamp(
        template: &str,
        keys: &TestKeys,
        timestamp: &str,
    ) -> String {
        keys.substitute_keys(template.to_string())
            .replace("TIMESTAMP", timestamp)
    }

    #[test]
    fn test_parsing() {
        let keys = TestKeys::new(10);
        let json_template = r#"
    {
      "version": 1,
      "timestamp": "TIMESTAMP",
      "artifact_signers": [
        {
          "signers": [
            { "kind": "key", "data": { "pubkey": "PUBKEY0_PLACEHOLDER"} },
            { "kind": "key", "data": { "pubkey": "PUBKEY1_PLACEHOLDER"} },
            { "kind": "key", "data": { "pubkey": "PUBKEY2_PLACEHOLDER"} }
          ],
          "threshold": 2
        }
      ],
      "master_keys": [
        {
          "signers": [
            { "kind": "key", "data": { "pubkey": "PUBKEY4_PLACEHOLDER"} },
            { "kind": "key", "data": { "pubkey": "PUBKEY5_PLACEHOLDER"} },
            { "kind": "key", "data": { "pubkey": "PUBKEY6_PLACEHOLDER"} }
          ],
          "threshold": 2
        }
      ],
      "admin_keys": [
        {
          "signers": [
            { "kind": "key", "data": { "pubkey": "PUBKEY7_PLACEHOLDER"} },
            { "kind": "key", "data": { "pubkey": "PUBKEY8_PLACEHOLDER"} },
            { "kind": "key", "data": { "pubkey": "PUBKEY9_PLACEHOLDER"} }
          ],
          "threshold": 3
        }
      ]
    }
    "#;
        let json_str = render_fixture_template(json_template, &keys);
        let config: SignersConfig =
            parse_signers_config(json_str.as_str()).expect("Failed to parse JSON");
        assert_eq!(config.version(), 1);
        assert_eq!(config.artifact_signers().len(), 1);
        assert_eq!(config.artifact_signers()[0].threshold, 2);
        assert_eq!(
            config.artifact_signers()[0].signers[0].kind,
            SignerKind::Key
        );
        assert_eq!(config.master_keys().unwrap_or_default().len(), 1);
        assert_eq!(config.master_keys().unwrap_or_default()[0].threshold, 2);
        assert_eq!(
            config.master_keys().unwrap_or_default()[0].signers[0].kind,
            SignerKind::Key
        );
        let admin_keys = config.admin_keys();
        assert_eq!(admin_keys[0].threshold, 3);
        assert_eq!(admin_keys[0].signers[0].kind, SignerKind::Key);

        // Check admin key are equal to artifact_signers if not set explicitly
        let json_template = r#"
    {
      "version": 1,
          "timestamp": "TIMESTAMP",
      "artifact_signers": [
        {
          "signers": [
            { "kind": "key", "data": { "pubkey": "PUBKEY0_PLACEHOLDER"} },
            { "kind": "key", "data": { "pubkey": "PUBKEY1_PLACEHOLDER"} },
            { "kind": "key", "data": { "pubkey": "PUBKEY2_PLACEHOLDER"} }
          ],
          "threshold": 3
        }
      ],
      "master_keys": [
        {
          "signers": [
            { "kind": "key", "data": { "pubkey": "PUBKEY3_PLACEHOLDER"} },
            { "kind": "key", "data": { "pubkey": "PUBKEY4_PLACEHOLDER"} },
            { "kind": "key", "data": { "pubkey": "PUBKEY5_PLACEHOLDER"} }
          ],
          "threshold": 2
        }
      ]
    }
    "#;
        let json_str = render_fixture_template(json_template, &keys);
        let config: SignersConfig =
            parse_signers_config(json_str.as_str()).expect("Failed to parse JSON");
        assert_eq!(config.version(), 1);
        assert_eq!(config.artifact_signers().len(), 1);
        assert_eq!(config.artifact_signers()[0].threshold, 3);
        assert_eq!(
            config.artifact_signers()[0].signers[0].kind,
            SignerKind::Key
        );
        assert_eq!(config.admin_keys(), config.artifact_signers());

        let json_template = r#"
    {
      "version": 1,
      "timestamp": "TIMESTAMP",
      "artifact_signers": [
        {
          "signers": [
            { "kind": "key", "data": { "pubkey": "PUBKEY0_PLACEHOLDER"} },
            { "kind": "key", "data": { "pubkey": "asfaload-pub:not-valid-base64-at-all"} },
            { "kind": "key", "data": { "pubkey": "PUBKEY2_PLACEHOLDER"} }
          ],
          "threshold": 2
        }
      ],
      "master_keys": [
        {
          "signers": [
            { "kind": "key", "data": { "pubkey": "PUBKEY3_PLACEHOLDER"} },
            { "kind": "key", "data": { "pubkey": "PUBKEY4_PLACEHOLDER"} },
            { "kind": "key", "data": { "pubkey": "PUBKEY5_PLACEHOLDER"} }
          ],
          "threshold": 2
        }
      ]
    }
    "#;
        let json_str = render_fixture_template(json_template, &keys);
        let config: Result<SignersConfig, serde_json::Error> = parse_signers_config(&json_str);
        assert!(config.is_err());
        let error = config.err().unwrap();
        assert!(error.to_string().contains("Problem parsing pubkey base64"));

        // Test the threshold validation
        let json_template = r#"
    {
      "version": 1,
          "timestamp": "TIMESTAMP",
      "artifact_signers": [
        {
          "signers": [
            { "kind": "key", "data": { "pubkey": "PUBKEY0_PLACEHOLDER"} },
            { "kind": "key", "data": { "pubkey": "PUBKEY1_PLACEHOLDER"} },
            { "kind": "key", "data": { "pubkey": "PUBKEY2_PLACEHOLDER"} }
          ],
          "threshold": 4
        }
      ],
      "master_keys": [
        {
          "signers": [
            { "kind": "key", "data": { "pubkey": "PUBKEY3_PLACEHOLDER"} },
            { "kind": "key", "data": { "pubkey": "PUBKEY4_PLACEHOLDER"} },
            { "kind": "key", "data": { "pubkey": "PUBKEY5_PLACEHOLDER"} }
          ],
          "threshold": 2
        }
      ]
    }
    "#;
        let json_str = render_fixture_template(json_template, &keys);
        let config: Result<SignersConfig, serde_json::Error> = parse_signers_config(&json_str);
        assert!(config.is_err());
        let error = config.err().unwrap();
        assert!(
            error
                .to_string()
                .starts_with("Threshold (4) cannot be greater than the number of signers (3)")
        );
        // Reject empty groups
        let json_template = r#"
    {
      "version": 1,
          "timestamp": "TIMESTAMP",
      "artifact_signers": [
        {
          "signers": [
            { "kind": "key", "data": { "pubkey": "PUBKEY0_PLACEHOLDER"} },
            { "kind": "key", "data": { "pubkey": "PUBKEY1_PLACEHOLDER"} },
            { "kind": "key", "data": { "pubkey": "PUBKEY2_PLACEHOLDER"} }
          ],
          "threshold": 3
        }
      ],
      "admin_keys": [
        {
          "signers": [
            { "kind": "key", "data": { "pubkey": "PUBKEY3_PLACEHOLDER"} },
            { "kind": "key", "data": { "pubkey": "PUBKEY4_PLACEHOLDER"} },
            { "kind": "key", "data": { "pubkey": "PUBKEY5_PLACEHOLDER"} }
          ],
          "threshold": 2
        }
      ],
      "master_keys" : [ { "signers" : [] , "threshold" : 0}]
    }
    "#;
        let json_str = render_fixture_template(json_template, &keys);
        let config: Result<SignersConfig, serde_json::Error> = parse_signers_config(&json_str);
        assert!(config.is_err());
        let error = config.err().unwrap();
        assert!(
            error
                .to_string()
                .starts_with("Group size must be at least 1")
        );

        // Test empty master
        // Empty groups are never complete, so this is the same as an absent master_keys field
        let json_template = r#"
    {
      "version": 1,
          "timestamp": "TIMESTAMP",
      "artifact_signers": [
        {
          "signers": [
            { "kind": "key", "data": { "pubkey": "PUBKEY0_PLACEHOLDER"} },
            { "kind": "key", "data": { "pubkey": "PUBKEY1_PLACEHOLDER"} },
            { "kind": "key", "data": { "pubkey": "PUBKEY2_PLACEHOLDER"} }
          ],
          "threshold": 3
        }
      ],
      "admin_keys": [
        {
          "signers": [
            { "kind": "key", "data": { "pubkey": "PUBKEY3_PLACEHOLDER"} },
            { "kind": "key", "data": { "pubkey": "PUBKEY4_PLACEHOLDER"} },
            { "kind": "key", "data": { "pubkey": "PUBKEY5_PLACEHOLDER"} }
          ],
          "threshold": 2
        }
      ],
      "master_keys" : []}
    "#;
        let json_str = render_fixture_template(json_template, &keys);
        let config: Result<SignersConfig, serde_json::Error> = parse_signers_config(&json_str);
        assert!(config.is_ok());

        // Test empty admin array
        // If the json holds an empty array for admins, it returns the artifact signers just as
        // when it is not present at all
        let json_template = r#"
    {
      "version": 1,
          "timestamp": "TIMESTAMP",
      "artifact_signers": [
        {
          "signers": [
            { "kind": "key", "data": { "pubkey": "PUBKEY0_PLACEHOLDER"} },
            { "kind": "key", "data": { "pubkey": "PUBKEY1_PLACEHOLDER"} },
            { "kind": "key", "data": { "pubkey": "PUBKEY2_PLACEHOLDER"} }
          ],
          "threshold": 3
        }
      ],
      "master_keys": [
        {
          "signers": [
            { "kind": "key", "data": { "pubkey": "PUBKEY3_PLACEHOLDER"} },
            { "kind": "key", "data": { "pubkey": "PUBKEY4_PLACEHOLDER"} },
            { "kind": "key", "data": { "pubkey": "PUBKEY5_PLACEHOLDER"} }
          ],
          "threshold": 2
        }
      ],
      "admin_keys" : []}
    "#;
        let json_str = render_fixture_template(json_template, &keys);
        let result: Result<SignersConfig, serde_json::Error> = parse_signers_config(&json_str);
        assert!(result.is_ok());
        let config = result.unwrap();
        // Check admin_keys holds an one element array
        assert_eq!(config.admin_keys(), config.artifact_signers());

        let json_template = r#"
    {
      "version": 1,
          "timestamp": "TIMESTAMP",
      "artifact_signers": [
        {
          "signers": [
            { "kind": "key", "data": {  "pubkey": "PUBKEY4_PLACEHOLDER"} }
          ],
          "threshold": 0
        }
      ],
      "master_keys": [
        {
          "signers": [
            { "kind": "key", "data": { "pubkey": "PUBKEY4_PLACEHOLDER"} },
            { "kind": "key", "data": { "pubkey": "PUBKEY5_PLACEHOLDER"} }
          ],
          "threshold": 2
        }
      ]
    }
    "#;
        let json_str = render_fixture_template(json_template, &keys);
        let config: Result<SignersConfig, serde_json::Error> = parse_signers_config(&json_str);
        assert!(config.is_err());
        let error = config.err().unwrap();
        assert!(
            error
                .to_string()
                .starts_with("Threshold (0) must be strictly greater than 0")
        );
    }
    #[test]
    fn test_initialize_signers_file1() -> Result<()> {
        let temp_dir = TempDir::new().unwrap();
        let dir_path = temp_dir.path();

        let test_keys = TestKeys::new(3);

        // Example JSON content (from the existing test)
        let json_content_template = r#"
{
  "version": 1,
  "timestamp": "TIMESTAMP",
  "artifact_signers": [
    {
      "signers": [
        { "kind": "key", "data": { "pubkey": "PUBKEY0_PLACEHOLDER"} },
        { "kind": "key", "data": { "pubkey": "PUBKEY1_PLACEHOLDER"} }
      ],
      "threshold": 2
    }
  ],
  "master_keys": [],
  "admin_keys": null
}
"#;

        let json_content = &test_keys
            .substitute_keys(json_content_template.to_string())
            .replace("TIMESTAMP", chrono::Utc::now().to_string().as_str());

        // Call the function
        initialize_signers_file(
            dir_path,
            json_content,
            &test_metadata_json(),
            test_keys.pub_key(0).unwrap(),
        )
        .unwrap();

        // Check that the pending file exists
        let pending_file_path = dir_path.join(format!("{}/{}", PENDING_SIGNERS_DIR, SIGNERS_FILE));
        assert!(pending_file_path.exists());

        // Check the content
        let content = fs::read_to_string(&pending_file_path).unwrap();
        // We don't compare exactly because of formatting, but we can parse it again to validate
        let _config: SignersConfig = parse_signers_config(&content).unwrap();

        // Check that the complete signature does not exist
        let sig_file_path = dir_path.join(format!(
            "{}/{}.{}",
            PENDING_SIGNERS_DIR, SIGNERS_FILE, SIGNATURES_SUFFIX
        ));
        assert!(!sig_file_path.exists());
        assert_metadata_file_valid(dir_path, false);
        Ok(())
    }

    #[test]
    fn test_initialize_signers_with_2_signers_threshold_1() -> Result<()> {
        let temp_dir = TempDir::new().unwrap();
        let dir_path = temp_dir.path();

        let test_keys = TestKeys::new(3);

        // Extract used keys
        let pub_key0 = test_keys.pub_key(0).unwrap().clone();
        let pub_key1 = test_keys.pub_key(1).unwrap().clone();

        let signers_config = SignersConfig::with_keys(
            1,
            (vec![pub_key0.clone(), pub_key1.clone()], 1),
            None,
            None,
            None,
        )?;
        let json_content = serde_json::json!(signers_config).to_string();

        // Call the function
        initialize_signers_file(
            dir_path,
            json_content,
            &test_metadata_json(),
            test_keys.pub_key(0).unwrap(),
        )
        .unwrap();

        // Initialization creates a pending signers dir with empty pending signatures.
        // Signing happens separately.
        let pending_file_path = dir_path.join(format!("{}/{}", PENDING_SIGNERS_DIR, SIGNERS_FILE));
        assert!(pending_file_path.exists());

        // Check the content
        let content = fs::read_to_string(&pending_file_path).unwrap();
        let _config: SignersConfig = parse_signers_config(&content).unwrap();

        // Check that the complete signature does not exist
        let sig_file_path = dir_path.join(format!(
            "{}/{}.{}",
            PENDING_SIGNERS_DIR, SIGNERS_FILE, SIGNATURES_SUFFIX
        ));
        assert!(!sig_file_path.exists());
        assert_metadata_file_valid(dir_path, false);
        Ok(())
    }

    #[test]
    fn test_initialize_signers_file_with_1_signer() -> Result<()> {
        let temp_dir = TempDir::new().unwrap();
        let dir_path = temp_dir.path();

        let test_keys = TestKeys::new(3);

        // Get keys we work with here
        let pub_key = test_keys.pub_key(0).unwrap();

        // Build signers config
        let signers_config =
            SignersConfig::with_keys(1, (vec![pub_key.clone()], 1), None, None, None)?;
        let json_content = serde_json::json!(signers_config).to_string();

        // Call the function -- initialization no longer signs, so the file stays pending
        initialize_signers_file(
            dir_path,
            json_content,
            &test_metadata_json(),
            test_keys.pub_key(0).unwrap(),
        )
        .unwrap();

        // Check that the pending file exists (not activated since init doesn't sign)
        let pending_file_path = dir_path.join(format!("{}/{}", PENDING_SIGNERS_DIR, SIGNERS_FILE));
        assert!(pending_file_path.exists());

        // Check the content
        let content = fs::read_to_string(&pending_file_path).unwrap();
        let _config: SignersConfig = parse_signers_config(&content).unwrap();

        // Check that the complete signature does not exist
        let sig_file_path = dir_path.join(format!(
            "{}/{}.{}",
            PENDING_SIGNERS_DIR, SIGNERS_FILE, SIGNATURES_SUFFIX
        ));
        assert!(!sig_file_path.exists());

        assert_metadata_file_valid(dir_path, false);
        Ok(())
    }

    // test_initialize_signers_file_invalid_signature was removed because
    // initialize_signers_file no longer verifies signatures (only authorization).
    // Signature validation now happens at sign time via sign_signers_and_metadata_file.

    #[test]
    fn test_initialize_signers_file_with_admin_signers() -> Result<()> {
        let temp_dir = TempDir::new().unwrap();
        let dir_path = temp_dir.path();
        let test_keys = TestKeys::new(4);

        // Get keys
        let pubkey0 = test_keys.pub_key(0).unwrap().clone();
        let pubkey2 = test_keys.pub_key(2).unwrap().clone();
        let pubkey3 = test_keys.pub_key(3).unwrap().clone();

        // Generate config
        let json_content = SignersConfig::with_keys(
            1,
            (vec![pubkey0.clone()], 1),
            Some((vec![pubkey2.clone(), pubkey3.clone()], 2)),
            None,
            None,
        )?
        .to_json()?;

        // Pubkey must be in admin_keys for authorization
        initialize_signers_file(dir_path, &json_content, &test_metadata_json(), &pubkey2)?;

        assert_metadata_file_valid(dir_path, false);
        Ok(())
    }
    #[test]
    fn test_initialize_signers_file_with_one_signer() -> Result<()> {
        let temp_dir = TempDir::new().unwrap();
        let dir_path = temp_dir.path();
        let test_keys = TestKeys::new(1);

        // Get keys we work with here
        let pubkey = test_keys.pub_key(0).unwrap();

        // Generate config
        let json_content =
            SignersConfig::with_artifact_signers_only(1, (vec![pubkey.clone()], 1))?.to_json()?;

        let pending_signers_dir = dir_path.join(PENDING_SIGNERS_DIR);

        // Initialization no longer signs, so the file stays pending
        initialize_signers_file(dir_path, &json_content, &test_metadata_json(), pubkey)?;

        // Check that the pending file exists (not activated since init doesn't sign)
        assert!(pending_signers_dir.exists());
        let pending_file = pending_signers_dir.join(SIGNERS_FILE);
        assert!(pending_file.exists());

        assert_metadata_file_valid(dir_path, false);
        Ok(())
    }

    #[test]
    fn test_errors_in_initialize_signers_file() -> Result<()> {
        let temp_dir = TempDir::new().unwrap();
        let dir_path = temp_dir.path();
        let test_keys = TestKeys::new(1);

        let pub_key = test_keys.pub_key(0).unwrap();

        let json_content =
            SignersConfig::with_artifact_signers_only(1, (vec![pub_key.clone()], 1))?.to_json()?;

        // Test for IO error: Make the directory read-only
        let mut perms = fs::metadata(dir_path).unwrap().permissions();
        perms.set_readonly(true);
        fs::set_permissions(dir_path, perms).unwrap();

        // Try to initialize the signers file, which should fail with an IO error
        let result =
            initialize_signers_file(dir_path, &json_content, &test_metadata_json(), pub_key);

        // Check that we got an IO error
        assert!(result.is_err());
        match result.as_ref().unwrap_err() {
            SignersFileError::IoError(_) => {} // Expected
            _ => panic!(
                "Expected IoError, got something else: {:?}",
                result.unwrap_err()
            ),
        }
        // Check no overwrite happens
        // first create a signers file in an empty directory
        let temp_dir = TempDir::new().unwrap();
        let dir_path = temp_dir.path();
        initialize_signers_file(dir_path, &json_content, &test_metadata_json(), pub_key).unwrap();
        // Init no longer signs, so the file stays pending
        let pending_signers_file_path =
            dir_path.join(format!("{}/{}", PENDING_SIGNERS_DIR, SIGNERS_FILE));
        assert!(pending_signers_file_path.exists());
        // Trying to initialize again should fail because pending dir exists
        let result =
            initialize_signers_file(dir_path, &json_content, &test_metadata_json(), pub_key);
        assert!(result.is_err());
        match result.as_ref().unwrap_err() {
            SignersFileError::InitialisationError(_) => {} // Expected
            _ => panic!(
                "Expected InitialisationError, got something else: {:?}",
                result.unwrap_err()
            ),
        }
        Ok(())
    }
    #[test]
    fn test_refuse_initialize_signers_file_when_complete_signature_exists() -> Result<()> {
        let temp_dir = TempDir::new().unwrap();
        let dir_path = temp_dir.path();
        let test_keys = TestKeys::new(1);

        let pub_key = test_keys.pub_key(0).unwrap();

        let json_content =
            SignersConfig::with_artifact_signers_only(1, (vec![pub_key.clone()], 1))?.to_json()?;

        // Create complete signature file, content does not matter, only existence.
        let aggregate_signature_path = dir_path.join(format!(
            "{}/{}.{}",
            PENDING_SIGNERS_DIR, SIGNERS_FILE, SIGNATURES_SUFFIX
        ));
        std::fs::create_dir(aggregate_signature_path.parent().unwrap())?;
        std::fs::File::create(&aggregate_signature_path)?;

        // Try to initialize the signers file, which should fail with an Initialisation error
        let result =
            initialize_signers_file(dir_path, &json_content, &test_metadata_json(), pub_key);

        assert!(result.is_err());
        match result.as_ref().unwrap_err() {
            SignersFileError::InitialisationError(_) => {} // Expected
            _ => panic!(
                "Expected InitialisationError, got something else: {:?}",
                result.unwrap_err()
            ),
        }
        let pending_file_path = dir_path.join(format!("{}/{}", PENDING_SIGNERS_DIR, SIGNERS_FILE));
        assert!(!pending_file_path.exists());
        Ok(())
    }
    #[test]
    fn test_refuse_overwriting_existing_signers_file() -> Result<()> {
        let temp_dir = TempDir::new().unwrap();
        let dir_path = temp_dir.path();
        let test_keys = TestKeys::new(1);

        let pub_key = test_keys.pub_key(0).unwrap();

        let json_content =
            SignersConfig::with_artifact_signers_only(1, (vec![pub_key.clone()], 1))?.to_json()?;

        // Create existing signers file, content does not matter, only existence.
        let existing_signers_path =
            dir_path.join(format!("{}/{}", PENDING_SIGNERS_DIR, SIGNERS_FILE));
        std::fs::create_dir(existing_signers_path.parent().unwrap())?;
        std::fs::File::create(existing_signers_path)?;

        // Try to initialize the signers file, which should fail with an Initialisation error
        let result =
            initialize_signers_file(dir_path, &json_content, &test_metadata_json(), pub_key);

        assert!(result.is_err());
        match result.as_ref().unwrap_err() {
            SignersFileError::InitialisationError(_) => {} // Expected
            _ => panic!(
                "Expected InitialisationError, got something else: {:?}",
                result.unwrap_err()
            ),
        }
        let pending_file_path = dir_path.join(format!("{}/{}", PENDING_SIGNERS_DIR, SIGNERS_FILE));
        // Check the file is still there
        assert!(pending_file_path.exists());
        // And check it wasn't changed, i.e. it is still an empty file
        let file_size = std::fs::metadata(pending_file_path)?.len();
        assert_eq!(file_size, 0);
        Ok(())
    }

    // Test activate pending signers file
    // ----------------------------------

    // Helper function to create a test aggregate signature
    fn create_test_aggregate_signature(
        signed_file_path: &Path,
        test_keys: &TestKeys,
    ) -> Result<AggregateSignature<CompleteSignature>, SignersFileError> {
        // Compute the hash of the signers file
        let hash = common::sha512_for_file(signed_file_path)?;

        // Sign with the first key
        let pubkey0 = test_keys.pub_key(0).unwrap();
        let seckey0 = test_keys.sec_key(0).unwrap();
        let signature0 = seckey0.sign(&hash).unwrap();

        // Sign with second key
        let pubkey1 = test_keys.pub_key(1).unwrap();
        let seckey1 = test_keys.sec_key(1).unwrap();
        let signature1 = seckey1.sign(&hash).unwrap();

        // Create the agregate signature's files on disk using our api.
        // Start by loading the empty signature
        let _ = SignatureWithState::load_for_file(signed_file_path)?
            // As it is empty, is is pending
            .get_pending()
            .unwrap()
            // As it is pending, we can add an individual signature to it
            // After adding the signature, it is in this case complete.
            .add_individual_signature(&signature0, pubkey0)?
            // The threshold is 2 so it is pending here
            .get_pending()
            .unwrap()
            .add_individual_signature(&signature1, pubkey1)?;

        // Load the aggregate signature using the public API
        let sig_with_state = SignatureWithState::load_for_file(signed_file_path)?;
        match sig_with_state {
            SignatureWithState::Complete(sig) => Ok(sig),
            SignatureWithState::Pending(_) => Err(SignersFileError::InitialisationError(
                "Expected complete signature".to_string(),
            )),
        }
    }

    #[test]
    fn test_activate_signers_file_success() -> Result<()> {
        let temp_dir = TempDir::new()?;
        let root_dir = temp_dir.path();
        let test_keys = TestKeys::new(2);

        // Create pending directory and signers file
        let pending_dir = root_dir.join(PENDING_SIGNERS_DIR);
        fs::create_dir_all(&pending_dir)?;
        let signers_file_path = pending_dir.join(SIGNERS_FILE);
        let signers_content = create_test_signers_config(&test_keys);
        fs::write(&signers_file_path, signers_content.to_json()?)?;

        // Create aggregate signature
        let agg_sig = create_test_aggregate_signature(&signers_file_path, &test_keys)?;

        // Activate the signers file
        activate_signers_file(agg_sig)?;

        // Verify the pending directory was renamed to active
        let active_dir = root_dir.join(SIGNERS_DIR);
        assert!(active_dir.exists());
        assert!(!pending_dir.exists());

        // Verify the signers file is in the active directory
        let active_signers_file = active_dir.join(SIGNERS_FILE);
        assert!(active_signers_file.exists());

        // Verify the content is preserved
        let active_content = fs::read_to_string(&active_signers_file)?;
        assert_eq!(active_content, signers_content.to_json()?);

        Ok(())
    }

    #[test]
    fn test_activate_signers_file_with_existing_active() -> Result<()> {
        let temp_dir = TempDir::new()?;
        let root_dir = temp_dir.path();

        // Use distinct TestKeys instances for existing and new signers
        let existing_keys = TestKeys::new(1);
        let new_keys = TestKeys::new_from(1, 2);

        // Create existing active directory and signers file
        let active_dir = root_dir.join(SIGNERS_DIR);
        fs::create_dir_all(&active_dir)?;
        let existing_signers_file = active_dir.join(SIGNERS_FILE);

        // Create a template for the existing content
        // The permalink is specific
        let existing_content_template = r#"
{
  "version": 1,
  "timestamp": "TIMESTAMP",
  "artifact_signers": [
    {
      "signers": [
        { "kind": "key", "data": { "pubkey": "PUBKEY0_PLACEHOLDER" } }
      ],
      "threshold": 1
    }
  ],
  "master_keys": [],
  "admin_keys": null
}
"#;

        // Substitute the placeholder with an actual public key from existing_keys
        let config_timestamp = chrono::Utc::now();
        let existing_content = existing_keys
            .substitute_keys(existing_content_template.to_string())
            .replace("TIMESTAMP", config_timestamp.to_string().as_str());
        fs::write(&existing_signers_file, existing_content)?;

        // Write metadata file for the existing active signers
        let metadata = test_metadata();
        let metadata_path = metadata_path_for(&existing_signers_file).unwrap();
        fs::write(
            &metadata_path,
            serde_json::to_string_pretty(&metadata).unwrap(),
        )?;

        // Write metadata signatures file for the existing active signers
        let (_, metadata_sigs) = sign_metadata(&metadata, &existing_keys, &[0]).unwrap();
        let meta_sigs_path = metadata_signatures_path_for(&existing_signers_file).unwrap();
        fs::write(
            &meta_sigs_path,
            serde_json::to_string_pretty(&metadata_sigs).unwrap(),
        )?;

        // Create the signatures file for the existing signers file
        let hash = common::sha512_for_file(&existing_signers_file)?;
        let pubkey0 = existing_keys.pub_key(0).unwrap();
        let seckey0 = existing_keys.sec_key(0).unwrap();
        let signature0 = seckey0.sign(&hash).unwrap();

        // Create signature of current signers file
        let _ = SignatureWithState::load_for_file(&existing_signers_file)?
            .get_pending()
            .unwrap()
            .add_individual_signature(&signature0, pubkey0)?;

        // Create pending directory and signers file
        let pending_dir = root_dir.join(PENDING_SIGNERS_DIR);
        fs::create_dir_all(&pending_dir)?;
        let signers_file_path = pending_dir.join(SIGNERS_FILE);
        let completed_dir = root_dir.join(SIGNERS_DIR);
        let completed_signers_file_path = completed_dir.join(SIGNERS_FILE);

        // Use new_keys for the new signers config
        let new_content = create_test_signers_config(&new_keys);
        let new_signers_file_content = new_content.to_json()?;
        fs::write(&signers_file_path, &new_signers_file_content)?;
        let new_signers_content_hash = sha512_for_file(&signers_file_path)?;

        let existing_signer_sig = existing_keys
            .sec_key(0)
            .unwrap()
            .sign(&new_signers_content_hash)?;
        let sig_with_state_1 = SignatureWithState::load_for_file(&signers_file_path)?
            .get_pending()
            .unwrap()
            .add_individual_signature(&existing_signer_sig, existing_keys.pub_key(0).unwrap())?;

        match sig_with_state_1 {
            SignatureWithState::Pending(_) => {} // expected
            // As we do an update of the signers file, we need the signatures to complete the
            // existing signers file + complete the new one + get signatures from those new in the new file.
            SignatureWithState::Complete(_) => panic!("Signature was expected to be incomplete!"),
        }

        // Create aggregate signature using new_keys
        let agg_sig = create_test_aggregate_signature(&signers_file_path, &new_keys)?;
        agg_sig.save_to_file()?;

        // Activate the signers file
        activate_signers_file(agg_sig)?;

        // Verify the history file was created
        let history_file_path = root_dir.join(SIGNERS_HISTORY_FILE);
        assert!(history_file_path.exists());

        // Verify the history contains the old configuration
        let history: HistoryFile = HistoryFile::load_from_file(&history_file_path)?;
        assert_eq!(history.entries.len(), 1);

        // Verify the old configuration is in the history
        let old_config_in_history = history.entries[0].signers_config().unwrap();
        assert_eq!(old_config_in_history.timestamp(), config_timestamp);

        // Verify the metadata is preserved in the history (compare raw JSON strings)
        let expected_metadata_json = serde_json::to_string_pretty(&metadata).unwrap();
        assert_eq!(history.entries[0].metadata, expected_metadata_json);

        // Verify the new configuration is active
        let new_active_content = fs::read_to_string(active_dir.join(SIGNERS_FILE))?;
        assert_eq!(new_active_content, new_content.to_json()?);

        let local_copy_path = local_signers_path_for(completed_signers_file_path)?;
        assert!(!local_copy_path.exists());
        Ok(())
    }

    #[test]
    fn test_activate_signers_file_path_mismatch() -> Result<()> {
        let temp_dir = TempDir::new()?;
        let root_dir = temp_dir.path();
        let test_keys = TestKeys::new(2);

        // Create pending directory and signers file
        let pending_dir = root_dir.join(PENDING_SIGNERS_DIR);
        fs::create_dir_all(&pending_dir)?;
        let signers_file_path = pending_dir.join(SIGNERS_FILE);
        let signers_config = create_test_signers_config(&test_keys);
        let signers_content = signers_config.to_json()?;
        fs::write(&signers_file_path, &signers_content)?;

        // Create aggregate signature for a file with a signers file content but
        // with a different path
        let different_path = root_dir.join("different_file.json");
        fs::write(&different_path, &signers_content)?;

        // As this is an artifact file, the helper will look for an active signers file
        // when creating the agg sig. But it is not present, hence the error.
        let result = create_test_aggregate_signature(&different_path, &test_keys);

        // Verify the error
        assert!(result.is_err());
        match result.err().unwrap() {
            SignersFileError::AggregateSignatureError(e) => {
                assert!(
                    e.to_string()
                        .contains("No signers file found in parent directories")
                );
            }
            other => panic!(
                "Expected InitialisationError for path mismatch, got {:?}",
                other
            ),
        }

        // Verify the pending directory still exists
        assert!(pending_dir.exists());

        Ok(())
    }

    #[test]
    fn test_activate_signers_file_no_parent_directory() -> Result<()> {
        let temp_dir = TempDir::new()?;
        let test_keys = TestKeys::new(2);

        // Create a file at the root level (no parent directory)
        let signers_file_path = temp_dir.path().join(SIGNERS_FILE);
        let signers_config = create_test_signers_config(&test_keys);
        let signers_content = signers_config.to_json()?;
        fs::write(&signers_file_path, signers_content)?;

        // Create aggregate signature
        // As the file signed has the name of a signers file but is not in a signers dir,
        // it is handled as an artifact, which requires the presence of an active signers
        // file when signing. As there is none, it causes the error.
        let result = create_test_aggregate_signature(&signers_file_path, &test_keys);

        // Verify the error
        assert!(result.is_err());
        match result.err().unwrap() {
            SignersFileError::AggregateSignatureError(e) => {
                assert!(
                    e.to_string()
                        .contains("No signers file found in parent directories")
                );
            }
            other => panic!(
                "Expected InitialisationError for path mismatch, got {:?}",
                other
            ),
        }

        Ok(())
    }

    #[test]
    fn test_activate_signers_file_with_signature_files() -> Result<()> {
        let temp_dir = TempDir::new()?;
        let root_dir = temp_dir.path();
        let test_keys = TestKeys::new(2);

        // Create pending directory and signers file
        let pending_dir = root_dir.join(PENDING_SIGNERS_DIR);
        fs::create_dir_all(&pending_dir)?;
        let signers_file_path = pending_dir.join(SIGNERS_FILE);
        let signers_config = create_test_signers_config(&test_keys);
        let signers_content = signers_config.to_json()?;
        fs::write(&signers_file_path, signers_content)?;

        // Create aggregate signature
        let agg_sig = create_test_aggregate_signature(&signers_file_path, &test_keys)?;

        // Activate the signers file
        activate_signers_file(agg_sig)?;

        // Verify the pending directory was renamed to active
        let active_dir = root_dir.join(SIGNERS_DIR);
        assert!(active_dir.exists());
        assert!(!pending_dir.exists());

        // Verify the signature files were removed
        let pending_sig_path = common::fs::names::pending_signatures_path_for(&signers_file_path)?;
        let complete_sig_path = common::fs::names::signatures_path_for(&signers_file_path)?;
        assert!(!pending_sig_path.exists());
        assert!(!complete_sig_path.exists());

        // Verify the signers file is in the active directory
        let active_signers_file = active_dir.join(SIGNERS_FILE);
        assert!(active_signers_file.exists());

        Ok(())
    }

    #[test]
    fn test_activate_signers_file_nested_directory() -> Result<()> {
        let temp_dir = TempDir::new()?;
        let root_dir = temp_dir.path();
        let nested_dir = root_dir.join("nested");
        fs::create_dir_all(&nested_dir)?;
        let test_keys = TestKeys::new(2);

        // Create pending directory in nested directory
        let pending_dir = nested_dir.join(PENDING_SIGNERS_DIR);
        fs::create_dir_all(&pending_dir)?;
        let signers_file_path = pending_dir.join(SIGNERS_FILE);
        let signers_config = create_test_signers_config(&test_keys);
        let signers_content = signers_config.to_json()?;
        fs::write(&signers_file_path, signers_content)?;

        // Create aggregate signature
        let agg_sig = create_test_aggregate_signature(&signers_file_path, &test_keys)?;

        // Activate the signers file
        activate_signers_file(agg_sig)?;

        // Verify the pending directory was renamed to active
        let active_dir = nested_dir.join(SIGNERS_DIR);
        assert!(active_dir.exists());
        assert!(!pending_dir.exists());

        // Verify the signers file is in the active directory
        let active_signers_file = active_dir.join(SIGNERS_FILE);
        assert!(active_signers_file.exists());

        // Verify the content is preserved
        let active_content = fs::read_to_string(&active_signers_file)?;
        assert_eq!(active_content, signers_config.to_json()?);

        Ok(())
    }
    use chrono::{DateTime, Utc};
    // Helper function to create a test active signers setup
    fn create_test_active_signers(
        root_dir: &Path,
        test_keys: &TestKeys,
    ) -> Result<PathBuf, SignersFileError> {
        let active_signers_dir = root_dir.join(SIGNERS_DIR);
        fs::create_dir_all(&active_signers_dir)?;

        let signers_file_path = active_signers_dir.join(SIGNERS_FILE);
        let signers_config = create_test_signers_config(test_keys);
        let signers_content = signers_config.to_json()?;
        fs::write(&signers_file_path, signers_content)?;

        // Write metadata file
        let metadata = test_metadata();
        let metadata_path = metadata_path_for(&signers_file_path).unwrap();
        fs::write(
            &metadata_path,
            serde_json::to_string_pretty(&metadata).unwrap(),
        )?;

        // Sign metadata file with both keys
        let metadata_hash = common::sha512_for_file(&metadata_path)?;
        let mut meta_sigs = SignaturesFile::new();
        for i in 0..2 {
            let sig = test_keys.sec_key(i).unwrap().sign(&metadata_hash).unwrap();
            meta_sigs.entries.insert(
                test_keys.pub_key(i).unwrap().to_base64(),
                TaggedSignature {
                    format: test_keys.pub_key(i).unwrap().key_format(),
                    signature: sig.to_base64(),
                },
            );
        }
        let meta_sigs_path = metadata_signatures_path_for(&signers_file_path).unwrap();
        fs::write(
            &meta_sigs_path,
            serde_json::to_string_pretty(&meta_sigs).unwrap(),
        )?;

        let hash = common::sha512_for_file(&signers_file_path)?;

        // Sign with both keys
        let pubkey0 = test_keys.pub_key(0).unwrap();
        let seckey0 = test_keys.sec_key(0).unwrap();
        let signature0 = seckey0.sign(&hash).unwrap();

        let pubkey1 = test_keys.pub_key(1).unwrap();
        let seckey1 = test_keys.sec_key(1).unwrap();
        let signature1 = seckey1.sign(&hash).unwrap();

        // Create the aggregate signature
        SignatureWithState::load_for_file(&signers_file_path)?
            .get_pending()
            .unwrap()
            .add_individual_signature(&signature0, pubkey0)?
            .get_pending()
            .unwrap()
            .add_individual_signature(&signature1, pubkey1)?;

        Ok(signers_file_path)
    }

    #[test]
    fn test_move_to_history_creates_new_history_file() -> Result<()> {
        let temp_dir = TempDir::new()?;
        let root_dir = temp_dir.path();
        let test_keys = TestKeys::new(2);

        // Create active signers setup
        let signers_file_path = create_test_active_signers(root_dir, &test_keys)?;
        let history_file_path = root_dir.join(SIGNERS_HISTORY_FILE);

        // Read the original signers file content
        let original_signers_config = SignersConfig::from_file(&signers_file_path)?;

        // Read the original signatures file content
        let signatures_file_path = signatures_path_for(&signers_file_path)?;
        let original_signatures_content = fs::read_to_string(&signatures_file_path)?;
        let original_signatures: SignaturesFile =
            serde_json::from_str(&original_signatures_content)?;

        // Read the original metadata signatures file content
        let metadata_signatures_file_path = metadata_signatures_path_for(&signers_file_path)?;
        let original_metadata_signatures_content =
            fs::read_to_string(&metadata_signatures_file_path)?;
        let original_metadata_signatures: SignaturesFile =
            serde_json::from_str(&original_metadata_signatures_content)?;

        // Ensure history file doesn't exist initially
        assert!(!history_file_path.exists());

        // Move to history
        move_current_signers_to_history(root_dir)?;

        // Verify history file was created
        assert!(history_file_path.exists());

        // Verify active directory was removed
        assert!(!signers_file_path.exists());
        assert!(!root_dir.join(SIGNERS_DIR).exists());

        // Verify history content
        let history_content = fs::read_to_string(&history_file_path)?;
        let history_file: HistoryFile = serde_json::from_str(&history_content)?;
        let history_entries = history_file.entries;
        assert_eq!(history_entries.len(), 1);

        let entry = history_entries[0].clone();

        // Verify signers file content matches original
        let signers_config_in_history = entry.signers_config().unwrap();
        assert_eq!(signers_config_in_history, original_signers_config);

        // Verify signatures content matches original
        let signatures_in_history = entry.signatures;
        assert_eq!(signatures_in_history, original_signatures);

        // Verify metadata signatures content matches original
        let metadata_signatures_in_history = &entry.metadata_signatures;
        assert_eq!(
            *metadata_signatures_in_history,
            original_metadata_signatures
        );
        assert!(!metadata_signatures_in_history.entries.is_empty());

        Ok(())
    }

    #[test]
    fn test_move_to_history_appends_to_existing_history() -> Result<()> {
        let temp_dir = TempDir::new()?;
        let root_dir = temp_dir.path();
        let test_keys = TestKeys::new(2);
        let signers_file_json = render_fixture_template(
            r#"{
                "version": 1,
                "timestamp": "TIMESTAMP",
                "artifact_signers": [
                    {
                    "signers": [
                        { "kind": "key", "data": { "pubkey": "PUBKEY0_PLACEHOLDER"} }
                    ],
                    "threshold": 1
                    }
                ],
                "master_keys": [],
                "threshold": 1
            }"#,
            &test_keys,
        );
        let history_file_path = root_dir.join(SIGNERS_HISTORY_FILE);

        // Create existing history file
        // Note the timestamp of the history entry is earlier than its obsoleted_at field,
        // which makes it a consistent entry
        let metadata = test_metadata();
        let (metadata_json, metadata_sigs) = sign_metadata(&metadata, &test_keys, &[0, 1]).unwrap();
        let existing_entry = HistoryEntry {
            obsoleted_at: "2023-01-01T00:00:00Z".parse().unwrap(),
            signers_file: signers_file_json,
            signatures: SignaturesFile::new(),
            metadata: metadata_json,
            metadata_signatures: metadata_sigs,
        };

        let mut existing_history: HistoryFile = HistoryFile::new();
        existing_history.add_entry(existing_entry);
        fs::write(
            &history_file_path,
            serde_json::to_string_pretty(&existing_history)?,
        )?;

        // Read the existing history content before the move
        let original_history_content = fs::read_to_string(&history_file_path)?;
        let original_history: HistoryFile = serde_json::from_str(&original_history_content)?;
        let original_history_entries = original_history.entries;
        assert_eq!(original_history_entries.len(), 1);

        // Create active signers setup
        let signers_file_path = create_test_active_signers(root_dir, &test_keys)?;

        // Read the original signers file content
        let original_signers_config = SignersConfig::from_file(&signers_file_path)?;

        // Read the original signatures file content
        let signatures_file_path = signatures_path_for(&signers_file_path)?;
        let original_signatures_content = fs::read_to_string(&signatures_file_path)?;
        let original_signatures: SignaturesFile =
            serde_json::from_str(&original_signatures_content)?;

        // Move to history
        move_current_signers_to_history(root_dir)?;

        // Verify history content
        let history_content = fs::read_to_string(&history_file_path)?;
        let history_file: HistoryFile = serde_json::from_str(&history_content)?;
        let history_entries = history_file.entries;
        assert_eq!(history_entries.len(), 2);

        // Verify first entry is unchanged and matches the original
        let first_entry = &history_entries[0];
        let original_first_entry = &original_history_entries[0];
        assert_eq!(first_entry, original_first_entry);

        // Verify second entry is the new one with correct content
        let second_entry = &history_entries[1];

        // Verify signers file content matches original
        let signers_config_in_history = second_entry.signers_config().unwrap();
        assert_eq!(signers_config_in_history, original_signers_config);

        // Verify signatures content matches original
        let signatures_in_history = second_entry.clone().signatures;
        assert_eq!(signatures_in_history, original_signatures);

        // Verify entries are sorted chronologically
        assert!(first_entry.obsoleted_at < second_entry.obsoleted_at);

        Ok(())
    }

    #[test]
    fn test_move_to_history_preserves_all_existing_entries() -> Result<()> {
        let temp_dir = TempDir::new()?;
        let root_dir = temp_dir.path();
        let test_keys = TestKeys::new(2);
        let history_file_path = root_dir.join(SIGNERS_HISTORY_FILE);

        // Create multiple existing history entries
        let metadata = test_metadata();
        let (metadata_json, metadata_sigs) = sign_metadata(&metadata, &test_keys, &[0, 1]).unwrap();
        let entry1 = HistoryEntry {
            obsoleted_at: "2023-01-01T00:00:00Z".parse().unwrap(),
            signers_file: serde_json::json!({
                "version": 1,
                "timestamp": chrono::Utc::now().to_string(),
                "artifact_signers": [],
                "master_keys": []
            })
            .to_string(),
            signatures: serde_json::from_str(
                r#"{"entries":{"key1":{"format":"asfaload","signature":"sig1"}}}"#,
            )
            .unwrap(),
            metadata: metadata_json.clone(),
            metadata_signatures: metadata_sigs.clone(),
        };

        let entry2 = HistoryEntry {
            obsoleted_at: "2023-02-01T00:00:00Z".parse().unwrap(),
            signers_file: serde_json::json!({
                "version": 2,
                "timestamp": chrono::Utc::now().to_string(),
                "artifact_signers": [],
                "master_keys": []
            })
            .to_string(),
            signatures: serde_json::from_str(
                r#"{"entries":{"key2":{"format":"asfaload","signature":"sig2"}}}"#,
            )
            .unwrap(),
            metadata: metadata_json,
            metadata_signatures: metadata_sigs,
        };

        let mut existing_history: HistoryFile = HistoryFile::new();
        existing_history.add_entry(entry1);
        existing_history.add_entry(entry2);
        fs::write(
            &history_file_path,
            serde_json::to_string_pretty(&existing_history)?,
        )?;

        assert_eq!(existing_history.entries.len(), 2);

        // Create active signers setup
        let signers_file_path = create_test_active_signers(root_dir, &test_keys)?;

        // Read the original signers file content
        let original_signers_config = SignersConfig::from_file(&signers_file_path)?;

        // Read the original signatures file content
        let signatures_file_path = signatures_path_for(&signers_file_path)?;
        let original_signatures_content = fs::read_to_string(&signatures_file_path)?;
        let original_signatures: SignaturesFile =
            serde_json::from_str(&original_signatures_content)?;

        // Move to history
        move_current_signers_to_history(root_dir)?;

        // Verify history content
        let history = HistoryFile::load_from_file(&history_file_path)?;
        assert_eq!(history.entries.len(), 3);

        // Verify all existing entries are unchanged
        for i in 0..existing_history.entries.len() {
            assert_eq!(&history.entries[i], &existing_history.entries[i]);
        }

        // Verify the new entry is the last one with correct content
        let new_entry = &history.entries[2];

        // Verify signers file content matches original
        let signers_config_in_history = new_entry.signers_config().unwrap();
        assert_eq!(signers_config_in_history, original_signers_config);

        // Verify signatures content matches original
        let signatures_in_history = new_entry.signatures.clone();
        assert_eq!(signatures_in_history, original_signatures);

        // Verify entries are sorted chronologically
        for i in 0..history.entries.len() - 1 {
            let current_time = history.entries[i].obsoleted_at;
            let next_time = history.entries[i + 1].obsoleted_at;
            assert!(current_time <= next_time);
        }

        Ok(())
    }
    #[test]
    fn test_move_to_history_timestamp_format() -> Result<()> {
        let temp_dir = TempDir::new()?;
        let root_dir = temp_dir.path();
        let test_keys = TestKeys::new(2);

        // Create active signers setup
        let _signers_file_path = create_test_active_signers(root_dir, &test_keys)?;
        let history_file_path = root_dir.join(SIGNERS_HISTORY_FILE);

        // Record time before operation
        let before_time = Utc::now();

        // Move to history
        move_current_signers_to_history(root_dir)?;

        // Record time after operation
        let after_time = Utc::now();

        // Verify history content
        let history: HistoryFile = HistoryFile::load_from_file(&history_file_path)?;
        assert_eq!(history.entries.len(), 1);

        let entry = &history.entries[0];
        let timestamp = entry.obsoleted_at;

        // Verify timestamp is recent (between before and after)
        assert!(timestamp >= before_time);
        assert!(timestamp <= after_time);

        Ok(())
    }

    #[test]
    fn test_move_to_history_preserves_signatures_content() -> Result<()> {
        let temp_dir = TempDir::new()?;
        let root_dir = temp_dir.path();
        let test_keys = TestKeys::new(2);

        // Create active signers setup
        let signers_file_path = create_test_active_signers(root_dir, &test_keys)?;
        let signatures_path = signatures_path_for(&signers_file_path)?;

        // Read original signatures content
        let original_signatures_content = fs::read_to_string(&signatures_path)?;
        let original_signatures: SignaturesFile =
            serde_json::from_str(&original_signatures_content)?;

        // Move to history
        move_current_signers_to_history(root_dir)?;

        // Verify history content
        let history_file_path = root_dir.join(SIGNERS_HISTORY_FILE);
        let history: HistoryFile = HistoryFile::load_from_file(&history_file_path)?;
        assert_eq!(history.entries.len(), 1);

        let entry = &history.entries[0];
        let signatures_in_history = entry.signatures.clone();

        // Verify signatures content is preserved
        assert_eq!(signatures_in_history, original_signatures);

        Ok(())
    }

    #[test]
    fn test_move_to_history_with_multiple_entries_sorted() -> Result<()> {
        let temp_dir = TempDir::new()?;
        let root_dir = temp_dir.path();
        let test_keys = TestKeys::new(2);
        let history_file_path = root_dir.join(SIGNERS_HISTORY_FILE);

        // Create multiple existing history entries with different timestamps
        let entry1 = create_test_history_entry(&test_keys, "2023-01-01T00:00:00Z".parse().unwrap());
        let entry2 = create_test_history_entry(&test_keys, "2023-02-01T00:00:00Z".parse().unwrap());

        let mut existing_history: HistoryFile = HistoryFile::new();
        existing_history.add_entry(entry1);
        existing_history.add_entry(entry2);
        existing_history.save_to_file(&history_file_path)?;

        // Create active signers setup
        let _signers_file_path = create_test_active_signers(root_dir, &test_keys)?;

        // Record time before operation
        let before_time = Utc::now();

        // Move to history
        move_current_signers_to_history(root_dir)?;

        // Verify history content
        let history: HistoryFile = HistoryFile::load_from_file(&history_file_path)?;
        assert_eq!(history.entries.len(), 3);

        // Verify entries are sorted chronologically
        for i in 0..history.entries.len() - 1 {
            let current_time: DateTime<Utc> = history.entries[i].obsoleted_at;
            let next_time: DateTime<Utc> = history.entries[i + 1].obsoleted_at;
            assert!(current_time <= next_time);
        }

        // Verify the new entry is the last one
        let last_entry = &history.entries[2];
        let last_timestamp: DateTime<Utc> = last_entry.obsoleted_at;
        assert!(last_timestamp >= before_time);

        Ok(())
    }

    #[test]
    fn test_move_to_history_error_when_no_active_signers() -> Result<()> {
        let temp_dir = TempDir::new()?;
        let root_dir = temp_dir.path();

        // Don't create active signers directory
        let result = move_current_signers_to_history(root_dir);

        // Should fail with IO error
        assert!(result.is_err());
        match result.unwrap_err() {
            SignersFileError::IoError(_) => {} // Expected
            _ => panic!("Expected IoError"),
        }

        Ok(())
    }

    #[test]
    fn test_move_to_history_error_when_no_signatures_file() -> Result<()> {
        let temp_dir = TempDir::new()?;
        let root_dir = temp_dir.path();
        let test_keys = TestKeys::new(2);

        // Create active signers directory and file but no signatures file
        let active_signers_dir = root_dir.join(SIGNERS_DIR);
        fs::create_dir_all(&active_signers_dir)?;

        let signers_file_path = active_signers_dir.join(SIGNERS_FILE);
        let signers_config = create_test_signers_config(&test_keys);
        let signers_content = signers_config.to_json()?;
        fs::write(&signers_file_path, signers_content)?;

        // Try to move to history
        let result = move_current_signers_to_history(root_dir);

        // Should fail with IO error
        assert!(result.is_err());
        match result.unwrap_err() {
            SignersFileError::IoError(_) => {} // Expected
            _ => panic!("Expected IoError"),
        }

        Ok(())
    }
    #[test]
    fn test_move_to_history_with_empty_history_file() -> Result<()> {
        let temp_dir = TempDir::new()?;
        let root_dir = temp_dir.path();
        let test_keys = TestKeys::new(2);
        let history_file_path = root_dir.join(SIGNERS_HISTORY_FILE);

        // Create an empty history file
        fs::write(&history_file_path, "")?;

        // Verify the history file exists but is empty
        assert!(history_file_path.exists());
        let initial_content = fs::read_to_string(&history_file_path)?;
        assert!(initial_content.is_empty());

        // Create active signers setup
        let signers_file_path = create_test_active_signers(root_dir, &test_keys)?;

        // Read the original signers file content
        let original_signers_config = SignersConfig::from_file(&signers_file_path)?;

        // Read the original signatures file content
        let signatures_file_path = signatures_path_for(&signers_file_path)?;
        let original_signatures_content = fs::read_to_string(&signatures_file_path)?;
        let original_signatures: SignaturesFile =
            serde_json::from_str(&original_signatures_content)?;

        // Move to history
        move_current_signers_to_history(root_dir)?;

        // Verify history content
        let history: HistoryFile = HistoryFile::load_from_file(&history_file_path)?;
        assert_eq!(history.entries.len(), 1);

        let entry = &history.entries[0];

        // Verify signers file content matches original
        assert_eq!(entry.signers_config().unwrap(), original_signers_config);

        // Verify signatures content matches original
        assert_eq!(entry.signatures, original_signatures);

        // Verify active directory was removed
        assert!(!signers_file_path.exists());
        assert!(!root_dir.join(SIGNERS_DIR).exists());

        Ok(())
    }
    // History file serialisation tests
    // --------------------------------

    #[test]
    fn test_history_entry_creation() {
        let test_keys = TestKeys::new(2);
        let timestamp: DateTime<Utc> = "2023-01-01T00:00:00Z".parse().unwrap();

        let entry = create_test_history_entry(&test_keys, timestamp);
        let config = entry.signers_config().unwrap();

        assert_eq!(entry.obsoleted_at, timestamp);
        assert_eq!(config.version(), 1);
        assert_eq!(config.artifact_signers().len(), 1);
        assert_eq!(config.artifact_signers()[0].threshold, 2);
        assert_eq!(config.artifact_signers()[0].signers.len(), 2);
        assert_eq!(entry.signatures.entries.len(), 2);
    }

    #[test]
    fn test_history_file_new() {
        let history_file: HistoryFile = HistoryFile::new();

        assert!(history_file.entries().is_empty());
    }

    #[test]
    fn test_history_file_default() {
        let history_file: HistoryFile = HistoryFile::default();

        assert!(history_file.entries().is_empty());
    }

    #[test]
    fn test_history_file_add_entry() {
        let test_keys = TestKeys::new(2);
        let mut history_file: HistoryFile = HistoryFile::new();

        let entry1 = create_test_history_entry(&test_keys, "2023-01-01T00:00:00Z".parse().unwrap());
        let entry2 = create_test_history_entry(&test_keys, "2023-02-01T00:00:00Z".parse().unwrap());

        history_file.add_entry(entry1);
        history_file.add_entry(entry2);

        assert_eq!(history_file.entries().len(), 2);
        assert_eq!(
            history_file.entries()[0].obsoleted_at,
            "2023-01-01T00:00:00Z".parse::<DateTime<Utc>>().unwrap()
        );
        assert_eq!(
            history_file.entries()[1].obsoleted_at,
            "2023-02-01T00:00:00Z".parse::<DateTime<Utc>>().unwrap()
        );
    }

    #[test]
    fn test_history_file_latest_entry() {
        let test_keys = TestKeys::new(2);
        let mut history_file: HistoryFile = HistoryFile::new();

        // Empty history file
        assert!(history_file.latest_entry().is_none());

        // Add one entry
        let entry1 = create_test_history_entry(
            &test_keys,
            "2023-01-01T00:00:00Z".parse::<DateTime<Utc>>().unwrap(),
        );
        history_file.add_entry(entry1);
        assert_eq!(
            history_file.latest_entry().unwrap().obsoleted_at,
            "2023-01-01T00:00:00Z".parse::<DateTime<Utc>>().unwrap()
        );

        // Add another entry
        let entry2 = create_test_history_entry(
            &test_keys,
            "2023-02-01T00:00:00Z".parse::<DateTime<Utc>>().unwrap(),
        );
        history_file.add_entry(entry2);
        assert_eq!(
            history_file.latest_entry().unwrap().obsoleted_at,
            "2023-02-01T00:00:00Z".parse::<DateTime<Utc>>().unwrap()
        );
    }

    #[test]
    fn test_history_file_to_json() {
        let test_keys = TestKeys::new(2);
        let mut history_file: HistoryFile = HistoryFile::new();

        let entry = create_test_history_entry(
            &test_keys,
            "2023-01-01T00:00:00Z".parse::<DateTime<Utc>>().unwrap(),
        );
        history_file.add_entry(entry);

        let json = history_file.to_json().unwrap();

        // Verify it's valid JSON
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();

        // Verify structure
        assert!(parsed.is_object());
        assert_eq!(parsed.get("entries").unwrap().as_array().unwrap().len(), 1);

        let entry = &parsed.get("entries").unwrap()[0];
        assert!(entry.get("obsoleted_at").is_some());
        assert!(entry.get("signers_file").is_some());
        assert!(entry.get("signatures").is_some());
        assert!(entry.get("metadata").is_some());
    }

    #[test]
    fn test_history_file_from_json() {
        let test_keys = TestKeys::new(2);

        let pubkey0 = test_keys.pub_key(0).unwrap().to_base64();
        let pubkey1 = test_keys.pub_key(1).unwrap().to_base64();

        // Compute actual signatures
        let test_data = b"test data for signing";
        let hash = common::sha512_for_content(test_data.to_vec()).unwrap();

        let signature0 = test_keys.sec_key(0).unwrap().sign(&hash).unwrap();
        let signature1 = test_keys.sec_key(1).unwrap().sign(&hash).unwrap();

        let signature0_b64 = signature0.to_base64();
        let signature1_b64 = signature1.to_base64();

        // Build signers config with both keys
        let signers_config = SignersConfig::with_artifact_signers_only(
            1,
            (
                vec![
                    test_keys.pub_key(0).unwrap().clone(),
                    test_keys.pub_key(1).unwrap().clone(),
                ],
                2,
            ),
        )
        .unwrap();

        // Build signatures
        let mut signatures = SignaturesFile::new();
        signatures.entries.insert(
            pubkey0.clone(),
            TaggedSignature {
                format: test_keys.pub_key(0).unwrap().key_format(),
                signature: signature0_b64.clone(),
            },
        );
        signatures.entries.insert(
            pubkey1.clone(),
            TaggedSignature {
                format: test_keys.pub_key(1).unwrap().key_format(),
                signature: signature1_b64.clone(),
            },
        );

        // Build the history file programmatically
        let metadata = test_metadata();
        let (metadata_json, metadata_sigs) = sign_metadata(&metadata, &test_keys, &[0, 1]).unwrap();
        let mut original_history = HistoryFile::new();
        original_history.add_entry(HistoryEntry {
            obsoleted_at: "2023-01-01T00:00:00Z".parse().unwrap(),
            signers_file: signers_config.to_json().unwrap(),
            signatures,
            metadata: metadata_json,
            metadata_signatures: metadata_sigs,
        });

        // Serialize and parse back via parse_history_file
        let json_content = serde_json::to_string_pretty(&original_history).unwrap();
        let history_file: HistoryFile = parse_history_file(&json_content).unwrap();

        // Verify the content
        assert_eq!(history_file.entries().len(), 1);
        assert_eq!(
            history_file.entries()[0].obsoleted_at,
            "2023-01-01T00:00:00Z".parse::<DateTime<Utc>>().unwrap()
        );
        let config = history_file.entries()[0].signers_config().unwrap();
        assert_eq!(config.version(), 1);
        assert_eq!(config.artifact_signers().len(), 1);
        assert_eq!(config.artifact_signers()[0].threshold, 2);
        assert_eq!(config.artifact_signers()[0].signers.len(), 2);

        // Verify the public keys in the signers file
        assert_eq!(
            config.artifact_signers()[0].signers[0]
                .data
                .pubkey
                .to_base64(),
            pubkey0
        );
        assert_eq!(
            config.artifact_signers()[0].signers[1]
                .data
                .pubkey
                .to_base64(),
            pubkey1
        );

        // Verify the signatures
        assert_eq!(history_file.entries()[0].signatures.entries.len(), 2);
        assert_eq!(
            history_file.entries()[0].signatures.entries[&pubkey0].signature,
            signature0_b64
        );
        assert_eq!(
            history_file.entries()[0].signatures.entries[&pubkey1].signature,
            signature1_b64
        );

        // Verify that the signatures are valid for the test data
        assert!(
            test_keys
                .pub_key(0)
                .unwrap()
                .verify(&signature0, &hash)
                .is_ok()
        );
        assert!(
            test_keys
                .pub_key(1)
                .unwrap()
                .verify(&signature1, &hash)
                .is_ok()
        );
    }

    #[test]
    fn test_history_file_from_json_invalid() {
        let invalid_json = r#"
{ "entries" :
[
  {
    "obsoleted_at": "2023-01-01T00:00:00Z",
    "signers_file": {
      "version": "invalid",  // Should be a number
          "timestamp": "TIMESTAMP",
      "artifact_signers": [],
      "master_keys": [],
      "admin_keys": null
    },
    "signatures": {"entries": {}},
    "metadata": {
      "data": {
        "Forge": {
          "kind": "Github",
          "url": "https://example.com/test",
          "retrieved_at": "2023-01-01T00:00:00Z"
        }
      }
    }
  }
]
}
"#
        .replace("TIMESTAMP", chrono::Utc::now().to_string().as_str());

        let result: Result<HistoryFile, _> = parse_history_file(&invalid_json);

        assert!(result.is_err());
    }

    #[test]
    fn test_history_file_save_and_load() {
        let temp_dir = TempDir::new().unwrap();
        let file_path = temp_dir.path().join("history.json");
        let test_keys = TestKeys::new(2);
        let mut history_file: HistoryFile = HistoryFile::new();

        let entry = create_test_history_entry(
            &test_keys,
            "2023-01-01T00:00:00Z".parse::<DateTime<Utc>>().unwrap(),
        );
        history_file.add_entry(entry);

        // Save to file
        history_file.save_to_file(&file_path).unwrap();
        assert!(file_path.exists());

        // Load from file
        let loaded_history_file: HistoryFile = HistoryFile::load_from_file(&file_path).unwrap();

        // Verify content
        assert_eq!(loaded_history_file.entries().len(), 1);
        assert_eq!(
            loaded_history_file.entries()[0].obsoleted_at,
            "2023-01-01T00:00:00Z".parse::<DateTime<Utc>>().unwrap()
        );
        assert_eq!(
            loaded_history_file.entries()[0]
                .signers_config()
                .unwrap()
                .version(),
            1
        );
        assert_eq!(loaded_history_file.entries()[0].signatures.entries.len(), 2);
    }

    #[test]
    fn test_history_file_load_nonexistent() {
        let temp_dir = TempDir::new().unwrap();
        let file_path = temp_dir.path().join("nonexistent.json");

        let result: Result<HistoryFile, _> = HistoryFile::load_from_file(&file_path);

        assert!(result.is_err());
        match result.unwrap_err() {
            SignersFileError::IoError(_) => {} // Expected
            _ => panic!("Expected IoError"),
        }
    }

    #[test]
    fn test_history_file_save_to_nonexistent_directory() {
        let temp_dir = TempDir::new().unwrap();
        let nonexistent_dir = temp_dir.path().join("nonexistent");
        let file_path = nonexistent_dir.join("history.json");
        let test_keys = TestKeys::new(2);
        let mut history_file: HistoryFile = HistoryFile::new();

        let entry = create_test_history_entry(&test_keys, "2023-01-01T00:00:00Z".parse().unwrap());
        history_file.add_entry(entry);

        // Try to save to nonexistent directory
        let result = history_file.save_to_file(&file_path);

        assert!(result.is_err());
        match result.unwrap_err() {
            SignersFileError::IoError(_) => {} // Expected
            _ => panic!("Expected IoError"),
        }
    }

    #[test]
    fn test_history_file_multiple_entries() {
        let test_keys = TestKeys::new(2);
        let mut history_file: HistoryFile = HistoryFile::new();

        // Add multiple entries with different timestamps
        let entry1 = create_test_history_entry(
            &test_keys,
            "2023-01-01T00:00:00Z".parse::<DateTime<Utc>>().unwrap(),
        );
        let entry2 = create_test_history_entry(
            &test_keys,
            "2023-02-01T00:00:00Z".parse::<DateTime<Utc>>().unwrap(),
        );
        let entry3 = create_test_history_entry(
            &test_keys,
            "2023-03-01T00:00:00Z".parse::<DateTime<Utc>>().unwrap(),
        );

        history_file.add_entry(entry1);
        history_file.add_entry(entry2);
        history_file.add_entry(entry3);

        // Verify all entries are present
        assert_eq!(history_file.entries().len(), 3);

        // Verify chronological order
        for i in 0..history_file.entries().len() - 1 {
            let current_time: DateTime<Utc> = history_file.entries()[i].obsoleted_at;
            let next_time: DateTime<Utc> = history_file.entries()[i + 1].obsoleted_at;
            assert!(current_time <= next_time);
        }

        // Verify latest entry
        assert_eq!(
            history_file.latest_entry().unwrap().obsoleted_at,
            "2023-03-01T00:00:00Z".parse::<DateTime<Utc>>().unwrap()
        );
    }

    #[test]
    fn test_history_file_roundtrip() {
        let test_keys = TestKeys::new(2);
        let mut original_history_file: HistoryFile = HistoryFile::new();

        // Add multiple entries
        let entry1 = create_test_history_entry(&test_keys, "2023-01-01T00:00:00Z".parse().unwrap());
        let entry2 = create_test_history_entry(&test_keys, "2023-02-01T00:00:00Z".parse().unwrap());

        original_history_file.add_entry(entry1);
        original_history_file.add_entry(entry2);

        // Convert to JSON and back
        let json = original_history_file.to_json().unwrap();
        let deserialized_history_file: HistoryFile = parse_history_file(&json).unwrap();

        // Verify they are identical
        assert_eq!(
            original_history_file.entries().len(),
            deserialized_history_file.entries().len()
        );

        for (original_entry, deserialized_entry) in original_history_file
            .entries()
            .iter()
            .zip(deserialized_history_file.entries().iter())
        {
            assert_eq!(original_entry.obsoleted_at, deserialized_entry.obsoleted_at);
            assert_eq!(original_entry.signers_file, deserialized_entry.signers_file);
            assert_eq!(original_entry.signatures, deserialized_entry.signatures);
            assert_eq!(original_entry.metadata, deserialized_entry.metadata);
        }
    }

    #[test]
    fn test_history_file_with_empty_signatures() {
        let test_keys = TestKeys::new(2);
        let mut history_file: HistoryFile = HistoryFile::new();

        // Create an entry with empty signatures
        let metadata = test_metadata();
        let (metadata_json, metadata_sigs) = sign_metadata(&metadata, &test_keys, &[0, 1]).unwrap();
        let entry = HistoryEntry {
            obsoleted_at: "2023-01-01T00:00:00Z".parse().unwrap(),
            signers_file: create_test_signers_config(&test_keys).to_json().unwrap(),
            signatures: SignaturesFile::new(),
            metadata: metadata_json,
            metadata_signatures: metadata_sigs,
        };

        history_file.add_entry(entry);

        // Verify it serializes and deserializes correctly
        let json = history_file.to_json().unwrap();
        let deserialized: HistoryFile = parse_history_file(&json).unwrap();

        assert_eq!(deserialized.entries().len(), 1);
        assert_eq!(deserialized.entries()[0].signatures.entries.len(), 0);
    }

    // Helper function to create a test active signers setup
    fn create_test_active_signers_for_update(
        root_dir: &Path,
        test_keys: &TestKeys,
        admin_count: usize,
        master_count: usize,
    ) -> Result<PathBuf, SignersFileError> {
        let active_signers_dir = root_dir.join(SIGNERS_DIR);
        fs::create_dir_all(&active_signers_dir)?;

        let signers_file_path = active_signers_dir.join(SIGNERS_FILE);

        // Write metadata file
        let metadata = test_metadata();
        let metadata_path = metadata_path_for(&signers_file_path).unwrap();
        fs::write(
            &metadata_path,
            serde_json::to_string_pretty(&metadata).unwrap(),
        )?;

        // Create a template for the active signers content
        let mut template = r#"
{
  "version": 1,
  "timestamp": "TIMESTAMP",
  "artifact_signers": [
    {
      "signers": [
        { "kind": "key", "data": { "pubkey": "PUBKEY0_PLACEHOLDER" } },
        { "kind": "key", "data": { "pubkey": "PUBKEY1_PLACEHOLDER" } }
      ],
      "threshold": 2
    }
  ]
  "#
        .replace("TIMESTAMP", chrono::Utc::now().to_string().as_str());
        let mut key_index = 2;

        if master_count > 0 {
            template.push_str(
                r#",
  "master_keys": [
    {
      "signers": [ "#,
            );

            for master in 0..master_count {
                template.push_str(
                format!(r#"        {{ "kind": "key", "data": {{ "pubkey": "PUBKEY{key_index}_PLACEHOLDER" }} }}
  "#).as_ref(),
            );
                if master < master_count - 1 {
                    template.push(',');
                }
                key_index += 1;
            }

            template.push_str(
                format!(
                    r#"
        ],
      "threshold": {master_count}
    }}
  ]"#
                )
                .as_ref(),
            );
        } else {
            template.push_str(
                r#",
  "master_keys": []"#,
            );
        }

        if admin_count > 0 {
            template.push_str(
                r#",
  "admin_keys": [
    {
      "signers": [ "#,
            );

            for admin in 0..admin_count {
                template.push_str(
                format!(r#"        {{ "kind": "key", "data": {{ "pubkey": "PUBKEY{key_index}_PLACEHOLDER" }} }}
  "#).as_ref(),
            );
                key_index += 1;
                if admin < admin_count - 1 {
                    template.push(',');
                }
            }

            template.push_str(
                format!(
                    r#"
        ],
      "threshold": {admin_count}
    }}
  ]"#
                )
                .as_ref(),
            );
        }

        template.push_str("\n}");

        // Substitute placeholders with actual keys
        let content = test_keys.substitute_keys(template);
        fs::write(&signers_file_path, content)?;

        // Create signatures for the active signers file
        let hash = common::sha512_for_file(&signers_file_path)?;

        // Sign with the first two keys (artifact signers)
        let pubkey0 = test_keys.pub_key(0).unwrap();
        let seckey0 = test_keys.sec_key(0).unwrap();
        let signature0 = seckey0.sign(&hash).unwrap();

        let pubkey1 = test_keys.pub_key(1).unwrap();
        let seckey1 = test_keys.sec_key(1).unwrap();
        let signature1 = seckey1.sign(&hash).unwrap();

        // Create the aggregate signature
        SignatureWithState::load_for_file(&signers_file_path)?
            .get_pending()
            .unwrap()
            .add_individual_signature(&signature0, pubkey0)?
            .get_pending()
            .unwrap()
            .add_individual_signature(&signature1, pubkey1)?;

        let key_index = 2;
        // If master keys are included, sign with them too
        if master_count > 0 {
            let sig = SignatureWithState::load_for_file(&signers_file_path)?;

            (0..master_count)
                .collect::<Vec<usize>>()
                .iter()
                .fold(sig, |acc, i| {
                    let pubkey = test_keys.pub_key(i + key_index).unwrap();
                    let seckey = test_keys.sec_key(i + key_index).unwrap();
                    let signature = seckey.sign(&hash).unwrap();

                    acc.get_pending()
                        .unwrap()
                        .add_individual_signature(&signature, pubkey)
                        .unwrap()
                });
        }

        let key_index = 2 + master_count;
        // If admin keys are included, sign with them too
        if admin_count > 0 {
            let sig = SignatureWithState::load_for_file(&signers_file_path)?;

            (0..admin_count)
                .collect::<Vec<usize>>()
                .iter()
                .fold(sig, |acc, i| {
                    let pubkey = test_keys.pub_key(i + key_index).unwrap();
                    let seckey = test_keys.sec_key(i + key_index).unwrap();
                    let signature = seckey.sign(&hash).unwrap();

                    acc.get_pending()
                        .unwrap()
                        .add_individual_signature(&signature, pubkey)
                        .unwrap()
                });
        }

        Ok(signers_file_path)
    }

    // Helper function to create a test proposal content string
    fn create_test_proposal(test_keys: &TestKeys) -> String {
        // Create a template for the proposal
        let template = r#"
{
  "version": 2,
          "timestamp": "TIMESTAMP",
  "artifact_signers": [
    {
      "signers": [
        { "kind": "key", "data": { "pubkey": "PUBKEY0_PLACEHOLDER" } },
        { "kind": "key", "data": { "pubkey": "PUBKEY1_PLACEHOLDER" } }
      ],
      "threshold": 2
    }
  ],
  "master_keys": [],
  "admin_keys": null
}
"#
        .replace("TIMESTAMP", chrono::Utc::now().to_string().as_str());

        // Substitute placeholders with actual keys
        test_keys.substitute_keys(template.to_string())
    }

    #[test]
    fn test_propose_signers_file_with_admin_signer() -> Result<()> {
        let temp_dir = TempDir::new()?;
        let root_dir = temp_dir.path();
        let test_keys = TestKeys::new(4);

        // Create active signers with admin keys
        create_test_active_signers_for_update(root_dir, &test_keys, 1, 0)?;

        // Create a proposal
        let proposal_content = create_test_proposal(&test_keys);

        // Propose the new signers file (no longer signs)
        // key2 is the admin key in the active config
        propose_signers_file(
            root_dir,
            &proposal_content,
            &test_metadata_json(),
            test_keys.pub_key(2).unwrap(),
        )?;

        // Verify the pending file was created (propose no longer signs/activates)
        let pending_file_path = root_dir.join(format!("{}/{}", PENDING_SIGNERS_DIR, SIGNERS_FILE));
        assert!(pending_file_path.exists());

        // Verify the content
        let content = fs::read_to_string(&pending_file_path)?;
        let _config: SignersConfig = parse_signers_config(&content)?;

        assert_metadata_file_valid(root_dir, false);
        Ok(())
    }

    #[test]
    fn test_propose_signers_file_wrong_timestamp() -> Result<()> {
        let temp_dir = TempDir::new()?;
        let root_dir = temp_dir.path();
        let test_keys = TestKeys::new(4);

        // Create a proposal before we setup the active signers file
        // This means that the timestamp of the update will be smaller than the active signers
        // file, which we reject
        let proposal_content = create_test_proposal(&test_keys);

        // Create active signers with admin keys
        create_test_active_signers_for_update(root_dir, &test_keys, 1, 0)?;

        // Propose the new signers file
        let result = propose_signers_file(
            root_dir,
            &proposal_content,
            &test_metadata_json(),
            test_keys.pub_key(2).unwrap(),
        );

        match result {
            Err(SignersFileError::InvalidData(s)) => {
                assert!(s.starts_with("Timestamp of update is smaller than active signers file's:"))
            }
            Err(e) => panic!(
                "Expected InvalidaData(Timestamp of update is smaller than active signers file's), but got {} ",
                e
            ),
            Ok(_) => panic!(
                "Expected InvalidaData(Timestamp of update is smaller than active signers file's) but got a success result!"
            ),
        }
        Ok(())
    }
    #[test]
    fn test_propose_signers_file_with_multiple_admin_signers() -> Result<()> {
        let temp_dir = TempDir::new()?;
        let root_dir = temp_dir.path();
        let test_keys = TestKeys::new(5);

        // Create active signers with admin keys
        create_test_active_signers_for_update(root_dir, &test_keys, 2, 0)?;

        // Create a proposal
        let proposal_content = create_test_proposal(&test_keys);

        // Propose the new signers file
        propose_signers_file(
            root_dir,
            &proposal_content,
            &test_metadata_json(),
            test_keys.pub_key(2).unwrap(),
        )?;

        // Verify the pending file was created
        let pending_file_path = root_dir.join(format!("{}/{}", PENDING_SIGNERS_DIR, SIGNERS_FILE));
        assert!(pending_file_path.exists());

        // Verify the content
        let content = fs::read_to_string(&pending_file_path)?;
        let _config: SignersConfig = parse_signers_config(&content)?;

        assert_metadata_file_valid(root_dir, false);
        Ok(())
    }

    #[test]
    fn test_propose_signers_file_with_multiple_master_signers() -> Result<()> {
        let temp_dir = TempDir::new()?;
        let root_dir = temp_dir.path();
        let test_keys = TestKeys::new(5);

        // Create active signers with admin keys
        create_test_active_signers_for_update(root_dir, &test_keys, 1, 2)?;

        // Create a proposal
        let proposal_content = create_test_proposal(&test_keys);

        // Propose the new signers file; key4 is the admin key
        propose_signers_file(
            root_dir,
            &proposal_content,
            &test_metadata_json(),
            test_keys.pub_key(4).unwrap(),
        )?;

        // Verify the pending file was created
        let pending_file_path = root_dir.join(format!("{}/{}", PENDING_SIGNERS_DIR, SIGNERS_FILE));
        assert!(pending_file_path.exists());

        // Verify the content
        let content = fs::read_to_string(&pending_file_path)?;
        let _config: SignersConfig = parse_signers_config(&content)?;

        assert_metadata_file_valid(root_dir, false);
        Ok(())
    }

    #[test]
    fn test_propose_signers_file_with_master_signer() -> Result<()> {
        let temp_dir = TempDir::new()?;
        let root_dir = temp_dir.path();
        let test_keys = TestKeys::new(3);

        // Create active signers with master keys
        create_test_active_signers_for_update(root_dir, &test_keys, 0, 1)?;

        // Create a proposal
        let proposal_content = create_test_proposal(&test_keys);

        // Propose the new signers file; key2 is a master key
        propose_signers_file(
            root_dir,
            &proposal_content,
            &test_metadata_json(),
            test_keys.pub_key(2).unwrap(),
        )?;

        // Verify the pending file is created. Threshold is 1, but need signature from previous
        // signers file.
        let pending_file_path = root_dir.join(format!("{}/{}", PENDING_SIGNERS_DIR, SIGNERS_FILE));
        assert!(pending_file_path.exists());

        // Check the pending signers dir is  present
        let pending_signers_dir = root_dir.join(PENDING_SIGNERS_DIR);
        assert!(pending_signers_dir.exists());

        // Verify the content
        let content = fs::read_to_string(&pending_file_path)?;
        let _config: SignersConfig = parse_signers_config(&content)?;

        // Check no local copy of the signers was taken as it is a signers file
        let local_signers_path = root_dir.join(format!(
            "{}/{}.{}",
            SIGNERS_DIR, SIGNERS_FILE, SIGNERS_SUFFIX
        ));
        assert!(!local_signers_path.exists());

        assert_metadata_file_valid(root_dir, false);
        Ok(())
    }

    // test_propose_signers_file_with_invalid_signature_fails was removed because
    // propose_signers_file no longer verifies signatures (only authorization).
    // Signature validation now happens at sign time via sign_signers_and_metadata_file.
    #[test]
    fn test_propose_signers_file_without_active_signers_fails() -> Result<()> {
        let temp_dir = TempDir::new()?;
        let root_dir = temp_dir.path();
        let test_keys = TestKeys::new(1);

        // Don't create active signers

        // Create a proposal
        let proposal_content = create_test_proposal(&test_keys);

        // Try to propose the new signers file (fails before auth check: no active signers)
        let result = propose_signers_file(
            root_dir,
            &proposal_content,
            &test_metadata_json(),
            test_keys.pub_key(0).unwrap(),
        );

        // Verify it fails
        assert!(result.is_err());
        match result.unwrap_err() {
            SignersFileError::InitialisationError(_) => {} // Expected
            _ => panic!("Expected InitialisationError error"),
        }

        // Verify no pending file was created
        let pending_file_path = root_dir.join(format!("{}/{}", PENDING_SIGNERS_DIR, SIGNERS_FILE));
        assert!(!pending_file_path.exists());

        Ok(())
    }

    // test_propose_signers_file_with_invalid_signature_fails was removed because
    // propose_signers_file no longer verifies signatures.
    // Signature validation now happens at sign time via sign_signers_and_metadata_file.

    #[test]
    fn test_propose_signers_file_with_existing_pending_file_fails() -> Result<()> {
        let temp_dir = TempDir::new()?;
        let root_dir = temp_dir.path();
        let test_keys = TestKeys::new(4);

        // Create active signers with admin keys
        create_test_active_signers_for_update(root_dir, &test_keys, 1, 0)?;

        // Create an existing pending file
        let pending_dir = root_dir.join(PENDING_SIGNERS_DIR);
        fs::create_dir_all(&pending_dir)?;
        let pending_file_path = pending_dir.join(SIGNERS_FILE);
        fs::write(&pending_file_path, "existing content")?;

        // Create a proposal
        let proposal_content = create_test_proposal(&test_keys);

        // Try to propose the new signers file
        let result = propose_signers_file(
            root_dir,
            &proposal_content,
            &test_metadata_json(),
            test_keys.pub_key(2).unwrap(),
        );

        // Verify it fails
        assert!(result.is_err());
        match result.unwrap_err() {
            SignersFileError::InitialisationError(_) => {} // Expected
            _ => panic!("Expected InitialisationError error"),
        }

        // Verify the existing pending file is unchanged
        let content = fs::read_to_string(&pending_file_path)?;
        assert_eq!(content, "existing content");

        Ok(())
    }

    #[test]
    fn test_propose_signers_file_with_existing_pending_signature_file_fails() -> Result<()> {
        let temp_dir = TempDir::new()?;
        let root_dir = temp_dir.path();
        let test_keys = TestKeys::new(4);

        // Create active signers with admin keys
        create_test_active_signers_for_update(root_dir, &test_keys, 1, 0)?;

        // Create an existing pending signature file
        let pending_dir = root_dir.join(PENDING_SIGNERS_DIR);
        fs::create_dir_all(&pending_dir)?;
        let pending_sig_file_path =
            pending_dir.join(format!("{}.{}", SIGNERS_FILE, PENDING_SIGNATURES_SUFFIX));
        fs::write(&pending_sig_file_path, "existing signature")?;

        // Create a proposal
        let proposal_content = create_test_proposal(&test_keys);

        // Try to propose the new signers file
        let result = propose_signers_file(
            root_dir,
            &proposal_content,
            &test_metadata_json(),
            test_keys.pub_key(2).unwrap(),
        );

        // Verify it fails
        assert!(result.is_err());
        match result.unwrap_err() {
            SignersFileError::InitialisationError(_) => {} // Expected
            _ => panic!("Expected InitialisationError error"),
        }

        // Verify the existing pending signature file is unchanged
        let content = fs::read_to_string(&pending_sig_file_path)?;
        assert_eq!(content, "existing signature");

        Ok(())
    }

    #[test]
    fn test_propose_signers_file_with_existing_complete_signature_file_fails() -> Result<()> {
        let temp_dir = TempDir::new()?;
        let root_dir = temp_dir.path();
        let test_keys = TestKeys::new(4);

        // Create active signers with admin keys
        create_test_active_signers_for_update(root_dir, &test_keys, 1, 0)?;

        // Create an existing complete signature file
        let pending_dir = root_dir.join(PENDING_SIGNERS_DIR);
        fs::create_dir_all(&pending_dir)?;
        let complete_sig_file_path =
            pending_dir.join(format!("{}.{}", SIGNERS_FILE, SIGNATURES_SUFFIX));
        fs::write(&complete_sig_file_path, "existing signature")?;

        // Create a proposal
        let proposal_content = create_test_proposal(&test_keys);

        // Try to propose the new signers file
        let result = propose_signers_file(
            root_dir,
            &proposal_content,
            &test_metadata_json(),
            test_keys.pub_key(2).unwrap(),
        );

        // Verify it fails
        assert!(result.is_err());
        match result.unwrap_err() {
            SignersFileError::InitialisationError(_) => {} // Expected
            _ => panic!("Expected InitialisationError error"),
        }

        // Verify the existing complete signature file is unchanged
        let content = fs::read_to_string(&complete_sig_file_path)?;
        assert_eq!(content, "existing signature");

        Ok(())
    }

    #[test]
    fn test_propose_signers_file_for_nested_directory() -> Result<()> {
        let temp_dir = TempDir::new()?;
        let root_dir = temp_dir.path();
        let nested_dir = root_dir.join("nested");
        let test_keys = TestKeys::new(4);

        // Create active signers with admin keys in nested directory
        create_test_active_signers_for_update(root_dir, &test_keys, 1, 0)?;

        // Create a proposal
        let proposal_content = create_test_proposal(&test_keys);

        // Propose the new signers file; key2 is the admin key
        propose_signers_file(
            &nested_dir,
            &proposal_content,
            &test_metadata_json(),
            test_keys.pub_key(2).unwrap(),
        )?;

        // Verify the pending file was created in the nested directory
        // File is pending as old signers did not sign the update
        let pending_file_path =
            nested_dir.join(format!("{}/{}", PENDING_SIGNERS_DIR, SIGNERS_FILE));
        assert!(pending_file_path.exists());

        // Verify the content
        let content = fs::read_to_string(&pending_file_path)?;
        let _config: SignersConfig = parse_signers_config(&content)?;

        assert_metadata_file_valid(&nested_dir, false);
        Ok(())
    }

    // write_valid_signers_file
    // ------------------------
    #[test]
    fn test_write_valid_signers_file_success_incomplete() -> Result<()> {
        let temp_dir = TempDir::new()?;
        let dir_path = temp_dir.path();
        let test_keys = TestKeys::new(3);

        // Create a test config with threshold 2 (incomplete with 1 signature)
        let json_content_template = r#"
        {
          "version": 1,
      "timestamp": "TIMESTAMP",
          "artifact_signers": [
            {
              "signers": [
                { "kind": "key", "data": { "pubkey": "PUBKEY0_PLACEHOLDER"} },
                { "kind": "key", "data": { "pubkey": "PUBKEY1_PLACEHOLDER"} }
              ],
              "threshold": 2
            }
          ],
          "master_keys": [],
          "admin_keys": null
        }
        "#
        .replace("TIMESTAMP", chrono::Utc::now().to_string().as_str());

        let json_content = test_keys.substitute_keys(json_content_template.to_string());

        // Call write_valid_signers_file
        write_valid_signers_file(dir_path, &json_content, &test_metadata_json())?;

        // Verify pending signers file exists
        let pending_file_path = dir_path.join(format!("{}/{}", PENDING_SIGNERS_DIR, SIGNERS_FILE));
        assert!(pending_file_path.exists());

        // Verify content matches
        let content = fs::read_to_string(&pending_file_path)?;
        assert_eq!(content, json_content);

        assert_metadata_file_valid(dir_path, false);
        Ok(())
    }

    #[test]
    fn test_write_valid_signers_file_success_complete() -> Result<()> {
        let temp_dir = TempDir::new()?;
        let dir_path = temp_dir.path();
        let test_keys = TestKeys::new(2);

        // Create a test config with threshold 1 (complete with 1 signature)
        let json_content_template = r#"
        {
          "version": 1,
      "timestamp": "TIMESTAMP",
          "artifact_signers": [
            {
              "signers": [
                { "kind": "key", "data": { "pubkey": "PUBKEY0_PLACEHOLDER"} }
              ],
              "threshold": 1
            }
          ],
          "master_keys": [],
          "admin_keys": null
        }
        "#
        .replace("TIMESTAMP", chrono::Utc::now().to_string().as_str());

        let json_content = test_keys.substitute_keys(json_content_template.to_string());

        // Call write_valid_signers_file (no longer signs, so stays pending)
        write_valid_signers_file(dir_path, &json_content, &test_metadata_json())?;

        // Verify pending signers file exists (write no longer signs/activates)
        let pending_file_path = dir_path.join(format!("{}/{}", PENDING_SIGNERS_DIR, SIGNERS_FILE));
        assert!(pending_file_path.exists());

        assert_metadata_file_valid(dir_path, false);
        Ok(())
    }

    #[test]
    fn test_write_valid_signers_file_fails_with_existing_signers_file() -> Result<()> {
        let temp_dir = TempDir::new()?;
        let dir_path = temp_dir.path();

        // Create an existing signers file
        let pending_dir = dir_path.join(PENDING_SIGNERS_DIR);
        fs::create_dir_all(&pending_dir)?;
        let existing_file = pending_dir.join(SIGNERS_FILE);
        fs::write(&existing_file, "existing content")?;

        let json_content = r#"
        {
          "version": 1,
      "timestamp": "TIMESTAMP",
          "artifact_signers": [
            {
              "signers": [
                { "kind": "key", "data": { "pubkey": "asfaload-pub:b5S+CxuqICIUn/DGBdMKeTMZCgQcg78ohiWQ1sC00c8"} }
              ],
              "threshold": 1
            }
          ],
          "master_keys": [],
          "admin_keys": null
        }
        "#.replace("TIMESTAMP", chrono::Utc::now().to_string().as_str());

        // Should fail
        let result =
            write_valid_signers_file(dir_path, json_content.as_str(), &test_metadata_json());
        assert!(result.is_err());
        match result.unwrap_err() {
            SignersFileError::InitialisationError(msg) => {
                assert!(msg.contains("Signers file exists"));
            }
            e => panic!("Expected InitialisationError, got {}", e),
        }

        // Verify existing file is unchanged
        let content = fs::read_to_string(&existing_file)?;
        assert_eq!(content, "existing content");

        Ok(())
    }

    #[test]
    fn test_write_valid_signers_file_fails_with_existing_pending_signature() -> Result<()> {
        let temp_dir = TempDir::new()?;
        let dir_path = temp_dir.path();

        // Create an existing pending signature file
        let pending_dir = dir_path.join(PENDING_SIGNERS_DIR);
        fs::create_dir_all(&pending_dir)?;
        let existing_sig =
            pending_dir.join(format!("{}.{}", SIGNERS_FILE, PENDING_SIGNATURES_SUFFIX));
        fs::write(&existing_sig, "existing signature")?;

        let json_content = r#"
        {
          "version": 1,
      "timestamp": "TIMESTAMP",
          "artifact_signers": [
            {
              "signers": [
                { "kind": "key", "data": { "pubkey": "asfaload-pub:b5S+CxuqICIUn/DGBdMKeTMZCgQcg78ohiWQ1sC00c8"} }
              ],
              "threshold": 1
            }
          ],
          "master_keys": [],
          "admin_keys": null
        }
        "#.replace("TIMESTAMP", chrono::Utc::now().to_string().as_str());

        // Should fail
        let result =
            write_valid_signers_file(dir_path, json_content.as_str(), &test_metadata_json());
        assert!(result.is_err());
        match result.unwrap_err() {
            SignersFileError::InitialisationError(msg) => {
                assert!(msg.contains("Pending signature file exists"));
            }
            _ => panic!("Expected InitialisationError"),
        }

        // Verify existing signature file is unchanged
        let content = fs::read_to_string(&existing_sig)?;
        assert_eq!(content, "existing signature");

        Ok(())
    }

    #[test]
    fn test_write_valid_signers_file_fails_with_existing_complete_signature() -> Result<()> {
        let temp_dir = TempDir::new()?;
        let dir_path = temp_dir.path();

        // Create an existing complete signature file
        let pending_dir = dir_path.join(PENDING_SIGNERS_DIR);
        fs::create_dir_all(&pending_dir)?;
        let existing_sig = pending_dir.join(format!("{}.{}", SIGNERS_FILE, SIGNATURES_SUFFIX));
        fs::write(&existing_sig, "existing signature")?;

        let json_content = r#"
        {
          "version": 1,
          "timestamp": "TIMESTAMP",
          "artifact_signers": [
            {
              "signers": [
                { "kind": "key", "data": { "pubkey": "asfaload-pub:b5S+CxuqICIUn/DGBdMKeTMZCgQcg78ohiWQ1sC00c8"} }
              ],
              "threshold": 1
            }
          ],
          "master_keys": [],
          "admin_keys": null
        }
        "#.replace("TIMESTAMP", chrono::Utc::now().to_string().as_str());

        // Should fail
        let result =
            write_valid_signers_file(dir_path, json_content.as_str(), &test_metadata_json());
        assert!(result.is_err());
        match result.unwrap_err() {
            SignersFileError::InitialisationError(msg) => {
                assert!(msg.contains("Complete signature file exists"));
            }
            _ => panic!("Expected InitialisationError"),
        }

        // Verify existing signature file is unchanged
        let content = fs::read_to_string(&existing_sig)?;
        assert_eq!(content, "existing signature");

        Ok(())
    }

    #[test]
    fn test_write_valid_signers_file_fails_with_invalid_json() -> Result<()> {
        let temp_dir = TempDir::new()?;
        let dir_path = temp_dir.path();

        let invalid_json = r#"
        {
          "version": "invalid",
          "timestamp": "TIMESTAMP",
          "artifact_signers": [
            {
              "signers": [
                { "kind": "key", "data": { "pubkey": "asfaload-pub:b5S+CxuqICIUn/DGBdMKeTMZCgQcg78ohiWQ1sC00c8"} }
              ],
              "threshold": 1
            }
          ],
          "master_keys": [],
          "admin_keys": null
        }
        "#.replace("TIMESTAMP", chrono::Utc::now().to_string().as_str());

        // Should fail
        let result = write_valid_signers_file(dir_path, &invalid_json, &test_metadata_json());
        assert!(result.is_err());
        match result.unwrap_err() {
            SignersFileError::JsonError(_) => {} // Expected
            e => panic!("Expected JsonError, got {}", e),
        }

        // Verify no files were created
        let pending_dir = dir_path.join(PENDING_SIGNERS_DIR);
        assert!(!pending_dir.exists());

        Ok(())
    }

    // test_write_valid_signers_file_fails_with_validator_error and
    // test_write_valid_signers_file_fails_with_invalid_signature were removed because
    // write_valid_signers_file no longer takes signature/pubkey/validator arguments.

    #[test]
    fn test_write_valid_signers_file_with_nested_directory() -> Result<()> {
        let temp_dir = TempDir::new()?;
        let root_dir = temp_dir.path();
        let nested_dir = root_dir.join("nested");

        let json_content = r#"
        {
          "version": 1,
          "timestamp": "TIMESTAMP",
          "artifact_signers": [
            {
              "signers": [
                { "kind": "key", "data": { "pubkey": "asfaload-pub:b5S+CxuqICIUn/DGBdMKeTMZCgQcg78ohiWQ1sC00c8"} }
              ],
              "threshold": 1
            }
          ],
          "master_keys": [],
          "admin_keys": null
        }
        "#.replace("TIMESTAMP", chrono::Utc::now().to_string().as_str());

        // Should succeed
        write_valid_signers_file(&nested_dir, &json_content, &test_metadata_json())?;

        // Verify files are in the nested directory
        let pending_dir = nested_dir.join(PENDING_SIGNERS_DIR);
        assert!(pending_dir.exists());

        let pending_file = pending_dir.join(SIGNERS_FILE);
        assert!(pending_file.exists());

        Ok(())
    }

    #[test]
    fn test_write_valid_signers_file_io_error_on_write() -> Result<()> {
        let temp_dir = TempDir::new()?;
        let dir_path = temp_dir.path();

        // Create the pending directory but make it read-only
        let pending_dir = dir_path.join(PENDING_SIGNERS_DIR);
        fs::create_dir_all(&pending_dir)?;

        let mut perms = fs::metadata(&pending_dir)?.permissions();
        perms.set_readonly(true);
        fs::set_permissions(&pending_dir, perms)?;

        let json_content = r#"
        {
          "version": 1,
          "timestamp": "TIMESTAMP",
          "artifact_signers": [
            {
              "signers": [
                { "kind": "key", "data": { "pubkey": "asfaload-pub:b5S+CxuqICIUn/DGBdMKeTMZCgQcg78ohiWQ1sC00c8"} }
              ],
              "threshold": 1
            }
          ],
          "master_keys": [],
          "admin_keys": null
        }
        "#.replace("TIMESTAMP", chrono::Utc::now().to_string().as_str());

        // Should fail with IO error
        let result = write_valid_signers_file(dir_path, &json_content, &test_metadata_json());
        assert!(result.is_err());
        match result.unwrap_err() {
            SignersFileError::IoError(_e) => {} // Expected
            e => panic!("Expected IoError, got {}", e),
        }

        // The rollback in write_valid_signers_file removes the pending directory
        // (remove_dir_all succeeds because the parent directory is writable).
        assert!(
            !pending_dir.exists(),
            "Pending directory should have been cleaned up by rollback"
        );
        Ok(())
    }

    #[test]
    fn test_write_valid_signers_file_with_already_pending_dir() -> Result<()> {
        let temp_dir = TempDir::new()?;
        let dir_path = temp_dir.path();

        // Create the pending directory in advance
        let pending_dir = dir_path.join(PENDING_SIGNERS_DIR);
        fs::create_dir_all(&pending_dir)?;

        let json_content = r#"
        {
          "version": 1,
          "timestamp": "TIMESTAMP",
          "artifact_signers": [
            {
              "signers": [
                { "kind": "key", "data": { "pubkey": "asfaload-pub:b5S+CxuqICIUn/DGBdMKeTMZCgQcg78ohiWQ1sC00c8"} }
              ],
              "threshold": 1
            }
          ],
          "master_keys": [],
          "admin_keys": null
        }
        "#.replace("TIMESTAMP", chrono::Utc::now().to_string().as_str());

        // Should succeed
        write_valid_signers_file(dir_path, &json_content, &test_metadata_json())?;

        // Verify files were created
        let pending_file = pending_dir.join(SIGNERS_FILE);
        assert!(pending_file.exists());

        Ok(())
    }

    #[test]
    fn test_write_valid_signers_file_with_path_already_ending_in_pending() -> Result<()> {
        let temp_dir = TempDir::new()?;
        let root_dir = temp_dir.path();
        let pending_dir = root_dir.join(PENDING_SIGNERS_DIR);

        let json_content = r#"
        {
          "version": 1,
          "timestamp": "TIMESTAMP",
          "artifact_signers": [
            {
              "signers": [
                { "kind": "key", "data": { "pubkey": "asfaload-pub:b5S+CxuqICIUn/DGBdMKeTMZCgQcg78ohiWQ1sC00c8"} }
              ],
              "threshold": 1
            }
          ],
          "master_keys": [],
          "admin_keys": null
        }
        "#.replace("TIMESTAMP", chrono::Utc::now().to_string().as_str());

        // Pass path that already ends with PENDING_SIGNERS_DIR
        write_valid_signers_file(&pending_dir, &json_content, &test_metadata_json())?;

        // Verify files were created in the correct location
        let pending_file = pending_dir.join(SIGNERS_FILE);
        assert!(pending_file.exists());

        // Verify no nested pending directory was created
        let nested_pending = pending_dir.join(PENDING_SIGNERS_DIR);
        assert!(!nested_pending.exists());

        Ok(())
    }

    // Tests for sign_signers_and_metadata_file
    // ----------------------------------------

    // Helper function to create a test signers file with given content,
    // including metadata file and empty pending signatures for both.
    fn create_test_signers_file_with_content(
        dir_path: &Path,
        content: &str,
    ) -> Result<PathBuf, SignersFileError> {
        let pending_dir = dir_path.join(PENDING_SIGNERS_DIR);
        fs::create_dir_all(&pending_dir)?;
        let signers_file_path = pending_dir.join(SIGNERS_FILE);
        fs::write(&signers_file_path, content)?;

        // Create metadata file
        let metadata_path = metadata_path_for(&signers_file_path)?;
        let metadata = test_metadata();
        let metadata_file = std::fs::File::create(&metadata_path)?;
        serde_json::to_writer_pretty(&metadata_file, &metadata)?;

        // Create empty pending signatures for metadata file
        let metadata_pending_sig_path = pending_signatures_path_for(&metadata_path)?;
        let empty_sigs = SignaturesFile::new();
        fs::write(
            metadata_pending_sig_path,
            serde_json::to_string_pretty(&empty_sigs)?,
        )?;

        Ok(signers_file_path)
    }

    // Helper to compute a metadata signature for a signers file
    fn compute_metadata_signature(
        signers_file_path: &Path,
        test_keys: &TestKeys,
        key_index: usize,
    ) -> Result<AsfaloadSignatures, SignersFileError> {
        let metadata_path = metadata_path_for(signers_file_path)?;
        let metadata_hash = common::sha512_for_file(&metadata_path)?;
        Ok(test_keys
            .sec_key(key_index)
            .unwrap()
            .sign(&metadata_hash)
            .unwrap())
    }

    // Helper function to create a test signature file
    fn create_test_signature_file(
        signers_file_path: &Path,
        test_keys: &TestKeys,
        signer_indices: &[usize],
    ) -> Result<(), SignersFileError> {
        let hash = common::sha512_for_file(signers_file_path)?;
        let mut sig_file = SignaturesFile::new();

        for &index in signer_indices {
            let pubkey = test_keys.pub_key(index).unwrap();
            let seckey = test_keys.sec_key(index).unwrap();
            let signature = seckey.sign(&hash).unwrap();
            sig_file.entries.insert(
                pubkey.to_base64(),
                TaggedSignature {
                    format: pubkey.key_format(),
                    signature: signature.to_base64(),
                },
            );
        }

        let pending_sig_path = pending_signatures_path_for(signers_file_path)?;
        fs::write(pending_sig_path, serde_json::to_string(&sig_file)?)?;

        Ok(())
    }

    #[test]
    fn test_sign_signers_and_metadata_file_success() -> Result<()> {
        let temp_dir = TempDir::new()?;
        let dir_path = temp_dir.path();
        let test_keys = TestKeys::new(2);

        // Create a test signers file
        let signers_config = create_test_signers_config(&test_keys);
        let signers_content = signers_config.to_json()?;
        let signers_file_path = create_test_signers_file_with_content(dir_path, &signers_content)?;

        // Compute hash and sign
        let hash = common::sha512_for_file(&signers_file_path)?;
        let pubkey = test_keys.pub_key(0).unwrap();
        let seckey = test_keys.sec_key(0).unwrap();
        let signature = seckey.sign(&hash).unwrap();
        let metadata_sig = compute_metadata_signature(&signers_file_path, &test_keys, 0)?;

        // Call sign_signers_and_metadata_file
        sign_signers_and_metadata_file(&signers_file_path, &signature, pubkey, &metadata_sig)?;

        // Verify the pending signature file exists
        let pending_sig_path = pending_signatures_path_for(&signers_file_path)?;
        assert!(pending_sig_path.exists());

        // Verify the signature file content
        let sig_content = fs::read_to_string(&pending_sig_path)?;
        let sig_map: SignaturesFile = serde_json::from_str(&sig_content)?;
        assert_eq!(sig_map.entries.len(), 1);
        assert!(sig_map.entries.contains_key(&pubkey.to_base64()));
        assert_eq!(
            sig_map.entries[&pubkey.to_base64()].signature,
            signature.to_base64()
        );

        Ok(())
    }

    #[test]
    fn test_sign_signers_and_metadata_file_on_non_signers() -> Result<()> {
        let temp_dir = TempDir::new()?;
        let dir_path = temp_dir.path();
        let test_keys = TestKeys::new(2);

        // Create a test signers file
        let signers_config = create_test_signers_config(&test_keys);
        let signers_content = signers_config.to_json()?;
        let signers_file_path = create_test_signers_file_with_content(dir_path, &signers_content)?;
        let my_file = dir_path.join("myfile");
        std::fs::rename(&signers_file_path, &my_file)?;
        // Compute metadata sig before removing the dir
        let metadata_sig = compute_metadata_signature(&signers_file_path, &test_keys, 0)?;
        std::fs::remove_dir_all(dir_path.join(PENDING_SIGNERS_DIR))?;

        // Compute hash and sign
        let hash = common::sha512_for_file(&my_file)?;
        let pubkey = test_keys.pub_key(0).unwrap();
        let seckey = test_keys.sec_key(0).unwrap();
        let signature = seckey.sign(&hash).unwrap();

        // Call sign_signers_and_metadata_file -- should fail because file is not in signers dir
        let result = sign_signers_and_metadata_file(&my_file, &signature, pubkey, &metadata_sig);

        assert!(result.is_err());
        match result.err().unwrap() {
            SignersFileError::FileSystemHierarchyError(_) => {} // Expected
            e => panic!("Expected FileSystemHierarchyError, got {}", e),
        }

        Ok(())
    }

    #[test]
    fn test_sign_signers_and_metadata_file_with_existing_signatures() -> Result<()> {
        let temp_dir = TempDir::new()?;
        let dir_path = temp_dir.path();
        let test_keys = TestKeys::new(3);

        // Create a test signers file
        let signers_config = create_test_signers_config(&test_keys);
        let signers_content = signers_config.to_json()?;
        let signers_file_path = create_test_signers_file_with_content(dir_path, &signers_content)?;

        // Create an existing signature file with one signature
        create_test_signature_file(&signers_file_path, &test_keys, &[0])?;

        // Also add corresponding metadata signature for key 0
        let metadata_path = metadata_path_for(&signers_file_path)?;
        let metadata_hash = common::sha512_for_file(&metadata_path)?;
        let meta_sig0 = test_keys.sec_key(0).unwrap().sign(&metadata_hash)?;
        let metadata_pending_sig_path = pending_signatures_path_for(&metadata_path)?;
        let mut meta_sig_file: SignaturesFile =
            serde_json::from_str(&fs::read_to_string(&metadata_pending_sig_path)?)?;
        meta_sig_file.entries.insert(
            test_keys.pub_key(0).unwrap().to_base64(),
            TaggedSignature {
                format: test_keys.pub_key(0).unwrap().key_format(),
                signature: meta_sig0.to_base64(),
            },
        );
        fs::write(
            &metadata_pending_sig_path,
            serde_json::to_string(&meta_sig_file)?,
        )?;

        // Compute hash and sign with a different key
        let hash = common::sha512_for_file(&signers_file_path)?;
        let pubkey = test_keys.pub_key(1).unwrap();
        let seckey = test_keys.sec_key(1).unwrap();
        let signature = seckey.sign(&hash).unwrap();
        let metadata_sig = compute_metadata_signature(&signers_file_path, &test_keys, 1)?;

        // Call sign_signers_and_metadata_file
        sign_signers_and_metadata_file(&signers_file_path, &signature, pubkey, &metadata_sig)?;

        // Verify the signature is complete and the signers file was activated
        let pending_sig_path = pending_signatures_path_for(&signers_file_path)?;
        assert!(!pending_sig_path.exists());
        let active_signers_path = temp_dir.path().join(SIGNERS_DIR).join(SIGNERS_FILE);
        let complete_sig_path = signatures_path_for(&active_signers_path)?;
        assert!(complete_sig_path.exists());

        // Verify the signature file content contains both signatures
        let sig_content = fs::read_to_string(&complete_sig_path)?;
        let sig_map: SignaturesFile = serde_json::from_str(&sig_content)?;
        assert_eq!(sig_map.entries.len(), 2);
        assert!(
            sig_map
                .entries
                .contains_key(&test_keys.pub_key(0).unwrap().to_base64())
        );
        assert!(sig_map.entries.contains_key(&pubkey.to_base64()));

        Ok(())
    }

    #[test]
    fn test_sign_signers_and_metadata_file_with_2_steps_to_complete() -> Result<()> {
        let temp_dir = TempDir::new()?;
        let dir_path = temp_dir.path();
        let test_keys = TestKeys::new(2);

        // Create a test signers file with threshold 1
        let mut signers_config_proposal = create_test_signers_config(&test_keys).as_proposal();
        signers_config_proposal.artifact_signers[0].threshold = 1;
        let signers_config = signers_config_proposal.build()?;
        let signers_content = signers_config.to_json()?;
        let signers_file_path = create_test_signers_file_with_content(dir_path, &signers_content)?;

        // Compute hash and sign
        let hash = common::sha512_for_file(&signers_file_path)?;
        let pubkey0 = test_keys.pub_key(0).unwrap();
        let seckey0 = test_keys.sec_key(0).unwrap();
        let signature0 = seckey0.sign(&hash).unwrap();
        let metadata_sig0 = compute_metadata_signature(&signers_file_path, &test_keys, 0)?;

        let pubkey1 = test_keys.pub_key(1).unwrap();
        let seckey1 = test_keys.sec_key(1).unwrap();
        let signature1 = seckey1.sign(&hash).unwrap();
        let metadata_sig1 = compute_metadata_signature(&signers_file_path, &test_keys, 1)?;

        // Define our pending and complete signatures path here.
        let pending_sig_path = pending_signatures_path_for(&signers_file_path)?;
        let active_signers_path = temp_dir.path().join(SIGNERS_DIR).join(SIGNERS_FILE);
        let complete_sig_path = signatures_path_for(&active_signers_path)?;

        // Call sign_signers_and_metadata_file
        sign_signers_and_metadata_file(&signers_file_path, &signature0, pubkey0, &metadata_sig0)?;

        // Verify we have still the pending signature in the
        // PENDING_SIGNERS_DIR. The threshold is 1, but for a new signers
        // file we need all sigers to sign before we activate it.
        assert!(pending_sig_path.exists());

        // Verify the signature file content
        let sig_content = fs::read_to_string(&pending_sig_path)?;
        let sig_map: SignaturesFile = serde_json::from_str(&sig_content)?;
        assert_eq!(sig_map.entries.len(), 1);
        assert!(sig_map.entries.contains_key(&pubkey0.to_base64()));
        assert_eq!(
            sig_map.entries[&pubkey0.to_base64()].signature,
            signature0.to_base64()
        );

        // Add second signature
        sign_signers_and_metadata_file(&signers_file_path, &signature1, pubkey1, &metadata_sig1)?;
        assert!(!pending_sig_path.exists());
        assert!(complete_sig_path.exists());
        //
        // Verify the signature file content contains both signatures
        let sig_content = fs::read_to_string(&complete_sig_path)?;
        let sig_map: SignaturesFile = serde_json::from_str(&sig_content)?;
        assert_eq!(sig_map.entries.len(), 2);
        assert!(sig_map.entries.contains_key(&pubkey0.to_base64()));
        assert!(sig_map.entries.contains_key(&pubkey1.to_base64()));

        Ok(())
    }

    #[test]
    fn test_sign_signers_and_metadata_file_io_error() -> Result<()> {
        let temp_dir = TempDir::new()?;
        let dir_path = temp_dir.path();
        let test_keys = TestKeys::new(2);

        // Create a test signers file
        let signers_config = create_test_signers_config(&test_keys);
        let signers_content = signers_config.to_json()?;
        let signers_file_path = create_test_signers_file_with_content(dir_path, &signers_content)?;

        // Compute hash and sign
        let hash = common::sha512_for_file(&signers_file_path)?;
        let pubkey = test_keys.pub_key(0).unwrap();
        let seckey = test_keys.sec_key(0).unwrap();
        let signature = seckey.sign(&hash).unwrap();
        let metadata_sig = compute_metadata_signature(&signers_file_path, &test_keys, 0)?;

        // Make the directory read-only to cause an IO error
        let pending_dir = signers_file_path.parent().unwrap();
        let mut perms = fs::metadata(pending_dir)?.permissions();
        perms.set_readonly(true);
        fs::set_permissions(pending_dir, perms)?;

        // Call sign_signers_and_metadata_file and expect an error.
        // The IO error is wrapped in AggregateSignatureError since
        // that is what add_individual_signature returns
        let result =
            sign_signers_and_metadata_file(&signers_file_path, &signature, pubkey, &metadata_sig);
        match result {
            Err(SignersFileError::AggregateSignatureError(AggregateSignatureError::Io(_))) => {} // Expected
            Err(e) => panic!("Expected AggregateSignatureError(Io(_)), got {}", e),
            Ok(_) => panic!("Expected error, got Ok"),
        }

        // Restore permissions for cleanup
        let mut perms = fs::metadata(pending_dir)?.permissions();
        #[allow(clippy::permissions_set_readonly_false)]
        perms.set_readonly(false);
        fs::set_permissions(pending_dir, perms)?;

        Ok(())
    }

    #[test]
    fn test_sign_signers_and_metadata_file_signature_operation_error() -> Result<()> {
        let temp_dir = TempDir::new()?;
        let dir_path = temp_dir.path();
        let test_keys = TestKeys::new(2);

        // Create a test signers file
        let signers_config = create_test_signers_config(&test_keys);
        let signers_content = signers_config.to_json()?;
        let signers_file_path = create_test_signers_file_with_content(dir_path, &signers_content)?;

        // Create a corrupted signature file for the signers file that will cause an error
        let pending_sig_path = pending_signatures_path_for(&signers_file_path)?;
        fs::write(&pending_sig_path, "invalid json")?;

        // Compute hash and sign
        let hash = common::sha512_for_file(&signers_file_path)?;
        let pubkey = test_keys.pub_key(0).unwrap();
        let seckey = test_keys.sec_key(0).unwrap();
        let signature = seckey.sign(&hash).unwrap();
        let metadata_sig = compute_metadata_signature(&signers_file_path, &test_keys, 0)?;

        // Call sign_signers_and_metadata_file and expect an error.
        // The JSON error is wrapped in AggregateSignatureError since
        // that is what add_individual_signature returns
        let result =
            sign_signers_and_metadata_file(&signers_file_path, &signature, pubkey, &metadata_sig);
        match result {
            Err(SignersFileError::AggregateSignatureError(AggregateSignatureError::JsonError(
                _,
            ))) => {} // Expected
            Err(e) => panic!("Expected AggregateSignatureError(JsonError(_)), got {}", e),
            Ok(_) => panic!("Expected error, got Ok"),
        }

        Ok(())
    }

    // Tests for sign_signers_and_metadata_file with active signers file in parent directory
    // ---------------------------------------------------------------------------------

    // Helper function to create an active signers file in a parent directory
    fn create_active_signers_in_parent(
        parent_dir: &Path,
        test_keys: &TestKeys,
    ) -> Result<PathBuf, SignersFileError> {
        let active_signers_dir = parent_dir.join(SIGNERS_DIR);
        fs::create_dir_all(&active_signers_dir)?;
        let active_signers_file = active_signers_dir.join(SIGNERS_FILE);

        // Create a simple signers config with the test keys
        let signers_config = create_test_signers_config(test_keys);
        let signers_content = signers_config.to_json()?;
        fs::write(&active_signers_file, signers_content)?;

        // Create signatures for the active signers file
        let hash = common::sha512_for_file(&active_signers_file)?;

        // Sign with both keys to make it complete
        let pubkey0 = test_keys.pub_key(0).unwrap();
        let seckey0 = test_keys.sec_key(0).unwrap();
        let signature0 = seckey0.sign(&hash).unwrap();

        let pubkey1 = test_keys.pub_key(1).unwrap();
        let seckey1 = test_keys.sec_key(1).unwrap();
        let signature1 = seckey1.sign(&hash).unwrap();

        // Create the aggregate signature
        SignatureWithState::load_for_file(&active_signers_file)?
            .get_pending()
            .unwrap()
            .add_individual_signature(&signature0, pubkey0)?
            .get_pending()
            .unwrap()
            .add_individual_signature(&signature1, pubkey1)?;

        Ok(active_signers_file)
    }

    #[test]
    fn test_sign_signers_and_metadata_file_with_parent_active_signers_complete_after_all_signatures()
    -> Result<()> {
        let temp_dir = TempDir::new()?;
        let parent_dir = temp_dir.path();
        let child_dir = parent_dir.join("child");
        fs::create_dir(&child_dir)?;

        // These keys are used in the existing signers file, with a threshold of 2
        // It means those 2 keys have to sign for the activation to take place
        let test_keys = TestKeys::new(2);
        // These keys are used in the new signers file placed in a child directory,
        // with a threshold of 2
        // As those are new signers, both signatures have also to be collected for the
        // signers file to be activated.
        let new_keys = TestKeys::new_from(2, 2);

        // Create active signers in parent directory
        let _active_signers_file = create_active_signers_in_parent(parent_dir, &test_keys)?;

        // Create a test signers file in child directory
        let signers_config = create_test_signers_config(&new_keys);
        let signers_content = signers_config.to_json()?;
        let signers_file_path =
            create_test_signers_file_with_content(&child_dir, &signers_content)?;

        // Define paths for assertions
        let pending_sig_path = pending_signatures_path_for(&signers_file_path)?;
        let active_signers_path = child_dir.join(SIGNERS_DIR).join(SIGNERS_FILE);
        let complete_sig_path = signatures_path_for(&active_signers_path)?;

        // Compute hashes once
        let hash = common::sha512_for_file(&signers_file_path)?;
        let metadata_path = metadata_path_for(&signers_file_path)?;
        let metadata_hash = common::sha512_for_file(&metadata_path)?;

        // Sign with first key (present in existing signers file in parent dir)
        let pubkey0 = test_keys.pub_key(0).unwrap();
        let seckey0 = test_keys.sec_key(0).unwrap();
        let signature0 = seckey0.sign(&hash).unwrap();
        let meta_sig0 = seckey0.sign(&metadata_hash).unwrap();

        // Call sign_signers_and_metadata_file with first signature
        sign_signers_and_metadata_file(&signers_file_path, &signature0, pubkey0, &meta_sig0)?;

        // Assert after first signature: pending exists, not complete
        assert!(
            pending_sig_path.exists(),
            "Pending signature file should exist after first signature"
        );
        assert!(
            !complete_sig_path.exists(),
            "Complete signature file should not exist yet"
        );

        let sig_content = fs::read_to_string(&pending_sig_path)?;
        let sig_map: SignaturesFile = serde_json::from_str(&sig_content)?;
        assert_eq!(sig_map.entries.len(), 1, "Should have one signature");
        assert!(
            sig_map.entries.contains_key(&pubkey0.to_base64()),
            "Should contain first signature"
        );
        assert_eq!(
            sig_map.entries[&pubkey0.to_base64()].signature,
            signature0.to_base64()
        );

        // Sign with second key (present in existing signers file in parent dir)
        let pubkey1 = test_keys.pub_key(1).unwrap();
        let seckey1 = test_keys.sec_key(1).unwrap();
        let signature1 = seckey1.sign(&hash).unwrap();
        let meta_sig1 = seckey1.sign(&metadata_hash).unwrap();

        // Call sign_signers_and_metadata_file with second signature
        sign_signers_and_metadata_file(&signers_file_path, &signature1, pubkey1, &meta_sig1)?;

        // Assert after second signature: still pending, not complete
        assert!(
            pending_sig_path.exists(),
            "Pending signature file should still exist"
        );
        assert!(
            !complete_sig_path.exists(),
            "Complete signature file should not exist yet"
        );

        let sig_content = fs::read_to_string(&pending_sig_path)?;
        let sig_map: SignaturesFile = serde_json::from_str(&sig_content)?;
        assert_eq!(sig_map.entries.len(), 2, "Should have two signatures");
        assert!(
            sig_map.entries.contains_key(&pubkey0.to_base64()),
            "Should contain first signature"
        );
        assert!(
            sig_map.entries.contains_key(&pubkey1.to_base64()),
            "Should contain second signature"
        );
        assert_eq!(
            sig_map.entries[&pubkey1.to_base64()].signature,
            signature1.to_base64()
        );

        // Sign with third key (present in new signers file)
        let pubkey2 = new_keys.pub_key(0).unwrap();
        let seckey2 = new_keys.sec_key(0).unwrap();
        let signature2 = seckey2.sign(&hash).unwrap();
        let meta_sig2 = seckey2.sign(&metadata_hash).unwrap();

        // Call sign_signers_and_metadata_file with third signature
        sign_signers_and_metadata_file(&signers_file_path, &signature2, pubkey2, &meta_sig2)?;

        // Assert after third signature: still pending, not complete
        assert!(
            pending_sig_path.exists(),
            "Pending signature file should still exist"
        );
        assert!(
            !complete_sig_path.exists(),
            "Complete signature file should not exist yet"
        );

        let sig_content = fs::read_to_string(&pending_sig_path)?;
        let sig_map: SignaturesFile = serde_json::from_str(&sig_content)?;
        assert_eq!(sig_map.entries.len(), 3, "Should have three signatures");
        assert!(
            sig_map.entries.contains_key(&pubkey0.to_base64()),
            "Should contain first signature"
        );
        assert!(
            sig_map.entries.contains_key(&pubkey1.to_base64()),
            "Should contain second signature"
        );
        assert!(
            sig_map.entries.contains_key(&pubkey2.to_base64()),
            "Should contain third signature"
        );
        assert_eq!(
            sig_map.entries[&pubkey2.to_base64()].signature,
            signature2.to_base64()
        );

        // Sign with fourth key (present in new signers file)
        let pubkey3 = new_keys.pub_key(1).unwrap();
        let seckey3 = new_keys.sec_key(1).unwrap();
        let signature3 = seckey3.sign(&hash).unwrap();
        let meta_sig3 = seckey3.sign(&metadata_hash).unwrap();

        // Call sign_signers_and_metadata_file with fourth signature
        sign_signers_and_metadata_file(&signers_file_path, &signature3, pubkey3, &meta_sig3)?;

        // Assert after fourth signature: complete, pending moved
        assert!(
            !pending_sig_path.exists(),
            "Pending signature file should be gone"
        );
        assert!(
            complete_sig_path.exists(),
            "Complete signature file should exist"
        );
        assert!(
            active_signers_path.exists(),
            "Active signers file should exist"
        );

        let sig_content = fs::read_to_string(&complete_sig_path)?;
        let sig_map: SignaturesFile = serde_json::from_str(&sig_content)?;
        assert_eq!(sig_map.entries.len(), 4, "Should have all four signatures");
        assert!(
            sig_map.entries.contains_key(&pubkey0.to_base64()),
            "Should contain first signature"
        );
        assert!(
            sig_map.entries.contains_key(&pubkey1.to_base64()),
            "Should contain second signature"
        );
        assert!(
            sig_map.entries.contains_key(&pubkey2.to_base64()),
            "Should contain third signature"
        );
        assert!(
            sig_map.entries.contains_key(&pubkey3.to_base64()),
            "Should contain fourth signature"
        );
        assert_eq!(
            sig_map.entries[&pubkey3.to_base64()].signature,
            signature3.to_base64()
        );

        Ok(())
    }
    #[test]
    fn test_sign_signers_and_metadata_file_with_parent_active_signers_complete_after_2_signatures()
    -> Result<()> {
        let temp_dir = TempDir::new()?;
        let parent_dir = temp_dir.path();
        let child_dir = parent_dir.join("child");
        fs::create_dir(&child_dir)?;

        // The parent and new signers file have the same signers.
        // There's no reason to not support that scenario. It could be useful
        // to copy a signers file to a child dir before making chages in the parent.
        let test_keys = TestKeys::new(2);

        // Create active signers in parent directory
        let _active_signers_file = create_active_signers_in_parent(parent_dir, &test_keys)?;

        // Create a test signers file in child directory
        let signers_config = create_test_signers_config(&test_keys);
        let signers_content = signers_config.to_json()?;
        let signers_file_path =
            create_test_signers_file_with_content(&child_dir, &signers_content)?;

        // Define paths for assertions
        let pending_sig_path = pending_signatures_path_for(&signers_file_path)?;
        let active_signers_path = child_dir.join(SIGNERS_DIR).join(SIGNERS_FILE);
        let complete_sig_path = signatures_path_for(&active_signers_path)?;

        // Compute hashes once
        let hash = common::sha512_for_file(&signers_file_path)?;
        let metadata_path = metadata_path_for(&signers_file_path)?;
        let metadata_hash = common::sha512_for_file(&metadata_path)?;

        // Sign with first key
        let pubkey0 = test_keys.pub_key(0).unwrap();
        let seckey0 = test_keys.sec_key(0).unwrap();
        let signature0 = seckey0.sign(&hash).unwrap();
        let meta_sig0 = seckey0.sign(&metadata_hash).unwrap();

        // Call sign_signers_and_metadata_file with first signature
        sign_signers_and_metadata_file(&signers_file_path, &signature0, pubkey0, &meta_sig0)?;

        // Assert after first signature: pending exists, not complete
        assert!(
            pending_sig_path.exists(),
            "Pending signature file should exist after first signature"
        );
        assert!(
            !complete_sig_path.exists(),
            "Complete signature file should not exist yet"
        );

        let sig_content = fs::read_to_string(&pending_sig_path)?;
        let sig_map: SignaturesFile = serde_json::from_str(&sig_content)?;
        assert_eq!(sig_map.entries.len(), 1, "Should have one signature");
        assert!(
            sig_map.entries.contains_key(&pubkey0.to_base64()),
            "Should contain first signature"
        );
        assert_eq!(
            sig_map.entries[&pubkey0.to_base64()].signature,
            signature0.to_base64()
        );

        // Sign with second key
        let pubkey1 = test_keys.pub_key(1).unwrap();
        let seckey1 = test_keys.sec_key(1).unwrap();
        let signature1 = seckey1.sign(&hash).unwrap();
        let meta_sig1 = seckey1.sign(&metadata_hash).unwrap();

        // Call sign_signers_and_metadata_file with second signature
        sign_signers_and_metadata_file(&signers_file_path, &signature1, pubkey1, &meta_sig1)?;

        // Assert after second signature: complete as the signers are the same
        // in parent and new signers files
        assert!(
            !pending_sig_path.exists(),
            "Pending signature file should not exist"
        );
        assert!(
            complete_sig_path.exists(),
            "Complete signature file should exist"
        );

        let sig_content = fs::read_to_string(&complete_sig_path)?;
        let sig_map: SignaturesFile = serde_json::from_str(&sig_content)?;
        assert_eq!(sig_map.entries.len(), 2, "Should have two signatures");
        assert!(
            sig_map.entries.contains_key(&pubkey0.to_base64()),
            "Should contain first signature"
        );
        assert!(
            sig_map.entries.contains_key(&pubkey1.to_base64()),
            "Should contain second signature"
        );
        assert_eq!(
            sig_map.entries[&pubkey1.to_base64()].signature,
            signature1.to_base64()
        );

        Ok(())
    }

    // Tests for metadata behavior
    // ---------------------------

    #[test]
    fn test_metadata_file_is_created() -> Result<()> {
        let temp_dir = TempDir::new()?;
        let dir_path = temp_dir.path();
        let test_keys = TestKeys::new(2);

        let pubkey = test_keys.pub_key(0).unwrap();

        let json_content = SignersConfig::with_artifact_signers_only(
            1,
            (
                vec![pubkey.clone(), test_keys.pub_key(1).unwrap().clone()],
                2,
            ),
        )?
        .to_json()?;

        write_valid_signers_file(dir_path, &json_content, &test_metadata_json())?;

        // Verify metadata file exists in the pending directory
        let metadata_path =
            metadata_path_for(dir_path.join(PENDING_SIGNERS_DIR).join(SIGNERS_FILE)).unwrap();
        assert!(metadata_path.exists(), "metadata file should exist");

        // Verify it deserializes to a valid SignersConfigMetadata
        let metadata_content = fs::read_to_string(&metadata_path)?;
        let _metadata: SignersConfigMetadata = serde_json::from_str(&metadata_content)?;

        Ok(())
    }

    #[test]
    fn test_metadata_file_overwrite_guard() -> Result<()> {
        let temp_dir = TempDir::new()?;
        let dir_path = temp_dir.path();
        let test_keys = TestKeys::new(1);

        let pubkey = test_keys.pub_key(0).unwrap();

        let json_content =
            SignersConfig::with_artifact_signers_only(1, (vec![pubkey.clone()], 1))?.to_json()?;

        // Pre-create the metadata file
        let pending_dir = dir_path.join(PENDING_SIGNERS_DIR);
        fs::create_dir_all(&pending_dir)?;
        let metadata_path = metadata_path_for(pending_dir.join(SIGNERS_FILE)).unwrap();
        fs::write(&metadata_path, "{}")?;

        let result = write_valid_signers_file(dir_path, &json_content, &test_metadata_json());

        assert!(result.is_err());
        match result.unwrap_err() {
            SignersFileError::InitialisationError(msg) => {
                assert!(
                    msg.contains("Metadata file exists"),
                    "Expected 'Metadata file exists' in error, got: {}",
                    msg
                );
            }
            e => panic!("Expected InitialisationError, got {}", e),
        }

        Ok(())
    }

    #[test]
    fn test_metadata_content_matches_input() -> Result<()> {
        let temp_dir = TempDir::new()?;
        let dir_path = temp_dir.path();
        let test_keys = TestKeys::new(2);

        let pubkey = test_keys.pub_key(0).unwrap();

        let json_content = SignersConfig::with_artifact_signers_only(
            1,
            (
                vec![pubkey.clone(), test_keys.pub_key(1).unwrap().clone()],
                2,
            ),
        )?
        .to_json()?;

        let metadata = test_metadata();
        // Serialize to compare later
        let expected_json = serde_json::to_string_pretty(&metadata)?;

        write_valid_signers_file(dir_path, &json_content, &expected_json)?;

        // Read back the metadata file and compare
        let metadata_path =
            metadata_path_for(dir_path.join(PENDING_SIGNERS_DIR).join(SIGNERS_FILE)).unwrap();
        let actual_json = fs::read_to_string(&metadata_path)?;
        // Both should deserialize to valid metadata
        let actual: SignersConfigMetadata = serde_json::from_str(&actual_json)?;
        let expected: SignersConfigMetadata = serde_json::from_str(&expected_json)?;
        // Verify round-trip: re-serialize and compare
        assert_eq!(actual, expected);

        Ok(())
    }

    #[test]
    fn metadata_file_written_with_trailing_newline() -> Result<()> {
        let temp_dir = TempDir::new()?;
        let dir_path = temp_dir.path();
        let test_keys = TestKeys::new(1);

        let pubkey = test_keys.pub_key(0).unwrap();
        let json_content =
            SignersConfig::with_artifact_signers_only(1, (vec![pubkey.clone()], 1))?.to_json()?;

        initialize_signers_file(dir_path, &json_content, &test_metadata_json(), pubkey)?;

        let meta_path =
            metadata_path_for(dir_path.join(PENDING_SIGNERS_DIR).join(SIGNERS_FILE)).unwrap();
        let bytes = std::fs::read_to_string(&meta_path)?;
        assert!(bytes.ends_with("}\n"), "metadata file must end with }}\\n");
        assert!(
            !bytes.ends_with("\n\n"),
            "metadata file must not end with two newlines"
        );

        Ok(())
    }

    #[test]
    fn test_signers_chain_for_artifact_filters_by_cutoff() -> Result<()> {
        use test_helpers::history_helpers::sign_metadata;

        let test_keys = TestKeys::new(2);
        let signers_config = create_test_signers_config(&test_keys);
        let signers_json = signers_config.to_json()?;

        let metadata = test_metadata();
        let (metadata_json, metadata_sigs) = sign_metadata(&metadata, &test_keys, &[0, 1]).unwrap();

        let t1: DateTime<Utc> = "2024-01-01T00:00:00Z".parse().unwrap();
        let t2: DateTime<Utc> = "2024-06-01T00:00:00Z".parse().unwrap();
        let t3: DateTime<Utc> = "2025-01-01T00:00:00Z".parse().unwrap();
        let cutoff: DateTime<Utc> = "2024-08-01T00:00:00Z".parse().unwrap();

        let mut history = HistoryFile::new();
        history.add_entry(HistoryEntry {
            obsoleted_at: t1,
            signers_file: signers_json.clone(),
            signatures: SignaturesFile::new(),
            metadata: metadata_json.clone(),
            metadata_signatures: metadata_sigs.clone(),
        });
        history.add_entry(HistoryEntry {
            obsoleted_at: t2,
            signers_file: signers_json.clone(),
            signatures: SignaturesFile::new(),
            metadata: metadata_json.clone(),
            metadata_signatures: metadata_sigs.clone(),
        });
        history.add_entry(HistoryEntry {
            obsoleted_at: t3,
            signers_file: signers_json.clone(),
            signatures: SignaturesFile::new(),
            metadata: metadata_json.clone(),
            metadata_signatures: metadata_sigs.clone(),
        });

        let active_signers = signers_json.clone();
        let active_signatures = SignaturesFile::new();
        let active_metadata_content = metadata_json.clone();

        let chain = signers_chain_for_artifact(
            &history,
            &active_signers,
            &active_signatures,
            &active_metadata_content,
            &metadata_sigs,
            cutoff,
        )?;

        // History should include entries at t1 and t2 (both <= cutoff). t3
        // is filtered out. The active config is set as `current_signers_info`,
        // which carries no `obsoleted_at`.
        assert_eq!(chain.history_entries().len(), 2);
        assert_eq!(chain.history_entries()[0].obsoleted_at, t1);
        assert_eq!(chain.history_entries()[1].obsoleted_at, t2);
        assert!(chain.current_signers_info().is_some());
        Ok(())
    }

    #[test]
    fn test_signers_chain_for_artifact_empty_history() -> Result<()> {
        use test_helpers::history_helpers::sign_metadata;

        let test_keys = TestKeys::new(2);
        let signers_config = create_test_signers_config(&test_keys);
        let signers_json = signers_config.to_json()?;
        let cutoff: DateTime<Utc> = "2024-08-01T00:00:00Z".parse().unwrap();

        let metadata = test_metadata();
        let (metadata_json, metadata_sigs) = sign_metadata(&metadata, &test_keys, &[0, 1]).unwrap();

        let history = HistoryFile::new();

        let chain = signers_chain_for_artifact(
            &history,
            &signers_json,
            &SignaturesFile::new(),
            &metadata_json,
            &metadata_sigs,
            cutoff,
        )?;

        // No history, only the active config as `current_signers_info`.
        assert!(chain.history_entries().is_empty());
        assert!(chain.current_signers_info().is_some());
        Ok(())
    }

    /// Create an initial signers file (pending), have all listed keys sign it
    /// (signers file + metadata), then activate it. Returns the path to the
    /// active signers file.
    fn setup_valid_initial_signers(
        root: &Path,
        keys: &TestKeys,
        key_indices: &[usize],
        threshold: u32,
    ) -> Result<PathBuf> {
        let pub_keys: Vec<_> = key_indices
            .iter()
            .map(|&i| keys.pub_key(i).unwrap().clone())
            .collect();
        let config = SignersConfig::with_artifact_signers_only(1, (pub_keys, threshold))?;
        let json_content = config.to_json()?;

        initialize_signers_file(
            root,
            &json_content,
            &test_metadata_json(),
            keys.pub_key(0).unwrap(),
        )?;

        let pending_path = root.join(PENDING_SIGNERS_DIR).join(SIGNERS_FILE);
        let file_hash = sha512_for_file(&pending_path)?;
        let metadata_path = metadata_path_for(&pending_path)?;
        let metadata_hash = sha512_for_file(&metadata_path)?;

        for &i in key_indices {
            let sig = keys.sec_key(i).unwrap().sign(&file_hash)?;
            let meta_sig = keys.sec_key(i).unwrap().sign(&metadata_hash)?;
            sign_signers_and_metadata_file(
                &pending_path,
                &sig,
                keys.pub_key(i).unwrap(),
                &meta_sig,
            )?;
        }

        let active_path = root.join(SIGNERS_DIR).join(SIGNERS_FILE);
        assert!(
            active_path.exists(),
            "Active signers file should exist after activation"
        );
        Ok(active_path)
    }

    #[test]
    fn valid_initial_signers_file_passes_validation() -> Result<()> {
        let temp_dir = TempDir::new()?;
        let keys = TestKeys::new(2);
        let active_path = setup_valid_initial_signers(temp_dir.path(), &keys, &[0, 1], 2)?;
        validate_signers_chain_on_disk(&active_path)?;
        Ok(())
    }

    #[test]
    fn missing_signatures_file_fails_validation() -> Result<()> {
        let temp_dir = TempDir::new()?;
        let keys = TestKeys::new(2);
        let active_path = setup_valid_initial_signers(temp_dir.path(), &keys, &[0, 1], 2)?;

        let sig_path = common::fs::names::signatures_path_for(&active_path)?;
        fs::remove_file(&sig_path)?;

        let err = validate_signers_chain_on_disk(&active_path).unwrap_err();
        assert!(matches!(
            err,
            common::errors::SignersFileError::ChainValidationFailed(_)
        ));
        Ok(())
    }

    #[test]
    fn rogue_signers_file_with_partial_signatures_fails_validation() -> Result<()> {
        let temp_dir = TempDir::new()?;
        let root = temp_dir.path();

        let attacker_keys = TestKeys::new(2);
        let attacker_config = SignersConfig::with_artifact_signers_only(
            1,
            (
                vec![
                    attacker_keys.pub_key(0).unwrap().clone(),
                    attacker_keys.pub_key(1).unwrap().clone(),
                ],
                1,
            ),
        )?;

        let signers_dir = root.join(SIGNERS_DIR);
        fs::create_dir_all(&signers_dir)?;
        let signers_file_path = signers_dir.join(SIGNERS_FILE);
        let json_content = attacker_config.to_json()?;
        fs::write(&signers_file_path, &json_content)?;

        // Attacker signs with only one key (initial signers require ALL keys).
        let file_hash = common::sha512_for_content(json_content.as_bytes().to_vec())?;
        let sig0 = attacker_keys.sec_key(0).unwrap().sign(&file_hash)?;
        let mut signatures = SignaturesFile::new();
        signatures.entries.insert(
            attacker_keys.pub_key(0).unwrap().to_base64(),
            TaggedSignature {
                format: attacker_keys.pub_key(0).unwrap().key_format(),
                signature: sig0.to_base64(),
            },
        );
        let sig_path = common::fs::names::signatures_path_for(&signers_file_path)?;
        fs::write(&sig_path, serde_json::to_string_pretty(&signatures)?)?;

        // Write a metadata file and an empty metadata-signatures file so the
        // build step succeeds and validation is what fails.
        let metadata_path = metadata_path_for(&signers_file_path)?;
        let metadata = test_metadata();
        fs::write(&metadata_path, serde_json::to_string_pretty(&metadata)?)?;
        let meta_sigs_path = metadata_signatures_path_for(&signers_file_path)?;
        fs::write(
            &meta_sigs_path,
            serde_json::to_string_pretty(&SignaturesFile::new())?,
        )?;

        let err = validate_signers_chain_on_disk(&signers_file_path).unwrap_err();
        assert!(matches!(
            err,
            common::errors::SignersFileError::ChainValidationFailed(_)
        ));
        Ok(())
    }

    #[test]
    fn tampered_signatures_file_fails_validation() -> Result<()> {
        let temp_dir = TempDir::new()?;
        let keys = TestKeys::new(2);
        let active_path = setup_valid_initial_signers(temp_dir.path(), &keys, &[0, 1], 2)?;

        let sig_path = common::fs::names::signatures_path_for(&active_path)?;
        let content = fs::read_to_string(&sig_path)?;
        let corrupted = content.replacen('A', "B", 1);
        let corrupted = if corrupted == content {
            content.replacen('a', "b", 1)
        } else {
            corrupted
        };
        fs::write(&sig_path, corrupted)?;

        let err = validate_signers_chain_on_disk(&active_path).unwrap_err();
        assert!(matches!(
            err,
            common::errors::SignersFileError::ChainValidationFailed(_)
        ));
        Ok(())
    }

    /// Writes a self-valid current signers file on disk plus a history file
    /// containing a deliberately invalid first entry. The current entry alone
    /// passes `validate_chain`, so any implementation that ignores the
    /// on-disk history file would erroneously return Ok. The presence of the
    /// invalid prior entry must cause validation to fail.
    #[test]
    fn validate_signers_chain_on_disk_loads_history_file_from_disk() -> Result<()> {
        let temp_dir = TempDir::new()?;
        let keys = TestKeys::new(2);
        let active_path = setup_valid_initial_signers(temp_dir.path(), &keys, &[0, 1], 2)?;

        // Sanity: the on-disk current entry alone is valid.
        validate_signers_chain_on_disk(&active_path)?;

        // Now drop a history file next to the signers dir with a garbage first
        // entry. validate_chain must reject the resulting chain.
        let signers_dir = active_path.parent().unwrap();
        let history_path = common::fs::names::history_file_path_for(signers_dir);
        let bogus_history = HistoryFile {
            entries: vec![HistoryEntry {
                obsoleted_at: chrono::Utc::now() - chrono::Duration::seconds(1),
                signers_file: "not valid json".to_string(),
                signatures: SignaturesFile::new(),
                metadata: "not valid json".to_string(),
                metadata_signatures: SignaturesFile::new(),
            }],
        };
        bogus_history.save_to_file(&history_path)?;

        let err = validate_signers_chain_on_disk(&active_path).unwrap_err();
        assert!(matches!(
            err,
            common::errors::SignersFileError::ChainValidationFailed(_)
        ));
        Ok(())
    }

    /// On-disk: a valid history with one prior entry plus a current signers
    /// file that is a valid rotation from it must validate successfully.
    #[test]
    fn validate_signers_chain_on_disk_valid_two_entries() -> Result<()> {
        let temp_dir = TempDir::new()?;
        let root = temp_dir.path();
        let keys = TestKeys::new(3);

        // config1: artifact signers [0,1] threshold 1 — historical entry.
        let config1 = SignersConfig::with_artifact_signers_only(
            1,
            (
                vec![
                    keys.pub_key(0).unwrap().clone(),
                    keys.pub_key(1).unwrap().clone(),
                ],
                1,
            ),
        )?;
        // config2: adds key 2 — becomes the current on-disk active config.
        let config2 = SignersConfig::with_artifact_signers_only(
            1,
            (
                vec![
                    keys.pub_key(0).unwrap().clone(),
                    keys.pub_key(1).unwrap().clone(),
                    keys.pub_key(2).unwrap().clone(),
                ],
                1,
            ),
        )?;

        let metadata = test_metadata();
        let (json1, sig1) = sign_config(&config1, &keys, &[0, 1])?;
        let (meta_json1, meta_sig1) = sign_metadata(&metadata, &keys, &[0, 1])?;
        // Rotation requires old admin + new admin + newly added signer.
        let (json2, sig2) = sign_config(&config2, &keys, &[0, 1, 2])?;
        let (meta_json2, meta_sig2) = sign_metadata(&metadata, &keys, &[0, 1, 2])?;

        // Write the active signers file and its sidecars on disk.
        let signers_dir = root.join(SIGNERS_DIR);
        fs::create_dir_all(&signers_dir)?;
        let active_path = signers_dir.join(SIGNERS_FILE);
        fs::write(&active_path, &json2)?;
        fs::write(
            common::fs::names::signatures_path_for(&active_path)?,
            serde_json::to_string_pretty(&sig2)?,
        )?;
        fs::write(metadata_path_for(&active_path)?, &meta_json2)?;
        fs::write(
            metadata_signatures_path_for(&active_path)?,
            serde_json::to_string_pretty(&meta_sig2)?,
        )?;

        // Write the history file containing entry1 as the prior trust anchor.
        let history = HistoryFile {
            entries: vec![HistoryEntry {
                obsoleted_at: chrono::Utc::now() - chrono::Duration::seconds(1),
                signers_file: json1,
                signatures: sig1,
                metadata: meta_json1,
                metadata_signatures: meta_sig1,
            }],
        };
        history.save_to_file(common::fs::names::history_file_path_for(&signers_dir))?;

        validate_signers_chain_on_disk(&active_path)?;
        Ok(())
    }
}

#[cfg(test)]
mod validate_history_tests {
    use anyhow::Result;
    use chrono::Utc;
    use signers_file_types::{
        CurrentSignersInfo, HistoryEntry, HistoryFile, SignersChain, SignersConfig,
    };
    use test_helpers::history_helpers::{sign_config, sign_json_bytes, sign_metadata};
    use test_helpers::{TestKeys, test_metadata};

    use super::validate_chain;

    /// Promote a `HistoryEntry` (only used for legacy-style test fixtures) to a
    /// `CurrentSignersInfo`, dropping the `obsoleted_at` field which has no place
    /// on the active entry.
    fn current_from_he(e: HistoryEntry) -> Option<CurrentSignersInfo> {
        Some(CurrentSignersInfo {
            signers_file: e.signers_file,
            signatures: e.signatures,
            metadata: e.metadata,
            metadata_signatures: e.metadata_signatures,
        })
    }

    #[test]
    fn validate_history_valid_two_entries() -> Result<()> {
        let keys = TestKeys::new(3);

        // config1: artifact signers = keys 0,1 with threshold 1
        let config1 = SignersConfig::with_artifact_signers_only(
            1,
            (
                vec![
                    keys.pub_key(0).unwrap().clone(),
                    keys.pub_key(1).unwrap().clone(),
                ],
                1,
            ),
        )?;

        // config2: artifact signers = keys 0,1,2 with threshold 1 (adds key 2)
        let config2 = SignersConfig::with_artifact_signers_only(
            1,
            (
                vec![
                    keys.pub_key(0).unwrap().clone(),
                    keys.pub_key(1).unwrap().clone(),
                    keys.pub_key(2).unwrap().clone(),
                ],
                1,
            ),
        )?;

        // entry1 signatures: signed by admin of config1 (keys 0 and 1)
        let (json1, sig1) = sign_config(&config1, &keys, &[0, 1])?;

        // entry2 signatures: must be signed by admin of old config (config1),
        // admin of new config (config2), AND newly added signers (key 2).
        // Keys 0,1 cover old admin. Keys 0,1,2 cover new admin. Key 2 is the new signer.
        let (json2, sig2) = sign_config(&config2, &keys, &[0, 1, 2])?;

        let metadata = test_metadata();
        let (metadata_json1, meta_sigs1) = sign_metadata(&metadata, &keys, &[0, 1])?;
        let (metadata_json2, meta_sigs2) = sign_metadata(&metadata, &keys, &[0, 1, 2])?;

        let entry1 = HistoryEntry {
            obsoleted_at: Utc::now() - chrono::Duration::seconds(1),
            signers_file: json1,
            signatures: sig1,
            metadata: metadata_json1,
            metadata_signatures: meta_sigs1,
        };
        let entry2 = HistoryEntry {
            obsoleted_at: Utc::now(),
            signers_file: json2,
            signatures: sig2,
            metadata: metadata_json2,
            metadata_signatures: meta_sigs2,
        };
        let chain = SignersChain {
            history_entries: vec![entry1],
            current_signers_info: current_from_he(entry2),
        };

        assert!(validate_chain(&chain).is_ok());
        Ok(())
    }

    #[test]
    fn validate_history_invalid_missing_new_signer_signature() -> Result<()> {
        let keys = TestKeys::new(3);

        let config1 = SignersConfig::with_artifact_signers_only(
            1,
            (
                vec![
                    keys.pub_key(0).unwrap().clone(),
                    keys.pub_key(1).unwrap().clone(),
                ],
                1,
            ),
        )?;

        // config2 adds key 2
        let config2 = SignersConfig::with_artifact_signers_only(
            1,
            (
                vec![
                    keys.pub_key(0).unwrap().clone(),
                    keys.pub_key(1).unwrap().clone(),
                    keys.pub_key(2).unwrap().clone(),
                ],
                1,
            ),
        )?;

        let (json1, sig1) = sign_config(&config1, &keys, &[0, 1])?;

        // Only sign with keys 0,1 — missing key 2 (the newly added signer)
        let (json2, sig2) = sign_config(&config2, &keys, &[0, 1])?;

        let metadata = test_metadata();
        let (metadata_json, meta_sigs) = sign_metadata(&metadata, &keys, &[0, 1])?;

        let entry1 = HistoryEntry {
            obsoleted_at: Utc::now() - chrono::Duration::seconds(1),
            signers_file: json1,
            signatures: sig1,
            metadata: metadata_json.clone(),
            metadata_signatures: meta_sigs.clone(),
        };
        let entry2 = HistoryEntry {
            obsoleted_at: Utc::now(),
            signers_file: json2,
            signatures: sig2,
            metadata: metadata_json,
            metadata_signatures: meta_sigs,
        };
        let chain = SignersChain {
            history_entries: vec![entry1],
            current_signers_info: current_from_he(entry2),
        };

        assert!(validate_chain(&chain).is_err());
        Ok(())
    }

    #[test]
    fn validate_history_single_entry_is_valid() -> Result<()> {
        let keys = TestKeys::new(1);

        let config = SignersConfig::with_artifact_signers_only(
            1,
            (vec![keys.pub_key(0).unwrap().clone()], 1),
        )?;

        let (json, sig) = sign_config(&config, &keys, &[0])?;

        let metadata = test_metadata();
        let (metadata_json, meta_sigs) = sign_metadata(&metadata, &keys, &[0])?;

        let entry = HistoryEntry {
            obsoleted_at: Utc::now(),
            signers_file: json,
            signatures: sig,
            metadata: metadata_json,
            metadata_signatures: meta_sigs,
        };
        let chain = SignersChain {
            history_entries: vec![],
            current_signers_info: current_from_he(entry),
        };

        assert!(validate_chain(&chain).is_ok());
        Ok(())
    }

    #[test]
    fn validate_chain_rejects_empty_chain() {
        let chain = SignersChain::default();
        assert!(validate_chain(&chain).is_err());
    }

    #[test]
    fn validate_history_rejects_first_entry_without_all_signers() -> Result<()> {
        // 2 signers required, only 1 signs the signers_file — must fail.
        let keys = TestKeys::new(2);
        let config = SignersConfig::with_artifact_signers_only(
            1,
            (
                vec![
                    keys.pub_key(0).unwrap().clone(),
                    keys.pub_key(1).unwrap().clone(),
                ],
                2,
            ),
        )?;

        // Signers partially signed
        let (json, sig_partial) = sign_config(&config, &keys, &[0])?;
        let metadata = test_metadata();
        let (meta_json, meta_sig) = sign_metadata(&metadata, &keys, &[0, 1])?;

        let entry = HistoryEntry {
            obsoleted_at: Utc::now(),
            signers_file: json,
            signatures: sig_partial,
            metadata: meta_json,
            metadata_signatures: meta_sig,
        };
        let chain = SignersChain {
            history_entries: vec![],
            current_signers_info: current_from_he(entry),
        };

        assert!(
            validate_chain(&chain).is_err(),
            "first entry missing a signersfile signer must fail"
        );

        // Metadata partially signed
        let (json, sig_partial) = sign_config(&config, &keys, &[0, 1])?;
        let metadata = test_metadata();
        let (meta_json, meta_sig) = sign_metadata(&metadata, &keys, &[1])?;

        let entry = HistoryEntry {
            obsoleted_at: Utc::now(),
            signers_file: json,
            signatures: sig_partial,
            metadata: meta_json,
            metadata_signatures: meta_sig,
        };
        let chain = SignersChain {
            history_entries: vec![],
            current_signers_info: current_from_he(entry),
        };

        assert!(
            validate_chain(&chain).is_err(),
            "first entry missing a metadata signer must fail"
        );
        Ok(())
    }

    #[test]
    fn validate_history_rejects_unsorted_entries() -> Result<()> {
        let keys = TestKeys::new(3);

        let config1 = SignersConfig::with_artifact_signers_only(
            1,
            (
                vec![
                    keys.pub_key(0).unwrap().clone(),
                    keys.pub_key(1).unwrap().clone(),
                ],
                1,
            ),
        )?;

        let config2 = SignersConfig::with_artifact_signers_only(
            1,
            (
                vec![
                    keys.pub_key(0).unwrap().clone(),
                    keys.pub_key(1).unwrap().clone(),
                    keys.pub_key(2).unwrap().clone(),
                ],
                1,
            ),
        )?;

        let (json1, sig1) = sign_config(&config1, &keys, &[0, 1])?;
        let (json2, sig2) = sign_config(&config2, &keys, &[0, 1, 2])?;

        let metadata = test_metadata();
        let (metadata_json1, meta_sigs1) = sign_metadata(&metadata, &keys, &[0, 1])?;
        let (metadata_json2, meta_sigs2) = sign_metadata(&metadata, &keys, &[0, 1, 2])?;

        let now = Utc::now();
        let earlier = now - chrono::Duration::hours(1);

        // Place the later timestamp first — history entries are not sorted by
        // obsoleted_at. The chain's `current_signers_info` reuses entry2's bytes
        // so genesis and signature transitions could otherwise pass — only the
        // timestamp ordering check on `history_entries` should reject this chain.
        let entry1 = HistoryEntry {
            obsoleted_at: now,
            signers_file: json1,
            signatures: sig1,
            metadata: metadata_json1,
            metadata_signatures: meta_sigs1,
        };
        let entry2 = HistoryEntry {
            obsoleted_at: earlier,
            signers_file: json2.clone(),
            signatures: sig2.clone(),
            metadata: metadata_json2.clone(),
            metadata_signatures: meta_sigs2.clone(),
        };
        let current = CurrentSignersInfo {
            signers_file: json2,
            signatures: sig2,
            metadata: metadata_json2,
            metadata_signatures: meta_sigs2,
        };
        let chain = SignersChain {
            history_entries: vec![entry1, entry2],
            current_signers_info: Some(current),
        };

        assert!(validate_chain(&chain).is_err());
        Ok(())
    }

    /// Generator test: creates a fixture file with one history entry signed
    /// over pretty JSON and one signed over compact JSON, so validation must
    /// compare the stored strings and not re-serialize them.
    ///
    /// Run with: cargo test --package signers_file generate_fixture_history_with_non_canonical_json -- --ignored
    #[test]
    #[ignore]
    fn generate_fixture_history_with_non_canonical_json() -> Result<()> {
        let keys = TestKeys::new(3);

        // config1: the "parent" entry, signed with pretty JSON
        let config1 = SignersConfig::with_artifact_signers_only(
            1,
            (
                vec![
                    keys.pub_key(0).unwrap().clone(),
                    keys.pub_key(1).unwrap().clone(),
                ],
                1,
            ),
        )?;
        let pretty_json1 = serde_json::to_string_pretty(&config1)?;
        let sig1 = sign_json_bytes(pretty_json1.as_bytes(), &keys, &[0, 1])?;

        // config2: the "updated" entry, signed with COMPACT JSON
        let config2 = SignersConfig::with_artifact_signers_only(
            1,
            (
                vec![
                    keys.pub_key(0).unwrap().clone(),
                    keys.pub_key(1).unwrap().clone(),
                    keys.pub_key(2).unwrap().clone(),
                ],
                1,
            ),
        )?;
        let compact_json2 = serde_json::to_string(&config2)?;
        let sig2 = sign_json_bytes(compact_json2.as_bytes(), &keys, &[0, 1, 2])?;

        let metadata = test_metadata();
        let (metadata_json1, meta_sigs1) = sign_metadata(&metadata, &keys, &[0, 1])?;
        let (metadata_json2, meta_sigs2) = sign_metadata(&metadata, &keys, &[0, 1, 2])?;

        let history = HistoryFile {
            entries: vec![
                HistoryEntry {
                    obsoleted_at: Utc::now() - chrono::Duration::seconds(1),
                    signers_file: pretty_json1,
                    signatures: sig1,
                    metadata: metadata_json1,
                    metadata_signatures: meta_sigs1,
                },
                HistoryEntry {
                    obsoleted_at: Utc::now(),
                    signers_file: compact_json2,
                    signatures: sig2,
                    metadata: metadata_json2,
                    metadata_signatures: meta_sigs2,
                },
            ],
        };

        let fixture_path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../test_helpers/fixtures/history_with_non_canonical_json.json");
        history.save_to_file(&fixture_path)?;
        println!("Fixture written to: {}", fixture_path.display());

        Ok(())
    }

    /// Test that loads the fixture with non-canonical JSON and validates it.
    #[test]
    fn validate_history_from_fixture_with_non_canonical_json() -> Result<()> {
        let fixture_path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../test_helpers/fixtures/history_with_non_canonical_json.json");
        let mut history = HistoryFile::load_from_file(&fixture_path)?;

        // The fixture is on-disk in `HistoryFile` format; convert to a `SignersChain`
        // by treating the last entry as the current active config.
        let last = history.entries.pop();
        let chain = SignersChain {
            history_entries: history.entries,
            current_signers_info: last.and_then(current_from_he),
        };

        assert!(
            validate_chain(&chain).is_ok(),
            "validate_chain should accept valid signatures regardless of JSON formatting"
        );
        Ok(())
    }

    struct FirstEntryScenario {
        name: &'static str,
        chain: SignersChain,
        expected_valid: bool,
    }

    fn first_entry_scenarios() -> Vec<FirstEntryScenario> {
        use signatures::keys::AsfaloadPublicKeyTrait;
        use signatures::signatures_file::{SignaturesFile, TaggedSignature};
        use signers_file_types::{Forge, SignersConfigMetadata, VerifiedForgeContent};

        let keys_1 = TestKeys::new(1);
        let keys_2 = TestKeys::new(2);
        let keys_3 = TestKeys::new(3);
        let keys_5 = TestKeys::new(5);

        let single = |entry: HistoryEntry| -> SignersChain {
            SignersChain {
                history_entries: vec![],
                current_signers_info: current_from_he(entry),
            }
        };

        let make_metadata = |url: &str| -> SignersConfigMetadata {
            SignersConfigMetadata::new(
                Forge::Github,
                url.to_string(),
                VerifiedForgeContent::new_for_test(url.to_string(), "test_hash".to_string()),
                Utc::now(),
            )
        };

        let default_metadata = test_metadata();

        let mut scenarios: Vec<FirstEntryScenario> = Vec::new();

        // 1. valid_single_signer
        {
            let config = SignersConfig::with_artifact_signers_only(
                1,
                (vec![keys_1.pub_key(0).unwrap().clone()], 1),
            )
            .unwrap();
            let (json, sig) = sign_config(&config, &keys_1, &[0]).unwrap();
            let (meta_json, meta_sig) = sign_metadata(&default_metadata, &keys_1, &[0]).unwrap();
            scenarios.push(FirstEntryScenario {
                name: "valid_single_signer",
                chain: single(HistoryEntry {
                    obsoleted_at: Utc::now(),
                    signers_file: json,
                    signatures: sig,
                    metadata: meta_json,
                    metadata_signatures: meta_sig,
                }),
                expected_valid: true,
            });
        }

        // 2. valid_multiple_signers
        {
            let config = SignersConfig::with_artifact_signers_only(
                1,
                (
                    vec![
                        keys_2.pub_key(0).unwrap().clone(),
                        keys_2.pub_key(1).unwrap().clone(),
                    ],
                    2,
                ),
            )
            .unwrap();
            let (json, sig) = sign_config(&config, &keys_2, &[0, 1]).unwrap();
            let (meta_json, meta_sig) = sign_metadata(&default_metadata, &keys_2, &[0, 1]).unwrap();
            scenarios.push(FirstEntryScenario {
                name: "valid_multiple_signers",
                chain: single(HistoryEntry {
                    obsoleted_at: Utc::now(),
                    signers_file: json,
                    signatures: sig,
                    metadata: meta_json,
                    metadata_signatures: meta_sig,
                }),
                expected_valid: true,
            });
        }

        // 3. valid_with_full_key_config
        {
            let config = SignersConfig::with_keys(
                1,
                (vec![keys_5.pub_key(0).unwrap().clone()], 1),
                Some((vec![keys_5.pub_key(1).unwrap().clone()], 1)),
                Some((vec![keys_5.pub_key(2).unwrap().clone()], 1)),
                Some((vec![keys_5.pub_key(3).unwrap().clone()], 1)),
            )
            .unwrap();
            let (json, sig) = sign_config(&config, &keys_5, &[0, 1, 2, 3]).unwrap();
            let (meta_json, meta_sig) =
                sign_metadata(&default_metadata, &keys_5, &[0, 1, 2, 3]).unwrap();
            scenarios.push(FirstEntryScenario {
                name: "valid_with_full_key_config",
                chain: single(HistoryEntry {
                    obsoleted_at: Utc::now(),
                    signers_file: json,
                    signatures: sig,
                    metadata: meta_json,
                    metadata_signatures: meta_sig,
                }),
                expected_valid: true,
            });
        }

        // 4. missing_one_signer_signature
        {
            let config = SignersConfig::with_artifact_signers_only(
                1,
                (
                    vec![
                        keys_2.pub_key(0).unwrap().clone(),
                        keys_2.pub_key(1).unwrap().clone(),
                    ],
                    2,
                ),
            )
            .unwrap();
            let (json, sig) = sign_config(&config, &keys_2, &[0]).unwrap();
            let (meta_json, meta_sig) = sign_metadata(&default_metadata, &keys_2, &[0, 1]).unwrap();
            scenarios.push(FirstEntryScenario {
                name: "missing_one_signer_signature_of_signers_file",
                chain: single(HistoryEntry {
                    obsoleted_at: Utc::now(),
                    signers_file: json,
                    signatures: sig,
                    metadata: meta_json,
                    metadata_signatures: meta_sig,
                }),
                expected_valid: false,
            });
        }

        {
            let config = SignersConfig::with_artifact_signers_only(
                1,
                (
                    vec![
                        keys_2.pub_key(0).unwrap().clone(),
                        keys_2.pub_key(1).unwrap().clone(),
                    ],
                    2,
                ),
            )
            .unwrap();
            let (json, sig) = sign_config(&config, &keys_2, &[0, 1]).unwrap();
            let (meta_json, meta_sig) = sign_metadata(&default_metadata, &keys_2, &[1]).unwrap();
            scenarios.push(FirstEntryScenario {
                name: "missing_one_signer_signature_of_metadata",
                chain: single(HistoryEntry {
                    obsoleted_at: Utc::now(),
                    signers_file: json,
                    signatures: sig,
                    metadata: meta_json,
                    metadata_signatures: meta_sig,
                }),
                expected_valid: false,
            });
        }
        // 5. no_signatures_at_all_of_signers
        {
            let config = SignersConfig::with_artifact_signers_only(
                1,
                (vec![keys_1.pub_key(0).unwrap().clone()], 1),
            )
            .unwrap();
            let json = config.to_json().unwrap();
            let (meta_json, meta_sig) = sign_metadata(&default_metadata, &keys_1, &[0]).unwrap();
            scenarios.push(FirstEntryScenario {
                name: "no_signatures_at_all_of_signers_file",
                chain: single(HistoryEntry {
                    obsoleted_at: Utc::now(),
                    signers_file: json,
                    signatures: SignaturesFile::new(),
                    metadata: meta_json,
                    metadata_signatures: meta_sig,
                }),
                expected_valid: false,
            });
        }

        {
            let config = SignersConfig::with_artifact_signers_only(
                1,
                (vec![keys_1.pub_key(0).unwrap().clone()], 1),
            )
            .unwrap();
            let json_metadata = serde_json::to_string_pretty(&default_metadata).unwrap();
            let (json, sig) = sign_config(&config, &keys_1, &[0]).unwrap();
            scenarios.push(FirstEntryScenario {
                name: "no_signatures_at_all_of_signers_file",
                chain: single(HistoryEntry {
                    obsoleted_at: Utc::now(),
                    signers_file: json,
                    signatures: sig,
                    metadata: json_metadata,
                    metadata_signatures: SignaturesFile::new(),
                }),
                expected_valid: false,
            });
        }
        // 6. signature_from_wrong_key
        {
            let config = SignersConfig::with_artifact_signers_only(
                1,
                (
                    vec![
                        keys_3.pub_key(0).unwrap().clone(),
                        keys_3.pub_key(1).unwrap().clone(),
                    ],
                    2,
                ),
            )
            .unwrap();
            // Sign config with key 2 (not in config)
            let (json, sig) = sign_config(&config, &keys_3, &[2]).unwrap();
            let (meta_json, meta_sig) = sign_metadata(&default_metadata, &keys_3, &[0]).unwrap();
            scenarios.push(FirstEntryScenario {
                name: "signature_from_wrong_key",
                chain: single(HistoryEntry {
                    obsoleted_at: Utc::now(),
                    signers_file: json,
                    signatures: sig,
                    metadata: meta_json,
                    metadata_signatures: meta_sig,
                }),
                expected_valid: false,
            });
        }

        {
            let config = SignersConfig::with_artifact_signers_only(
                1,
                (
                    vec![
                        keys_3.pub_key(0).unwrap().clone(),
                        keys_3.pub_key(1).unwrap().clone(),
                    ],
                    2,
                ),
            )
            .unwrap();
            // Sign config with key 2 (not in config)
            let (json, sig) = sign_config(&config, &keys_3, &[0]).unwrap();
            let (meta_json, meta_sig) = sign_metadata(&default_metadata, &keys_3, &[2]).unwrap();
            scenarios.push(FirstEntryScenario {
                name: "signature_from_wrong_key_of_metadata",
                chain: single(HistoryEntry {
                    obsoleted_at: Utc::now(),
                    signers_file: json,
                    signatures: sig,
                    metadata: meta_json,
                    metadata_signatures: meta_sig,
                }),
                expected_valid: false,
            });
        }
        // 7. invalid_signature_base64
        {
            let config = SignersConfig::with_artifact_signers_only(
                1,
                (vec![keys_1.pub_key(0).unwrap().clone()], 1),
            )
            .unwrap();
            let json = config.to_json().unwrap();
            let pubkey = keys_1.pub_key(0).unwrap();
            let mut sig_file = SignaturesFile::new();
            sig_file.entries.insert(
                pubkey.to_base64(),
                TaggedSignature {
                    format: pubkey.key_format(),
                    signature: "!!!not-base64!!!".to_string(),
                },
            );
            let (meta_json, meta_sig) = sign_metadata(&default_metadata, &keys_1, &[0]).unwrap();
            scenarios.push(FirstEntryScenario {
                name: "invalid_signature_base64",
                chain: single(HistoryEntry {
                    obsoleted_at: Utc::now(),
                    signers_file: json,
                    signatures: sig_file,
                    metadata: meta_json,
                    metadata_signatures: meta_sig,
                }),
                expected_valid: false,
            });
        }

        {
            let config = SignersConfig::with_artifact_signers_only(
                1,
                (vec![keys_1.pub_key(0).unwrap().clone()], 1),
            )
            .unwrap();
            let (json, sig) = sign_config(&config, &keys_1, &[0]).unwrap();
            let meta_json = serde_json::to_string_pretty(&default_metadata).unwrap();
            let pubkey = keys_1.pub_key(0).unwrap();
            let mut meta_sig_file = SignaturesFile::new();
            meta_sig_file.entries.insert(
                pubkey.to_base64(),
                TaggedSignature {
                    format: pubkey.key_format(),
                    signature: "!!!not-base64!!!".to_string(),
                },
            );
            scenarios.push(FirstEntryScenario {
                name: "invalid_signature_base64_of_metadata",
                chain: single(HistoryEntry {
                    obsoleted_at: Utc::now(),
                    signers_file: json,
                    signatures: sig,
                    metadata: meta_json,
                    metadata_signatures: meta_sig_file,
                }),
                expected_valid: false,
            });
        }

        // 8. invalid_signers_config_json
        {
            let (meta_json, meta_sig) = sign_metadata(&default_metadata, &keys_1, &[0]).unwrap();
            scenarios.push(FirstEntryScenario {
                name: "invalid_signers_config_json",
                chain: single(HistoryEntry {
                    obsoleted_at: Utc::now(),
                    signers_file: "not valid json".to_string(),
                    signatures: SignaturesFile::new(),
                    metadata: meta_json,
                    metadata_signatures: meta_sig,
                }),
                expected_valid: false,
            });
        }

        // 9. empty_signers_file
        {
            let (meta_json, meta_sig) = sign_metadata(&default_metadata, &keys_1, &[0]).unwrap();
            scenarios.push(FirstEntryScenario {
                name: "empty_signers_file",
                chain: single(HistoryEntry {
                    obsoleted_at: Utc::now(),
                    signers_file: String::new(),
                    signatures: SignaturesFile::new(),
                    metadata: meta_json,
                    metadata_signatures: meta_sig,
                }),
                expected_valid: false,
            });
        }

        // 10. missing_admin_key_signature
        {
            let config = SignersConfig::with_keys(
                1,
                (vec![keys_5.pub_key(0).unwrap().clone()], 1),
                Some((vec![keys_5.pub_key(1).unwrap().clone()], 1)),
                Some((vec![keys_5.pub_key(2).unwrap().clone()], 1)),
                Some((vec![keys_5.pub_key(3).unwrap().clone()], 1)),
            )
            .unwrap();
            // Sign with [0, 2, 3] — missing admin (key 1)
            let (json, sig) = sign_config(&config, &keys_5, &[0, 2, 3]).unwrap();
            let (meta_json, meta_sig) =
                sign_metadata(&default_metadata, &keys_5, &[0, 2, 3]).unwrap();
            scenarios.push(FirstEntryScenario {
                name: "missing_admin_key_signature",
                chain: single(HistoryEntry {
                    obsoleted_at: Utc::now(),
                    signers_file: json,
                    signatures: sig,
                    metadata: meta_json,
                    metadata_signatures: meta_sig,
                }),
                expected_valid: false,
            });
        }

        {
            let config = SignersConfig::with_keys(
                1,
                (vec![keys_5.pub_key(0).unwrap().clone()], 1),
                Some((vec![keys_5.pub_key(1).unwrap().clone()], 1)),
                Some((vec![keys_5.pub_key(2).unwrap().clone()], 1)),
                Some((vec![keys_5.pub_key(3).unwrap().clone()], 1)),
            )
            .unwrap();
            // Signers file fully signed; metadata missing admin (key 1)
            let (json, sig) = sign_config(&config, &keys_5, &[0, 1, 2]).unwrap();
            let (meta_json, meta_sig) = sign_metadata(&default_metadata, &keys_5, &[0, 2]).unwrap();
            scenarios.push(FirstEntryScenario {
                name: "missing_admin_key_signature_of_metadata",
                chain: single(HistoryEntry {
                    obsoleted_at: Utc::now(),
                    signers_file: json,
                    signatures: sig,
                    metadata: meta_json,
                    metadata_signatures: meta_sig,
                }),
                expected_valid: false,
            });
        }

        // 11. tampered_metadata_signatures
        {
            let config = SignersConfig::with_artifact_signers_only(
                1,
                (vec![keys_1.pub_key(0).unwrap().clone()], 1),
            )
            .unwrap();
            let (json, sig) = sign_config(&config, &keys_1, &[0]).unwrap();
            let metadata_a = make_metadata("https://example.test/a.json");
            let metadata_b = make_metadata("https://example.test/b.json");
            let (_a_json, sig_a) = sign_metadata(&metadata_a, &keys_1, &[0]).unwrap();
            let (b_json, _b_sig) = sign_metadata(&metadata_b, &keys_1, &[0]).unwrap();
            scenarios.push(FirstEntryScenario {
                name: "tampered_metadata_signatures",
                chain: single(HistoryEntry {
                    obsoleted_at: Utc::now(),
                    signers_file: json,
                    signatures: sig,
                    metadata: b_json,
                    metadata_signatures: sig_a,
                }),
                expected_valid: false,
            });
        }

        // 12. metadata_signed_by_wrong_key
        {
            let config = SignersConfig::with_artifact_signers_only(
                1,
                (vec![keys_1.pub_key(0).unwrap().clone()], 1),
            )
            .unwrap();
            let (json, sig) = sign_config(&config, &keys_1, &[0]).unwrap();
            // Sign metadata with key 2 from keys_3 (not in config)
            let (meta_json, meta_sig) = sign_metadata(&default_metadata, &keys_3, &[2]).unwrap();
            scenarios.push(FirstEntryScenario {
                name: "metadata_signed_by_wrong_key",
                chain: single(HistoryEntry {
                    obsoleted_at: Utc::now(),
                    signers_file: json,
                    signatures: sig,
                    metadata: meta_json,
                    metadata_signatures: meta_sig,
                }),
                expected_valid: false,
            });
        }

        scenarios
    }

    #[test]
    fn validate_history_first_entry_scenarios() {
        for sc in first_entry_scenarios() {
            let result = validate_chain(&sc.chain);
            assert_eq!(
                result.is_ok(),
                sc.expected_valid,
                "Scenario '{}': expected valid={}, got valid={} (result: {result:?})",
                sc.name,
                sc.expected_valid,
                result.is_ok(),
            );
        }
    }
}
