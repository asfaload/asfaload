pub mod revocation;

use common::errors::AggregateSignatureError;
use common::errors::keys::SignatureError;
use common::fs::names::{
    create_local_signers_for, find_global_signers_for, local_signers_path_for,
    pending_signatures_path_for, revocation_path_for, signatures_path_for,
    subject_path_from_metadata, subject_path_from_pending_signatures,
};
use common::{AsfaloadHashes, FileType, SignedFileLoader, SignedFileWithKind};
use signatures::keys::{AsfaloadPublicKeyTrait, AsfaloadSignatureTrait};
use signatures::signatures_file::{SignaturesFile, TaggedSignature};
use signatures::types::{AsfaloadPublicKeys, AsfaloadSignatures};
use signers_file_types::{SignerGroup, SignersConfig};
use std::collections::{HashMap, HashSet};
use std::fs::File;
use std::marker::PhantomData;
use std::path::{Path, PathBuf};

// Type aliases for enum-based types to support incremental migration
pub type EnumSignatureWithState = SignatureWithState;
pub type EnumAggregateSignature<SS> = AggregateSignature<SS>;
pub type EnumPendingSignature = EnumAggregateSignature<PendingSignature>;
pub type EnumCompleteSignature = EnumAggregateSignature<CompleteSignature>;

pub struct PendingSignature;
pub struct CompleteSignature;

// This trait allows to have one implementation of the save_to_file fn, saving
// to the correct location according to completeness of the signature (with or
// without the .pending suffix)
pub trait SignatureState {
    fn signature_path_for(origin: &Path) -> Result<PathBuf, AggregateSignatureError>;
}

impl SignatureState for PendingSignature {
    fn signature_path_for(origin: &Path) -> Result<PathBuf, AggregateSignatureError> {
        pending_signatures_path_for(origin).map_err(|e| e.into())
    }
}

impl SignatureState for CompleteSignature {
    fn signature_path_for(origin: &Path) -> Result<PathBuf, AggregateSignatureError> {
        signatures_path_for(origin).map_err(|e| e.into())
    }
}

pub enum SignatureWithState {
    Pending(AggregateSignature<PendingSignature>),
    Complete(AggregateSignature<CompleteSignature>),
}

impl SignatureWithState {
    pub fn load_for_file<PP: AsRef<Path>>(path_in: PP) -> Result<Self, AggregateSignatureError> {
        generic_load_for_file(path_in)
    }
    // Consumes self to do as get_pending
    pub fn get_complete(self) -> Option<AggregateSignature<CompleteSignature>> {
        match self {
            Self::Pending(_s) => None,
            Self::Complete(s) => Some(s),
        }
    }
    // Consumes self. Made so that after calling get_pending we can call add_individual_signature
    // that also consumes self, becaus it can update the agg_sig on disk, so using the old value
    // makes no sense.
    pub fn get_pending(self) -> Option<AggregateSignature<PendingSignature>> {
        match self {
            Self::Complete(_s) => None,
            Self::Pending(s) => Some(s),
        }
    }
    // Function allowing to check the agg sig status without consuming it
    pub fn is_pending(&self) -> bool {
        match self {
            Self::Complete(_) => false,
            Self::Pending(_) => true,
        }
    }
    pub fn is_complete(&self) -> bool {
        !self.is_pending()
    }
}

#[derive(Clone)]
pub struct AggregateSignature<SS> {
    signatures: HashMap<AsfaloadPublicKeys, AsfaloadSignatures>,
    // The origin is a String. I originally wanted to make it a Url, but
    // then the path must be absolute, and I didn't want to set that restriction right now
    origin: String,
    subject: SignedFileWithKind,
    marker: PhantomData<SS>,
}

impl<SS> AggregateSignature<SS> {
    // Function left private so it can only be used in this module
    fn new(
        signatures: HashMap<AsfaloadPublicKeys, AsfaloadSignatures>,
        origin: String,
        subject: SignedFileWithKind,
    ) -> Self {
        AggregateSignature {
            signatures,
            origin,
            subject,
            marker: PhantomData,
        }
    }
}

impl<SS> AggregateSignature<SS> {
    pub fn origin(&self) -> &str {
        self.origin.as_str()
    }
    pub fn subject(&self) -> SignedFileWithKind {
        self.subject.clone()
    }
}

/// Check if all groups in a category meet their thresholds with valid signatures
/// Note that invalid signatures are ignored, they are not reported as errors.
pub fn check_groups(
    groups: &[SignerGroup],
    signatures: &HashMap<AsfaloadPublicKeys, AsfaloadSignatures>,
    data: &AsfaloadHashes,
) -> bool {
    !groups.is_empty()
        && groups.iter().all(|group| {
            let count = group
                .signers
                .iter()
                .filter(|signer| {
                    signatures
                        .get(&signer.data.pubkey)
                        .is_some_and(|signature| signer.data.pubkey.verify(signature, data).is_ok())
                })
                .count();
            count >= group.threshold as usize
        })
}

// Check that all signers in signers config have signed.
// This does not take the thresholds in account.
pub fn check_all_signers(
    signatures: &HashMap<AsfaloadPublicKeys, AsfaloadSignatures>,
    signers_config: &SignersConfig,
    admin_data: &AsfaloadHashes,
) -> bool {
    let all_signer_keys = signers_config.all_signer_keys();
    !all_signer_keys.is_empty()
        && all_signer_keys.iter().all(|pubkey| {
            signatures
                .get(pubkey)
                .is_some_and(|signature| pubkey.verify(signature, admin_data).is_ok())
        })
}

/// Verify that every signer listed in `signers_config` has a valid signature
/// over `content` in `signatures`. Hashes the raw bytes with SHA-512, parses
/// the tagged signatures, then delegates to `check_all_signers`.
pub fn verify_all_signers_signed(
    content: &[u8],
    signatures: &SignaturesFile,
    signers_config: &SignersConfig,
) -> Result<bool, AggregateSignatureError> {
    let hash = common::sha512_for_content(content.to_vec())?;
    let parsed = parse_tagged_signatures(&signatures.entries)?;
    Ok(check_all_signers(&parsed, signers_config, &hash))
}

pub fn check_signers<P, S>(
    signatures: &HashMap<P, S>,
    signers: &[P],
    admin_data: &AsfaloadHashes,
) -> bool
where
    P: AsfaloadPublicKeyTrait<Signature = S> + Eq + std::hash::Hash + Clone,
    S: AsfaloadSignatureTrait,
{
    signers.iter().all(|signer| {
        signatures
            .get(signer)
            .is_some_and(|signature| signer.verify(signature, admin_data).is_ok())
    })
}

// Load individual signatures from the file.
// If the file does not exist, act as if no signature was collected yet.
pub fn get_individual_signatures_from_file<P, S, PP: AsRef<Path>>(
    sig_file_path: PP,
) -> Result<HashMap<P, S>, AggregateSignatureError>
where
    P: AsfaloadPublicKeyTrait<Signature = S> + Eq + std::hash::Hash + Clone,
    S: AsfaloadSignatureTrait,
{
    let sig_file: SignaturesFile = match std::fs::File::open(&sig_file_path) {
        Ok(file) => serde_json::from_reader(file)?,
        Err(ref e) if e.kind() == std::io::ErrorKind::NotFound => SignaturesFile::new(),
        Err(e) => return Err(e.into()),
    };

    parse_tagged_signatures(&sig_file.entries)
}

pub fn get_individual_signatures_from_bytes<P, S, T: std::borrow::Borrow<[u8]>>(
    signatures_content_in: T,
) -> Result<HashMap<P, S>, AggregateSignatureError>
where
    P: AsfaloadPublicKeyTrait<Signature = S> + Eq + std::hash::Hash + Clone,
    S: AsfaloadSignatureTrait,
{
    let signature_content = signatures_content_in.borrow();
    if signature_content.is_empty() {
        return Ok(HashMap::new());
    }
    let sig_file: SignaturesFile = serde_json::from_slice(signature_content)?;

    parse_tagged_signatures(&sig_file.entries)
}

pub fn parse_tagged_signatures<P, S>(
    entries: &HashMap<String, TaggedSignature>,
) -> Result<HashMap<P, S>, AggregateSignatureError>
where
    P: AsfaloadPublicKeyTrait<Signature = S> + Eq + std::hash::Hash + Clone,
    S: AsfaloadSignatureTrait,
{
    let mut signatures: HashMap<P, S> = HashMap::new();

    for (pubkey_b64, tagged) in entries {
        let pubkey = P::from_base64_with_format(pubkey_b64, &tagged.format)
            .map_err(|e| AggregateSignatureError::PublicKey(format!("{}", e)))?;
        let signature = S::from_base64_with_format(&tagged.signature, &tagged.format)
            .map_err(|e| AggregateSignatureError::Signature(e.to_string()))?;
        signatures.insert(pubkey, signature);
    }
    Ok(signatures)
}

// A user can revoke a signature if it is member of the most provileged
// group defined in the SignersConfig
pub fn can_revoke(pubkey: &AsfaloadPublicKeys, signers_config: &SignersConfig) -> bool {
    let is_in_groups = |groups: &[SignerGroup]| {
        groups.iter().any(|group| {
            group
                .signers
                .iter()
                .any(|signer| signer.data.pubkey == *pubkey)
        })
    };

    // Using the admin_keys() accessor will implicitly return the
    // artifact signers if the admin group definition is empty.
    // It is thus sufficient to check if the key is in the vec of
    // keys returned by admin_keys()
    is_in_groups(signers_config.revocation_keys())
}

/// Load signers configuration from a file
pub fn load_signers_config(
    signers_file_path: &Path,
) -> Result<SignersConfig, AggregateSignatureError> {
    SignersConfig::from_file(signers_file_path).map_err(|e| match e {
        common::errors::SignersConfigError::IOError(io_err) => {
            AggregateSignatureError::Io(std::io::Error::other(format!(
                "could not read {} at {}:{}\n {}",
                signers_file_path.to_string_lossy(),
                file!(),
                line!(),
                io_err
            )))
        }
        other => other.into(),
    })
}

/// Returns the public keys of signers that are present in `new_config` but not in `old_config`.
///
/// This function compares the public keys of signers in both configurations
/// and returns a `Vec` of public keys from `new_config` that are not
/// found in `old_config`, regardless of the groups they belong to.
pub fn get_newly_added_signer_keys(
    old_config: &SignersConfig,
    new_config: &SignersConfig,
) -> Vec<AsfaloadPublicKeys> {
    // Create a HashSet of public keys from the old configuration for efficient lookup.
    let old_signers: HashSet<AsfaloadPublicKeys> = old_config.all_signer_keys();
    let new_signers: HashSet<AsfaloadPublicKeys> = new_config.all_signer_keys();

    new_signers.difference(&old_signers).cloned().collect()
}

/// Get all public keys authorized to sign a file
///
/// Returns the complete set of public keys that are authorized to contribute signatures
/// to a file, based on the file's type and the relevant signers configurations.
///
/// # Arguments
/// * `file_path` - Path to the file being signed
///
/// # Returns
/// * `Ok(HashSet<AsfaloadPublicKeys>)` - Set of all authorized public keys
///
/// # Errors
/// * `AggregateSignatureError::Io` - If signers files cannot be read
/// * `AggregateSignatureError::JsonError` - If signers configs cannot be parsed
///
/// # Authorized Keys by File Type
///
/// **Artifact files:** All keys from the `artifact_signers` group in the global signers config.
/// Master and admin keys are NOT authorized to sign artifacts.
///
/// **Signers file updates:** Union of:
/// - Old config: all admin keys
/// - Old config: all master keys (if defined)
/// - New config: all admin keys
/// - New config: all master keys (if defined)
/// - All newly added signers (from any group: artifact, admin, or master)
///
/// **Initial signers files:** All keys from the signers config (admin, master, and artifact)
pub fn get_authorized_signers_for_file<P: AsRef<Path>>(
    file_path: P,
) -> Result<HashSet<AsfaloadPublicKeys>, AggregateSignatureError> {
    let file_path = file_path.as_ref();
    let signed_file = SignedFileLoader::load(file_path)?;

    match signed_file {
        SignedFileWithKind::Artifact(_) => authorized_signers_for_artifact(file_path),
        SignedFileWithKind::SignersFile(_) => authorized_signers_for_signers_update(file_path),
        SignedFileWithKind::InitialSignersFile(_) => {
            authorized_signers_for_initial_signers(file_path)
        }
        SignedFileWithKind::Revocation(_) => {
            let artifact_path = signed_file.artifact_path_for_revocation()?;
            let signers_file_path = find_global_signers_for(&artifact_path)?;
            let config = load_signers_config(&signers_file_path)?;
            let mut signers = HashSet::new();

            for group in config.revocation_keys() {
                for signer in &group.signers {
                    signers.insert(signer.data.pubkey.clone());
                }
            }
            Ok(signers)
        }
        SignedFileWithKind::RevokedArtifact(_) => Err(AggregateSignatureError::FileRevoked),
        SignedFileWithKind::Metadata(_) => {
            // Helpers receive the parent path because they use it to locate
            // the signers config (e.g. find_global_signers_for traverses from
            // the parent, and the artifact's local signers copy lives at
            // artifact.txt.signers.json, not artifact.txt.metadata.json.signers.json).
            let parent_path = subject_path_from_metadata(file_path)?;
            let parent_type = common::determine_file_type(&parent_path)?;
            match parent_type {
                FileType::InitialSigners => authorized_signers_for_initial_signers(&parent_path),
                FileType::Signers => authorized_signers_for_signers_update(&parent_path),
                FileType::Artifact => authorized_signers_for_artifact(&parent_path),
                FileType::Metadata => Err(AggregateSignatureError::Io(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "Metadata of a metadata file is not supported",
                ))),
                _ => Err(AggregateSignatureError::Io(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    format!("Unsupported parent file type for metadata: {}", parent_type),
                ))),
            }
        }
    }
}

/// Get authorized signers for an initial signers file.
/// All signers in the config must sign.
fn authorized_signers_for_initial_signers(
    signers_path: &Path,
) -> Result<HashSet<AsfaloadPublicKeys>, AggregateSignatureError> {
    let config = load_signers_config(signers_path)?;
    Ok(config.all_signer_keys())
}

/// Get authorized signers for a signers file update.
/// Returns the union of old/new admin+master keys plus all newly added signers.
fn authorized_signers_for_signers_update(
    new_signers_path: &Path,
) -> Result<HashSet<AsfaloadPublicKeys>, AggregateSignatureError> {
    let old_config_path = find_global_signers_for(new_signers_path)?;
    let old_config = load_signers_config(&old_config_path)?;
    let new_config = load_signers_config(new_signers_path)?;

    let added_signers = get_newly_added_signer_keys(&old_config, &new_config);

    let mut all_keys = HashSet::new();

    for group in old_config.admin_keys() {
        for signer in &group.signers {
            all_keys.insert(signer.data.pubkey.clone());
        }
    }

    if let Some(master_groups) = old_config.master_keys() {
        for group in master_groups {
            for signer in &group.signers {
                all_keys.insert(signer.data.pubkey.clone());
            }
        }
    }

    for group in new_config.admin_keys() {
        for signer in &group.signers {
            all_keys.insert(signer.data.pubkey.clone());
        }
    }

    if let Some(master_groups) = new_config.master_keys() {
        for group in master_groups {
            for signer in &group.signers {
                all_keys.insert(signer.data.pubkey.clone());
            }
        }
    }

    all_keys.extend(added_signers);

    Ok(all_keys)
}

/// Get authorized signers for an artifact file.
/// Only artifact_signers can sign artifacts (NOT admin or master keys).
fn authorized_signers_for_artifact(
    artifact_path: &Path,
) -> Result<HashSet<AsfaloadPublicKeys>, AggregateSignatureError> {
    let signers_file_path = find_global_signers_for(artifact_path)?;
    let signers_config = load_signers_config(&signers_file_path)?;
    Ok(signers_config
        .artifact_signers()
        .iter()
        .flat_map(|group| group.signers.iter().map(|s| s.data.pubkey.clone()))
        .collect())
}

pub fn validate_signers_update(
    new_signers_config: &SignersConfig,
    signers_config: &SignersConfig,
    signatures: &HashMap<AsfaloadPublicKeys, AsfaloadSignatures>,
    file_hash: &AsfaloadHashes,
) -> bool {
    let added_signers = get_newly_added_signer_keys(signers_config, new_signers_config);
    (check_groups(signers_config.admin_keys(), signatures, file_hash)
        || check_groups(
            &signers_config.master_keys().unwrap_or_default(),
            signatures,
            file_hash,
        ))
        && (check_groups(new_signers_config.admin_keys(), signatures, file_hash)
            || check_groups(
                &new_signers_config.master_keys().unwrap_or_default(),
                signatures,
                file_hash,
            ))
        && (check_signers(signatures, &added_signers, file_hash))
}
/// Check completeness for an initial signers file.
/// All signers in the config must have signed.
fn is_initial_signers_sig_complete(
    signers_path: &Path,
    signatures: &HashMap<AsfaloadPublicKeys, AsfaloadSignatures>,
    file_hash: &AsfaloadHashes,
) -> Result<bool, AggregateSignatureError> {
    let signers_config = load_signers_config(signers_path)?;
    Ok(check_all_signers(signatures, &signers_config, file_hash))
}

/// Check completeness for a signers file update.
/// Requires old+new admin/master approval plus all newly added signers.
fn is_signers_update_sig_complete(
    new_signers_path: &Path,
    signatures: &HashMap<AsfaloadPublicKeys, AsfaloadSignatures>,
    file_hash: &AsfaloadHashes,
) -> Result<bool, AggregateSignatureError> {
    let signers_file_path = find_global_signers_for(new_signers_path)?;
    let signers_config = load_signers_config(&signers_file_path)?;
    let new_signers_config = load_signers_config(new_signers_path)?;
    Ok(validate_signers_update(
        &new_signers_config,
        &signers_config,
        signatures,
        file_hash,
    ))
}

/// Check completeness for an artifact file.
/// Uses global signers when pending, local signers when complete.
fn is_artifact_sig_complete(
    artifact_path: &Path,
    look_at_pending: bool,
    signatures: &HashMap<AsfaloadPublicKeys, AsfaloadSignatures>,
    file_hash: &AsfaloadHashes,
) -> Result<bool, AggregateSignatureError> {
    let signers_file_path = if look_at_pending {
        find_global_signers_for(artifact_path)
    } else {
        local_signers_path_for(artifact_path)
    }?;
    let signers_config = load_signers_config(&signers_file_path)?;
    Ok(check_groups(
        signers_config.artifact_signers(),
        signatures,
        file_hash,
    ))
}

/// Check if an aggregate signature for a file is complete
pub fn is_aggregate_signature_complete<P: AsRef<Path>>(
    file_path: P,
    look_at_pending: bool,
) -> Result<bool, AggregateSignatureError> {
    let file_path = file_path.as_ref();

    //  Determine the file type
    let signed_file = SignedFileLoader::load(file_path)?;

    //  Get the path to the signatures file
    let sig_file_path = if look_at_pending {
        pending_signatures_path_for(file_path)?
    } else {
        signatures_path_for(file_path)?
    };

    //  Load individual signatures if the complete signature file exists
    let signatures = if sig_file_path.exists() {
        get_individual_signatures_from_file(&sig_file_path)?
    } else {
        HashMap::new()
    };

    //  Compute the file's hash, as this is what is signed.
    let file_hash = common::sha512_for_file(file_path)?;

    //  Check completeness based on file type
    let is_complete = match signed_file {
        SignedFileWithKind::Artifact(_) => {
            is_artifact_sig_complete(file_path, look_at_pending, &signatures, &file_hash)?
        }
        SignedFileWithKind::SignersFile(_) => {
            is_signers_update_sig_complete(file_path, &signatures, &file_hash)?
        }
        SignedFileWithKind::InitialSignersFile(_) => {
            is_initial_signers_sig_complete(file_path, &signatures, &file_hash)?
        }
        SignedFileWithKind::Revocation(_) => {
            let signers_file_path = if look_at_pending {
                find_global_signers_for(file_path)
            } else {
                local_signers_path_for(file_path)
            }?;
            let signers_config = load_signers_config(&signers_file_path)?;
            check_groups(signers_config.revocation_keys(), &signatures, &file_hash)
        }
        SignedFileWithKind::RevokedArtifact(_) => false,
        SignedFileWithKind::Metadata(_) => {
            // Helpers receive the parent path because they use it to locate
            // the signers config (e.g. local_signers_path_for creates
            // artifact.txt.signers.json. A signers file copy is not taken for and metadata file,
            // and so artifact.txt.metadata.json.signers.json would not be found).
            let parent_path = subject_path_from_metadata(file_path)?;
            let parent_type = common::determine_file_type(&parent_path)?;
            match parent_type {
                FileType::InitialSigners => {
                    is_initial_signers_sig_complete(&parent_path, &signatures, &file_hash)?
                }
                FileType::Signers => {
                    is_signers_update_sig_complete(&parent_path, &signatures, &file_hash)?
                }
                FileType::Artifact => is_artifact_sig_complete(
                    &parent_path,
                    look_at_pending,
                    &signatures,
                    &file_hash,
                )?,
                FileType::Metadata => {
                    return Err(AggregateSignatureError::Io(std::io::Error::new(
                        std::io::ErrorKind::InvalidInput,
                        "Metadata of a metadata file is not supported",
                    )));
                }
                _ => {
                    return Err(AggregateSignatureError::Io(std::io::Error::new(
                        std::io::ErrorKind::InvalidInput,
                        format!("Unsupported parent file type for metadata: {}", parent_type),
                    )));
                }
            }
        }
    };
    if !(signed_file.kind() == FileType::RevokedArtifact) && !look_at_pending && !is_complete {
        Err(AggregateSignatureError::MissingSignaturesInCompleteSignature)
    } else {
        Ok(is_complete)
    }
}
/// Returns the set of authorized signers who have not yet provided a valid
/// pending signature for the given file. Works for all signed file types
/// (artifacts, signers file updates, initial signers files).
///
/// Returns an empty set if the signatures are already complete.
// FIXME: is_aggregate_signature_complete reads the signatures, and
// get_individual_signatures_for_file does the same.
pub fn get_missing_signers<P: AsRef<Path>>(
    file_path: P,
) -> Result<HashSet<AsfaloadPublicKeys>, AggregateSignatureError> {
    let file_path = file_path.as_ref();

    // Guard: return empty set if file in question does not exist
    if !file_path.exists() {
        return Ok(HashSet::new());
    }
    // Guard: return empty set if signatures are already complete
    let complete_sig_path_in_pending_dir = signatures_path_for(file_path)?;
    if complete_sig_path_in_pending_dir.exists() {
        return Ok(HashSet::new());
    }

    // Guard: return empty set if pending signatures already meet completeness criteria
    if is_aggregate_signature_complete(file_path, true)? {
        return Ok(HashSet::new());
    }

    // Load current pending signatures (empty HashMap if no file yet)
    let sig_file_path = pending_signatures_path_for(file_path)?;
    let signatures: HashMap<AsfaloadPublicKeys, AsfaloadSignatures> =
        get_individual_signatures_from_file(&sig_file_path)?;

    // Compute hash (this is what signers sign)
    let file_hash = common::sha512_for_file(file_path)?;

    // Get all authorized signers for this file type
    let authorized = get_authorized_signers_for_file(file_path)?;

    // Return those without a valid signature
    Ok(authorized
        .into_iter()
        .filter(|pubkey| {
            signatures
                .get(pubkey)
                .is_none_or(|sig| pubkey.verify(sig, &file_hash).is_err())
        })
        .collect())
}

/// Load signatures for a file from the corresponding signatures file
// This function cannot be placed in the implementation of AggregateSignature<P,S,SS> because
// in that case, it would have to be called like this: AggregateSignature<_,_,_>::load_for_file(...)
// which requires to determine the phantom type on AggregateSignature before load can be called.
// This is annoying but also makes no sense as a call like this one
//   AggregateSignature<_,_,CompleteSignature>::load_for_file(...)
// could still return a pending signature.
fn generic_load_for_file<PP: AsRef<Path>>(
    path_in: PP,
) -> Result<SignatureWithState, AggregateSignatureError> {
    let signed_file = SignedFileLoader::load(&path_in)?;
    let file_path = path_in.as_ref();

    // Check if the aggregate signature is complete
    let complete_sig_path = signatures_path_for(file_path)?;

    if complete_sig_path.exists() && complete_sig_path.is_file() {
        // Load the complete signature file
        // We double check the signature is complete. If it is not, it
        // will return an error. If it is complete, we don't care about
        // its true return value
        is_aggregate_signature_complete(file_path, false)?;
        let signatures = get_individual_signatures_from_file(&complete_sig_path)?;
        Ok(SignatureWithState::Complete(AggregateSignature::new(
            signatures,
            file_path.to_string_lossy().to_string(),
            signed_file,
        )))
    } else {
        // Load the pending signature file
        let pending_sig_file_path = pending_signatures_path_for(file_path)?;
        let signatures = get_individual_signatures_from_file(pending_sig_file_path)?;

        Ok(SignatureWithState::Pending(AggregateSignature::new(
            signatures,
            file_path.to_string_lossy().to_string(),
            signed_file,
        )))
    }
}

// Warning: this only adds the file to a pending signatures file, but it does not transition
// to complete if needed. So the way to add a signature to an aggregate on the backend should be by
// calling AggregateSignature::add_individual_signature.
#[doc(hidden)]
pub fn add_to_aggregate_for_file<P: AsRef<Path>, S: AsfaloadSignatureTrait>(
    sig: &S,
    signed_file: P,
    pub_key: &S::PublicKeyType,
) -> Result<(), SignatureError> {
    if signed_file.as_ref().is_dir() {
        return Err(SignatureError::IoError(std::io::Error::new(
            std::io::ErrorKind::IsADirectory,
            "Requires a file, cannot sign a directory",
        )));
    }
    let signed_file_path = signed_file.as_ref();
    let signatures_path = signatures_path_for(signed_file_path)?;

    if signatures_path.exists() && signatures_path.is_file() {
        return Err(SignatureError::IoError(std::io::Error::new(
            std::io::ErrorKind::AlreadyExists,
            "Aggregate signature is already complete",
        )));
    }

    let revocation_path = revocation_path_for(signed_file_path)?;
    if revocation_path.exists() && revocation_path.is_file() {
        return Err(SignatureError::FileRevoked(signed_file_path.to_path_buf()));
    }

    let pending_sig_file_path = pending_signatures_path_for(signed_file_path)?;

    let mut sig_file: SignaturesFile = match File::open(&pending_sig_file_path) {
        Ok(file) => serde_json::from_reader(file)?,
        Err(ref e) if e.kind() == std::io::ErrorKind::NotFound => SignaturesFile::new(),
        Err(e) => return Err(e.into()),
    };

    let signed_data = common::sha512_for_file(signed_file_path)?;
    if pub_key.verify(sig, &signed_data).is_ok() {
        let key_format = pub_key.key_format();
        let pubkey_b64 = pub_key.to_base64();
        if sig_file.entries.contains_key(&pubkey_b64) {
            return Err(SignatureError::DuplicateSignature);
        }
        sig_file.entries.insert(
            pubkey_b64,
            TaggedSignature {
                format: key_format,
                signature: sig.to_base64(),
            },
        );

        let json_content = common::to_posix_json(&sig_file)?;
        std::fs::write(&pending_sig_file_path, json_content)?;

        Ok(())
    } else {
        Err(SignatureError::InvalidSignatureForAggregate(
            signed_file_path.to_path_buf(),
        ))
    }
}

impl<SS> AggregateSignature<SS>
where
    SS: SignatureState,
{
    /// Check if aggregate signature meets all thresholds in signers config for artifacts
    pub fn is_artifact_complete(
        &self,
        signers_config: &SignersConfig,
        artifact_data: &AsfaloadHashes,
    ) -> bool {
        // Check artifact_signers groups
        check_groups(
            signers_config.artifact_signers(),
            &self.signatures,
            artifact_data,
        )
    }

    /// Check if aggregate signature meets all thresholds in signers config for master keys
    pub fn is_master_complete(
        &self,
        signers_config: &SignersConfig,
        master_data: &AsfaloadHashes,
    ) -> bool {
        // Check master_keys groups
        check_groups(
            &signers_config.master_keys().unwrap_or_default(),
            &self.signatures,
            master_data,
        )
    }

    /// Check if aggregate signature meets all thresholds in signers config for admin keys
    pub fn is_admin_complete(
        &self,
        signers_config: &SignersConfig,
        admin_data: &AsfaloadHashes,
    ) -> bool {
        // Check admin_keys groups if present
        let keys = signers_config.admin_keys();
        check_groups(keys, &self.signatures, admin_data)
    }

    pub fn save_to_file(&self) -> Result<(), AggregateSignatureError> {
        let file_path = PathBuf::from(&self.origin);
        let sig_file_path = SS::signature_path_for(&file_path)?;

        let entries = self
            .signatures
            .iter()
            .map(|(pubkey, sig)| {
                (
                    pubkey.to_base64(),
                    TaggedSignature {
                        format: pubkey.key_format(),
                        signature: sig.to_base64(),
                    },
                )
            })
            .collect();

        let sig_file = SignaturesFile { entries };
        let json_content = common::to_posix_json(&sig_file)?;
        std::fs::write(&sig_file_path, json_content)?;

        Ok(())
    }
}

impl AggregateSignature<PendingSignature> {
    pub fn try_transition_to_complete(
        &self,
    ) -> Result<AggregateSignature<CompleteSignature>, AggregateSignatureError> {
        let pending_sig_path = pending_signatures_path_for(&self.subject)?;
        if !pending_sig_path.exists() {
            return Err({
                AggregateSignatureError::Io(std::io::Error::new(
                    std::io::ErrorKind::NotFound,
                    format!(
                        "Pending signatures not found for moving to complete ({})",
                        pending_sig_path.to_string_lossy()
                    ),
                ))
            });
        }
        let complete_sig_path = signatures_path_for(&self.subject)?;
        if complete_sig_path.exists() {
            if complete_sig_path.is_file() {
                return Err({
                    AggregateSignatureError::Io(std::io::Error::new(
                        std::io::ErrorKind::AlreadyExists,
                        format!(
                            "Not overwriting existing complete aggregate signature {}",
                            complete_sig_path.to_string_lossy()
                        ),
                    ))
                });
            } else {
                return Err({
                    AggregateSignatureError::Io(std::io::Error::new(
                        std::io::ErrorKind::AlreadyExists,
                        format!(
                            "The move to a complete signature cannot take place as a directory with the destination name exists: {}",
                            complete_sig_path.to_string_lossy()
                        ),
                    ))
                });
            }
        }
        if is_aggregate_signature_complete(&self.subject, true)? {
            // For artifact signatures, we copy the signers file at the time the
            // aggregate signature is completed.
            if self.subject.is_artifact() {
                create_local_signers_for(&self.subject)?;
            }
            // For revocation signatures, we need to finalize the revocation
            // which moves the pending files and the artifact signatures.
            // finalise_revocation_for handles all file moves, so we don't
            // need to rename the signature file separately.
            if self.subject.is_revocation() {
                let artifact_path = self.subject.artifact_path_for_revocation()?;
                crate::revocation::finalise_revocation_for(artifact_path)?;
            } else {
                std::fs::rename(&pending_sig_path, &complete_sig_path).map_err(|e| {
                    AggregateSignatureError::Io(std::io::Error::other(format!(
                        "Error renaming pending to complete: {} -> {} : {}",
                        pending_sig_path.to_string_lossy(),
                        complete_sig_path.to_string_lossy(),
                        e
                    )))
                })?;
            }
            Ok(AggregateSignature::<CompleteSignature>::new(
                self.signatures.clone(),
                self.origin.clone(),
                self.subject.clone(),
            ))
        } else {
            Err(AggregateSignatureError::IsIncomplete)
        }
    }

    // IMPROVE: improve performance by limiting IO operations.
    // see https://github.com/asfaload/asfasign/pull/39#discussion_r2435860732
    pub fn add_individual_signature(
        self,
        sig: &AsfaloadSignatures,
        pubkey: &AsfaloadPublicKeys,
    ) -> Result<SignatureWithState, AggregateSignatureError> {
        // Add the signature to the aggregate
        add_to_aggregate_for_file(sig, self.subject.location().clone(), pubkey).map_err(
            |e| match e {
                common::errors::keys::SignatureError::DuplicateSignature => {
                    AggregateSignatureError::DuplicateSignature
                }
                common::errors::keys::SignatureError::IoError(io_err) => {
                    AggregateSignatureError::Io(io_err)
                }
                common::errors::keys::SignatureError::JsonError(json_err) => {
                    AggregateSignatureError::JsonError(json_err)
                }
                common::errors::keys::SignatureError::Base64DecodeFailed(err) => {
                    AggregateSignatureError::Base64Decode(err)
                }
                other => AggregateSignatureError::Signature(other.to_string()),
            },
        )?;
        let agg_sig_with_state = SignatureWithState::load_for_file(self.subject.location().clone());
        match agg_sig_with_state {
            Ok(SignatureWithState::Pending(pending_agg_sig)) => {
                match pending_agg_sig.try_transition_to_complete() {
                    Ok(agg_sig) => Ok(SignatureWithState::Complete(agg_sig)),
                    Err(AggregateSignatureError::IsIncomplete) => Ok(SignatureWithState::Pending(pending_agg_sig)),
                    Err(e) => Err(e),
                }
            }
            Ok(SignatureWithState::Complete(_)) => Err(AggregateSignatureError::Signature(
                "Complete signature loaded from file after adding individual signature, which is supposed to be impossible".to_string(),
            )),
            Err(e) => Err(e)
        }
    }
}

/// Check if a signer is authorized to add a signature and has not already signed.
///
/// This function performs authorization checks only (group membership and
/// duplicate detection). It does NOT check for revocation status of the file.
/// Revocation is enforced at the signature addition level in
/// `add_to_aggregate_for_file`.
pub fn can_signer_add_signature<PP: AsRef<Path>>(
    pending_sig_path: PP,
    signer: &AsfaloadPublicKeys,
) -> Result<bool, AggregateSignatureError> {
    let subject_path = subject_path_from_pending_signatures(&pending_sig_path)?;
    let authorized = get_authorized_signers_for_file(&subject_path)?;

    if !authorized.contains(signer) {
        return Ok(false);
    }

    let existing_signatures: HashMap<AsfaloadPublicKeys, AsfaloadSignatures> =
        get_individual_signatures_from_file(pending_sig_path)?;

    Ok(!existing_signatures.contains_key(signer))
}

#[cfg(test)]
mod tests {
    use super::*;
    use anyhow::Result;
    use common::errors::keys::KeyError;
    use common::fs::names::create_local_signers_for;
    use common::{ArtifactMarker, SignedFile, sha512_for_file};
    use constants::{
        PENDING_SIGNATURES_SUFFIX, PENDING_SIGNERS_DIR, SIGNATURES_SUFFIX, SIGNERS_DIR,
        SIGNERS_FILE, SIGNERS_SUFFIX,
    };
    use signatures::keys::asfaload::format::Argon2Params;
    use signatures::keys::{AsfaloadKeyPairTrait, AsfaloadSecretKeyTrait};
    use signatures::types::{AsfaloadKeyPairs, AsfaloadSecretKeys};
    use signers_file_types::{
        KeyFormat, Signer, SignerData, SignerGroup, SignerKind, SignersConfig,
        SignersConfigProposal,
    };
    use std::fs;
    use std::path::PathBuf;
    use std::str::FromStr;
    use tempfile::TempDir;
    use test_helpers::{
        TestKeys, create_complete_signers_setup, create_group, get_asfaload_key_pair, get_key_pair,
        get_two_asfaload_key_pairs, get_two_key_pairs, write_artifact_file,
        write_pending_signatures, write_pending_signers_config, write_revocation_file,
        write_signers_config,
    };

    #[test]
    fn test_load_and_complete() -> Result<()> {
        // Generate keypairs
        let test_keys = TestKeys::new(2);
        let pubkey = test_keys.pub_key(0).unwrap().clone();
        let seckey = test_keys.sec_key(0).unwrap();
        let pubkey2 = test_keys.pub_key(1).unwrap().clone();

        // Create signature
        let data = common::sha512_for_content(b"test data".to_vec())?;
        let signature = seckey.sign(&data).unwrap();

        // Create signatures map manually
        let mut signatures = HashMap::new();
        signatures.insert(pubkey.clone(), signature);

        // Create a dummy file path to represent the signed file
        let signed_file_path = PathBuf::from("test_file.txt");

        // Create pending aggregate signature manually
        let agg_sig: AggregateSignature<PendingSignature> = AggregateSignature::new(
            signatures,
            signed_file_path.to_string_lossy().to_string(),
            SignedFileLoader::load(signed_file_path)?,
        );

        // Create signers config JSON string
        let json_config_template = r#"
    {
      "timestamp": "TIMESTAMP",
      "version": 1,
      "artifact_signers": [
        {
          "signers": [
            { "kind": "key", "data": { "pubkey": "PUBKEY1_PLACEHOLDER" } },
            { "kind": "key", "data": { "pubkey": "PUBKEY2_PLACEHOLDER" } }
          ],
          "threshold": THRESHOLD_PLACEHOLDER
        }
      ],
      "master_keys": [],
      "admin_keys": null
    }
    "#;

        // Replace placeholders with actual timestamp and public keys
        let json_config = json_config_template
            .replace("TIMESTAMP", chrono::Utc::now().to_string().as_str())
            .replace("PUBKEY1_PLACEHOLDER", &pubkey.to_base64())
            .replace("PUBKEY2_PLACEHOLDER", &pubkey2.to_base64())
            .replace("THRESHOLD_PLACEHOLDER", "1");

        // Parse signers config from JSON
        let signers_config: SignersConfig =
            signers_file_types::parse_signers_config(&json_config).unwrap();

        // Should be complete with threshold 1
        assert!(agg_sig.is_artifact_complete(&signers_config, &data));

        // Should be incomplete with threshold 2
        let high_threshold_config = json_config_template
            .replace("TIMESTAMP", chrono::Utc::now().to_string().as_str())
            .replace("PUBKEY1_PLACEHOLDER", &pubkey.to_base64())
            .replace("PUBKEY2_PLACEHOLDER", &pubkey2.to_base64())
            .replace("THRESHOLD_PLACEHOLDER", "2");
        let signers_config: SignersConfig =
            signers_file_types::parse_signers_config(&high_threshold_config).unwrap();
        assert!(!agg_sig.is_artifact_complete(&signers_config, &data));
        assert_eq!(agg_sig.origin, "test_file.txt");
        Ok(())
    }

    // This test illustrates how a signers config can be defined programmatically. This
    // will not be the usual case, but could be handy.
    #[test]
    fn test_load_and_complete_programmatically() -> Result<()> {
        // Create temp directory
        let temp_dir = TempDir::new().unwrap();
        // Crete a work_dir so we can place the  asfaload_signers dir
        // in its parent directory temp_dir
        let dir_path = temp_dir.path().join("work_dir");
        fs::create_dir_all(&dir_path).unwrap();

        // Generate keypairs
        let test_keys = TestKeys::new(2);
        let pubkey = test_keys.pub_key(0).unwrap().clone();
        let seckey = test_keys.sec_key(0).unwrap();
        let pubkey2 = test_keys.pub_key(1).unwrap().clone();

        // Create signers configuration with threshold 2

        // Create signers config with threshold 1
        let signer = signers_file_types::Signer {
            kind: SignerKind::Key,
            data: signers_file_types::SignerData {
                pubkey: pubkey.clone(),
            },
        };
        let signer2 = signers_file_types::Signer {
            kind: SignerKind::Key,
            data: signers_file_types::SignerData {
                pubkey: pubkey2.clone(),
            },
        };
        let group = SignerGroup {
            signers: vec![signer, signer2],
            threshold: 1,
        };
        let signers_config_proposal = SignersConfigProposal {
            timestamp: chrono::Utc::now(),
            version: 1,
            artifact_signers: vec![group.clone()],
            master_keys: None,
            admin_keys: None,
            revocation_keys: None,
        };
        let signers_config = signers_config_proposal.build()?;
        // Write signers configuration
        let signers_dir = temp_dir.path().join(SIGNERS_DIR);
        fs::create_dir_all(&signers_dir).unwrap();
        let signers_file = signers_dir.join(SIGNERS_FILE);
        let config_json = serde_json::to_string_pretty(&signers_config).unwrap();
        fs::write(&signers_file, config_json).unwrap();

        // Create signature
        let data = b"test data";
        let hash_for_content = common::sha512_for_content(data.to_vec())?;
        let signature = seckey.sign(&hash_for_content).unwrap();

        // Create a dummy file to represent the signed file
        let signed_file_path = dir_path.join("data.txt");
        std::fs::write(&signed_file_path, data).unwrap();

        // Load aggregate signature from disk, it is empty
        let agg_sig = SignatureWithState::load_for_file(&signed_file_path)?
            // As it is empty, is is pending
            .get_pending()
            .unwrap()
            // As it is pending, we can add an individual signature to it
            // After adding the signature, it is in this case complete.
            .add_individual_signature(&signature, &pubkey)?;

        let agg_sig = agg_sig
            .get_complete()
            .ok_or(anyhow::anyhow!("Signature should have been complete"))?;

        // Should be complete with threshold 1
        assert!(agg_sig.is_artifact_complete(&signers_config, &hash_for_content));

        // Should still be complete when threshold set to 2
        // in global signers file as local file still has threshold 1
        let mut high_threshold_group = group.clone();
        high_threshold_group.threshold = 2;
        let high_threshold_config = SignersConfigProposal {
            artifact_signers: vec![high_threshold_group],
            ..signers_config_proposal.clone()
        }
        .build()?;

        let config_json = serde_json::to_string_pretty(&high_threshold_config).unwrap();
        fs::write(&signers_file, config_json).unwrap();

        let agg_sig: SignatureWithState = SignatureWithState::load_for_file(&signed_file_path)?;
        let agg_sig = agg_sig
            .get_complete()
            .ok_or(anyhow::anyhow!("Signature should have been complete"))?;
        assert!(agg_sig.is_artifact_complete(&signers_config, &hash_for_content));

        assert_eq!(
            agg_sig.origin,
            signed_file_path.to_string_lossy().to_string()
        );
        Ok(())
    }

    #[test]
    fn test_multiple_groups() -> Result<()> {
        // Generate two keypairs
        let test_keys = TestKeys::new(2);
        let pubkey1 = test_keys.pub_key(0).unwrap().clone();
        let seckey1 = test_keys.sec_key(0).unwrap();
        let pubkey2 = test_keys.pub_key(1).unwrap().clone();
        let seckey2 = test_keys.sec_key(1).unwrap();

        // Create signatures
        let data = common::sha512_for_content(b"test data".to_vec())?;
        let sig1 = seckey1.sign(&data).unwrap();
        let sig2 = seckey2.sign(&data).unwrap();

        // Create signatures map manually
        let mut signatures = HashMap::new();
        signatures.insert(pubkey1.clone(), sig1);
        signatures.insert(pubkey2.clone(), sig2);

        // Create aggregate signature manually
        let agg_sig: AggregateSignature<CompleteSignature> = AggregateSignature::new(
            signatures,
            "test_origin".to_string(),
            SignedFileWithKind::Artifact(SignedFile::<ArtifactMarker>::new(
                PathBuf::from_str("/data/file")
                    .unwrap()
                    .to_string_lossy()
                    .to_string(),
                None,
            )),
        );

        // Create signers config JSON string with two groups
        let json_config = r#"
    {
      "timestamp": "TIMESTAMP",
      "version": 1,
      "artifact_signers": [
        {
          "signers": [
            { "kind": "key", "data": { "pubkey": "PUBKEY1_PLACEHOLDER" } }
          ],
          "threshold": 1
        },
        {
          "signers": [
            { "kind": "key", "data": { "pubkey": "PUBKEY2_PLACEHOLDER" } }
          ],
          "threshold": 1
        }
      ],
      "master_keys": [],
      "admin_keys": null
    }
    "#;

        // Replace placeholders with actual public keys
        let json_config = json_config
            .replace("TIMESTAMP", chrono::Utc::now().to_string().as_str())
            .replace("PUBKEY1_PLACEHOLDER", &pubkey1.to_base64())
            .replace("PUBKEY2_PLACEHOLDER", &pubkey2.to_base64());

        // Parse signers config from JSON
        let signers_config: SignersConfig =
            signers_file_types::parse_signers_config(&json_config).unwrap();

        // Should be complete with both groups
        assert!(agg_sig.is_artifact_complete(&signers_config, &data));

        // Test mixed configuration (one group in artifact_signers, one in master_keys)
        let json_config_mixed = r#"
    {
      "timestamp": "TIMESTAMP",
      "version": 1,
      "artifact_signers": [
        {
          "signers": [
            { "kind": "key", "data": { "pubkey": "PUBKEY1_PLACEHOLDER" } }
          ],
          "threshold": 1
        }
      ],
      "master_keys": [
        {
          "signers": [
            { "kind": "key", "data": { "pubkey": "PUBKEY2_PLACEHOLDER" } }
          ],
          "threshold": 1
        }
      ],
      "admin_keys": null
    }
    "#;

        // Replace placeholders with actual timestamp and public keys
        let json_config_mixed = json_config_mixed
            .replace("TIMESTAMP", chrono::Utc::now().to_string().as_str())
            .replace("PUBKEY1_PLACEHOLDER", &pubkey1.to_base64())
            .replace("PUBKEY2_PLACEHOLDER", &pubkey2.to_base64());

        // Parse mixed signers config from JSON
        let signers_config_mixed: SignersConfig =
            signers_file_types::parse_signers_config(&json_config_mixed).unwrap();

        // Should be complete with mixed configuration
        assert!(agg_sig.is_artifact_complete(&signers_config_mixed, &data));
        assert!(agg_sig.is_master_complete(&signers_config_mixed, &data));
        // The admin group is implicitly made equal to the artifacti signers group here
        assert!(agg_sig.is_admin_complete(&signers_config_mixed, &data));

        assert_eq!(agg_sig.origin, "test_origin");
        Ok(())
    }

    #[test]
    fn test_check_groups_from_json_minimal() -> Result<()> {
        // Generate keypairs
        let test_keys = TestKeys::new(5);
        // Keys 0 are not used because in a previous version of the code
        // before switching to the use of TestKeys, the keys were generated
        // manually with index starting at 1 and refactoring it is a lot of work
        // for no benefit...
        let _pubkey0 = test_keys.pub_key(0).unwrap();
        let _seckey0 = test_keys.sec_key(0).unwrap();
        let pubkey1 = test_keys.pub_key(1).unwrap();
        let seckey1 = test_keys.sec_key(1).unwrap();
        let pubkey2 = test_keys.pub_key(2).unwrap();
        let seckey2 = test_keys.sec_key(2).unwrap();
        let pubkey3 = test_keys.pub_key(3).unwrap();
        let seckey3 = test_keys.sec_key(3).unwrap();
        let pubkey4 = test_keys.pub_key(4).unwrap();
        let seckey4 = test_keys.sec_key(4).unwrap();

        let data = common::sha512_for_content(b"test data".to_vec())?;

        let build_groups = |tpl: String| {
            let json = test_keys.substitute_keys(tpl);

            let groups: Vec<SignerGroup> = serde_json::from_str(&json).unwrap();
            groups
        };

        let check_validity = |tpl: String,
                              signatures: &HashMap<AsfaloadPublicKeys, AsfaloadSignatures>,
                              expected_valid: bool| {
            let groups = build_groups(tpl);
            if expected_valid {
                assert!(check_groups(&groups, signatures, &data))
            } else {
                assert!(!check_groups(&groups, signatures, &data))
            }
        };
        // Create signatures
        let sig1 = seckey1.sign(&data).unwrap();
        let sig2 = seckey2.sign(&data).unwrap();
        let sig3 = seckey3.sign(&data).unwrap();
        let sig4 = seckey4.sign(&data).unwrap();

        // Create also signature for other data
        let other_data = common::sha512_for_content(b"my other data".to_vec())?;
        let _other_sig1 = seckey1.sign(&other_data).unwrap();
        let _other_sig2 = seckey2.sign(&other_data).unwrap();
        let other_sig3 = seckey3.sign(&other_data).unwrap();
        let _other_sig4 = seckey4.sign(&other_data).unwrap();

        // Create signatures maps
        // The name of the variable indicates which signatures is contains
        let mut signatures_1 = HashMap::new();
        signatures_1.insert(pubkey1.clone(), sig1.clone());
        let mut signatures_1_2 = HashMap::new();
        signatures_1_2.insert(pubkey1.clone(), sig1.clone());
        signatures_1_2.insert(pubkey2.clone(), sig2.clone());
        let mut signatures_1_2_4 = HashMap::new();
        signatures_1_2_4.insert(pubkey1.clone(), sig1.clone());
        signatures_1_2_4.insert(pubkey2.clone(), sig2.clone());
        signatures_1_2_4.insert(pubkey4.clone(), sig4.clone());
        let mut signatures_1_3 = HashMap::new();
        signatures_1_3.insert(pubkey1.clone(), sig1.clone());
        signatures_1_3.insert(pubkey3.clone(), sig3.clone());
        let mut signatures_2_4 = HashMap::new();
        signatures_2_4.insert(pubkey2.clone(), sig2.clone());
        signatures_2_4.insert(pubkey4.clone(), sig4.clone());
        let mut signatures_1_3_4 = HashMap::new();
        signatures_1_3_4.insert(pubkey1.clone(), sig1.clone());
        signatures_1_3_4.insert(pubkey3.clone(), sig3.clone());
        signatures_1_3_4.insert(pubkey4.clone(), sig4.clone());
        let mut signatures_1_2_3_4 = HashMap::new();
        signatures_1_2_3_4.insert(pubkey1.clone(), sig1.clone());
        signatures_1_2_3_4.insert(pubkey2.clone(), sig2.clone());
        signatures_1_2_3_4.insert(pubkey3.clone(), sig3.clone());
        signatures_1_2_3_4.insert(pubkey4.clone(), sig4.clone());

        // Signature by key 3 signed other data, which should make
        // it invalid, hence the i indicator.
        let mut signatures_1_2_i3_4 = HashMap::new();
        signatures_1_2_i3_4.insert(pubkey1.clone(), sig1.clone());
        signatures_1_2_i3_4.insert(pubkey2.clone(), sig2.clone());
        signatures_1_2_i3_4.insert(pubkey3.clone(), other_sig3.clone());
        signatures_1_2_i3_4.insert(pubkey4.clone(), sig4.clone());

        // Aliases for explicit meaning of argument passed
        let complete = true;
        let incomplete = false;

        // Define group check tests in this vector of tuples of the form
        // (json_string, signatures_present, expected_completeness)
        let test_groups = [
            //------------------------------------------------------------
            // 1-of-1 complete
            (
                r#"
    [
      {
        "signers": [
          { "kind": "key", "data": { "pubkey": "PUBKEY1_PLACEHOLDER" } }
        ],
        "threshold": 1
      }
    ]
    "#,
                signatures_1.clone(),
                complete,
            ),
            //------------------------------------------------------------
            // 1-of-1 complete, with additional irrelevant signature
            // The signature by someone not in the signers groups is not an error
            (
                r#"
    [
      {
        "signers": [
          { "kind": "key", "data": { "pubkey": "PUBKEY1_PLACEHOLDER" } }
        ],
        "threshold": 1
      }
    ]
    "#,
                signatures_1_2.clone(),
                complete,
            ),
            //------------------------------------------------------------
            // 2-of-2 complete
            (
                r#"
    [
      {
        "signers": [
          { "kind": "key", "data": { "pubkey": "PUBKEY1_PLACEHOLDER" } },
          { "kind": "key", "data": { "pubkey": "PUBKEY2_PLACEHOLDER" } }
        ],
        "threshold": 2
      }
    ]
    "#,
                signatures_1_2.clone(),
                complete,
            ),
            //------------------------------------------------------------
            // 2-of-2 incomplete
            (
                r#"
    [
      {
        "signers": [
          { "kind": "key", "data": { "pubkey": "PUBKEY1_PLACEHOLDER" } },
          { "kind": "key", "data": { "pubkey": "PUBKEY2_PLACEHOLDER" } }
        ],
        "threshold": 2
      }
    ]
    "#,
                signatures_1.clone(),
                incomplete,
            ),
            //------------------------------------------------------------
            // 2-of-2 incomplete but with an additional irrelevant signature.
            // The signature from a signer not in the group does not help reach the threshold.
            (
                r#"
    [
      {
        "signers": [
          { "kind": "key", "data": { "pubkey": "PUBKEY1_PLACEHOLDER" } },
          { "kind": "key", "data": { "pubkey": "PUBKEY2_PLACEHOLDER" } }
        ],
        "threshold": 2
      }
    ]
    "#,
                signatures_1_3.clone(),
                incomplete,
            ),
            //------------------------------------------------------------
            // 2-of-2 complete but with additional irrelevant signatures.
            // This is not an error.
            (
                r#"
    [
      {
        "signers": [
          { "kind": "key", "data": { "pubkey": "PUBKEY1_PLACEHOLDER" } },
          { "kind": "key", "data": { "pubkey": "PUBKEY2_PLACEHOLDER" } }
        ],
        "threshold": 2
      }
    ]
    "#,
                signatures_1_2_3_4.clone(),
                complete,
            ),
            //------------------------------------------------------------
            // Multiple 1-of-1 groups.
            // This is equivalent to one 2-of-2 group with the same signers.
            // All groups must have their threshold reached for the signature to be complete.
            (
                r#"
    [
      {
        "signers": [
          { "kind": "key", "data": { "pubkey": "PUBKEY1_PLACEHOLDER" } }
        ],
        "threshold": 1
      },
      {
        "signers": [
          { "kind": "key", "data": { "pubkey": "PUBKEY2_PLACEHOLDER" } }
        ],
        "threshold": 1
      }
    ]
    "#,
                signatures_1_2.clone(),
                complete,
            ),
            //------------------------------------------------------------
            // Multiple 1-of-1 groups.
            // When the threshold of one group is not reached, the signature is not complete.
            (
                r#"
    [
      {
        "signers": [
          { "kind": "key", "data": { "pubkey": "PUBKEY1_PLACEHOLDER" } }
        ],
        "threshold": 1
      },
      {
        "signers": [
          { "kind": "key", "data": { "pubkey": "PUBKEY3_PLACEHOLDER" } }
        ],
        "threshold": 1
      }
    ]
    "#,
                signatures_1_2.clone(),
                incomplete,
            ),
            //------------------------------------------------------------
            // Two 2-of-2 groups, complete
            (
                r#"
    [
      {
        "signers": [
          { "kind": "key", "data": { "pubkey": "PUBKEY1_PLACEHOLDER" } }
          ,{ "kind": "key", "data": { "pubkey": "PUBKEY2_PLACEHOLDER" } }
        ],
        "threshold": 2
      },
      {
        "signers": [
          { "kind": "key", "data": { "pubkey": "PUBKEY3_PLACEHOLDER" } }
          ,{ "kind": "key", "data": { "pubkey": "PUBKEY4_PLACEHOLDER" } }
        ],
        "threshold": 2
      }
    ]
    "#,
                signatures_1_2_3_4.clone(),
                complete,
            ),
            //------------------------------------------------------------
            // Two 2-of-2 groups, but sig3 covers other data
            (
                r#"
    [
      {
        "signers": [
          { "kind": "key", "data": { "pubkey": "PUBKEY1_PLACEHOLDER" } }
          ,{ "kind": "key", "data": { "pubkey": "PUBKEY2_PLACEHOLDER" } }
        ],
        "threshold": 2
      },
      {
        "signers": [
          { "kind": "key", "data": { "pubkey": "PUBKEY3_PLACEHOLDER" } }
          ,{ "kind": "key", "data": { "pubkey": "PUBKEY4_PLACEHOLDER" } }
        ],
        "threshold": 2
      }
    ]
    "#,
                signatures_1_2_i3_4.clone(),
                incomplete,
            ),
            //------------------------------------------------------------
            // Two 4-of-4 groups, but sig3 covers other data
            (
                r#"
    [
      {
        "signers": [
          { "kind": "key", "data": { "pubkey": "PUBKEY1_PLACEHOLDER" } }
          ,{ "kind": "key", "data": { "pubkey": "PUBKEY2_PLACEHOLDER" } }
          ,{ "kind": "key", "data": { "pubkey": "PUBKEY3_PLACEHOLDER" } }
          ,{ "kind": "key", "data": { "pubkey": "PUBKEY4_PLACEHOLDER" } }
        ],
        "threshold": 4
      }
    ]
    "#,
                signatures_1_2_i3_4.clone(),
                incomplete,
            ),
            //------------------------------------------------------------
            // Two 2-of-2 groups, first group incomplete
            (
                r#"
    [
      {
        "signers": [
          { "kind": "key", "data": { "pubkey": "PUBKEY1_PLACEHOLDER" } }
          ,{ "kind": "key", "data": { "pubkey": "PUBKEY2_PLACEHOLDER" } }
        ],
        "threshold": 2
      },
      {
        "signers": [
          { "kind": "key", "data": { "pubkey": "PUBKEY3_PLACEHOLDER" } }
          ,{ "kind": "key", "data": { "pubkey": "PUBKEY4_PLACEHOLDER" } }
        ],
        "threshold": 2
      }
    ]
    "#,
                signatures_1_3_4.clone(),
                incomplete,
            ),
            //------------------------------------------------------------
            // Two 2-of-2 groups, second group incomplete
            (
                r#"
    [
      {
        "signers": [
          { "kind": "key", "data": { "pubkey": "PUBKEY1_PLACEHOLDER" } }
          ,{ "kind": "key", "data": { "pubkey": "PUBKEY2_PLACEHOLDER" } }
        ],
        "threshold": 2
      },
      {
        "signers": [
          { "kind": "key", "data": { "pubkey": "PUBKEY3_PLACEHOLDER" } }
          ,{ "kind": "key", "data": { "pubkey": "PUBKEY4_PLACEHOLDER" } }
        ],
        "threshold": 2
      }
    ]
    "#,
                signatures_1_2_4.clone(),
                incomplete,
            ),
            //------------------------------------------------------------
            // Two 2-of-2 groups, all groups incomplete
            (
                r#"
    [
      {
        "signers": [
          { "kind": "key", "data": { "pubkey": "PUBKEY1_PLACEHOLDER" } }
          ,{ "kind": "key", "data": { "pubkey": "PUBKEY2_PLACEHOLDER" } }
        ],
        "threshold": 2
      },
      {
        "signers": [
          { "kind": "key", "data": { "pubkey": "PUBKEY3_PLACEHOLDER" } }
          ,{ "kind": "key", "data": { "pubkey": "PUBKEY4_PLACEHOLDER" } }
        ],
        "threshold": 2
      }
    ]
    "#,
                signatures_1_3.clone(),
                incomplete,
            ),
            //------------------------------------------------------------
            // Empty group never complete
            (
                r#"
    [

    ]
    "#,
                signatures_1_3.clone(),
                incomplete,
            ),
        ];

        // ------------------------------------------------------------
        // Run all defined tests
        // ------------------------------------------------------------
        test_groups
            .iter()
            .for_each(|g| check_validity(g.0.to_string(), &g.1, g.2));

        // Empty groups are always incomplete
        assert!(!check_groups(
            &[],
            &HashMap::<AsfaloadPublicKeys, AsfaloadSignatures>::new(),
            &data
        ));
        assert!(!check_groups(&[], &signatures_1_2_3_4, &data));
        Ok(())
    }

    #[test]
    fn test_find_signers_file() {
        // Create a temporary directory
        let temp_dir = TempDir::new().unwrap();
        let root = temp_dir.path();

        // Create directory structure:
        // root/
        //   project/
        //     asfaload.signers/
        //       index.json
        //     src/
        //       file.txt
        let project_dir = root.join("project");
        fs::create_dir_all(&project_dir).unwrap();

        let signers_dir = project_dir.join(SIGNERS_DIR);
        fs::create_dir_all(&signers_dir).unwrap();

        let signers_file = signers_dir.join(SIGNERS_FILE);
        fs::write(&signers_file, "{}").unwrap();

        let src_dir = project_dir.join("src");
        fs::create_dir_all(&src_dir).unwrap();

        let test_file = src_dir.join("file.txt");
        fs::write(&test_file, "content").unwrap();

        // Test finding signers file from the file
        let found = find_global_signers_for(&test_file).unwrap();
        assert_eq!(found, signers_file);

        // Test when no signers file exists
        let no_signers_dir = root.join("no_signers");
        fs::create_dir_all(&no_signers_dir).unwrap();
        let result = find_global_signers_for(&no_signers_dir).map_err(|e| e.into());
        assert!(matches!(result, Err(AggregateSignatureError::Io(_))));

        // Test that for the signers file, we don't consider itself
        let result = find_global_signers_for(&signers_file);
        assert!(result.is_err());
    }

    #[test]
    fn test_is_aggregate_signature_complete() -> Result<()> {
        // Create a temporary directory
        let temp_dir = TempDir::new().unwrap();
        let root = temp_dir.path();

        // Create directory structure:
        // root/
        //   asfaload.signers/
        //     index.json
        //   file.txt
        //   file.txt.signatures.json
        let signers_dir = root.join(SIGNERS_DIR);
        fs::create_dir_all(&signers_dir).unwrap();

        // Create a test file
        let test_file = root.join("file.txt");
        let file_content = b"test content";
        fs::write(&test_file, file_content).unwrap();
        let hash_for_content = common::sha512_for_content(file_content.to_vec())?;

        // Generate keys for testing
        let test_keys = TestKeys::new(2);
        let pubkey1 = test_keys.pub_key(0).unwrap();
        let seckey1 = test_keys.sec_key(0).unwrap();
        let pubkey2 = test_keys.pub_key(1).unwrap();
        let seckey2 = test_keys.sec_key(1).unwrap();

        // Create signers configuration with threshold 2
        let signers_config = SignersConfigProposal {
            timestamp: chrono::Utc::now(),
            version: 1,
            artifact_signers: vec![SignerGroup {
                signers: vec![
                    Signer {
                        kind: SignerKind::Key,
                        data: SignerData {
                            pubkey: pubkey1.clone(),
                        },
                    },
                    Signer {
                        kind: SignerKind::Key,
                        data: SignerData {
                            pubkey: pubkey2.clone(),
                        },
                    },
                ],
                threshold: 2,
            }],
            master_keys: None,
            admin_keys: None,
            revocation_keys: None,
        }
        .build()?;

        // Write signers configuration
        let signers_file = signers_dir.join(SIGNERS_FILE);
        let config_json = serde_json::to_string_pretty(&signers_config).unwrap();
        fs::write(&signers_file, config_json).unwrap();

        // Create signatures
        let sig1 = seckey1.sign(&hash_for_content).unwrap();
        let sig2 = seckey2.sign(&hash_for_content).unwrap();

        // Copy global signers file to local
        let result = create_local_signers_for(&test_file);
        assert!(result.is_ok());

        // Test incomplete signature (only one signature)
        let sig_file_path = test_file.with_file_name(format!(
            "{}.{}",
            test_file.file_name().unwrap().to_string_lossy(),
            SIGNATURES_SUFFIX
        ));

        let mut incomplete_sig_file = SignaturesFile::new();
        incomplete_sig_file.entries.insert(
            pubkey1.clone().to_base64(),
            TaggedSignature {
                format: pubkey1.key_format(),
                signature: sig1.to_base64(),
            },
        );
        let incomplete_json = serde_json::to_string_pretty(&incomplete_sig_file).unwrap();
        fs::write(&sig_file_path, incomplete_json).unwrap();

        let result = is_aggregate_signature_complete(&test_file, false);
        assert!(result.is_err());
        assert_eq!(
            result.err().unwrap().to_string(),
            AggregateSignatureError::MissingSignaturesInCompleteSignature.to_string()
        );

        // Test complete signature (both signatures)
        let mut complete_sig_file = SignaturesFile::new();
        complete_sig_file.entries.insert(
            pubkey1.to_base64(),
            TaggedSignature {
                format: pubkey1.key_format(),
                signature: sig1.to_base64(),
            },
        );
        complete_sig_file.entries.insert(
            pubkey2.to_base64(),
            TaggedSignature {
                format: pubkey2.key_format(),
                signature: sig2.to_base64(),
            },
        );
        let complete_json = serde_json::to_string_pretty(&complete_sig_file).unwrap();
        fs::write(&sig_file_path, complete_json).unwrap();

        assert!(is_aggregate_signature_complete(&test_file, false).unwrap());

        // Test when signature file doesn't exist
        fs::remove_file(&sig_file_path).unwrap();
        let res = is_aggregate_signature_complete(&test_file, false);
        assert!(res.is_err());
        assert_eq!(
            res.err().unwrap().to_string(),
            AggregateSignatureError::MissingSignaturesInCompleteSignature.to_string()
        );

        // Test invalid signature (wrong content)
        let mut invalid_sig_file = SignaturesFile::new();
        invalid_sig_file.entries.insert(
            pubkey1.to_base64(),
            TaggedSignature {
                format: pubkey1.key_format(),
                signature: seckey1
                    .sign(&common::sha512_for_content(b"wrong content".to_vec())?)
                    .unwrap()
                    .to_base64(),
            },
        );
        invalid_sig_file.entries.insert(
            pubkey2.to_base64(),
            TaggedSignature {
                format: pubkey2.key_format(),
                signature: sig2.to_base64(),
            },
        );
        let invalid_json = serde_json::to_string_pretty(&invalid_sig_file).unwrap();
        fs::write(&sig_file_path, invalid_json).unwrap();

        let res = is_aggregate_signature_complete(&test_file, false);
        assert!(res.is_err());
        assert_eq!(
            res.err().unwrap().to_string(),
            AggregateSignatureError::MissingSignaturesInCompleteSignature.to_string()
        );
        Ok(())
    }

    #[test]
    fn test_create_local_signers_for_success() {
        // Create a temporary directory structure
        let temp_dir = TempDir::new().unwrap();
        let root = temp_dir.path();

        // Create directory structure:
        // root/
        //   asfaload.signers/
        //     index.json
        //   project/
        //     src/
        //       file.txt
        let project_dir = root.join("project");
        fs::create_dir_all(&project_dir).unwrap();

        let signers_dir = root.join(SIGNERS_DIR);
        fs::create_dir_all(&signers_dir).unwrap();

        // Create global signers file
        let global_signers_file = signers_dir.join(SIGNERS_FILE);
        let global_content = r#"{
            "version": 1,
            "artifact_signers": [],
            "master_keys": [],
            "admin_keys": null
        }"#;
        fs::write(&global_signers_file, global_content).unwrap();

        // Create a test file
        let src_dir = project_dir.join("src");
        fs::create_dir_all(&src_dir).unwrap();
        let test_file = src_dir.join("file.txt");
        fs::write(&test_file, "test content").unwrap();

        // Call the function to create local signers
        let local_signers_path = create_local_signers_for(&test_file).unwrap();

        // Verify the local signers file was created in the correct location
        let expected_local_path = test_file.with_file_name(format!("file.txt.{}", SIGNERS_SUFFIX));
        assert_eq!(local_signers_path, expected_local_path);
        assert!(local_signers_path.exists());

        // Verify the content matches the global signers file
        let local_content = fs::read_to_string(&local_signers_path).unwrap();
        assert_eq!(local_content, global_content);
    }

    #[test]
    fn test_create_local_signers_for_directory_input() {
        // Create a temporary directory
        let temp_dir = TempDir::new().unwrap();
        let dir_path = temp_dir.path();

        // Try to create local signers for a directory - should fail
        let result = create_local_signers_for(dir_path);
        assert!(result.is_err());
        match result.unwrap_err().into() {
            AggregateSignatureError::Io(e) => {
                assert_eq!(e.kind(), std::io::ErrorKind::InvalidInput);
                assert!(
                    e.to_string()
                        .contains("Not creating local signers for a directory")
                );
            }
            _ => panic!("Expected IO error 'Not creating local signers for a directory'"),
        }
    }

    #[test]
    fn test_create_local_signers_for_existing_local_signers() {
        // Create a temporary directory structure
        let temp_dir = TempDir::new().unwrap();
        let root = temp_dir.path();
        // Create directory structure:
        // root/
        //   asfaload.signers/
        //     index.json
        //   project/
        //     src/
        //       file.txt
        let project_dir = root.join("project");
        fs::create_dir_all(&project_dir).unwrap();

        let signers_dir = root.join(SIGNERS_DIR);
        fs::create_dir_all(&signers_dir).unwrap();

        // Create global signers file
        let global_signers_file = signers_dir.join(SIGNERS_FILE);
        let global_content = r#"{
            "version": 1,
            "artifact_signers": [],
            "master_keys": [],
            "admin_keys": null
        }"#;
        fs::write(&global_signers_file, global_content).unwrap();

        // Create a test file
        let src_dir = project_dir.join("src");
        fs::create_dir_all(&src_dir).unwrap();
        let test_file = src_dir.join("file.txt");
        fs::write(&test_file, "test content").unwrap();

        let existing_local_signers = src_dir.join(format!("file.txt.{}", SIGNERS_SUFFIX));
        fs::write(
            &existing_local_signers,
            "content does not matter, only existence",
        )
        .unwrap();

        // Try to create local signers - should fail because local file already exists
        let result = create_local_signers_for(&test_file);
        assert!(result.is_err());
        match result.unwrap_err().into() {
            AggregateSignatureError::Io(e) => {
                assert_eq!(e.kind(), std::io::ErrorKind::AlreadyExists);
                assert!(
                    e.to_string()
                        .contains("Not overwriting existing local signers file")
                );
            }
            _ => panic!("Expected IO error"),
        }
    }

    #[test]
    fn test_create_local_signers_for_no_global_signers() {
        // Create a temporary directory structure without global signers
        let temp_dir = TempDir::new().unwrap();
        let root = temp_dir.path();

        // Create directory structure:
        // root/
        //   project/
        //     src/
        //       file.txt
        let project_dir = root.join("project");
        fs::create_dir_all(&project_dir).unwrap();

        // Create a test file
        let src_dir = project_dir.join("src");
        fs::create_dir_all(&src_dir).unwrap();
        let test_file = src_dir.join("file.txt");
        fs::write(&test_file, "test content").unwrap();

        // Try to create local signers - should fail because no global signers found
        let result = create_local_signers_for(&test_file);
        assert!(result.is_err());
        match result.unwrap_err().into() {
            AggregateSignatureError::Io(e) => {
                assert_eq!(e.kind(), std::io::ErrorKind::NotFound);
                assert!(
                    e.to_string()
                        .contains("No signers file found in parent directories")
                );
            }
            _ => panic!("Expected IO error"),
        }
    }

    #[test]
    fn test_create_local_signers_for_nested_project() {
        // Create a temporary directory structure with nested projects
        let temp_dir = TempDir::new().unwrap();
        let root = temp_dir.path();

        // Create directory structure:
        // root/
        //   asfaload.signers/
        //     index.json
        //   project/
        //     submodule/
        //       src/
        //         file.txt
        let project_dir = root.join("project").join("submodule");
        fs::create_dir_all(&project_dir).unwrap();

        // Create global signers file at root
        let signers_dir = root.join(SIGNERS_DIR);
        fs::create_dir_all(&signers_dir).unwrap();
        let global_signers_file = signers_dir.join(SIGNERS_FILE);
        let global_content = r#"{"version": 1}"#;
        fs::write(&global_signers_file, global_content).unwrap();

        // Create a test file in the nested project
        let src_dir = project_dir.join("src");
        fs::create_dir_all(&src_dir).unwrap();
        let test_file = src_dir.join("file.txt");
        fs::write(&test_file, "test content").unwrap();

        // Call the function to create local signers
        let local_signers_path = create_local_signers_for(&test_file).unwrap();

        // Verify the local signers file was created in the nested project directory
        let expected_local_path = src_dir.join(format!("file.txt.{}", SIGNERS_SUFFIX));
        assert_eq!(local_signers_path, expected_local_path);
        assert!(local_signers_path.exists());

        // Verify the content matches the global signers file
        let local_content = fs::read_to_string(&local_signers_path).unwrap();
        assert_eq!(local_content, global_content);
    }

    #[test]
    fn test_transition_to_complete_success() -> Result<()> {
        // Create a temporary directory
        let temp_dir = TempDir::new().unwrap();
        let root = temp_dir.path();

        // Create a test file with content
        let test_file = root.join("test_file.txt");
        let file_content = b"test content for signing";
        let hash_for_content = common::sha512_for_content(file_content.to_vec())?;
        fs::write(&test_file, file_content).unwrap();

        // Generate a keypair for signing
        let test_keys = TestKeys::new(1);
        let pubkey = test_keys.pub_key(0).unwrap().clone();
        let seckey = test_keys.sec_key(0).unwrap();

        // Create a signature for the file content
        let signature = seckey.sign(&hash_for_content).unwrap();

        // Create a signers configuration with threshold 1
        let signers_config = SignersConfigProposal {
            timestamp: chrono::Utc::now(),
            version: 1,
            artifact_signers: vec![SignerGroup {
                signers: vec![Signer {
                    kind: SignerKind::Key,
                    data: SignerData {
                        pubkey: pubkey.clone(),
                    },
                }],
                threshold: 1,
            }],
            master_keys: None,
            admin_keys: None,
            revocation_keys: None,
        }
        .build()?;

        // Create global signers directory and file
        let signers_dir = root.join(SIGNERS_DIR);
        fs::create_dir_all(&signers_dir).unwrap();
        let signers_file = signers_dir.join(SIGNERS_FILE);
        let config_json = serde_json::to_string_pretty(&signers_config).unwrap();
        fs::write(&signers_file, config_json).unwrap();

        // Create a pending signatures file with the signature
        let pending_sig_path = pending_signatures_path_for(&test_file).unwrap();
        let mut sig_file = SignaturesFile::new();
        sig_file.entries.insert(
            pubkey.to_base64(),
            TaggedSignature {
                format: pubkey.key_format(),
                signature: signature.to_base64(),
            },
        );
        let signatures_json = serde_json::to_string_pretty(&sig_file).unwrap();
        fs::write(&pending_sig_path, signatures_json).unwrap();

        // Create an AggregateSignature in Pending state
        let mut signatures = HashMap::new();
        signatures.insert(pubkey.clone(), signature.clone());
        let agg_sig: AggregateSignature<PendingSignature> = AggregateSignature::new(
            signatures,
            test_file.to_string_lossy().to_string(),
            SignedFileLoader::load(&test_file)?,
        );

        // Transition to complete
        let complete_sig = agg_sig.try_transition_to_complete().unwrap();

        // Verify the pending file is gone
        assert!(!pending_sig_path.exists());

        // Verify the complete file exists
        let complete_sig_path = signatures_path_for(&test_file).unwrap();
        assert!(complete_sig_path.exists());

        // Verify the content is preserved
        let content = fs::read_to_string(&complete_sig_path).unwrap();
        let parsed_content: SignaturesFile = serde_json::from_str(&content).unwrap();
        assert_eq!(parsed_content.entries.len(), 1);
        assert!(parsed_content.entries.contains_key(&pubkey.to_base64()));
        assert_eq!(
            parsed_content.entries[&pubkey.to_base64()].signature,
            signature.to_base64()
        );

        // Verify the returned signature is in Complete state
        assert_eq!(complete_sig.signatures.len(), 1);
        assert_eq!(complete_sig.origin, test_file.to_string_lossy().to_string());
        assert!(complete_sig.subject.is_artifact());
        assert_eq!(
            complete_sig.subject.location(),
            test_file.to_string_lossy().to_string()
        );
        Ok(())
    }

    #[test]
    fn test_transition_to_complete_no_pending_file() {
        // Create a temporary directory
        let temp_dir = TempDir::new().unwrap();
        let root = temp_dir.path();

        // Create a test file but no pending signature file
        let test_file = root.join("test_file.txt");
        fs::write(&test_file, "test content").unwrap();

        // Create an AggregateSignature in Pending state
        let agg_sig: AggregateSignature<PendingSignature> = AggregateSignature::new(
            HashMap::new(),
            test_file.to_string_lossy().to_string(),
            SignedFileLoader::load(&test_file).unwrap(),
        );

        // Attempt to transition to complete
        let result = agg_sig.try_transition_to_complete();

        // Verify the error
        assert!(result.is_err());
        match result.err().unwrap() {
            AggregateSignatureError::Io(e) => {
                assert_eq!(e.kind(), std::io::ErrorKind::NotFound);
                assert!(e.to_string().contains("Pending signatures not found"));
            }
            _ => panic!("Expected IO error of kind NotFound"),
        }
    }

    #[test]
    fn test_transition_to_complete_complete_file_exists() {
        // Create a temporary directory
        let temp_dir = TempDir::new().unwrap();
        let root = temp_dir.path();

        // Create a test file
        let test_file = root.join("test_file.txt");
        fs::write(&test_file, "test content").unwrap();

        // Create both pending and complete signature files
        let pending_sig_path = pending_signatures_path_for(&test_file).unwrap();
        fs::write(&pending_sig_path, r#"{"key": "value"}"#).unwrap();

        let complete_sig_path = signatures_path_for(&test_file).unwrap();
        fs::write(&complete_sig_path, r#"{"existing": "content"}"#).unwrap();

        // Create an AggregateSignature in Pending state
        let agg_sig: AggregateSignature<PendingSignature> = AggregateSignature::new(
            HashMap::new(),
            test_file.to_string_lossy().to_string(),
            SignedFileLoader::load(&test_file).unwrap(),
        );

        // Attempt to transition to complete
        let result = agg_sig.try_transition_to_complete();

        // Verify the error
        assert!(result.is_err());
        match result.err().unwrap() {
            AggregateSignatureError::Io(e) => {
                assert_eq!(e.kind(), std::io::ErrorKind::AlreadyExists);
                assert!(
                    e.to_string()
                        .contains("Not overwriting existing complete aggregate signature")
                );
            }
            _ => panic!("Expected IO error of kind AlreadyExists"),
        }

        // Verify the pending file still exists
        assert!(pending_sig_path.exists());

        // Verify the complete file is unchanged
        let content = fs::read_to_string(&complete_sig_path).unwrap();
        assert_eq!(content, r#"{"existing": "content"}"#);
    }
    #[test]
    fn test_is_aggregate_signature_complete_pending() -> Result<()> {
        // Create a temporary directory
        let temp_dir = TempDir::new().unwrap();
        let root = temp_dir.path();

        // Create directory structure:
        // root/
        //   asfaload.signers/
        //     index.json
        //   file.txt
        //   file.txt.pending_signatures.json
        let signers_dir = root.join(SIGNERS_DIR);
        fs::create_dir_all(&signers_dir).unwrap();

        // Create a test file
        let test_file = root.join("file.txt");
        let file_content = b"test content";
        fs::write(&test_file, file_content).unwrap();
        let hash_for_content = common::sha512_for_content(file_content.to_vec())?;

        // Generate keys for testing
        let test_keys = TestKeys::new(2);
        let pubkey1 = test_keys.pub_key(0).unwrap();
        let seckey1 = test_keys.sec_key(0).unwrap();
        let pubkey2 = test_keys.pub_key(1).unwrap();
        let seckey2 = test_keys.sec_key(1).unwrap();

        // Create signers configuration with threshold 2
        let signers_config_proposal = SignersConfigProposal {
            timestamp: chrono::Utc::now(),
            version: 1,
            artifact_signers: vec![SignerGroup {
                signers: vec![
                    Signer {
                        kind: SignerKind::Key,
                        data: SignerData {
                            pubkey: pubkey1.clone(),
                        },
                    },
                    Signer {
                        kind: SignerKind::Key,
                        data: SignerData {
                            pubkey: pubkey2.clone(),
                        },
                    },
                ],
                threshold: 2,
            }],
            master_keys: None,
            admin_keys: None,
            revocation_keys: None,
        };
        let signers_config = signers_config_proposal.build()?;

        // Write signers configuration
        let signers_file = signers_dir.join(SIGNERS_FILE);
        let config_json = serde_json::to_string_pretty(&signers_config).unwrap();
        fs::write(&signers_file, config_json).unwrap();

        // Create signatures
        let sig1 = seckey1.sign(&hash_for_content).unwrap();
        let sig2 = seckey2.sign(&hash_for_content).unwrap();

        // Copy global signers file to local
        //let result = create_local_signers_for(&test_file);
        //assert!(result.is_ok());

        // Test when pending signature file doesn't exist
        let res = is_aggregate_signature_complete(&test_file, true);
        assert!(res.is_ok());
        assert!(!res.unwrap()); // Should be incomplete when no pending file exists

        // Create pending signature file path
        let pending_sig_file_path = test_file.with_file_name(format!(
            "{}.{}",
            test_file.file_name().unwrap().to_string_lossy(),
            PENDING_SIGNATURES_SUFFIX
        ));

        // Test incomplete signature (only one signature)
        let mut incomplete_sig_file = SignaturesFile::new();
        incomplete_sig_file.entries.insert(
            pubkey1.clone().to_base64(),
            TaggedSignature {
                format: pubkey1.key_format(),
                signature: sig1.to_base64(),
            },
        );
        let incomplete_json = serde_json::to_string_pretty(&incomplete_sig_file).unwrap();
        fs::write(&pending_sig_file_path, &incomplete_json).unwrap();

        let res = is_aggregate_signature_complete(&test_file, true);
        assert!(res.is_ok());
        assert!(!res.unwrap()); // Should be incomplete with only one signature

        // Test complete signature (both signatures)
        let mut complete_sig_file = SignaturesFile::new();
        complete_sig_file.entries.insert(
            pubkey1.to_base64(),
            TaggedSignature {
                format: pubkey1.key_format(),
                signature: sig1.to_base64(),
            },
        );
        complete_sig_file.entries.insert(
            pubkey2.to_base64(),
            TaggedSignature {
                format: pubkey2.key_format(),
                signature: sig2.to_base64(),
            },
        );
        let complete_json = serde_json::to_string_pretty(&complete_sig_file).unwrap();
        fs::write(&pending_sig_file_path, complete_json).unwrap();

        assert!(is_aggregate_signature_complete(&test_file, true).unwrap()); // Should be complete with both signatures

        // Test invalid signature (wrong content)
        let mut invalid_sig_file = SignaturesFile::new();
        invalid_sig_file.entries.insert(
            pubkey1.to_base64(),
            TaggedSignature {
                format: pubkey1.key_format(),
                signature: seckey1
                    .sign(&common::sha512_for_content(b"wrong content".to_vec())?)
                    .unwrap()
                    .to_base64(),
            },
        );
        invalid_sig_file.entries.insert(
            pubkey2.to_base64(),
            TaggedSignature {
                format: pubkey2.key_format(),
                signature: sig2.to_base64(),
            },
        );
        let invalid_json = serde_json::to_string_pretty(&invalid_sig_file).unwrap();
        fs::write(&pending_sig_file_path, invalid_json).unwrap();

        let res = is_aggregate_signature_complete(&test_file, true);
        assert!(res.is_ok());
        assert!(!res.unwrap()); // Should be incomplete with invalid signature

        // Test with threshold 1 (should be complete with just one valid signature)
        let mut low_threshold_config_proposal = signers_config_proposal.clone();
        low_threshold_config_proposal.artifact_signers[0].threshold = 1;
        let low_threshold_config = low_threshold_config_proposal.build()?;

        // Overwrite the global signers file as it is the one looked at for pending signatures.
        let config_json = serde_json::to_string_pretty(&low_threshold_config).unwrap();
        fs::write(&signers_file, config_json).unwrap();

        // Reset to pending signatures with one valid signature
        fs::write(&pending_sig_file_path, incomplete_json).unwrap();

        let res = is_aggregate_signature_complete(&test_file, true);
        assert!(res.is_ok());
        assert!(res.unwrap()); // Should be complete with threshold 1 and one valid signature

        // Test with empty signatures file
        let empty_sigs = SignaturesFile::new();
        let empty_json = serde_json::to_string_pretty(&empty_sigs).unwrap();
        fs::write(&pending_sig_file_path, empty_json).unwrap();

        let res = is_aggregate_signature_complete(&test_file, true);
        assert!(!res.unwrap()); // Should be incomplete with empty signatures
        Ok(())
    }
    #[test]
    fn test_is_aggregate_signature_complete_with_different_admin_master_keys() -> Result<()> {
        let temp_dir = TempDir::new().unwrap();
        let root = temp_dir.path();

        // Create directory structure:
        // root/
        //   asfaload.signers/
        //     index.json (global signers)
        //   asfaload.pending_signers/
        //     index.json (new signers file)
        //     index.json.signatures.json
        let signers_dir = root.join(SIGNERS_DIR);
        fs::create_dir_all(&signers_dir).unwrap();

        // Signer 1 is master but becomes artifact signer in the new version.
        // Generate keys for testing
        let test_keys = TestKeys::new(5);
        let pubkey1 = test_keys.pub_key(1).unwrap();
        let seckey1 = test_keys.sec_key(1).unwrap();
        let pubkey2 = test_keys.pub_key(2).unwrap();
        let seckey2 = test_keys.sec_key(2).unwrap();
        let pubkey3 = test_keys.pub_key(3).unwrap();
        let seckey3 = test_keys.sec_key(3).unwrap();
        let pubkey4 = test_keys.pub_key(4).unwrap();
        let seckey4 = test_keys.sec_key(4).unwrap();

        // Create current (global) signers configuration with specific admin and master keys
        let current_signers_config = SignersConfigProposal {
            timestamp: chrono::Utc::now(),
            version: 1,
            artifact_signers: vec![],
            master_keys: Some(vec![SignerGroup {
                signers: vec![Signer {
                    kind: SignerKind::Key,
                    data: SignerData {
                        pubkey: pubkey1.clone(),
                    },
                }],
                threshold: 1,
            }]),
            admin_keys: Some(vec![SignerGroup {
                signers: vec![Signer {
                    kind: SignerKind::Key,
                    data: SignerData {
                        pubkey: pubkey2.clone(),
                    },
                }],
                threshold: 1,
            }]),
            revocation_keys: None,
        }
        .build()?;

        // Write current (global) signers configuration
        let global_signers_file = signers_dir.join(SIGNERS_FILE);
        let config_json = serde_json::to_string_pretty(&current_signers_config).unwrap();
        fs::write(&global_signers_file, config_json).unwrap();

        // Create new signers configuration with different admin and master keys
        let new_signers_config = SignersConfigProposal {
            timestamp: chrono::Utc::now(),
            version: 1,
            artifact_signers: vec![SignerGroup {
                signers: vec![Signer {
                    kind: SignerKind::Key,
                    data: SignerData {
                        pubkey: pubkey1.clone(),
                    },
                }],
                threshold: 1,
            }],
            master_keys: Some(vec![SignerGroup {
                signers: vec![Signer {
                    kind: SignerKind::Key,
                    data: SignerData {
                        pubkey: pubkey3.clone(),
                    },
                }],
                threshold: 1,
            }]),
            admin_keys: Some(vec![SignerGroup {
                signers: vec![Signer {
                    kind: SignerKind::Key,
                    data: SignerData {
                        pubkey: pubkey4.clone(),
                    },
                }],
                threshold: 1,
            }]),
            revocation_keys: None,
        }
        .build()?;

        // Write new signers configuration to a file in the pending signers directory
        let pending_signers_dir = root.join(PENDING_SIGNERS_DIR);
        fs::create_dir_all(&pending_signers_dir).unwrap();
        let new_signers_file = pending_signers_dir.join(SIGNERS_FILE);
        let new_config_json = serde_json::to_string_pretty(&new_signers_config).unwrap();
        fs::write(&new_signers_file, new_config_json).unwrap();

        // Calculate hash for the new signers file
        let file_hash = common::sha512_for_file(&new_signers_file)?;

        // Create signatures for all four keys
        let sig1 = seckey1.sign(&file_hash).unwrap();
        let sig2 = seckey2.sign(&file_hash).unwrap();
        let sig3 = seckey3.sign(&file_hash).unwrap();
        let sig4 = seckey4.sign(&file_hash).unwrap();

        // Create signatures file with all four signatures
        let sig_file_path = signatures_path_for(&new_signers_file).unwrap();

        // Only old signatures is not sufficient
        let mut sig_file = SignaturesFile::new();
        sig_file.entries.insert(
            pubkey1.to_base64(),
            TaggedSignature {
                format: pubkey1.key_format(),
                signature: sig1.to_base64(),
            },
        );
        sig_file.entries.insert(
            pubkey2.to_base64(),
            TaggedSignature {
                format: pubkey2.key_format(),
                signature: sig2.to_base64(),
            },
        );
        let signatures_json = serde_json::to_string_pretty(&sig_file).unwrap();
        fs::write(&sig_file_path, signatures_json).unwrap();

        // With the current code, this will fail because it checks the same config twice
        // instead of checking both the current and new signers configs
        let result = is_aggregate_signature_complete(&new_signers_file, false);
        assert!(result.is_err());
        assert_eq!(
            result.err().unwrap().to_string(),
            AggregateSignatureError::MissingSignaturesInCompleteSignature.to_string()
        );

        // Only new signatures is not sufficient
        let mut sig_file = SignaturesFile::new();
        sig_file.entries.insert(
            pubkey3.to_base64(),
            TaggedSignature {
                format: pubkey3.key_format(),
                signature: sig3.to_base64(),
            },
        );
        sig_file.entries.insert(
            pubkey4.to_base64(),
            TaggedSignature {
                format: pubkey4.key_format(),
                signature: sig4.to_base64(),
            },
        );
        let signatures_json = serde_json::to_string_pretty(&sig_file).unwrap();
        fs::write(&sig_file_path, signatures_json).unwrap();

        let result = is_aggregate_signature_complete(&new_signers_file, false);
        assert!(result.is_err());
        assert_eq!(
            result.err().unwrap().to_string(),
            AggregateSignatureError::MissingSignaturesInCompleteSignature.to_string()
        );

        // only one of new signers is not sufficient
        let mut sig_file = SignaturesFile::new();
        sig_file.entries.insert(
            pubkey1.to_base64(),
            TaggedSignature {
                format: pubkey1.key_format(),
                signature: sig1.to_base64(),
            },
        );
        sig_file.entries.insert(
            pubkey3.to_base64(),
            TaggedSignature {
                format: pubkey3.key_format(),
                signature: sig3.to_base64(),
            },
        );
        let signatures_json = serde_json::to_string_pretty(&sig_file).unwrap();
        fs::write(&sig_file_path, signatures_json).unwrap();

        // With the current code, this will fail because it checks the same config twice
        // instead of checking both the current and new signers configs
        let result = is_aggregate_signature_complete(&new_signers_file, false);
        assert!(result.is_err());
        assert_eq!(
            result.err().unwrap().to_string(),
            AggregateSignatureError::MissingSignaturesInCompleteSignature.to_string()
        );

        // only master of old and all new is ok
        let mut sig_file = SignaturesFile::new();
        sig_file.entries.insert(
            pubkey1.to_base64(),
            TaggedSignature {
                format: pubkey1.key_format(),
                signature: sig1.to_base64(),
            },
        );
        sig_file.entries.insert(
            pubkey3.to_base64(),
            TaggedSignature {
                format: pubkey3.key_format(),
                signature: sig3.to_base64(),
            },
        );
        sig_file.entries.insert(
            pubkey4.to_base64(),
            TaggedSignature {
                format: pubkey4.key_format(),
                signature: sig4.to_base64(),
            },
        );
        let signatures_json = serde_json::to_string_pretty(&sig_file).unwrap();
        fs::write(&sig_file_path, signatures_json).unwrap();

        let result = is_aggregate_signature_complete(&new_signers_file, false);
        assert!(result.is_ok());
        // only admin of old and all new is ok
        let mut sig_file = SignaturesFile::new();
        sig_file.entries.insert(
            pubkey2.to_base64(),
            TaggedSignature {
                format: pubkey2.key_format(),
                signature: sig2.to_base64(),
            },
        );
        sig_file.entries.insert(
            pubkey3.to_base64(),
            TaggedSignature {
                format: pubkey3.key_format(),
                signature: sig3.to_base64(),
            },
        );
        sig_file.entries.insert(
            pubkey4.to_base64(),
            TaggedSignature {
                format: pubkey4.key_format(),
                signature: sig4.to_base64(),
            },
        );
        let signatures_json = serde_json::to_string_pretty(&sig_file).unwrap();
        fs::write(&sig_file_path, signatures_json).unwrap();

        // With the current code, this will fail because it checks the same config twice
        // instead of checking both the current and new signers configs
        let result = is_aggregate_signature_complete(&new_signers_file, false);
        assert!(result.is_ok());

        Ok(())
    }
    #[test]
    fn test_is_aggregate_signature_complete_validating_new() -> Result<()> {
        // We test the scenario where we have an artifact signer and an admin signers, and both
        // roles are inverted with the update.
        // This means that if the update is only signed by one party, is should not be accepted.
        // This was added to cover a bug where only the old signers file was used for validation.
        let temp_dir = TempDir::new().unwrap();
        let root = temp_dir.path();

        // Create directory structure:
        // root/
        //   asfaload.signers/
        //     index.json (global signers)
        //   asfaload.pending_signers/
        //     index.json (new signers file)
        //     index.json.signatures.json
        let signers_dir = root.join(SIGNERS_DIR);
        fs::create_dir_all(&signers_dir).unwrap();

        // Signer 2 is admin but becomes artifact signer in the new version.
        // Generate keys for testing
        let test_keys = TestKeys::new(3);
        let _pubkey0 = test_keys.pub_key(0).unwrap();
        let _seckey0 = test_keys.sec_key(0).unwrap();
        let pubkey1 = test_keys.pub_key(1).unwrap();
        let _seckey1 = test_keys.sec_key(1).unwrap();
        let pubkey2 = test_keys.pub_key(2).unwrap();
        let seckey2 = test_keys.sec_key(2).unwrap();

        // Create current (global) signers configuration with specific admin and master keys
        let current_signers_config = SignersConfigProposal {
            timestamp: chrono::Utc::now(),
            version: 1,
            master_keys: None,
            artifact_signers: vec![SignerGroup {
                signers: vec![Signer {
                    kind: SignerKind::Key,
                    data: SignerData {
                        pubkey: pubkey1.clone(),
                    },
                }],
                threshold: 1,
            }],
            admin_keys: Some(vec![SignerGroup {
                signers: vec![Signer {
                    kind: SignerKind::Key,
                    data: SignerData {
                        pubkey: pubkey2.clone(),
                    },
                }],
                threshold: 1,
            }]),
            revocation_keys: None,
        }
        .build()?;

        // Write current (global) signers configuration
        let global_signers_file = signers_dir.join(SIGNERS_FILE);
        let config_json = serde_json::to_string_pretty(&current_signers_config).unwrap();
        fs::write(&global_signers_file, config_json).unwrap();

        // Create new signers configuration with different admin and master keys
        let new_signers_config = SignersConfigProposal {
            timestamp: chrono::Utc::now(),
            version: 1,
            master_keys: None,
            artifact_signers: vec![SignerGroup {
                signers: vec![Signer {
                    kind: SignerKind::Key,
                    data: SignerData {
                        pubkey: pubkey2.clone(),
                    },
                }],
                threshold: 1,
            }],
            admin_keys: Some(vec![SignerGroup {
                signers: vec![Signer {
                    kind: SignerKind::Key,
                    data: SignerData {
                        pubkey: pubkey1.clone(),
                    },
                }],
                threshold: 1,
            }]),
            revocation_keys: None,
        }
        .build()?;

        // Write new signers configuration to a file in the pending signers directory
        let pending_signers_dir = root.join(PENDING_SIGNERS_DIR);
        fs::create_dir_all(&pending_signers_dir).unwrap();
        let new_signers_file = pending_signers_dir.join(SIGNERS_FILE);
        let new_config_json = serde_json::to_string_pretty(&new_signers_config).unwrap();
        fs::write(&new_signers_file, new_config_json).unwrap();

        // Calculate hash for the new signers file
        let file_hash = common::sha512_for_file(&new_signers_file)?;

        // Create signatures for all four keys
        let sig2 = seckey2.sign(&file_hash).unwrap();

        let sig_file_path = signatures_path_for(&new_signers_file).unwrap();

        // Only old admin signature is not sufficient, the new one also has to sign
        // even though it is not a new signer
        let mut sig_file = SignaturesFile::new();
        sig_file.entries.insert(
            pubkey2.to_base64(),
            TaggedSignature {
                format: pubkey2.key_format(),
                signature: sig2.to_base64(),
            },
        );
        let signatures_json = serde_json::to_string_pretty(&sig_file).unwrap();
        fs::write(&sig_file_path, signatures_json).unwrap();

        let result = is_aggregate_signature_complete(&new_signers_file, false);
        assert!(result.is_err());
        assert_eq!(
            result.err().unwrap().to_string(),
            AggregateSignatureError::MissingSignaturesInCompleteSignature.to_string()
        );

        Ok(())
    }

    #[test]
    fn test_check_all_signers() -> Result<()> {
        // Create test keys and data
        let test_keys = TestKeys::new(5);
        let data = common::sha512_for_content(b"test data".to_vec())?;

        // Get public and secret keys
        let pubkey0 = test_keys.pub_key(0).unwrap();
        let seckey0 = test_keys.sec_key(0).unwrap();
        let pubkey1 = test_keys.pub_key(1).unwrap();
        let seckey1 = test_keys.sec_key(1).unwrap();
        let pubkey2 = test_keys.pub_key(2).unwrap();
        let seckey2 = test_keys.sec_key(2).unwrap();
        let pubkey3 = test_keys.pub_key(3).unwrap();
        let seckey3 = test_keys.sec_key(3).unwrap();
        let pubkey4 = test_keys.pub_key(4).unwrap();
        let seckey4 = test_keys.sec_key(4).unwrap();

        // Create signatures
        let sig0 = seckey0.sign(&data).unwrap();
        let sig1 = seckey1.sign(&data).unwrap();
        let sig2 = seckey2.sign(&data).unwrap();
        let sig3 = seckey3.sign(&data).unwrap();
        let sig4 = seckey4.sign(&data).unwrap();

        // Helper function to create a Signer
        let create_signer = |pubkey: AsfaloadPublicKeys| Signer {
            kind: SignerKind::Key,
            data: SignerData { pubkey },
        };

        // Helper function to create a SignerGroup
        let create_group =
            |signers: Vec<Signer>, threshold: u32| SignerGroup { signers, threshold };

        // Scenario 1: Only artifact_signers group
        {
            let config = SignersConfigProposal {
                timestamp: chrono::Utc::now(),
                version: 1,
                artifact_signers: vec![create_group(vec![create_signer(pubkey0.clone())], 1)],
                master_keys: None,
                admin_keys: None,
                revocation_keys: None,
            }
            .build()?;

            // Test with valid signature
            let mut signatures = HashMap::new();
            signatures.insert(pubkey0.clone(), sig0.clone());
            assert!(check_all_signers(&signatures, &config, &data));

            // Test with irrelevant signature
            let mut signatures = HashMap::new();
            signatures.insert(pubkey4.clone(), sig4.clone());
            assert!(!check_all_signers(&signatures, &config, &data));

            // Test with missing signature
            let signatures = HashMap::new();
            assert!(!check_all_signers(&signatures, &config, &data));
        }

        // Scenario 2: Artifact_signers with 2 subgroups
        {
            let config = SignersConfigProposal {
                timestamp: chrono::Utc::now(),
                version: 1,
                artifact_signers: vec![
                    create_group(vec![create_signer(pubkey0.clone())], 1),
                    create_group(vec![create_signer(pubkey1.clone())], 1),
                ],
                master_keys: None,
                admin_keys: None,
                revocation_keys: None,
            }
            .build()?;

            // Test with valid signatures for both groups
            let mut signatures = HashMap::new();
            signatures.insert(pubkey0.clone(), sig0.clone());
            signatures.insert(pubkey1.clone(), sig1.clone());
            assert!(check_all_signers(&signatures, &config, &data));

            // Test with signature missing for one group
            let mut signatures = HashMap::new();
            signatures.insert(pubkey0.clone(), sig0.clone());
            assert!(!check_all_signers(&signatures, &config, &data));
        }

        // Scenario 3: Admin_keys present
        {
            let config = SignersConfigProposal {
                timestamp: chrono::Utc::now(),
                version: 1,
                artifact_signers: vec![create_group(vec![create_signer(pubkey1.clone())], 1)],
                master_keys: None,
                admin_keys: Some(vec![create_group(vec![create_signer(pubkey0.clone())], 1)]),
                revocation_keys: None,
            }
            .build()?;

            // Test with valid signature
            let mut signatures = HashMap::new();
            signatures.insert(pubkey0.clone(), sig0.clone());
            signatures.insert(pubkey1.clone(), sig1.clone());
            assert!(check_all_signers(&signatures, &config, &data));

            // Test with missing signature
            let mut signatures = HashMap::new();
            signatures.insert(pubkey0.clone(), sig0.clone());
            assert!(!check_all_signers(&signatures, &config, &data));
        }

        // Scenario 4: Master_keys present
        {
            let config = SignersConfigProposal {
                timestamp: chrono::Utc::now(),
                version: 1,
                artifact_signers: vec![create_group(vec![create_signer(pubkey1.clone())], 1)],
                master_keys: Some(vec![create_group(vec![create_signer(pubkey0.clone())], 1)]),
                admin_keys: None,
                revocation_keys: None,
            }
            .build()?;

            // Test with valid signature
            let mut signatures = HashMap::new();
            signatures.insert(pubkey0.clone(), sig0.clone());
            signatures.insert(pubkey1.clone(), sig1.clone());
            assert!(check_all_signers(&signatures, &config, &data));

            // Test with missing signature
            let mut signatures = HashMap::new();
            signatures.insert(pubkey0.clone(), sig0.clone());
            assert!(!check_all_signers(&signatures, &config, &data));
        }

        // Scenario 5: Key in both artifact_signers and admin_keys
        {
            let config = SignersConfigProposal {
                timestamp: chrono::Utc::now(),
                version: 1,
                artifact_signers: vec![create_group(vec![create_signer(pubkey0.clone())], 1)],
                master_keys: None,
                admin_keys: Some(vec![create_group(vec![create_signer(pubkey0.clone())], 1)]),
                revocation_keys: None,
            }
            .build()?;

            // Test with valid signature (should satisfy both groups)
            let mut signatures = HashMap::new();
            signatures.insert(pubkey0.clone(), sig0.clone());
            assert!(check_all_signers(&signatures, &config, &data));

            // Test with missing signature
            let signatures = HashMap::new();
            assert!(!check_all_signers(&signatures, &config, &data));
        }

        // Scenario 6: Complex scenario with all key types and overlapping keys
        {
            let config = SignersConfigProposal {
                timestamp: chrono::Utc::now(),
                version: 1,
                artifact_signers: vec![
                    create_group(vec![create_signer(pubkey0.clone())], 1),
                    create_group(vec![create_signer(pubkey1.clone())], 1),
                ],
                master_keys: Some(vec![create_group(vec![create_signer(pubkey2.clone())], 1)]),
                admin_keys: Some(vec![
                    create_group(vec![create_signer(pubkey0.clone())], 1),
                    create_group(vec![create_signer(pubkey3.clone())], 1),
                ]),
                revocation_keys: None,
            }
            .build()?;

            // Test with overlapping key (pubkey0) satisfying both artifact and admin groups
            let mut signatures = HashMap::new();
            signatures.insert(pubkey0.clone(), sig0.clone()); // Covers both artifact group 1 and admin group 1
            signatures.insert(pubkey1.clone(), sig1.clone()); // Covers artifact group 2
            signatures.insert(pubkey2.clone(), sig2.clone()); // Covers master_keys
            signatures.insert(pubkey3.clone(), sig3.clone()); // Covers admin group 2
            assert!(check_all_signers(&signatures, &config, &data));

            // Test with missing signature for one group
            let mut signatures = HashMap::new();
            signatures.insert(pubkey0.clone(), sig0.clone());
            signatures.insert(pubkey1.clone(), sig1.clone());
            signatures.insert(pubkey2.clone(), sig2.clone());
            // Missing signature for pubkey3 (admin_keys group)
            assert!(!check_all_signers(&signatures, &config, &data));
        }

        // Scenario 7: Test with threshold > 1
        {
            let config = SignersConfigProposal {
                timestamp: chrono::Utc::now(),
                version: 1,
                artifact_signers: vec![create_group(
                    vec![
                        create_signer(pubkey0.clone()),
                        create_signer(pubkey1.clone()),
                    ],
                    2,
                )],
                master_keys: None,
                admin_keys: None,
                revocation_keys: None,
            }
            .build()?;

            // Test with both signatures
            let mut signatures = HashMap::new();
            signatures.insert(pubkey0.clone(), sig0.clone());
            signatures.insert(pubkey1.clone(), sig1.clone());
            assert!(check_all_signers(&signatures, &config, &data));

            // Test with only one signature
            let mut signatures = HashMap::new();
            signatures.insert(pubkey0.clone(), sig0.clone());
            assert!(!check_all_signers(&signatures, &config, &data));
        }

        // Scenario 8: Test with empty configuration
        {
            let config = SignersConfigProposal {
                timestamp: chrono::Utc::now(),
                version: 1,
                artifact_signers: vec![],
                master_keys: None,
                admin_keys: None,
                revocation_keys: None,
            }
            .build()?;

            // Even with signatures, should return false for empty config
            let mut signatures = HashMap::new();
            signatures.insert(pubkey0.clone(), sig0.clone());
            assert!(!check_all_signers(&signatures, &config, &data));
        }

        // Scenario 9: Test with invalid signature
        {
            let config = SignersConfigProposal {
                timestamp: chrono::Utc::now(),
                version: 1,
                artifact_signers: vec![create_group(
                    vec![
                        create_signer(pubkey0.clone()),
                        create_signer(pubkey1.clone()),
                    ],
                    1,
                )],
                master_keys: None,
                admin_keys: None,
                revocation_keys: None,
            }
            .build()?;

            // Test with invalid signature (signed for different data)
            let other_data = common::sha512_for_content(b"other data".to_vec())?;
            let invalid_sig = seckey0.sign(&other_data).unwrap();
            let mut signatures = HashMap::new();
            signatures.insert(pubkey0.clone(), invalid_sig);
            signatures.insert(pubkey1.clone(), sig1.clone());
            assert!(!check_all_signers(&signatures, &config, &data));
        }

        // Scenario 10: Revocation keys must be signed too
        {
            let config = SignersConfigProposal {
                timestamp: chrono::Utc::now(),
                version: 1,
                artifact_signers: vec![create_group(vec![create_signer(pubkey0.clone())], 1)],
                master_keys: None,
                admin_keys: None,
                revocation_keys: Some(vec![create_group(vec![create_signer(pubkey1.clone())], 1)]),
            }
            .build()?;

            // Both artifact + revocation signed → true
            let mut signatures = HashMap::new();
            signatures.insert(pubkey0.clone(), sig0.clone());
            signatures.insert(pubkey1.clone(), sig1.clone());
            assert!(check_all_signers(&signatures, &config, &data));

            // Missing revocation key signature → false
            let mut signatures = HashMap::new();
            signatures.insert(pubkey0.clone(), sig0.clone());
            assert!(!check_all_signers(&signatures, &config, &data));
        }
        Ok(())
    }
    // ------------------------------------
    // saving aggregate signature to a file
    // ------------------------------------
    #[test]
    fn test_save_to_file_pending_signature() -> Result<()> {
        // Create a temporary directory
        let temp_dir = TempDir::new().unwrap();
        let root = temp_dir.path();

        // Create a test file
        let test_file = root.join("test_file.txt");
        let file_content = b"test content for signing";
        fs::write(&test_file, file_content)?;

        // Generate keypairs
        let test_keys = TestKeys::new(1);
        let pubkey = test_keys.pub_key(0).unwrap().clone();
        let seckey = test_keys.sec_key(0).unwrap();

        // Create a signature
        let hash_for_content = common::sha512_for_content(file_content.to_vec())?;
        let signature = seckey.sign(&hash_for_content).unwrap();

        // Create a pending aggregate signature
        let mut signatures = HashMap::new();
        signatures.insert(pubkey.clone(), signature.clone());
        let agg_sig: AggregateSignature<PendingSignature> = AggregateSignature::new(
            signatures,
            test_file.to_string_lossy().to_string(),
            SignedFileLoader::load(&test_file)?,
        );

        // Save the signature to file
        agg_sig.save_to_file()?;

        // Verify the pending signature file exists
        let pending_sig_path = test_file.with_file_name(format!(
            "{}.{}",
            test_file.file_name().unwrap().to_string_lossy(),
            PENDING_SIGNATURES_SUFFIX
        ));
        assert!(pending_sig_path.exists());

        // Verify the content
        let content = fs::read_to_string(&pending_sig_path)?;
        let parsed_content: SignaturesFile = serde_json::from_str(&content).unwrap();
        assert_eq!(parsed_content.entries.len(), 1);
        assert!(parsed_content.entries.contains_key(&pubkey.to_base64()));
        assert_eq!(
            parsed_content.entries[&pubkey.to_base64()].signature,
            signature.to_base64()
        );

        Ok(())
    }

    #[test]
    fn test_save_to_file_complete_signature() -> Result<()> {
        // Create a temporary directory
        let temp_dir = TempDir::new().unwrap();
        let root = temp_dir.path();

        // Create a test file
        let test_file = root.join("test_file.txt");
        let file_content = b"test content for signing";
        fs::write(&test_file, file_content)?;

        // Generate keypairs
        let test_keys = TestKeys::new(1);
        let pubkey = test_keys.pub_key(0).unwrap().clone();
        let seckey = test_keys.sec_key(0).unwrap();

        // Create a signature
        let hash_for_content = common::sha512_for_content(file_content.to_vec())?;
        let signature = seckey.sign(&hash_for_content).unwrap();

        // Create a complete aggregate signature
        let mut signatures = HashMap::new();
        signatures.insert(pubkey.clone(), signature.clone());
        let agg_sig: AggregateSignature<CompleteSignature> = AggregateSignature::new(
            signatures,
            test_file.to_string_lossy().to_string(),
            SignedFileLoader::load(&test_file)?,
        );

        // Save the signature to file
        agg_sig.save_to_file()?;

        // Verify the complete signature file exists
        let complete_sig_path = test_file.with_file_name(format!(
            "{}.{}",
            test_file.file_name().unwrap().to_string_lossy(),
            SIGNATURES_SUFFIX
        ));
        assert!(complete_sig_path.exists());

        // Verify the content
        let content = fs::read_to_string(&complete_sig_path)?;
        let parsed_content: SignaturesFile = serde_json::from_str(&content).unwrap();
        assert_eq!(parsed_content.entries.len(), 1);
        assert!(parsed_content.entries.contains_key(&pubkey.to_base64()));
        assert_eq!(
            parsed_content.entries[&pubkey.to_base64()].signature,
            signature.to_base64()
        );

        Ok(())
    }

    #[test]
    fn test_save_to_file_multiple_signatures() -> Result<()> {
        // Create a temporary directory
        let temp_dir = TempDir::new().unwrap();
        let root = temp_dir.path();

        // Create a test file
        let test_file = root.join("test_file.txt");
        let file_content = b"test content for signing";
        fs::write(&test_file, file_content)?;

        // Generate two keypairs
        let test_keys = TestKeys::new(2);
        let pubkey1 = test_keys.pub_key(0).unwrap().clone();
        let seckey1 = test_keys.sec_key(0).unwrap();
        let pubkey2 = test_keys.pub_key(1).unwrap().clone();
        let seckey2 = test_keys.sec_key(1).unwrap();

        // Create signatures
        let hash_for_content = common::sha512_for_content(file_content.to_vec())?;
        let signature1 = seckey1.sign(&hash_for_content).unwrap();
        let signature2 = seckey2.sign(&hash_for_content).unwrap();

        // Create a pending aggregate signature with multiple signatures
        let mut signatures = HashMap::new();
        signatures.insert(pubkey1.clone(), signature1.clone());
        signatures.insert(pubkey2.clone(), signature2.clone());
        let agg_sig: AggregateSignature<PendingSignature> = AggregateSignature::new(
            signatures,
            test_file.to_string_lossy().to_string(),
            SignedFileLoader::load(&test_file)?,
        );

        // Save the signature to file
        agg_sig.save_to_file()?;

        // Verify the pending signature file exists
        let pending_sig_path = test_file.with_file_name(format!(
            "{}.{}",
            test_file.file_name().unwrap().to_string_lossy(),
            PENDING_SIGNATURES_SUFFIX
        ));
        assert!(pending_sig_path.exists());

        // Verify the content contains both signatures
        let content = fs::read_to_string(&pending_sig_path)?;
        let parsed_content: SignaturesFile = serde_json::from_str(&content).unwrap();
        assert_eq!(parsed_content.entries.len(), 2);
        assert!(parsed_content.entries.contains_key(&pubkey1.to_base64()));
        assert!(parsed_content.entries.contains_key(&pubkey2.to_base64()));
        assert_eq!(
            parsed_content.entries[&pubkey1.to_base64()].signature,
            signature1.to_base64()
        );
        assert_eq!(
            parsed_content.entries[&pubkey2.to_base64()].signature,
            signature2.to_base64()
        );

        Ok(())
    }

    #[test]
    fn test_save_to_file_empty_signatures() -> Result<()> {
        // Create a temporary directory
        let temp_dir = TempDir::new().unwrap();
        let root = temp_dir.path();

        // Create a test file
        let test_file = root.join("test_file.txt");
        fs::write(&test_file, b"test content")?;

        // Create an empty pending aggregate signature
        let agg_sig: AggregateSignature<PendingSignature> = AggregateSignature::new(
            HashMap::new(),
            test_file.to_string_lossy().to_string(),
            SignedFileLoader::load(&test_file)?,
        );

        // Save the signature to file
        agg_sig.save_to_file()?;

        // Verify the pending signature file exists
        let pending_sig_path = test_file.with_file_name(format!(
            "{}.{}",
            test_file.file_name().unwrap().to_string_lossy(),
            PENDING_SIGNATURES_SUFFIX
        ));
        assert!(pending_sig_path.exists());

        // Verify the content is an empty signatures file
        let content = fs::read_to_string(&pending_sig_path)?;
        let parsed_content: SignaturesFile = serde_json::from_str(&content).unwrap();
        assert_eq!(parsed_content.entries.len(), 0);

        Ok(())
    }

    #[test]
    fn test_save_to_file_overwrites_existing() -> Result<()> {
        // Create a temporary directory
        let temp_dir = TempDir::new().unwrap();
        let root = temp_dir.path();

        // Create a test file
        let test_file = root.join("test_file.txt");
        fs::write(&test_file, b"test content")?;

        // Create an existing signature file with different content
        let pending_sig_path = test_file.with_file_name(format!(
            "{}.{}",
            test_file.file_name().unwrap().to_string_lossy(),
            PENDING_SIGNATURES_SUFFIX
        ));
        let existing_content = r#"{"old_key": "old_signature"}"#;
        fs::write(&pending_sig_path, existing_content)?;

        // Generate a keypair
        let test_keys = TestKeys::new(1);
        let pubkey = test_keys.pub_key(0).unwrap().clone();
        let seckey = test_keys.sec_key(0).unwrap();

        // Create a signature
        let hash_for_content = common::sha512_for_content(b"test content".to_vec())?;
        let signature = seckey.sign(&hash_for_content).unwrap();

        // Create a pending aggregate signature
        let mut signatures = HashMap::new();
        signatures.insert(pubkey.clone(), signature.clone());
        let agg_sig: AggregateSignature<PendingSignature> = AggregateSignature::new(
            signatures,
            test_file.to_string_lossy().to_string(),
            SignedFileLoader::load(&test_file)?,
        );

        // Save the signature to file (should overwrite)
        agg_sig.save_to_file()?;

        // Verify the content was overwritten
        let content = fs::read_to_string(&pending_sig_path)?;
        let parsed_content: SignaturesFile = serde_json::from_str(&content).unwrap();
        assert_eq!(parsed_content.entries.len(), 1);
        assert!(parsed_content.entries.contains_key(&pubkey.to_base64()));
        assert_eq!(
            parsed_content.entries[&pubkey.to_base64()].signature,
            signature.to_base64()
        );

        Ok(())
    }

    #[test]
    fn test_signatures_file_ends_with_single_newline() -> Result<()> {
        // Verify both add_to_aggregate_for_file and save_to_file write files
        // ending with exactly one trailing newline (POSIX convention).
        let temp_dir = TempDir::new().unwrap();
        let root = temp_dir.path();

        let test_file = root.join("test_file.txt");
        let file_content = b"test content for newline check";
        fs::write(&test_file, file_content)?;

        let test_keys = TestKeys::new(1);
        let pubkey = test_keys.pub_key(0).unwrap().clone();
        let seckey = test_keys.sec_key(0).unwrap();

        let hash_for_content = common::sha512_for_content(file_content.to_vec())?;
        let signature = seckey.sign(&hash_for_content).unwrap();

        // Exercise add_to_aggregate_for_file — writes a pending signatures file
        add_to_aggregate_for_file(&signature, &test_file, &pubkey)?;

        let pending_sig_path = pending_signatures_path_for(&test_file)?;
        let pending_bytes = fs::read(&pending_sig_path)?;
        assert!(
            pending_bytes.ends_with(b"\n"),
            "pending signatures file must end with a newline"
        );
        assert!(
            !pending_bytes.ends_with(b"\n\n"),
            "pending signatures file must not end with two consecutive newlines"
        );

        // Exercise save_to_file (PendingSignature) — writes another pending signatures file
        let mut signatures = HashMap::new();
        signatures.insert(pubkey.clone(), signature.clone());
        let agg_pending: AggregateSignature<PendingSignature> = AggregateSignature::new(
            signatures.clone(),
            test_file.to_string_lossy().to_string(),
            SignedFileLoader::load(&test_file)?,
        );
        // Use a separate file so save_to_file does not collide with the one above
        let test_file2 = root.join("test_file2.txt");
        fs::write(&test_file2, file_content)?;
        let agg_pending2: AggregateSignature<PendingSignature> = AggregateSignature::new(
            signatures,
            test_file2.to_string_lossy().to_string(),
            SignedFileLoader::load(&test_file2)?,
        );
        agg_pending2.save_to_file()?;

        let pending_sig_path2 = pending_signatures_path_for(&test_file2)?;
        let pending_bytes2 = fs::read(&pending_sig_path2)?;
        assert!(
            pending_bytes2.ends_with(b"\n"),
            "save_to_file pending signatures file must end with a newline"
        );
        assert!(
            !pending_bytes2.ends_with(b"\n\n"),
            "save_to_file pending signatures file must not end with two consecutive newlines"
        );

        // Exercise save_to_file (CompleteSignature) — writes a complete signatures file
        let mut signatures_complete = HashMap::new();
        signatures_complete.insert(pubkey.clone(), signature.clone());
        let test_file3 = root.join("test_file3.txt");
        fs::write(&test_file3, file_content)?;
        let agg_complete: AggregateSignature<CompleteSignature> = AggregateSignature::new(
            signatures_complete,
            test_file3.to_string_lossy().to_string(),
            SignedFileLoader::load(&test_file3)?,
        );
        agg_complete.save_to_file()?;

        let complete_sig_path = signatures_path_for(&test_file3)?;
        let complete_bytes = fs::read(&complete_sig_path)?;
        assert!(
            complete_bytes.ends_with(b"\n"),
            "complete signatures file must end with a newline"
        );
        assert!(
            !complete_bytes.ends_with(b"\n\n"),
            "complete signatures file must not end with two consecutive newlines"
        );

        // Suppress unused warning: agg_pending is intentional as a compile check
        let _ = agg_pending;

        Ok(())
    }

    // Tests for add_individual_signature
    // ---------------------------------------
    // Helper function to create a basic signers configuration
    fn create_signers_config(
        artifact_signers: Vec<AsfaloadPublicKeys>,
        threshold: u32,
    ) -> SignersConfig {
        let signers = artifact_signers
            .into_iter()
            .map(|pubkey| Signer {
                kind: SignerKind::Key,
                data: SignerData { pubkey },
            })
            .collect();

        SignersConfigProposal {
            timestamp: chrono::Utc::now(),
            version: 1,
            artifact_signers: vec![SignerGroup { signers, threshold }],
            master_keys: None,
            admin_keys: None,
            revocation_keys: None,
        }
        .build()
        .unwrap()
    }

    // Helper function to sign a file and write its signature to disk
    fn sign_and_write_sig_file(
        file_path: &Path,
        pubkey: &AsfaloadPublicKeys,
        seckey: &AsfaloadSecretKeys,
    ) -> Result<PathBuf, AggregateSignatureError> {
        let content = std::fs::read_to_string(file_path)?;
        let hash = common::sha512_for_content(content.into_bytes())?;
        let signature = seckey.sign(&hash).map_err(|e| {
            AggregateSignatureError::Signature(format!("Failed to sign file: {}", e))
        })?;

        let sig_file_path = file_path.with_file_name(format!(
            "{}.{}",
            file_path.file_name().unwrap().to_string_lossy(),
            SIGNATURES_SUFFIX
        ));

        let mut sigs = HashMap::new();
        sigs.insert(pubkey.to_base64(), signature.to_base64());
        let sig_json = serde_json::to_string_pretty(&sigs)?;
        std::fs::write(&sig_file_path, sig_json)?;

        Ok(sig_file_path)
    }

    // Helper function to create the test directory structure,
    // write the signers config, and sign it.
    // .
    // ├── asfaload_signers
    // │   ├── index.json
    // │   └── index.json.signatures.json
    // └── data
    //     └── test_file.txt
    fn setup_test_hierarchy(
        temp_dir: &TempDir,
        signers_config: &SignersConfig,
        signers_pubkey: &AsfaloadPublicKeys,
        signers_seckey: &AsfaloadSecretKeys,
    ) -> Result<(PathBuf, PathBuf), AggregateSignatureError> {
        let root = temp_dir.path();

        // Create the data directory and test file
        let data_dir = root.join("data");
        fs::create_dir_all(&data_dir)?;
        let test_file = data_dir.join("test_file.txt");
        fs::write(&test_file, "test content for signing")?;

        // Create the global signers directory and file
        let signers_dir = root.join(SIGNERS_DIR);
        fs::create_dir_all(&signers_dir)?;
        let signers_file = signers_dir.join(SIGNERS_FILE);
        let config_json = serde_json::to_string_pretty(signers_config)?;
        fs::write(&signers_file, &config_json)?;

        // Sign the signers file itself
        sign_and_write_sig_file(&signers_file, signers_pubkey, signers_seckey)?;

        Ok((test_file, signers_file))
    }

    #[test]
    fn test_add_individual_signature_success_pending_to_complete_threshold_2() -> Result<()> {
        let temp_dir = TempDir::new().unwrap();

        // Generate keypairs
        let test_keys = TestKeys::new(2);
        let artifact_pubkey = test_keys.pub_key(0).unwrap().clone();
        let artifact_seckey = test_keys.sec_key(0).unwrap();
        let signers_pubkey = test_keys.pub_key(1).unwrap();
        let signers_seckey = test_keys.sec_key(1).unwrap();

        // Create a signers configuration with threshold 1
        let signers_config = create_signers_config(vec![artifact_pubkey.clone()], 1);

        // Setup the test hierarchy
        let (test_file, _signers_file) =
            setup_test_hierarchy(&temp_dir, &signers_config, signers_pubkey, signers_seckey)?;

        // Create a signature for the file content
        let hash_for_content = common::sha512_for_content(fs::read(&test_file)?)?;
        let signature = artifact_seckey.sign(&hash_for_content).unwrap();

        // Create a pending signatures file
        let pending_sig_path = pending_signatures_path_for(&test_file).unwrap();
        let empty_sig_file = serde_json::to_string(&SignaturesFile::new()).unwrap();
        fs::write(&pending_sig_path, &empty_sig_file).unwrap();

        // Load the pending aggregate signature
        let agg_sig_with_state = SignatureWithState::load_for_file(&test_file)?;
        let agg_sig = agg_sig_with_state.get_pending().unwrap();

        // Add the individual signature
        let result = agg_sig.add_individual_signature(&signature, &artifact_pubkey)?;

        // Verify the result is a complete signature
        let complete_sig = result.get_complete().unwrap();
        assert_eq!(complete_sig.signatures.len(), 1);
        assert!(complete_sig.signatures.contains_key(&artifact_pubkey));

        // Verify the pending file is gone and complete file exists
        assert!(!pending_sig_path.exists());
        let complete_sig_path = signatures_path_for(&test_file).unwrap();
        assert!(complete_sig_path.exists());

        Ok(())
    }

    #[test]
    fn test_add_individual_signature_success_with_threshold_3() -> Result<()> {
        let temp_dir = TempDir::new().unwrap();

        // Generate keypairs (3 for artifact + 1 for signers file)
        let test_keys = TestKeys::new(4);
        let artifact_pubkey1 = test_keys.pub_key(0).unwrap().clone();
        let artifact_seckey1 = test_keys.sec_key(0).unwrap();
        let artifact_pubkey2 = test_keys.pub_key(1).unwrap().clone();
        let artifact_seckey2 = test_keys.sec_key(1).unwrap();
        let artifact_pubkey3 = test_keys.pub_key(2).unwrap().clone();
        let artifact_seckey3 = test_keys.sec_key(2).unwrap();
        let signers_pubkey = test_keys.pub_key(3).unwrap();
        let signers_seckey = test_keys.sec_key(3).unwrap();

        // Create a signers configuration with threshold 3
        let signers_config = create_signers_config(
            vec![
                artifact_pubkey1.clone(),
                artifact_pubkey2.clone(),
                artifact_pubkey3.clone(),
            ],
            3,
        );

        // Setup the test hierarchy
        let (test_file, _signers_file) =
            setup_test_hierarchy(&temp_dir, &signers_config, signers_pubkey, signers_seckey)?;

        // Create empty pending signatures file
        let pending_sig_path = pending_signatures_path_for(&test_file).unwrap();
        let empty_sig_file = serde_json::to_string(&SignaturesFile::new()).unwrap();
        fs::write(&pending_sig_path, &empty_sig_file).unwrap();

        // Load the initial empty aggregate signature
        let mut agg_sig_with_state = SignatureWithState::load_for_file(&test_file)?;
        let mut agg_sig = agg_sig_with_state.get_pending().unwrap();

        // --- Add the first signature ---
        let hash_for_content = common::sha512_for_content(fs::read(&test_file)?)?;
        let signature1 = artifact_seckey1.sign(&hash_for_content).unwrap();
        agg_sig_with_state = agg_sig.add_individual_signature(&signature1, &artifact_pubkey1)?;
        agg_sig = agg_sig_with_state.get_pending().unwrap();

        // Verify it's still pending
        assert_eq!(agg_sig.signatures.len(), 1);
        assert!(agg_sig.signatures.contains_key(&artifact_pubkey1));
        assert!(pending_sig_path.exists());

        // --- Add the second signature ---
        let signature2 = artifact_seckey2.sign(&hash_for_content).unwrap();
        agg_sig_with_state = agg_sig.add_individual_signature(&signature2, &artifact_pubkey2)?;
        agg_sig = agg_sig_with_state.get_pending().unwrap();

        // Verify it's still pending
        assert_eq!(agg_sig.signatures.len(), 2);
        assert!(agg_sig.signatures.contains_key(&artifact_pubkey1));
        assert!(agg_sig.signatures.contains_key(&artifact_pubkey2));
        assert!(pending_sig_path.exists());

        // --- Add the third signature ---
        let signature3 = artifact_seckey3.sign(&hash_for_content).unwrap();
        agg_sig_with_state = agg_sig.add_individual_signature(&signature3, &artifact_pubkey3)?;

        // Verify the result is now a complete signature
        let complete_sig = agg_sig_with_state.get_complete().unwrap();
        assert_eq!(complete_sig.signatures.len(), 3);
        assert!(complete_sig.signatures.contains_key(&artifact_pubkey1));
        assert!(complete_sig.signatures.contains_key(&artifact_pubkey2));
        assert!(complete_sig.signatures.contains_key(&artifact_pubkey3));

        // Verify the pending file is gone and complete file exists
        assert!(!pending_sig_path.exists());
        let complete_sig_path = signatures_path_for(&test_file).unwrap();
        assert!(complete_sig_path.exists());

        Ok(())
    }

    #[test]
    fn test_add_individual_signature_success_stays_pending() -> Result<()> {
        let temp_dir = TempDir::new().unwrap();

        // Generate keypairs (2 for artifact + 1 for signers file)
        let test_keys = TestKeys::new(3);
        let artifact_pubkey1 = test_keys.pub_key(0).unwrap().clone();
        let artifact_seckey1 = test_keys.sec_key(0).unwrap();
        let artifact_pubkey2 = test_keys.pub_key(1).unwrap().clone();
        let signers_pubkey = test_keys.pub_key(2).unwrap();
        let signers_seckey = test_keys.sec_key(2).unwrap();

        // Create a signers configuration with threshold 2
        let signers_config =
            create_signers_config(vec![artifact_pubkey1.clone(), artifact_pubkey2.clone()], 2);

        // Setup the test hierarchy
        let (test_file, _signers_file) =
            setup_test_hierarchy(&temp_dir, &signers_config, signers_pubkey, signers_seckey)?;

        // Create a signature for the file content
        let hash_for_content = common::sha512_for_content(fs::read(&test_file)?)?;
        let signature1 = artifact_seckey1.sign(&hash_for_content).unwrap();

        // Create a pending signatures file
        let pending_sig_path = pending_signatures_path_for(&test_file).unwrap();
        let empty_sig_file = serde_json::to_string(&SignaturesFile::new()).unwrap();
        fs::write(&pending_sig_path, &empty_sig_file).unwrap();

        // Load the pending aggregate signature
        let agg_sig_with_state = SignatureWithState::load_for_file(&test_file)?;
        let agg_sig = agg_sig_with_state.get_pending().unwrap();

        // Add the first individual signature
        let result = agg_sig.add_individual_signature(&signature1, &artifact_pubkey1)?;

        // Verify the result is still a pending signature
        let pending_sig = result.get_pending().unwrap();
        assert_eq!(pending_sig.signatures.len(), 1);
        assert!(pending_sig.signatures.contains_key(&artifact_pubkey1));

        // Verify the pending file still exists
        assert!(pending_sig_path.exists());

        Ok(())
    }

    #[test]
    fn test_add_individual_signature_io_error_on_save() -> Result<()> {
        let temp_dir = TempDir::new().unwrap();

        // Generate keypairs
        let test_keys = TestKeys::new(2);
        let artifact_pubkey = test_keys.pub_key(0).unwrap().clone();
        let artifact_seckey = test_keys.sec_key(0).unwrap();
        let signers_pubkey = test_keys.pub_key(1).unwrap();
        let signers_seckey = test_keys.sec_key(1).unwrap();

        // Create a signers configuration
        let signers_config = create_signers_config(vec![artifact_pubkey.clone()], 1);

        // Setup the test hierarchy
        let (test_file, _signers_file) =
            setup_test_hierarchy(&temp_dir, &signers_config, signers_pubkey, signers_seckey)?;

        // Create a signature for the file content
        let hash_for_content = common::sha512_for_content(fs::read(&test_file)?)?;
        let signature = artifact_seckey.sign(&hash_for_content).unwrap();

        // Create a pending signatures file
        let pending_sig_path = pending_signatures_path_for(&test_file).unwrap();
        let empty_sig_file = serde_json::to_string(&SignaturesFile::new()).unwrap();
        fs::write(&pending_sig_path, &empty_sig_file).unwrap();

        // Load the pending aggregate signature
        let agg_sig_with_state = SignatureWithState::load_for_file(&test_file)?;
        let agg_sig = agg_sig_with_state.get_pending().unwrap();

        // Make the pending signatures file read-only to cause an IO error
        let mut perms = fs::metadata(&pending_sig_path)?.permissions();
        perms.set_readonly(true);
        fs::set_permissions(&pending_sig_path, perms)?;

        // Try to add the individual signature
        let result = agg_sig.add_individual_signature(&signature, &artifact_pubkey);

        // Verify the result is an IO error
        assert!(result.is_err());
        match result.err().unwrap() {
            AggregateSignatureError::Io(e) => {
                assert_eq!(e.to_string(), "Permission denied (os error 13)");
            }
            other => panic!("Expected IO error, got {:?}", other),
        }

        // Restore permissions for cleanup to ensure TempDir is cleaned up on all platforms.
        let mut perms = fs::metadata(&pending_sig_path)?.permissions();
        #[allow(clippy::permissions_set_readonly_false)]
        perms.set_readonly(false);
        fs::set_permissions(&pending_sig_path, perms)?;
        Ok(())
    }

    #[test]
    fn test_add_individual_signature_signature_error() -> Result<()> {
        let temp_dir = TempDir::new().unwrap();

        // Generate keypairs
        let test_keys = TestKeys::new(2);
        let artifact_pubkey = test_keys.pub_key(0).unwrap().clone();
        let artifact_seckey = test_keys.sec_key(0).unwrap();
        let signers_pubkey = test_keys.pub_key(1).unwrap();
        let signers_seckey = test_keys.sec_key(1).unwrap();

        // Create a signers configuration
        let signers_config = create_signers_config(vec![artifact_pubkey.clone()], 1);

        // Setup the test hierarchy
        let (test_file, _signers_file) =
            setup_test_hierarchy(&temp_dir, &signers_config, signers_pubkey, signers_seckey)?;

        // Create a signature for different content with artifact_keypair
        let wrong_hash = common::sha512_for_content(b"wrong content".to_vec())?;
        let wrong_signature = artifact_seckey.sign(&wrong_hash).unwrap();

        // Create a pending signatures file
        let pending_sig_path = pending_signatures_path_for(&test_file).unwrap();
        let empty_sig_file = serde_json::to_string(&SignaturesFile::new()).unwrap();
        fs::write(&pending_sig_path, &empty_sig_file).unwrap();

        // Load the pending aggregate signature
        let agg_sig_with_state = SignatureWithState::load_for_file(&test_file)?;
        let agg_sig = agg_sig_with_state.get_pending().unwrap();

        // Try to add the wrong signature
        let result = agg_sig.add_individual_signature(&wrong_signature, &artifact_pubkey);

        // Verify the result is a Signature error
        assert!(result.is_err());
        match result.err().unwrap() {
            AggregateSignatureError::Signature(_) => {} // Expected
            _ => panic!("Expected Signature error"),
        }

        Ok(())
    }

    #[test]
    fn test_add_individual_signature_duplicate_signature() -> Result<()> {
        let temp_dir = TempDir::new().unwrap();

        // Generate keypairs (2 for artifact + 1 for signers file)
        let test_keys = TestKeys::new(3);
        let artifact_pubkey1 = test_keys.pub_key(0).unwrap().clone();
        let artifact_seckey1 = test_keys.sec_key(0).unwrap();
        let artifact_pubkey2 = test_keys.pub_key(1).unwrap().clone();
        let signers_pubkey = test_keys.pub_key(2).unwrap();
        let signers_seckey = test_keys.sec_key(2).unwrap();

        // Create a signers configuration with threshold 2 (so first sig stays pending)
        let signers_config =
            create_signers_config(vec![artifact_pubkey1.clone(), artifact_pubkey2.clone()], 2);

        // Setup the test hierarchy
        let (test_file, _signers_file) =
            setup_test_hierarchy(&temp_dir, &signers_config, signers_pubkey, signers_seckey)?;

        // Create a signature for the file content
        let hash_for_content = common::sha512_for_content(fs::read(&test_file)?)?;
        let signature1 = artifact_seckey1.sign(&hash_for_content).unwrap();

        // Create a pending signatures file
        let pending_sig_path = pending_signatures_path_for(&test_file).unwrap();
        let empty_sig_file = serde_json::to_string(&SignaturesFile::new()).unwrap();
        fs::write(&pending_sig_path, &empty_sig_file).unwrap();

        // Load the pending aggregate signature
        let agg_sig_with_state = SignatureWithState::load_for_file(&test_file)?;
        let agg_sig = agg_sig_with_state.get_pending().unwrap();

        // First signature should succeed and stay pending (threshold is 2)
        let result = agg_sig.add_individual_signature(&signature1, &artifact_pubkey1)?;
        assert!(result.is_pending());

        // Second signature with same key should fail with DuplicateSignature
        let agg_sig = result.get_pending().unwrap();
        let result = agg_sig.add_individual_signature(&signature1, &artifact_pubkey1);
        match result {
            Err(AggregateSignatureError::DuplicateSignature) => {}
            Ok(_) => panic!("Expected DuplicateSignature error, but got Ok"),
            Err(e) => panic!("Expected DuplicateSignature error, got: {:?}", e),
        }

        Ok(())
    }

    #[test]
    fn test_add_individual_signature_load_error() -> Result<()> {
        let temp_dir = TempDir::new().unwrap();

        // Generate keypairs
        let test_keys = TestKeys::new(2);
        let artifact_pubkey = test_keys.pub_key(0).unwrap().clone();
        let artifact_seckey = test_keys.sec_key(0).unwrap();
        let signers_pubkey = test_keys.pub_key(1).unwrap();
        let signers_seckey = test_keys.sec_key(1).unwrap();

        // Create a signers configuration
        let signers_config = create_signers_config(vec![artifact_pubkey.clone()], 1);

        // Setup the test hierarchy
        let (test_file, _signers_file) =
            setup_test_hierarchy(&temp_dir, &signers_config, signers_pubkey, signers_seckey)?;

        // Create a signature for the file content
        let hash_for_content = common::sha512_for_content(fs::read(&test_file)?)?;
        let signature = artifact_seckey.sign(&hash_for_content).unwrap();

        // Create a pending signatures file
        let pending_sig_path = pending_signatures_path_for(&test_file).unwrap();
        let empty_sig_file = serde_json::to_string(&SignaturesFile::new()).unwrap();
        fs::write(&pending_sig_path, &empty_sig_file).unwrap();

        // Load the pending aggregate signature
        let agg_sig_with_state = SignatureWithState::load_for_file(&test_file)?;
        let agg_sig = agg_sig_with_state.get_pending().unwrap();

        // Corrupt the pending signatures file to cause a load error
        fs::write(&pending_sig_path, "invalid json content")?;

        // Try to add the individual signature
        let result = agg_sig.add_individual_signature(&signature, &artifact_pubkey);

        // Verify the result is a JsonError
        assert!(result.is_err());
        match result.err().unwrap() {
            AggregateSignatureError::JsonError(e) => {
                assert_eq!(e.to_string(), "expected value at line 1 column 1")
            }
            other => panic!("Expected JsonError, got {:?}", other),
        }

        Ok(())
    }

    #[test]
    fn test_add_individual_signature_io_error_on_directory_creation() -> Result<()> {
        let temp_dir = TempDir::new().unwrap();

        // Generate keypairs
        let test_keys = TestKeys::new(2);
        let artifact_pubkey = test_keys.pub_key(0).unwrap().clone();
        let artifact_seckey = test_keys.sec_key(0).unwrap();
        let signers_pubkey = test_keys.pub_key(1).unwrap();
        let signers_seckey = test_keys.sec_key(1).unwrap();

        // Create a signers configuration
        let signers_config = create_signers_config(vec![artifact_pubkey.clone()], 2);

        // Setup the test hierarchy
        let (test_file, _signers_file) =
            setup_test_hierarchy(&temp_dir, &signers_config, signers_pubkey, signers_seckey)?;

        // Create a signature for the file content
        let hash_for_content = common::sha512_for_content(fs::read(&test_file)?)?;
        let signature = artifact_seckey.sign(&hash_for_content).unwrap();

        // Create a pending signatures file
        let pending_sig_path = pending_signatures_path_for(&test_file).unwrap();
        let empty_sig_file = serde_json::to_string(&SignaturesFile::new()).unwrap();
        fs::write(&pending_sig_path, &empty_sig_file).unwrap();

        // Load the pending aggregate signature
        let agg_sig_with_state = SignatureWithState::load_for_file(&test_file)?;
        let agg_sig = agg_sig_with_state.get_pending().unwrap();

        // Create a directory with the same name as the pending signatures file
        // This will cause an IO error when trying to write the file
        let pending_sig_dir = pending_sig_path.with_extension("");
        fs::create_dir_all(&pending_sig_dir)?;

        // Try to add the individual signature
        let result = agg_sig.add_individual_signature(&signature, &artifact_pubkey);

        // Verify the result is an IO error
        assert!(result.is_err());
        match result.err().unwrap() {
            AggregateSignatureError::Io(e) => {
                assert_eq!(e.kind(), std::io::ErrorKind::AlreadyExists);
                assert!(
                    e.to_string()
                        .contains("a directory with the destination name exists",)
                );
            }
            other => panic!("Expected IO error, got {:?}", other),
        }

        Ok(())
    }

    // ---------------------------------
    // Test get_newly_added_signer_keys
    // ---------------------------------

    #[test]
    fn test_no_new_signers_identical_configs() {
        let test_keys = TestKeys::new(3);
        let old_config = SignersConfigProposal {
            timestamp: chrono::Utc::now(),
            version: 1,
            artifact_signers: vec![create_group(&test_keys, vec![0, 1], 2)],
            master_keys: Some(vec![create_group(&test_keys, vec![2], 1)]),
            admin_keys: Some(vec![create_group(&test_keys, vec![0], 1)]),
            revocation_keys: None,
        }
        .build()
        .unwrap();

        let new_config = old_config.clone();

        let new_signers = get_newly_added_signer_keys(&old_config, &new_config);
        assert!(new_signers.is_empty());
    }

    #[test]
    fn test_no_new_signers_reordered_groups() {
        let test_keys = TestKeys::new(3);
        let old_config = SignersConfigProposal {
            timestamp: chrono::Utc::now(),
            version: 1,
            artifact_signers: vec![create_group(&test_keys, vec![0, 1], 2)],
            master_keys: Some(vec![create_group(&test_keys, vec![2], 1)]),
            admin_keys: Some(vec![create_group(&test_keys, vec![0], 1)]),
            revocation_keys: None,
        }
        .build()
        .unwrap();

        let new_config = SignersConfigProposal {
            timestamp: chrono::Utc::now(),
            version: 1,
            master_keys: Some(vec![create_group(&test_keys, vec![2], 1)]),
            admin_keys: Some(vec![create_group(&test_keys, vec![0], 1)]),
            artifact_signers: vec![create_group(&test_keys, vec![1, 0], 2)], // Reordered
            revocation_keys: None,
        }
        .build()
        .unwrap();

        let new_signers = get_newly_added_signer_keys(&old_config, &new_config);
        assert!(new_signers.is_empty());
    }

    #[test]
    fn test_new_signer_in_artifact_signers() {
        let test_keys = TestKeys::new(3);
        let old_config = SignersConfigProposal {
            timestamp: chrono::Utc::now(),
            version: 1,
            artifact_signers: vec![create_group(&test_keys, vec![0], 1)],
            master_keys: None,
            admin_keys: None,
            revocation_keys: None,
        }
        .build()
        .unwrap();

        let new_config = SignersConfigProposal {
            timestamp: chrono::Utc::now(),
            version: 1,
            artifact_signers: vec![create_group(&test_keys, vec![0, 1], 2)], // Added key 1
            master_keys: None,
            admin_keys: None,
            revocation_keys: None,
        }
        .build()
        .unwrap();

        let new_signers = get_newly_added_signer_keys(&old_config, &new_config);
        assert_eq!(new_signers.len(), 1);
        assert_eq!(new_signers[0], test_keys.pub_key(1).unwrap().clone());
    }

    #[test]
    fn test_new_signer_in_master_keys() {
        let test_keys = TestKeys::new(3);
        let old_config = SignersConfigProposal {
            timestamp: chrono::Utc::now(),
            version: 1,
            artifact_signers: vec![create_group(&test_keys, vec![0], 1)],
            master_keys: None,
            admin_keys: None,
            revocation_keys: None,
        }
        .build()
        .unwrap();

        let new_config = SignersConfigProposal {
            timestamp: chrono::Utc::now(),
            version: 1,
            artifact_signers: vec![create_group(&test_keys, vec![0], 1)],
            master_keys: Some(vec![create_group(&test_keys, vec![1], 1)]), // Added key 1
            admin_keys: None,
            revocation_keys: None,
        }
        .build()
        .unwrap();

        let new_signers = get_newly_added_signer_keys(&old_config, &new_config);
        assert_eq!(new_signers.len(), 1);
        assert_eq!(new_signers[0], test_keys.pub_key(1).unwrap().clone());
    }

    #[test]
    fn test_new_signer_in_admin_keys() {
        let test_keys = TestKeys::new(3);
        let old_config = SignersConfigProposal {
            timestamp: chrono::Utc::now(),
            version: 1,
            artifact_signers: vec![create_group(&test_keys, vec![0], 1)],
            master_keys: None,
            admin_keys: None,
            revocation_keys: None,
        }
        .build()
        .unwrap();

        let new_config = SignersConfigProposal {
            timestamp: chrono::Utc::now(),
            version: 1,
            artifact_signers: vec![create_group(&test_keys, vec![0], 1)],
            master_keys: None,
            admin_keys: Some(vec![create_group(&test_keys, vec![1], 1)]), // Added key 1
            revocation_keys: None,
        }
        .build()
        .unwrap();

        let new_signers = get_newly_added_signer_keys(&old_config, &new_config);
        assert_eq!(new_signers.len(), 1);
        assert_eq!(new_signers[0], test_keys.pub_key(1).unwrap().clone());
    }

    #[test]
    fn test_new_signers_and_removed_signers() {
        let test_keys = TestKeys::new(10);
        let old_config = SignersConfigProposal {
            timestamp: chrono::Utc::now(),
            version: 1,
            artifact_signers: vec![create_group(&test_keys, vec![0, 1], 2)],
            master_keys: Some(vec![create_group(&test_keys, vec![2], 1)]),
            admin_keys: Some(vec![create_group(&test_keys, vec![3], 1)]),
            revocation_keys: None,
        }
        .build()
        .unwrap();

        let new_config = SignersConfigProposal {
            timestamp: chrono::Utc::now(),
            version: 1,
            artifact_signers: vec![create_group(&test_keys, vec![0, 5, 8], 1)],
            master_keys: Some(vec![create_group(&test_keys, vec![2, 6, 9], 2)]),
            admin_keys: Some(vec![create_group(&test_keys, vec![7], 2)]),
            revocation_keys: None,
        }
        .build()
        .unwrap();

        let new_signers = get_newly_added_signer_keys(&old_config, &new_config);
        let new_signers_set: std::collections::HashSet<_> = new_signers.into_iter().collect();
        assert_eq!(new_signers_set.len(), 5);
        assert!(!new_signers_set.contains(test_keys.pub_key(1).unwrap()));
        assert!(!new_signers_set.contains(test_keys.pub_key(2).unwrap()));
        assert!(!new_signers_set.contains(test_keys.pub_key(3).unwrap()));
        assert!(!new_signers_set.contains(test_keys.pub_key(4).unwrap()));
        assert!(new_signers_set.contains(test_keys.pub_key(5).unwrap()));
        assert!(new_signers_set.contains(test_keys.pub_key(6).unwrap()));
        assert!(new_signers_set.contains(test_keys.pub_key(7).unwrap()));
        assert!(new_signers_set.contains(test_keys.pub_key(8).unwrap()));
        assert!(new_signers_set.contains(test_keys.pub_key(9).unwrap()));
    }

    #[test]
    fn test_all_signers_are_new() {
        let test_keys = TestKeys::new(3);
        let old_config = SignersConfigProposal {
            timestamp: chrono::Utc::now(),
            version: 1,
            artifact_signers: vec![],
            master_keys: None,
            admin_keys: None,
            revocation_keys: None,
        }
        .build()
        .unwrap();

        let new_config = SignersConfigProposal {
            timestamp: chrono::Utc::now(),
            version: 1,
            artifact_signers: vec![create_group(&test_keys, vec![0], 1)],
            master_keys: Some(vec![create_group(&test_keys, vec![1], 1)]),
            admin_keys: Some(vec![create_group(&test_keys, vec![2], 1)]),
            revocation_keys: None,
        }
        .build()
        .unwrap();

        let new_signers = get_newly_added_signer_keys(&old_config, &new_config);
        assert_eq!(new_signers.len(), 3);
        let new_signer_keys: HashSet<_> = new_signers.into_iter().collect();
        assert!(new_signer_keys.contains(test_keys.pub_key(0).unwrap()));
        assert!(new_signer_keys.contains(test_keys.pub_key(1).unwrap()));
        assert!(new_signer_keys.contains(test_keys.pub_key(2).unwrap()));
    }

    #[test]
    fn test_all_signers_are_removed() {
        let test_keys = TestKeys::new(3);
        let old_config = SignersConfigProposal {
            timestamp: chrono::Utc::now(),
            version: 1,
            artifact_signers: vec![create_group(&test_keys, vec![0], 1)],
            master_keys: Some(vec![create_group(&test_keys, vec![1], 1)]),
            admin_keys: Some(vec![create_group(&test_keys, vec![2], 1)]),
            revocation_keys: None,
        }
        .build()
        .unwrap();

        let new_config = SignersConfigProposal {
            timestamp: chrono::Utc::now(),
            version: 1,
            artifact_signers: vec![],
            master_keys: None,
            admin_keys: None,
            revocation_keys: None,
        }
        .build()
        .unwrap();

        let new_signers = get_newly_added_signer_keys(&old_config, &new_config);
        assert!(new_signers.is_empty());
    }

    // ---------------------------------
    // Test get_authorized_signers_for_file
    // ---------------------------------

    #[test]
    fn test_get_authorized_signers_for_file_artifact_only_artifact_signers() {
        let temp_dir = TempDir::new().unwrap();
        let test_keys = TestKeys::new(4);

        // Create signers config with artifact, admin, and master signers
        let artifact_group = create_group(&test_keys, vec![0, 1], 2);
        let admin_group = create_group(&test_keys, vec![2], 1);
        let master_group = create_group(&test_keys, vec![3], 1);
        let config = SignersConfigProposal {
            timestamp: chrono::Utc::now(),
            version: 1,
            artifact_signers: vec![artifact_group.clone()],
            admin_keys: Some(vec![admin_group]),
            master_keys: Some(vec![master_group]),
            revocation_keys: None,
        }
        .build()
        .unwrap();

        write_signers_config(temp_dir.path(), &config);
        let artifact_path = write_artifact_file(temp_dir.path());

        // Get authorized signers
        let authorized = get_authorized_signers_for_file(&artifact_path).expect("Should succeed");

        // Verify: Only artifact signers (keys 0 and 1) are authorized
        // Admin (key 2) and master (key 3) should NOT be authorized
        assert_eq!(authorized.len(), 2);
        assert!(authorized.contains(test_keys.pub_key(0).unwrap()));
        assert!(authorized.contains(test_keys.pub_key(1).unwrap()));
        assert!(!authorized.contains(test_keys.pub_key(2).unwrap()));
        assert!(!authorized.contains(test_keys.pub_key(3).unwrap()));
    }

    #[test]
    fn test_get_authorized_signers_for_file_artifact_no_admin_or_master() {
        let temp_dir = TempDir::new().unwrap();
        let test_keys = TestKeys::new(2);

        // Create signers config with only artifact signers
        let artifact_group = create_group(&test_keys, vec![0, 1], 2);
        let config = SignersConfigProposal {
            timestamp: chrono::Utc::now(),
            version: 1,
            artifact_signers: vec![artifact_group],
            admin_keys: None,
            master_keys: None,
            revocation_keys: None,
        }
        .build()
        .unwrap();

        write_signers_config(temp_dir.path(), &config);
        let artifact_path = write_artifact_file(temp_dir.path());

        // Get authorized signers
        let authorized = get_authorized_signers_for_file(&artifact_path).expect("Should succeed");

        // Verify: Both artifact signers are authorized
        assert_eq!(authorized.len(), 2);
        assert!(authorized.contains(test_keys.pub_key(0).unwrap()));
        assert!(authorized.contains(test_keys.pub_key(1).unwrap()));
    }

    #[test]
    fn test_get_authorized_signers_for_file_artifact_multiple_groups() {
        let temp_dir = TempDir::new().unwrap();
        let test_keys = TestKeys::new(5);
        // Create signers config with multiple artifact groups
        let artifact_group1 = create_group(&test_keys, vec![0, 1], 1);
        let artifact_group2 = create_group(&test_keys, vec![2, 3], 1);

        let config = SignersConfigProposal {
            timestamp: chrono::Utc::now(),
            version: 1,
            artifact_signers: vec![artifact_group1, artifact_group2],
            admin_keys: None,
            master_keys: None,
            revocation_keys: None,
        }
        .build()
        .unwrap();

        write_signers_config(temp_dir.path(), &config);
        let artifact_path = write_artifact_file(temp_dir.path());

        let authorized = get_authorized_signers_for_file(&artifact_path).expect("Should succeed");

        // Verify: All artifact signers from all groups are authorized
        assert_eq!(authorized.len(), 4);
        assert!(authorized.contains(test_keys.pub_key(0).unwrap()));
        assert!(authorized.contains(test_keys.pub_key(1).unwrap()));
        assert!(authorized.contains(test_keys.pub_key(2).unwrap()));
        assert!(authorized.contains(test_keys.pub_key(3).unwrap()));
        assert!(!authorized.contains(test_keys.pub_key(4).unwrap()));
    }

    #[test]
    fn test_get_authorized_signers_for_file_signers_update_old_new_all() {
        let temp_dir = TempDir::new().unwrap();
        let test_keys = TestKeys::new(6);

        // Old config: admins (key 0), masters (key 1), artifact (key 2)
        let old_config = SignersConfigProposal {
            timestamp: chrono::Utc::now(),
            version: 1,
            artifact_signers: vec![create_group(&test_keys, vec![2], 1)],
            admin_keys: Some(vec![create_group(&test_keys, vec![0], 1)]),
            master_keys: Some(vec![create_group(&test_keys, vec![1], 1)]),
            revocation_keys: None,
        }
        .build()
        .unwrap();
        write_signers_config(temp_dir.path(), &old_config);

        // New config: adds artifact signer (key 3), replaces admin (key 0 by key 4)
        let new_config = SignersConfigProposal {
            timestamp: chrono::Utc::now() + chrono::Duration::seconds(1),
            version: 2,
            artifact_signers: vec![create_group(&test_keys, vec![2, 3], 2)], // Added signer
            admin_keys: Some(vec![create_group(&test_keys, vec![4], 1)]),    // New admin
            master_keys: Some(vec![create_group(&test_keys, vec![1], 1)]),   // Same master
            revocation_keys: None,
        }
        .build()
        .unwrap();
        let pending_signers_file = write_pending_signers_config(temp_dir.path(), &new_config);

        let authorized =
            get_authorized_signers_for_file(&pending_signers_file).expect("Should succeed");

        // Old admin (0), old master (1), newly added artifact (3), new admin (4)
        assert_eq!(authorized.len(), 4);
        assert!(authorized.contains(test_keys.pub_key(0).unwrap()));
        assert!(authorized.contains(test_keys.pub_key(1).unwrap()));
        assert!(authorized.contains(test_keys.pub_key(3).unwrap()));
        assert!(authorized.contains(test_keys.pub_key(4).unwrap()));
        assert!(!authorized.contains(test_keys.pub_key(2).unwrap()));
        assert!(!authorized.contains(test_keys.pub_key(5).unwrap()));
    }

    #[test]
    fn test_get_authorized_signers_for_file_signers_update_no_master_in_configs() {
        let temp_dir = TempDir::new().unwrap();
        let test_keys = TestKeys::new(4);

        let old_config = SignersConfigProposal {
            timestamp: chrono::Utc::now(),
            version: 1,
            artifact_signers: vec![create_group(&test_keys, vec![1], 1)],
            admin_keys: Some(vec![create_group(&test_keys, vec![0], 1)]),
            master_keys: None,
            revocation_keys: None,
        }
        .build()
        .unwrap();
        write_signers_config(temp_dir.path(), &old_config);

        let new_config = SignersConfigProposal {
            timestamp: chrono::Utc::now() + chrono::Duration::seconds(1),
            version: 2,
            artifact_signers: vec![create_group(&test_keys, vec![1, 2], 1)],
            admin_keys: Some(vec![create_group(&test_keys, vec![0, 3], 1)]),
            master_keys: None,
            revocation_keys: None,
        }
        .build()
        .unwrap();
        let pending_signers_file = write_pending_signers_config(temp_dir.path(), &new_config);

        let authorized =
            get_authorized_signers_for_file(&pending_signers_file).expect("Should succeed");

        // Authorized: old admin (0), new admin (3), newly added artifact (2)
        // Old artifact (1) is NOT authorized (not newly added)
        assert!(authorized.contains(test_keys.pub_key(0).unwrap()));
        assert!(!authorized.contains(test_keys.pub_key(1).unwrap()));
        assert!(authorized.contains(test_keys.pub_key(2).unwrap()));
        assert!(authorized.contains(test_keys.pub_key(3).unwrap()));
    }

    #[test]
    fn test_get_authorized_signers_for_file_signers_update_only_new_signers_added() {
        let temp_dir = TempDir::new().unwrap();
        let test_keys = TestKeys::new(4);

        let old_config = SignersConfigProposal {
            timestamp: chrono::Utc::now(),
            version: 1,
            artifact_signers: vec![create_group(&test_keys, vec![2], 1)],
            admin_keys: Some(vec![create_group(&test_keys, vec![0], 1)]),
            master_keys: Some(vec![create_group(&test_keys, vec![1], 1)]),
            revocation_keys: None,
        }
        .build()
        .unwrap();
        write_signers_config(temp_dir.path(), &old_config);

        // New config: identical except adds admin (key 3)
        let new_config = SignersConfigProposal {
            timestamp: chrono::Utc::now() + chrono::Duration::seconds(1),
            version: 2,
            artifact_signers: vec![create_group(&test_keys, vec![2], 1)],
            admin_keys: Some(vec![create_group(&test_keys, vec![0, 3], 1)]),
            master_keys: Some(vec![create_group(&test_keys, vec![1], 1)]),
            revocation_keys: None,
        }
        .build()
        .unwrap();
        let pending_signers_file = write_pending_signers_config(temp_dir.path(), &new_config);

        let authorized =
            get_authorized_signers_for_file(&pending_signers_file).expect("Should succeed");

        // All admins and masters from both configs should be authorized
        // Old artifact (2) is NOT authorized (not newly added)
        // New admin (3) is authorized
        assert_eq!(authorized.len(), 3);
        assert!(authorized.contains(test_keys.pub_key(0).unwrap()));
        assert!(authorized.contains(test_keys.pub_key(1).unwrap()));
        assert!(!authorized.contains(test_keys.pub_key(2).unwrap()));
        assert!(authorized.contains(test_keys.pub_key(3).unwrap()));
    }

    #[test]
    fn test_get_authorized_signers_for_file_initial_signers() {
        let temp_dir = TempDir::new().unwrap();
        let test_keys = TestKeys::new(4);

        let config = SignersConfigProposal {
            timestamp: chrono::Utc::now(),
            version: 1,
            artifact_signers: vec![create_group(&test_keys, vec![0, 1], 2)],
            admin_keys: Some(vec![create_group(&test_keys, vec![2], 1)]),
            master_keys: Some(vec![create_group(&test_keys, vec![3], 1)]),
            revocation_keys: None,
        }
        .build()
        .unwrap();
        let pending_signers_file = write_pending_signers_config(temp_dir.path(), &config);

        let authorized =
            get_authorized_signers_for_file(&pending_signers_file).expect("Should succeed");

        // All signers in the config should be authorized
        assert_eq!(authorized.len(), 4);
        assert!(authorized.contains(test_keys.pub_key(0).unwrap()));
        assert!(authorized.contains(test_keys.pub_key(1).unwrap()));
        assert!(authorized.contains(test_keys.pub_key(2).unwrap()));
        assert!(authorized.contains(test_keys.pub_key(3).unwrap()));
    }

    #[test]
    fn test_get_authorized_signers_for_file_error_signers_file_not_found() {
        let temp_dir = TempDir::new().unwrap();

        // Create an artifact file WITHOUT a signers file
        let artifact_path = temp_dir.path().join("artifact.txt");
        fs::write(&artifact_path, "content").unwrap();

        // Should return error
        let result = get_authorized_signers_for_file(&artifact_path);

        assert!(result.is_err());
        match result.unwrap_err() {
            AggregateSignatureError::Io(e) => {
                assert!(e.to_string().contains("signers") || e.to_string().contains("Signers"));
            }
            other => panic!("Expected IO error, got {:?}", other),
        }
    }

    #[test]
    fn test_get_authorized_signers_for_file_revocation_with_explicit_revocation_keys() {
        let temp_dir = TempDir::new().unwrap();
        let test_keys = TestKeys::new(5);

        let (_signers_file, _) = create_complete_signers_setup(
            &temp_dir,
            &test_keys,
            Some(vec![1]),
            Some(vec![2]),
            Some(vec![3, 4]),
        )
        .expect("Should succeed");

        let artifact_path = write_artifact_file(temp_dir.path());

        let revocation_path = write_revocation_file(&artifact_path, test_keys.pub_key(3).unwrap());

        let authorized = get_authorized_signers_for_file(&revocation_path).expect("Should succeed");

        assert_eq!(authorized.len(), 2);
        assert!(!authorized.contains(test_keys.pub_key(0).unwrap()));
        assert!(!authorized.contains(test_keys.pub_key(1).unwrap()));
        assert!(!authorized.contains(test_keys.pub_key(2).unwrap()));
        assert!(authorized.contains(test_keys.pub_key(3).unwrap()));
        assert!(authorized.contains(test_keys.pub_key(4).unwrap()));
    }

    #[test]
    fn test_get_authorized_signers_for_file_revocation_fallback_to_admin_keys() {
        let temp_dir = TempDir::new().unwrap();
        let test_keys = TestKeys::new(3);

        // Create signers config with artifact, admin, but NO explicit revocation keys
        // revocation_keys() should fall back to admin_keys
        let artifact_group = create_group(&test_keys, vec![0], 1);
        let admin_group = create_group(&test_keys, vec![1], 1);
        let config = SignersConfigProposal {
            timestamp: chrono::Utc::now(),
            version: 1,
            artifact_signers: vec![artifact_group],
            admin_keys: Some(vec![admin_group]),
            master_keys: None,
            revocation_keys: None,
        }
        .build()
        .unwrap();

        // Write global signers config
        write_signers_config(temp_dir.path(), &config);

        // Create an artifact file
        let artifact_path = write_artifact_file(temp_dir.path());

        // Create a revocation file
        let revocation_path = write_revocation_file(&artifact_path, test_keys.pub_key(1).unwrap());

        // Get authorized signers for the revocation file
        let authorized = get_authorized_signers_for_file(&revocation_path).expect("Should succeed");

        // Verify: Admin key (key 1) is authorized (fallback from no revocation_keys)
        // Artifact signer (key 0) should NOT be authorized
        assert_eq!(authorized.len(), 1);
        assert!(!authorized.contains(test_keys.pub_key(0).unwrap()));
        assert!(authorized.contains(test_keys.pub_key(1).unwrap()));
        assert!(!authorized.contains(test_keys.pub_key(2).unwrap()));
    }

    #[test]
    fn test_get_authorized_signers_for_file_revocation_fallback_to_artifact_signers() {
        let temp_dir = TempDir::new().unwrap();
        let test_keys = TestKeys::new(2);

        // Create signers config with ONLY artifact signers (no admin, no master, no revocation)
        // revocation_keys() should fall back to artifact_signers
        let artifact_group = create_group(&test_keys, vec![0, 1], 2);
        let config = SignersConfigProposal {
            timestamp: chrono::Utc::now(),
            version: 1,
            artifact_signers: vec![artifact_group],
            admin_keys: None,
            master_keys: None,
            revocation_keys: None,
        }
        .build()
        .unwrap();

        // Write global signers config
        write_signers_config(temp_dir.path(), &config);

        // Create an artifact file
        let artifact_path = write_artifact_file(temp_dir.path());

        // Create a revocation file
        let revocation_path = write_revocation_file(&artifact_path, test_keys.pub_key(0).unwrap());

        // Get authorized signers for the revocation file
        let authorized = get_authorized_signers_for_file(&revocation_path).expect("Should succeed");

        // Verify: Artifact signers (keys 0 and 1) are authorized (fallback)
        assert_eq!(authorized.len(), 2);
        assert!(authorized.contains(test_keys.pub_key(0).unwrap()));
        assert!(authorized.contains(test_keys.pub_key(1).unwrap()));
    }

    #[test]
    fn test_get_authorized_signers_for_file_metadata_initial_signers() -> Result<()> {
        let temp_dir = tempfile::TempDir::new()?;
        let pending_dir = temp_dir.path().join(PENDING_SIGNERS_DIR);
        std::fs::create_dir_all(&pending_dir)?;

        let test_keys = test_helpers::TestKeys::new(2);

        let config = signers_file_types::SignersConfig::with_artifact_signers_only(
            1,
            (
                vec![
                    test_keys.pub_key(0).unwrap().clone(),
                    test_keys.pub_key(1).unwrap().clone(),
                ],
                2,
            ),
        )?;
        let json = config.to_json()?;

        let signers_path = pending_dir.join(SIGNERS_FILE);
        std::fs::write(&signers_path, &json)?;

        let metadata_path = common::fs::names::metadata_path_for(&signers_path)?;
        std::fs::write(
            &metadata_path,
            r#"{"origin":{"forge":"github","owner":"test","repo":"test"}}"#,
        )?;

        let authorized = get_authorized_signers_for_file(&metadata_path)?;

        // For initial signers, all signers should be authorized
        assert!(authorized.contains(test_keys.pub_key(0).unwrap()));
        assert!(authorized.contains(test_keys.pub_key(1).unwrap()));
        assert_eq!(authorized.len(), 2);

        Ok(())
    }

    #[test]
    fn test_get_authorized_signers_for_file_metadata_signers_update() {
        let temp_dir = TempDir::new().unwrap();
        let test_keys = TestKeys::new(6);

        // Old config: admins (key 0), masters (key 1), artifact (key 2)
        let old_config = SignersConfigProposal {
            timestamp: chrono::Utc::now(),
            version: 1,
            artifact_signers: vec![create_group(&test_keys, vec![2], 1)],
            admin_keys: Some(vec![create_group(&test_keys, vec![0], 1)]),
            master_keys: Some(vec![create_group(&test_keys, vec![1], 1)]),
            revocation_keys: None,
        }
        .build()
        .unwrap();
        write_signers_config(temp_dir.path(), &old_config);

        // New config: adds artifact signer (key 3), replaces admin (key 0 by key 4)
        let new_config = SignersConfigProposal {
            timestamp: chrono::Utc::now() + chrono::Duration::seconds(1),
            version: 2,
            artifact_signers: vec![create_group(&test_keys, vec![2, 3], 2)],
            admin_keys: Some(vec![create_group(&test_keys, vec![4], 1)]),
            master_keys: Some(vec![create_group(&test_keys, vec![1], 1)]),
            revocation_keys: None,
        }
        .build()
        .unwrap();
        let pending_signers_file = write_pending_signers_config(temp_dir.path(), &new_config);

        let metadata_path = common::fs::names::metadata_path_for(&pending_signers_file).unwrap();
        std::fs::write(
            &metadata_path,
            r#"{"origin":{"forge":"github","owner":"test","repo":"test"}}"#,
        )
        .unwrap();

        let authorized = get_authorized_signers_for_file(&metadata_path).expect("Should succeed");

        // Same as the signers update test: old admin (0), old master (1),
        // newly added artifact (3), new admin (4)
        assert_eq!(authorized.len(), 4);
        assert!(authorized.contains(test_keys.pub_key(0).unwrap()));
        assert!(authorized.contains(test_keys.pub_key(1).unwrap()));
        assert!(authorized.contains(test_keys.pub_key(3).unwrap()));
        assert!(authorized.contains(test_keys.pub_key(4).unwrap()));
        assert!(!authorized.contains(test_keys.pub_key(2).unwrap()));
        assert!(!authorized.contains(test_keys.pub_key(5).unwrap()));
    }

    #[test]
    fn test_get_authorized_signers_for_file_metadata_artifact() {
        let temp_dir = TempDir::new().unwrap();
        let test_keys = TestKeys::new(4);

        let config = SignersConfigProposal {
            timestamp: chrono::Utc::now(),
            version: 1,
            artifact_signers: vec![create_group(&test_keys, vec![0, 1], 2)],
            admin_keys: Some(vec![create_group(&test_keys, vec![2], 1)]),
            master_keys: Some(vec![create_group(&test_keys, vec![3], 1)]),
            revocation_keys: None,
        }
        .build()
        .unwrap();

        write_signers_config(temp_dir.path(), &config);
        let artifact_path = write_artifact_file(temp_dir.path());

        let metadata_path = common::fs::names::metadata_path_for(&artifact_path).unwrap();
        std::fs::write(
            &metadata_path,
            r#"{"origin":{"forge":"github","owner":"test","repo":"test"}}"#,
        )
        .unwrap();

        let authorized = get_authorized_signers_for_file(&metadata_path).expect("Should succeed");

        // Only artifact signers (keys 0 and 1) should be authorized,
        // same as for the artifact itself
        assert_eq!(authorized.len(), 2);
        assert!(authorized.contains(test_keys.pub_key(0).unwrap()));
        assert!(authorized.contains(test_keys.pub_key(1).unwrap()));
        assert!(!authorized.contains(test_keys.pub_key(2).unwrap()));
        assert!(!authorized.contains(test_keys.pub_key(3).unwrap()));
    }

    // ---------------------------------
    // Test get_missing_signers
    // ---------------------------------

    #[test]
    fn test_get_missing_signers_returns_empty_when_complete() {
        let temp_dir = TempDir::new().unwrap();
        let test_keys = TestKeys::new(2);

        let config = SignersConfigProposal {
            timestamp: chrono::Utc::now(),
            version: 1,
            artifact_signers: vec![create_group(&test_keys, vec![0, 1], 1)],
            admin_keys: None,
            master_keys: None,
            revocation_keys: None,
        }
        .build()
        .unwrap();
        write_signers_config(temp_dir.path(), &config);

        let artifact_path = write_artifact_file(temp_dir.path());

        // Write a complete signatures file (not pending)
        let complete_sig_path = signatures_path_for(&artifact_path).unwrap();
        let empty_sig_file = serde_json::to_string(&SignaturesFile::new()).unwrap();
        fs::write(&complete_sig_path, &empty_sig_file).unwrap();

        let missing = get_missing_signers(&artifact_path).expect("Should succeed");
        assert!(missing.is_empty());
    }

    #[test]
    fn test_get_missing_signers_artifact_no_signatures() {
        let temp_dir = TempDir::new().unwrap();
        let test_keys = TestKeys::new(3);

        let config = SignersConfigProposal {
            timestamp: chrono::Utc::now(),
            version: 1,
            artifact_signers: vec![create_group(&test_keys, vec![0, 1], 2)],
            admin_keys: Some(vec![create_group(&test_keys, vec![2], 1)]),
            master_keys: None,
            revocation_keys: None,
        }
        .build()
        .unwrap();
        write_signers_config(temp_dir.path(), &config);

        let artifact_path = write_artifact_file(temp_dir.path());

        let missing = get_missing_signers(&artifact_path).expect("Should succeed");

        // Only artifact signers (0, 1) are authorized, not admin (2)
        assert_eq!(missing.len(), 2);
        assert!(missing.contains(test_keys.pub_key(0).unwrap()));
        assert!(missing.contains(test_keys.pub_key(1).unwrap()));
        assert!(!missing.contains(test_keys.pub_key(2).unwrap()));
    }

    #[test]
    fn test_get_missing_signers_artifact_partial_signatures() {
        let temp_dir = TempDir::new().unwrap();
        let test_keys = TestKeys::new(3);

        let config = SignersConfigProposal {
            timestamp: chrono::Utc::now(),
            version: 1,
            artifact_signers: vec![create_group(&test_keys, vec![0, 1, 2], 2)],
            admin_keys: None,
            master_keys: None,
            revocation_keys: None,
        }
        .build()
        .unwrap();
        write_signers_config(temp_dir.path(), &config);

        let artifact_path = write_artifact_file(temp_dir.path());

        // Key 0 has signed
        write_pending_signatures(
            &artifact_path,
            &[(
                test_keys.pub_key(0).unwrap().clone(),
                test_keys.sec_key(0).unwrap().clone(),
            )],
        );

        let missing = get_missing_signers(&artifact_path).expect("Should succeed");

        // Key 0 signed, so only keys 1 and 2 are missing
        assert_eq!(missing.len(), 2);
        assert!(!missing.contains(test_keys.pub_key(0).unwrap()));
        assert!(missing.contains(test_keys.pub_key(1).unwrap()));
        assert!(missing.contains(test_keys.pub_key(2).unwrap()));
    }

    #[test]
    fn test_get_missing_signers_artifact_all_signed() {
        let temp_dir = TempDir::new().unwrap();
        let test_keys = TestKeys::new(2);

        let config = SignersConfigProposal {
            timestamp: chrono::Utc::now(),
            version: 1,
            artifact_signers: vec![create_group(&test_keys, vec![0, 1], 2)],
            admin_keys: None,
            master_keys: None,
            revocation_keys: None,
        }
        .build()
        .unwrap();
        write_signers_config(temp_dir.path(), &config);

        let artifact_path = write_artifact_file(temp_dir.path());

        // Both keys have signed
        write_pending_signatures(
            &artifact_path,
            &[
                (
                    test_keys.pub_key(0).unwrap().clone(),
                    test_keys.sec_key(0).unwrap().clone(),
                ),
                (
                    test_keys.pub_key(1).unwrap().clone(),
                    test_keys.sec_key(1).unwrap().clone(),
                ),
            ],
        );

        let missing = get_missing_signers(&artifact_path).expect("Should succeed");
        assert!(missing.is_empty());
    }

    #[test]
    fn test_get_missing_signers_signers_update_no_signatures() {
        let temp_dir = TempDir::new().unwrap();
        let test_keys = TestKeys::new(5);

        // Old config: admin (0), master (1), artifact (2)
        let old_config = SignersConfigProposal {
            timestamp: chrono::Utc::now(),
            version: 1,
            artifact_signers: vec![create_group(&test_keys, vec![2], 1)],
            admin_keys: Some(vec![create_group(&test_keys, vec![0], 1)]),
            master_keys: Some(vec![create_group(&test_keys, vec![1], 1)]),
            revocation_keys: None,
        }
        .build()
        .unwrap();
        write_signers_config(temp_dir.path(), &old_config);

        // New config: adds artifact (3), new admin (4)
        let new_config = SignersConfigProposal {
            timestamp: chrono::Utc::now() + chrono::Duration::seconds(1),
            version: 2,
            artifact_signers: vec![create_group(&test_keys, vec![2, 3], 2)],
            admin_keys: Some(vec![create_group(&test_keys, vec![4], 1)]),
            master_keys: Some(vec![create_group(&test_keys, vec![1], 1)]),
            revocation_keys: None,
        }
        .build()
        .unwrap();
        let pending_signers_file = write_pending_signers_config(temp_dir.path(), &new_config);

        let missing = get_missing_signers(&pending_signers_file).expect("Should succeed");

        // Authorized: old admin (0), old master (1), newly added artifact (3), new admin (4)
        assert_eq!(missing.len(), 4);
        assert!(missing.contains(test_keys.pub_key(0).unwrap()));
        assert!(missing.contains(test_keys.pub_key(1).unwrap()));
        assert!(missing.contains(test_keys.pub_key(3).unwrap()));
        assert!(missing.contains(test_keys.pub_key(4).unwrap()));
    }

    #[test]
    fn test_get_missing_signers_signers_update_partial() {
        let temp_dir = TempDir::new().unwrap();
        let test_keys = TestKeys::new(5);

        let old_config = SignersConfigProposal {
            timestamp: chrono::Utc::now(),
            version: 1,
            artifact_signers: vec![create_group(&test_keys, vec![2], 1)],
            admin_keys: Some(vec![create_group(&test_keys, vec![0], 1)]),
            master_keys: Some(vec![create_group(&test_keys, vec![1], 1)]),
            revocation_keys: None,
        }
        .build()
        .unwrap();
        write_signers_config(temp_dir.path(), &old_config);

        let new_config = SignersConfigProposal {
            timestamp: chrono::Utc::now() + chrono::Duration::seconds(1),
            version: 2,
            artifact_signers: vec![create_group(&test_keys, vec![2, 3], 2)],
            admin_keys: Some(vec![create_group(&test_keys, vec![4], 1)]),
            master_keys: Some(vec![create_group(&test_keys, vec![1], 1)]),
            revocation_keys: None,
        }
        .build()
        .unwrap();
        let pending_signers_file = write_pending_signers_config(temp_dir.path(), &new_config);

        // Keys 0 and 3 have signed
        write_pending_signatures(
            &pending_signers_file,
            &[
                (
                    test_keys.pub_key(0).unwrap().clone(),
                    test_keys.sec_key(0).unwrap().clone(),
                ),
                (
                    test_keys.pub_key(3).unwrap().clone(),
                    test_keys.sec_key(3).unwrap().clone(),
                ),
            ],
        );

        let missing = get_missing_signers(&pending_signers_file).expect("Should succeed");

        // Keys 1 and 4 still need to sign
        assert_eq!(missing.len(), 2);
        assert!(missing.contains(test_keys.pub_key(1).unwrap()));
        assert!(missing.contains(test_keys.pub_key(4).unwrap()));
    }

    #[test]
    fn test_get_missing_signers_signers_update_partial_but_ready_to_transition_to_complete() {
        let temp_dir = TempDir::new().unwrap();
        let test_keys = TestKeys::new(5);

        let old_config = SignersConfigProposal {
            timestamp: chrono::Utc::now(),
            version: 1,
            artifact_signers: vec![create_group(&test_keys, vec![2], 1)],
            admin_keys: Some(vec![create_group(&test_keys, vec![0], 1)]),
            master_keys: Some(vec![create_group(&test_keys, vec![1], 1)]),
            revocation_keys: None,
        }
        .build()
        .unwrap();
        write_signers_config(temp_dir.path(), &old_config);

        let new_config = SignersConfigProposal {
            timestamp: chrono::Utc::now() + chrono::Duration::seconds(1),
            version: 2,
            artifact_signers: vec![create_group(&test_keys, vec![2, 3], 2)],
            admin_keys: Some(vec![create_group(&test_keys, vec![4], 1)]),
            master_keys: Some(vec![create_group(&test_keys, vec![1], 1)]),
            revocation_keys: None,
        }
        .build()
        .unwrap();
        let pending_signers_file = write_pending_signers_config(temp_dir.path(), &new_config);

        // Keys 0,3 and 4 have signed, which makes it ready to transition to complete.
        write_pending_signatures(
            &pending_signers_file,
            &[
                (
                    test_keys.pub_key(0).unwrap().clone(),
                    test_keys.sec_key(0).unwrap().clone(),
                ),
                (
                    test_keys.pub_key(3).unwrap().clone(),
                    test_keys.sec_key(3).unwrap().clone(),
                ),
                (
                    test_keys.pub_key(4).unwrap().clone(),
                    test_keys.sec_key(4).unwrap().clone(),
                ),
            ],
        );

        let missing = get_missing_signers(&pending_signers_file).expect("Should succeed");
        assert!(missing.is_empty());
    }

    #[test]
    fn test_get_missing_signers_signers_update_all_signed() {
        let temp_dir = TempDir::new().unwrap();
        let test_keys = TestKeys::new(5);

        let old_config = SignersConfigProposal {
            timestamp: chrono::Utc::now(),
            version: 1,
            artifact_signers: vec![create_group(&test_keys, vec![2], 1)],
            admin_keys: Some(vec![create_group(&test_keys, vec![0], 1)]),
            master_keys: Some(vec![create_group(&test_keys, vec![1], 1)]),
            revocation_keys: None,
        }
        .build()
        .unwrap();
        write_signers_config(temp_dir.path(), &old_config);

        let new_config = SignersConfigProposal {
            timestamp: chrono::Utc::now() + chrono::Duration::seconds(1),
            version: 2,
            artifact_signers: vec![create_group(&test_keys, vec![2, 3], 2)],
            admin_keys: Some(vec![create_group(&test_keys, vec![4], 1)]),
            master_keys: Some(vec![create_group(&test_keys, vec![1], 1)]),
            revocation_keys: None,
        }
        .build()
        .unwrap();
        let pending_signers_file = write_pending_signers_config(temp_dir.path(), &new_config);

        // All authorized keys have signed
        write_pending_signatures(
            &pending_signers_file,
            &[
                (
                    test_keys.pub_key(0).unwrap().clone(),
                    test_keys.sec_key(0).unwrap().clone(),
                ),
                (
                    test_keys.pub_key(1).unwrap().clone(),
                    test_keys.sec_key(1).unwrap().clone(),
                ),
                (
                    test_keys.pub_key(3).unwrap().clone(),
                    test_keys.sec_key(3).unwrap().clone(),
                ),
                (
                    test_keys.pub_key(4).unwrap().clone(),
                    test_keys.sec_key(4).unwrap().clone(),
                ),
            ],
        );

        let missing = get_missing_signers(&pending_signers_file).expect("Should succeed");
        assert!(missing.is_empty());
    }

    #[test]
    fn test_get_missing_signers_initial_no_signatures() {
        let temp_dir = TempDir::new().unwrap();
        let test_keys = TestKeys::new(4);

        let config = SignersConfigProposal {
            timestamp: chrono::Utc::now(),
            version: 1,
            artifact_signers: vec![create_group(&test_keys, vec![0, 1], 2)],
            admin_keys: Some(vec![create_group(&test_keys, vec![2], 1)]),
            master_keys: Some(vec![create_group(&test_keys, vec![3], 1)]),
            revocation_keys: None,
        }
        .build()
        .unwrap();
        let pending_signers_file = write_pending_signers_config(temp_dir.path(), &config);

        let missing = get_missing_signers(&pending_signers_file).expect("Should succeed");

        // All signers should be missing
        assert_eq!(missing.len(), 4);
        assert!(missing.contains(test_keys.pub_key(0).unwrap()));
        assert!(missing.contains(test_keys.pub_key(1).unwrap()));
        assert!(missing.contains(test_keys.pub_key(2).unwrap()));
        assert!(missing.contains(test_keys.pub_key(3).unwrap()));
    }

    #[test]
    fn test_get_missing_signers_initial_one_signed() {
        let temp_dir = TempDir::new().unwrap();
        let test_keys = TestKeys::new(3);

        let config = SignersConfigProposal {
            timestamp: chrono::Utc::now(),
            version: 1,
            artifact_signers: vec![create_group(&test_keys, vec![0, 1], 2)],
            admin_keys: Some(vec![create_group(&test_keys, vec![2], 1)]),
            master_keys: None,
            revocation_keys: None,
        }
        .build()
        .unwrap();
        let pending_signers_file = write_pending_signers_config(temp_dir.path(), &config);

        // Key 0 has signed
        write_pending_signatures(
            &pending_signers_file,
            &[(
                test_keys.pub_key(0).unwrap().clone(),
                test_keys.sec_key(0).unwrap().clone(),
            )],
        );

        let missing = get_missing_signers(&pending_signers_file).expect("Should succeed");

        assert_eq!(missing.len(), 2);
        assert!(!missing.contains(test_keys.pub_key(0).unwrap()));
        assert!(missing.contains(test_keys.pub_key(1).unwrap()));
        assert!(missing.contains(test_keys.pub_key(2).unwrap()));
    }

    #[test]
    fn test_get_missing_signers_initial_all_signed() {
        let temp_dir = TempDir::new().unwrap();
        let test_keys = TestKeys::new(3);

        let config = SignersConfigProposal {
            timestamp: chrono::Utc::now(),
            version: 1,
            artifact_signers: vec![create_group(&test_keys, vec![0, 1], 2)],
            admin_keys: Some(vec![create_group(&test_keys, vec![2], 1)]),
            master_keys: None,
            revocation_keys: None,
        }
        .build()
        .unwrap();
        let pending_signers_file = write_pending_signers_config(temp_dir.path(), &config);

        // All keys have signed
        write_pending_signatures(
            &pending_signers_file,
            &[
                (
                    test_keys.pub_key(0).unwrap().clone(),
                    test_keys.sec_key(0).unwrap().clone(),
                ),
                (
                    test_keys.pub_key(1).unwrap().clone(),
                    test_keys.sec_key(1).unwrap().clone(),
                ),
                (
                    test_keys.pub_key(2).unwrap().clone(),
                    test_keys.sec_key(2).unwrap().clone(),
                ),
            ],
        );

        let missing = get_missing_signers(&pending_signers_file).expect("Should succeed");
        assert!(missing.is_empty());
    }

    #[test]
    fn test_get_missing_signers_inexisting_file() {
        let temp_dir = TempDir::new().unwrap();
        let inexisting_file = temp_dir.path().join("my_inexisting_file");
        let missing = get_missing_signers(&inexisting_file).expect("Should succeed");
        assert!(missing.is_empty());
    }
    #[test]
    fn test_check_signers_comprehensive() -> Result<()> {
        // Create test keys and data
        let test_keys = TestKeys::new(5);
        let data = common::sha512_for_content(b"test data".to_vec())?;

        // Get public and secret keys
        let pubkey0 = test_keys.pub_key(0).unwrap();
        let seckey0 = test_keys.sec_key(0).unwrap();
        let pubkey1 = test_keys.pub_key(1).unwrap();
        let seckey1 = test_keys.sec_key(1).unwrap();
        let pubkey2 = test_keys.pub_key(2).unwrap();
        let seckey2 = test_keys.sec_key(2).unwrap();
        let pubkey3 = test_keys.pub_key(3).unwrap();
        let seckey3 = test_keys.sec_key(3).unwrap();
        let pubkey4 = test_keys.pub_key(4).unwrap();
        let seckey4 = test_keys.sec_key(4).unwrap();

        // Create signatures
        let sig0 = seckey0.sign(&data).unwrap();
        let sig1 = seckey1.sign(&data).unwrap();
        let sig2 = seckey2.sign(&data).unwrap();
        let sig3 = seckey3.sign(&data).unwrap();
        let sig4 = seckey4.sign(&data).unwrap();

        // Create invalid signatures (signed for different data)
        let other_data = common::sha512_for_content(b"other data".to_vec())?;
        let invalid_sig0 = seckey0.sign(&other_data).unwrap();
        let invalid_sig1 = seckey1.sign(&other_data).unwrap();

        // Test 1: Empty signatures and empty signers
        let empty_signatures: HashMap<AsfaloadPublicKeys, AsfaloadSignatures> = HashMap::new();
        let empty_signers: Vec<AsfaloadPublicKeys> = Vec::new();
        assert!(check_signers(&empty_signatures, &empty_signers, &data));

        // Test 2: Empty signatures with non-empty signers
        let signers = vec![pubkey0.clone(), pubkey1.clone()];
        assert!(!check_signers(&empty_signatures, &signers, &data));

        // Test 3: Non-empty signatures with empty signers
        let mut signatures = HashMap::new();
        signatures.insert(pubkey0.clone(), sig0.clone());
        assert!(check_signers(&signatures, &empty_signers, &data));

        // Test 4: Matching signatures and signers (all valid)
        let mut signatures = HashMap::new();
        signatures.insert(pubkey0.clone(), sig0.clone());
        signatures.insert(pubkey1.clone(), sig1.clone());
        let signers = vec![pubkey0.clone(), pubkey1.clone()];
        assert!(check_signers(&signatures, &signers, &data));

        // Test 5: Missing signatures for some signers
        let mut signatures = HashMap::new();
        signatures.insert(pubkey0.clone(), sig0.clone());
        // Missing signature for pubkey1
        let signers = vec![pubkey0.clone(), pubkey1.clone()];
        assert!(!check_signers(&signatures, &signers, &data));

        // Test 6: Invalid signatures for some signers
        let mut signatures = HashMap::new();
        signatures.insert(pubkey0.clone(), sig0.clone());
        signatures.insert(pubkey1.clone(), invalid_sig1.clone()); // Invalid signature
        let signers = vec![pubkey0.clone(), pubkey1.clone()];
        assert!(!check_signers(&signatures, &signers, &data));

        // Test 7: Extra signatures not in the signers list
        let mut signatures = HashMap::new();
        signatures.insert(pubkey0.clone(), sig0.clone());
        signatures.insert(pubkey1.clone(), sig1.clone());
        signatures.insert(pubkey2.clone(), sig2.clone()); // Extra signature
        let signers = vec![pubkey0.clone(), pubkey1.clone()];
        assert!(check_signers(&signatures, &signers, &data));

        // Test 8: Duplicate signers in the list
        let mut signatures = HashMap::new();
        signatures.insert(pubkey0.clone(), sig0.clone());
        let signers = vec![pubkey0.clone(), pubkey0.clone()];
        assert!(check_signers(&signatures, &signers, &data));

        // Test 9: Large number of signers
        let mut signatures = HashMap::new();
        signatures.insert(pubkey0.clone(), sig0.clone());
        signatures.insert(pubkey1.clone(), sig1.clone());
        signatures.insert(pubkey2.clone(), sig2.clone());
        signatures.insert(pubkey3.clone(), sig3.clone());
        signatures.insert(pubkey4.clone(), sig4.clone());
        let signers = vec![
            pubkey0.clone(),
            pubkey1.clone(),
            pubkey2.clone(),
            pubkey3.clone(),
            pubkey4.clone(),
        ];
        assert!(check_signers(&signatures, &signers, &data));

        // Test 10: Mixed valid and invalid signatures
        let mut signatures = HashMap::new();
        signatures.insert(pubkey0.clone(), sig0.clone()); // Valid
        signatures.insert(pubkey1.clone(), invalid_sig1.clone()); // Invalid
        signatures.insert(pubkey2.clone(), sig2.clone()); // Valid
        signatures.insert(pubkey3.clone(), invalid_sig0.clone()); // Invalid
        let signers = vec![
            pubkey0.clone(),
            pubkey1.clone(),
            pubkey2.clone(),
            pubkey3.clone(),
        ];
        assert!(!check_signers(&signatures, &signers, &data));

        // Test 11: Signers with valid signatures but for wrong data
        let mut signatures = HashMap::new();
        signatures.insert(pubkey0.clone(), invalid_sig0.clone()); // Valid for wrong data
        signatures.insert(pubkey1.clone(), invalid_sig1.clone()); // Valid for wrong data
        let signers = vec![pubkey0.clone(), pubkey1.clone()];
        assert!(!check_signers(&signatures, &signers, &data));

        Ok(())
    }

    // can_revoke

    // Helper function used in revocation tests to generate signers configs
    // with 2 keys in groups to be present according to arguments passed.
    // This just returns the keys to be placed in the SignersConfig to be
    // built by the caller, so threshold can be set by the caller.
    #[allow(clippy::type_complexity)]
    fn signers_keys_for_revocation_tests(
        with_artifact: bool,
        with_admin: bool,
        with_master: bool,
        with_revocation: bool,
    ) -> (
        Vec<AsfaloadPublicKeys>,
        Vec<AsfaloadPublicKeys>,
        Vec<AsfaloadPublicKeys>,
        Vec<AsfaloadPublicKeys>,
    ) {
        let test_keys = TestKeys::new(8);
        let artifact_keys = if with_artifact {
            vec![
                test_keys.pub_key(0).unwrap().clone(),
                test_keys.pub_key(1).unwrap().clone(),
            ]
        } else {
            vec![]
        };
        let admin_keys = if with_admin {
            vec![
                test_keys.pub_key(2).unwrap().clone(),
                test_keys.pub_key(3).unwrap().clone(),
            ]
        } else {
            vec![]
        };
        let master_keys = if with_master {
            vec![
                test_keys.pub_key(4).unwrap().clone(),
                test_keys.pub_key(5).unwrap().clone(),
            ]
        } else {
            vec![]
        };

        let revocation_keys = if with_revocation {
            vec![
                test_keys.pub_key(6).unwrap().clone(),
                test_keys.pub_key(7).unwrap().clone(),
            ]
        } else {
            vec![]
        };
        (artifact_keys, admin_keys, master_keys, revocation_keys)
    }
    #[test]
    fn test_can_revoke_with_all_levels_present_in_config() -> Result<()> {
        let (artifact_keys, admin_keys, master_keys, revocation_keys) =
            signers_keys_for_revocation_tests(true, true, true, true);
        // Create a config with explicit revocation_keys set
        let config_with_all = SignersConfig::with_keys(
            1,
            (artifact_keys.clone(), 2),
            Some((admin_keys.clone(), 2)),
            Some((master_keys.clone(), 2)),
            Some((revocation_keys.clone(), 2)),
        )?;

        assert!(!can_revoke(
            artifact_keys.first().unwrap(),
            &config_with_all
        ));
        assert!(!can_revoke(admin_keys.first().unwrap(), &config_with_all));
        assert!(!can_revoke(admin_keys.get(1).unwrap(), &config_with_all));

        assert!(!can_revoke(master_keys.first().unwrap(), &config_with_all));
        assert!(!can_revoke(master_keys.get(1).unwrap(), &config_with_all));
        assert!(can_revoke(
            revocation_keys.first().unwrap(),
            &config_with_all
        ));
        assert!(can_revoke(
            revocation_keys.get(1).unwrap(),
            &config_with_all
        ));

        Ok(())
    }

    #[test]
    fn test_can_revoke_with_explicit_empty_admin_and_no_revocation_group() -> Result<()> {
        let (artifact_keys, admin_keys, master_keys, _revocation_keys) =
            signers_keys_for_revocation_tests(true, true, true, true);
        // Create a config with empty admin_keys list.
        // The SignersConfig will be built with None admin_keys.
        let config_with_all =
            SignersConfig::with_keys(1, (artifact_keys.clone(), 2), Some((vec![], 1)), None, None)?;

        assert!(can_revoke(artifact_keys.first().unwrap(), &config_with_all));
        assert!(!can_revoke(admin_keys.first().unwrap(), &config_with_all));
        assert!(!can_revoke(master_keys.first().unwrap(), &config_with_all));

        Ok(())
    }
    #[test]
    fn test_can_revoke_with_no_revocation_present_in_config() -> Result<()> {
        let (artifact_keys, admin_keys, master_keys, _revocation_keys) =
            signers_keys_for_revocation_tests(true, true, true, false);
        // Create a config with admin_keys
        let config_sans_revocation = SignersConfig::with_keys(
            1,
            (artifact_keys.clone(), 2),
            Some((admin_keys.clone(), 2)),
            None,
            None,
        )?;

        assert!(!can_revoke(
            artifact_keys.first().unwrap(),
            &config_sans_revocation
        ));
        assert!(can_revoke(
            admin_keys.first().unwrap(),
            &config_sans_revocation
        ));
        assert!(!can_revoke(
            master_keys.first().unwrap(),
            &config_sans_revocation
        ));

        Ok(())
    }

    #[test]
    fn test_can_revoke_with_only_artifact_present_in_config() -> Result<()> {
        let (artifact_keys, admin_keys, master_keys, _revocation_keys) =
            signers_keys_for_revocation_tests(true, true, true, false);
        // Create a config with admin_keys
        let config_sans_master =
            SignersConfig::with_keys(1, (artifact_keys.clone(), 2), None, None, None)?;

        assert!(can_revoke(
            artifact_keys.first().unwrap(),
            &config_sans_master
        ));
        assert!(!can_revoke(
            admin_keys.first().unwrap(),
            &config_sans_master
        ));
        assert!(!can_revoke(
            master_keys.first().unwrap(),
            &config_sans_master
        ));

        Ok(())
    }

    #[test]
    fn test_can_signer_add_signature_authorized() {
        let temp_dir = TempDir::new().unwrap();

        let test_keys = TestKeys::new(1);
        let public_key = test_keys.pub_key(0).unwrap().clone();

        let signers_config =
            SignersConfig::with_artifact_signers_only(1, (vec![public_key.clone()], 1)).unwrap();
        let signers_json = serde_json::to_string(&signers_config).unwrap();

        let artifact_dir = temp_dir.path().join("nested");
        fs::create_dir_all(&artifact_dir).unwrap();
        let artifact_path = artifact_dir.join("artifact.txt");
        fs::write(&artifact_path, "content").unwrap();

        let signers_dir = temp_dir.path().join(SIGNERS_DIR);
        fs::create_dir_all(&signers_dir).unwrap();
        fs::write(signers_dir.join(SIGNERS_FILE), signers_json).unwrap();

        let pending_sig_path = pending_signatures_path_for(&artifact_path).unwrap();
        let empty_sig_file = serde_json::to_string(&SignaturesFile::new()).unwrap();
        fs::write(&pending_sig_path, &empty_sig_file).unwrap();

        let result = can_signer_add_signature(&pending_sig_path, &public_key);
        assert!(result.is_ok());
        assert!(result.unwrap());
    }

    #[test]
    fn test_can_signer_add_signature_unauthorized() {
        let temp_dir = TempDir::new().unwrap();

        let test_keys = TestKeys::new(2);
        let public_key1 = test_keys.pub_key(0).unwrap().clone();
        let public_key2 = test_keys.pub_key(1).unwrap().clone();

        let signers_config =
            SignersConfig::with_artifact_signers_only(1, (vec![public_key1.clone()], 1)).unwrap();
        let signers_json = serde_json::to_string(&signers_config).unwrap();

        let artifact_dir = temp_dir.path().join("nested");
        fs::create_dir_all(&artifact_dir).unwrap();
        let artifact_path = artifact_dir.join("artifact.txt");
        fs::write(&artifact_path, "content").unwrap();

        let signers_dir = temp_dir.path().join(SIGNERS_DIR);
        fs::create_dir_all(&signers_dir).unwrap();
        fs::write(signers_dir.join(SIGNERS_FILE), signers_json).unwrap();

        let pending_sig_path = pending_signatures_path_for(&artifact_path).unwrap();
        let empty_sig_file = serde_json::to_string(&SignaturesFile::new()).unwrap();
        fs::write(&pending_sig_path, &empty_sig_file).unwrap();

        let result = can_signer_add_signature(&pending_sig_path, &public_key2);
        assert!(result.is_ok());
        assert!(!result.unwrap());
    }

    #[test]
    fn test_can_signer_add_signature_already_signed() {
        let temp_dir = TempDir::new().unwrap();

        let test_keys = TestKeys::new(1);
        let public_key = test_keys.pub_key(0).unwrap().clone();
        let secret_key = test_keys.sec_key(0).unwrap();

        let signers_config =
            SignersConfig::with_artifact_signers_only(1, (vec![public_key.clone()], 1)).unwrap();
        let signers_json = serde_json::to_string(&signers_config).unwrap();

        let artifact_dir = temp_dir.path().join("nested");
        fs::create_dir_all(&artifact_dir).unwrap();
        let artifact_path = artifact_dir.join("artifact.txt");
        fs::write(&artifact_path, "content").unwrap();

        let signers_dir = temp_dir.path().join(SIGNERS_DIR);
        fs::create_dir_all(&signers_dir).unwrap();
        fs::write(signers_dir.join(SIGNERS_FILE), signers_json).unwrap();

        let pending_sig_path = pending_signatures_path_for(&artifact_path).unwrap();
        let hash = sha512_for_file(&artifact_path).unwrap();
        let signature = secret_key.sign(&hash).unwrap();
        let mut sig_file = SignaturesFile::new();
        sig_file.entries.insert(
            public_key.to_base64(),
            TaggedSignature {
                format: public_key.key_format(),
                signature: signature.to_base64(),
            },
        );
        fs::write(&pending_sig_path, serde_json::to_string(&sig_file).unwrap()).unwrap();

        let result = can_signer_add_signature(pending_sig_path, &public_key);
        assert!(result.is_ok());
        assert!(!result.unwrap());
    }

    #[test]
    fn test_get_individual_signatures_file_not_found() -> Result<()> {
        let temp_dir = TempDir::new()?;
        let non_existent_path = temp_dir.path().join("non_existent.signatures.json");

        let result: Result<HashMap<AsfaloadPublicKeys, AsfaloadSignatures>, _> =
            get_individual_signatures_from_file(&non_existent_path);

        assert!(result.is_ok());
        let signatures = result.unwrap();
        assert!(signatures.is_empty());
        Ok(())
    }

    #[test]
    fn test_get_individual_signatures_valid_file() -> Result<()> {
        let temp_dir = TempDir::new()?;
        let sig_file_path = temp_dir.path().join("test.signatures.json");

        let test_keys = TestKeys::new(2);
        let pubkey1 = test_keys.pub_key(0).unwrap().clone();
        let seckey1 = test_keys.sec_key(0).unwrap();
        let pubkey2 = test_keys.pub_key(1).unwrap().clone();
        let seckey2 = test_keys.sec_key(1).unwrap();

        let data = common::sha512_for_content(b"test data".to_vec())?;
        let sig1 = seckey1.sign(&data)?;
        let sig2 = seckey2.sign(&data)?;

        let mut sig_file = SignaturesFile::new();
        sig_file.entries.insert(
            pubkey1.to_base64(),
            TaggedSignature {
                format: pubkey1.key_format(),
                signature: sig1.to_base64(),
            },
        );
        sig_file.entries.insert(
            pubkey2.to_base64(),
            TaggedSignature {
                format: pubkey2.key_format(),
                signature: sig2.to_base64(),
            },
        );

        let json_content = serde_json::to_string_pretty(&sig_file)?;
        fs::write(&sig_file_path, json_content)?;

        let result: Result<HashMap<AsfaloadPublicKeys, AsfaloadSignatures>, _> =
            get_individual_signatures_from_file(&sig_file_path);

        assert!(result.is_ok());
        let signatures = result.unwrap();
        assert_eq!(signatures.len(), 2);
        assert!(signatures.contains_key(&pubkey1));
        assert!(signatures.contains_key(&pubkey2));
        Ok(())
    }

    #[test]
    fn test_get_individual_signatures_invalid_json() -> Result<()> {
        let temp_dir = TempDir::new()?;
        let sig_file_path = temp_dir.path().join("test.signatures.json");

        fs::write(&sig_file_path, "invalid json content")?;

        let result: Result<HashMap<AsfaloadPublicKeys, AsfaloadSignatures>, _> =
            get_individual_signatures_from_file(&sig_file_path);

        assert!(result.is_err());
        Ok(())
    }

    #[test]
    fn test_get_individual_signatures_invalid_pubkey() -> Result<()> {
        let temp_dir = TempDir::new()?;
        let sig_file_path = temp_dir.path().join("test.signatures.json");

        let test_keys = TestKeys::new(1);
        let pubkey = test_keys.pub_key(0).unwrap().clone();
        let seckey = test_keys.sec_key(0).unwrap();

        let data = common::sha512_for_content(b"test data".to_vec())?;
        let sig = seckey.sign(&data)?;

        let mut sig_file = SignaturesFile::new();
        sig_file.entries.insert(
            "invalid_base64_pubkey".to_string(),
            TaggedSignature {
                format: pubkey.key_format(),
                signature: sig.to_base64(),
            },
        );

        let json_content = serde_json::to_string_pretty(&sig_file)?;
        fs::write(&sig_file_path, json_content)?;

        let result: Result<HashMap<AsfaloadPublicKeys, AsfaloadSignatures>, _> =
            get_individual_signatures_from_file(&sig_file_path);

        assert!(result.is_err());
        match result.unwrap_err() {
            AggregateSignatureError::PublicKey(_) => {}
            _ => panic!("Expected PublicKey error"),
        }
        Ok(())
    }

    #[test]
    fn test_get_individual_signatures_invalid_signature() -> Result<()> {
        let temp_dir = TempDir::new()?;
        let sig_file_path = temp_dir.path().join("test.signatures.json");

        let test_keys = TestKeys::new(1);
        let pubkey = test_keys.pub_key(0).unwrap().clone();

        let mut sig_file = SignaturesFile::new();
        sig_file.entries.insert(
            pubkey.to_base64(),
            TaggedSignature {
                format: pubkey.key_format(),
                signature: "invalid_base64_signature".to_string(),
            },
        );

        let json_content = serde_json::to_string_pretty(&sig_file)?;
        fs::write(&sig_file_path, json_content)?;

        let result: Result<HashMap<AsfaloadPublicKeys, AsfaloadSignatures>, _> =
            get_individual_signatures_from_file(&sig_file_path);

        assert!(result.is_err());
        match result.unwrap_err() {
            AggregateSignatureError::Signature(_) => {}
            _ => panic!("Expected Signature error"),
        }
        Ok(())
    }

    #[test]
    fn test_get_individual_signatures_empty_file() -> Result<()> {
        let temp_dir = TempDir::new()?;
        let sig_file_path = temp_dir.path().join("test.signatures.json");

        let empty_sig_file = SignaturesFile::new();
        let json_content = serde_json::to_string_pretty(&empty_sig_file)?;
        fs::write(&sig_file_path, json_content)?;

        let result: Result<HashMap<AsfaloadPublicKeys, AsfaloadSignatures>, _> =
            get_individual_signatures_from_file(&sig_file_path);

        assert!(result.is_ok());
        let signatures = result.unwrap();
        assert!(signatures.is_empty());
        Ok(())
    }

    #[test]
    fn test_parse_tagged_signatures_valid() -> Result<()> {
        let test_keys = TestKeys::new(2);
        let pubkey1 = test_keys.pub_key(0).unwrap().clone();
        let seckey1 = test_keys.sec_key(0).unwrap();
        let pubkey2 = test_keys.pub_key(1).unwrap().clone();
        let seckey2 = test_keys.sec_key(1).unwrap();

        let data = common::sha512_for_content(b"test data".to_vec())?;
        let sig1 = seckey1.sign(&data)?;
        let sig2 = seckey2.sign(&data)?;

        let mut entries = HashMap::new();
        entries.insert(
            pubkey1.to_base64(),
            TaggedSignature {
                format: pubkey1.key_format(),
                signature: sig1.to_base64(),
            },
        );
        entries.insert(
            pubkey2.to_base64(),
            TaggedSignature {
                format: pubkey2.key_format(),
                signature: sig2.to_base64(),
            },
        );

        let result: Result<HashMap<AsfaloadPublicKeys, AsfaloadSignatures>, _> =
            parse_tagged_signatures(&entries);

        assert!(result.is_ok());
        let signatures = result.unwrap();
        assert_eq!(signatures.len(), 2);
        assert!(signatures.contains_key(&pubkey1));
        assert!(signatures.contains_key(&pubkey2));
        Ok(())
    }

    #[test]
    fn test_parse_tagged_signatures_empty() -> Result<()> {
        let entries = HashMap::new();

        let result: Result<HashMap<AsfaloadPublicKeys, AsfaloadSignatures>, _> =
            parse_tagged_signatures(&entries);

        assert!(result.is_ok());
        let signatures = result.unwrap();
        assert!(signatures.is_empty());
        Ok(())
    }

    #[test]
    fn test_parse_tagged_signatures_invalid_pubkey() -> Result<()> {
        let test_keys = TestKeys::new(1);
        let pubkey = test_keys.pub_key(0).unwrap().clone();
        let seckey = test_keys.sec_key(0).unwrap();

        let data = common::sha512_for_content(b"test data".to_vec())?;
        let sig = seckey.sign(&data)?;

        let mut entries = HashMap::new();
        entries.insert(
            "invalid_base64_pubkey!!!".to_string(),
            TaggedSignature {
                format: pubkey.key_format(),
                signature: sig.to_base64(),
            },
        );

        let result: Result<HashMap<AsfaloadPublicKeys, AsfaloadSignatures>, _> =
            parse_tagged_signatures(&entries);

        assert!(result.is_err());
        match result.unwrap_err() {
            AggregateSignatureError::PublicKey(_) => {}
            _ => panic!("Expected PublicKey error"),
        }
        Ok(())
    }

    #[test]
    fn test_parse_tagged_signatures_invalid_signature() -> Result<()> {
        let test_keys = TestKeys::new(1);
        let pubkey = test_keys.pub_key(0).unwrap().clone();

        let mut entries = HashMap::new();
        entries.insert(
            pubkey.to_base64(),
            TaggedSignature {
                format: pubkey.key_format(),
                signature: "invalid_base64_signature!!!".to_string(),
            },
        );

        let result: Result<HashMap<AsfaloadPublicKeys, AsfaloadSignatures>, _> =
            parse_tagged_signatures(&entries);

        assert!(result.is_err());
        match result.unwrap_err() {
            AggregateSignatureError::Signature(_) => {}
            _ => panic!("Expected Signature error"),
        }
        Ok(())
    }

    #[test]
    fn test_parse_tagged_signatures_first_entry_invalid() -> Result<()> {
        let test_keys = TestKeys::new(2);
        let pubkey2 = test_keys.pub_key(1).unwrap().clone();
        let seckey2 = test_keys.sec_key(1).unwrap();

        let data = common::sha512_for_content(b"test data".to_vec())?;
        let sig2 = seckey2.sign(&data)?;

        let mut entries = HashMap::new();
        entries.insert(
            "invalid_base64_pubkey".to_string(),
            TaggedSignature {
                format: pubkey2.key_format(),
                signature: "any_signature".to_string(),
            },
        );
        entries.insert(
            pubkey2.to_base64(),
            TaggedSignature {
                format: pubkey2.key_format(),
                signature: sig2.to_base64(),
            },
        );

        let result: Result<HashMap<AsfaloadPublicKeys, AsfaloadSignatures>, _> =
            parse_tagged_signatures(&entries);

        assert!(result.is_err());
        match result.unwrap_err() {
            AggregateSignatureError::PublicKey(_) => {}
            _ => panic!("Expected PublicKey error"),
        }
        Ok(())
    }

    #[test]
    fn test_parse_tagged_signatures_single_entry() -> Result<()> {
        let test_keys = TestKeys::new(1);
        let pubkey = test_keys.pub_key(0).unwrap().clone();
        let seckey = test_keys.sec_key(0).unwrap();

        let data = common::sha512_for_content(b"test data".to_vec())?;
        let sig = seckey.sign(&data)?;

        let mut entries = HashMap::new();
        entries.insert(
            pubkey.to_base64(),
            TaggedSignature {
                format: pubkey.key_format(),
                signature: sig.to_base64(),
            },
        );

        let result: Result<HashMap<AsfaloadPublicKeys, AsfaloadSignatures>, _> =
            parse_tagged_signatures(&entries);

        assert!(result.is_ok());
        let signatures = result.unwrap();
        assert_eq!(signatures.len(), 1);
        assert!(signatures.contains_key(&pubkey));
        Ok(())
    }

    #[test]
    fn test_get_individual_signatures_from_bytes_valid() -> Result<()> {
        let test_keys = TestKeys::new(2);
        let pubkey1 = test_keys.pub_key(0).unwrap().clone();
        let seckey1 = test_keys.sec_key(0).unwrap();
        let pubkey2 = test_keys.pub_key(1).unwrap().clone();
        let seckey2 = test_keys.sec_key(1).unwrap();

        let data = common::sha512_for_content(b"test data".to_vec())?;
        let sig1 = seckey1.sign(&data)?;
        let sig2 = seckey2.sign(&data)?;

        let mut sig_file = SignaturesFile::new();
        sig_file.entries.insert(
            pubkey1.to_base64(),
            TaggedSignature {
                format: pubkey1.key_format(),
                signature: sig1.to_base64(),
            },
        );
        sig_file.entries.insert(
            pubkey2.to_base64(),
            TaggedSignature {
                format: pubkey2.key_format(),
                signature: sig2.to_base64(),
            },
        );

        let json_bytes = serde_json::to_vec(&sig_file)?;

        let result: Result<HashMap<AsfaloadPublicKeys, AsfaloadSignatures>, _> =
            get_individual_signatures_from_bytes(json_bytes);

        assert!(result.is_ok());
        let signatures = result.unwrap();
        assert_eq!(signatures.len(), 2);
        assert!(signatures.contains_key(&pubkey1));
        assert!(signatures.contains_key(&pubkey2));
        Ok(())
    }

    #[test]
    fn test_get_individual_signatures_from_bytes_invalid_json() {
        let invalid_json = b"invalid json content".to_vec();

        let result: Result<HashMap<AsfaloadPublicKeys, AsfaloadSignatures>, _> =
            get_individual_signatures_from_bytes(invalid_json);

        match result {
            Ok(_) => panic!("Expected JsonError but got Ok value!"),
            Err(AggregateSignatureError::JsonError(_)) => {}
            Err(e) => panic!("Expected JsonError but got {}", e),
        }
    }

    #[test]
    fn test_get_individual_signatures_from_bytes_empty() {
        let empty = b"".to_vec();

        let result: Result<HashMap<AsfaloadPublicKeys, AsfaloadSignatures>, _> =
            get_individual_signatures_from_bytes(empty);

        match result {
            Ok(v) => assert_eq!(v.len(), 0),
            Err(e) => panic!("Expected Ok value but got error {}", e),
        }
    }

    #[test]
    fn test_get_authorized_signers_for_revoked_artifact_returns_error() -> Result<()> {
        let temp_dir = TempDir::new()?;
        let test_keys = TestKeys::new(1);
        let pubkey = test_keys.pub_key(0).unwrap().clone();

        let signers_dir = temp_dir.path().join(SIGNERS_DIR);
        fs::create_dir_all(&signers_dir)?;
        let signers_file = signers_dir.join(SIGNERS_FILE);

        let signers_config =
            SignersConfig::with_artifact_signers_only(1, (vec![pubkey.clone()], 1))?;
        fs::write(&signers_file, serde_json::to_string(&signers_config)?)?;

        let subdir = temp_dir.path().join("releases");
        fs::create_dir_all(&subdir)?;
        let artifact_path = subdir.join("artifact.bin");
        fs::write(&artifact_path, "artifact content")?;

        let revocation_path = common::fs::names::revocation_path_for(&artifact_path)?;
        fs::write(&revocation_path, r#"{"revoked": true}"#)?;

        let result = get_authorized_signers_for_file(&artifact_path);

        match result {
            Err(AggregateSignatureError::FileRevoked) => {}
            other => panic!(
                "Expected AggregateSignatureError::FileRevoked, got: {:?}",
                other
            ),
        }

        Ok(())
    }

    #[test]
    fn test_is_aggregate_signature_complete_metadata_for_initial_signers() -> Result<()> {
        let temp_dir = tempfile::TempDir::new()?;
        let pending_dir = temp_dir.path().join(PENDING_SIGNERS_DIR);
        std::fs::create_dir_all(&pending_dir)?;

        let test_keys = TestKeys::new(2);

        // threshold=1 but 2 signers. InitialSigners requires ALL signers.
        // Using threshold=1 detects if code erroneously uses threshold.
        let config = SignersConfig::with_artifact_signers_only(
            1,
            (
                vec![
                    test_keys.pub_key(0).unwrap().clone(),
                    test_keys.pub_key(1).unwrap().clone(),
                ],
                1,
            ),
        )?;
        let json = config.to_json()?;

        let signers_path = pending_dir.join(SIGNERS_FILE);
        std::fs::write(&signers_path, &json)?;

        let metadata_path = common::fs::names::metadata_path_for(&signers_path)?;
        std::fs::write(
            &metadata_path,
            r#"{"origin":{"forge":"github","owner":"test","repo":"test"}}"#,
        )?;

        let metadata_hash = common::sha512_for_file(&metadata_path)?;
        let sig0 = test_keys.sec_key(0).unwrap().sign(&metadata_hash)?;
        add_to_aggregate_for_file(&sig0, &metadata_path, test_keys.pub_key(0).unwrap())?;

        // Should NOT be complete (requires ALL signers, not just threshold)
        assert!(!is_aggregate_signature_complete(&metadata_path, true)?);

        let sig1 = test_keys.sec_key(1).unwrap().sign(&metadata_hash)?;
        add_to_aggregate_for_file(&sig1, &metadata_path, test_keys.pub_key(1).unwrap())?;

        // Now should be complete
        assert!(is_aggregate_signature_complete(&metadata_path, true)?);

        Ok(())
    }

    // test get_missing_signers with metadata for initial signers
    // -----------------------------------------------------------
    #[test]
    fn test_get_missing_signers_metadata_initial_signers() -> Result<()> {
        let temp_dir = tempfile::TempDir::new()?;
        let pending_dir = temp_dir.path().join(PENDING_SIGNERS_DIR);
        std::fs::create_dir_all(&pending_dir)?;

        let test_keys = TestKeys::new(2);

        let config = SignersConfig::with_artifact_signers_only(
            1,
            (
                vec![
                    test_keys.pub_key(0).unwrap().clone(),
                    test_keys.pub_key(1).unwrap().clone(),
                ],
                2,
            ),
        )?;
        let json = config.to_json()?;

        let signers_path = pending_dir.join(SIGNERS_FILE);
        std::fs::write(&signers_path, &json)?;

        let metadata_path = common::fs::names::metadata_path_for(&signers_path)?;
        std::fs::write(
            &metadata_path,
            r#"{"origin":{"forge":"github","owner":"test","repo":"test"}}"#,
        )?;

        // Before any signatures, both signers should be missing
        let missing = get_missing_signers(&metadata_path)?;
        assert_eq!(missing.len(), 2);

        // Sign with key 0
        let metadata_hash = common::sha512_for_file(&metadata_path)?;
        let sig0 = test_keys.sec_key(0).unwrap().sign(&metadata_hash)?;
        add_to_aggregate_for_file(&sig0, &metadata_path, test_keys.pub_key(0).unwrap())?;

        // Now only key 1 should be missing
        let missing = get_missing_signers(&metadata_path)?;
        assert_eq!(missing.len(), 1);
        assert!(missing.contains(test_keys.pub_key(1).unwrap()));

        Ok(())
    }

    // test metadata-of-metadata rejection
    // ------------------------------------
    #[test]
    fn test_is_aggregate_signature_complete_rejects_metadata_of_metadata() -> Result<()> {
        let temp_dir = tempfile::TempDir::new()?;
        let pending_dir = temp_dir.path().join(PENDING_SIGNERS_DIR);
        std::fs::create_dir_all(&pending_dir)?;

        let test_keys = TestKeys::new(1);

        let config = SignersConfig::with_artifact_signers_only(
            1,
            (vec![test_keys.pub_key(0).unwrap().clone()], 1),
        )?;
        let json = config.to_json()?;

        let signers_path = pending_dir.join(SIGNERS_FILE);
        std::fs::write(&signers_path, &json)?;

        let metadata_path = common::fs::names::metadata_path_for(&signers_path)?;
        std::fs::write(
            &metadata_path,
            r#"{"origin":{"forge":"github","owner":"test","repo":"test"}}"#,
        )?;

        let meta_meta_path = common::fs::names::metadata_path_for(&metadata_path)?;
        std::fs::write(&meta_meta_path, "nested")?;

        let result = is_aggregate_signature_complete(&meta_meta_path, true);
        assert!(result.is_err());

        Ok(())
    }

    #[test]
    fn test_get_authorized_signers_rejects_metadata_of_metadata() -> Result<()> {
        let temp_dir = tempfile::TempDir::new()?;
        let pending_dir = temp_dir.path().join(PENDING_SIGNERS_DIR);
        std::fs::create_dir_all(&pending_dir)?;

        let test_keys = TestKeys::new(1);

        let config = SignersConfig::with_artifact_signers_only(
            1,
            (vec![test_keys.pub_key(0).unwrap().clone()], 1),
        )?;
        let json = config.to_json()?;

        let signers_path = pending_dir.join(SIGNERS_FILE);
        std::fs::write(&signers_path, &json)?;

        let metadata_path = common::fs::names::metadata_path_for(&signers_path)?;
        std::fs::write(
            &metadata_path,
            r#"{"origin":{"forge":"github","owner":"test","repo":"test"}}"#,
        )?;

        let meta_meta_path = common::fs::names::metadata_path_for(&metadata_path)?;
        std::fs::write(&meta_meta_path, "nested")?;

        let result = get_authorized_signers_for_file(&meta_meta_path);
        assert!(result.is_err());

        Ok(())
    }

    // Helper function to create a file to sign
    pub fn create_file_to_sign(
        dir: std::path::PathBuf,
    ) -> Result<std::path::PathBuf, std::io::Error> {
        let to_signed_file_name = "my_signed_file";
        let to_signed_file_path = dir.as_path().join(to_signed_file_name);
        std::fs::write(&to_signed_file_path, "data").map(|_| to_signed_file_path)
    }

    #[test]
    fn test_add_to_aggregate() -> Result<()> {
        // Create a temporary directory
        let temp_dir = tempfile::tempdir()?;
        let dir_path = temp_dir.path();
        let signed_file_path = create_file_to_sign(dir_path.to_path_buf())?;
        std::fs::write(&signed_file_path, "test data")?;

        // Load keypairs from fixtures
        let (pubkey, seckey, pubkey2, seckey2) = get_two_key_pairs()?;

        let data = common::sha512_for_content(b"test data".to_vec())?;
        let wrong_data = common::sha512_for_content(b"wrong data".to_vec())?;
        let signature = seckey.sign(&data)?;
        let signature2 = seckey2.sign(&data)?;
        let wrong_signature = seckey.sign(&wrong_data)?;

        // Signing a directory causes an error
        let result = add_to_aggregate_for_file(&signature, dir_path, &pubkey);
        assert!(result.is_err());
        match result.as_ref().unwrap_err() {
            SignatureError::IoError(io_err) => {
                let err: &std::io::Error = io_err; // Explicit type annotation
                if err.kind() != std::io::ErrorKind::IsADirectory {
                    panic!(
                        "Expected IoError with IsADirectory kind, got something else: {:?}",
                        err
                    )
                }
            }
            _ => panic!(
                "Expected SignatureError, got something else: {:?}",
                result.unwrap_err()
            ),
        }

        // Attempting to add the signature of another data than the signed file's hash to the aggregate should fail.
        let result = add_to_aggregate_for_file(&wrong_signature, &signed_file_path, &pubkey);
        match result {
            Err(SignatureError::InvalidSignatureForAggregate(_)) => {
                // Expected
            }
            Ok(_) => panic!("Expected an error, but got Ok"),
            _ => panic!(
                "Expected InvalidsignatureForAggregate, got something else: {:?}",
                result.unwrap_err()
            ),
        }

        // Add the signature to the aggregate
        add_to_aggregate_for_file(&signature, &signed_file_path, &pubkey)?;

        // Verify that the signature file was created
        let sig_file_path = signed_file_path.with_file_name(format!(
            "{}.{}",
            signed_file_path.to_string_lossy(),
            PENDING_SIGNATURES_SUFFIX
        ));
        assert!(
            sig_file_path.exists(),
            "Pending signature file should exist"
        );

        // Verify the content of the signatures file
        let sig_file_content = std::fs::read_to_string(&sig_file_path)?;
        let sig_file: SignaturesFile = serde_json::from_str(&sig_file_content)?;
        let pubkey_b64 = pubkey.to_base64();
        let pubkey2_b64 = pubkey2.to_base64();
        assert!(
            sig_file.entries.contains_key(&pubkey_b64),
            "Signatures file should contain an entry for the public key"
        );
        assert!(
            !sig_file.entries.contains_key(&pubkey2_b64),
            "Signatures file should NOT contain an entry for the second public key"
        );
        assert_eq!(
            sig_file.entries.get(&pubkey_b64).unwrap().signature,
            signature.to_base64(),
            "Signatures file should contain the correct signature"
        );

        // Add second signature to aggregate
        add_to_aggregate_for_file(&signature2, signed_file_path, &pubkey2)?;

        // Re-read the signatures file as it should have been modified
        let sig_file_content = std::fs::read_to_string(&sig_file_path)?;
        let sig_file: SignaturesFile = serde_json::from_str(&sig_file_content)?;
        // First signature is still there
        assert!(
            sig_file.entries.contains_key(&pubkey_b64),
            "Signatures file should contain an entry for the public key"
        );
        assert_eq!(
            sig_file.entries.get(&pubkey_b64).unwrap().signature,
            signature.to_base64(),
            "Signatures file should contain the correct signature"
        );
        // Second signature is added
        assert!(
            sig_file.entries.contains_key(&pubkey2_b64),
            "Signatures file should contain an entry for the second public key"
        );
        assert_eq!(
            sig_file.entries.get(&pubkey2_b64).unwrap().signature,
            signature2.to_base64(),
            "Signatures file should contain the correct second signature"
        );
        Ok(())
    }

    #[test]
    fn test_add_to_aggregate_duplicate_signature() -> Result<()> {
        // Create a temporary directory
        let temp_dir = tempfile::tempdir()?;
        let dir_path = temp_dir.path();
        let signed_file_path = create_file_to_sign(dir_path.to_path_buf())?;
        std::fs::write(&signed_file_path, "test data")?;

        // Load keypair from fixtures
        let (pubkey, seckey) = get_key_pair()?;

        let data = common::sha512_for_content(b"test data".to_vec())?;
        let signature = seckey.sign(&data)?;

        // First signature should succeed
        add_to_aggregate_for_file(&signature, &signed_file_path, &pubkey)?;

        // Attempting to sign again with the same key should fail with DuplicateSignature
        let result = add_to_aggregate_for_file(&signature, &signed_file_path, &pubkey);
        match result {
            Err(SignatureError::DuplicateSignature) => {}
            Ok(_) => panic!("Expected DuplicateSignature error, but got Ok"),
            Err(e) => panic!("Expected DuplicateSignature error, got: {:?}", e),
        }

        Ok(())
    }

    #[test]
    fn test_signature_trait_error_mapping() -> Result<()> {
        // Check underlying IO errors are mapped correctly to our IO error.
        let r = AsfaloadSignatures::from_file("/tmp/inexisting_path");
        assert!(matches!(r, Err(SignatureError::IoError(_))));

        let r = AsfaloadSignatures::from_base64("invalid");
        assert!(matches!(r, Err(SignatureError::Base64DecodeFailed(_))));

        let r = AsfaloadSignatures::from_string("invalid");
        assert!(r.is_err());
        Ok(())
    }

    #[test]
    fn test_public_key_from_secret_key() -> Result<()> {
        let (pubkey, seckey) = get_key_pair()?;

        let derived_pubkey = AsfaloadPublicKeys::from_secret_key(&seckey)?;
        assert_eq!(derived_pubkey.to_base64(), pubkey.to_base64());
        Ok(())
    }

    #[test]
    fn test_public_key_serde_round_trip() -> Result<()> {
        let (pubkey, _) = get_key_pair()?;

        // Serialize to JSON (should produce a base64 string)
        let json = serde_json::to_string(&pubkey)?;
        // The JSON value should be a quoted string matching to_base64()
        let expected_json = format!("\"{}\"", pubkey.to_base64());
        assert_eq!(json, expected_json);

        // Deserialize back from JSON
        let deserialized: AsfaloadPublicKeys = serde_json::from_str(&json)?;
        assert_eq!(deserialized.to_base64(), pubkey.to_base64());
        assert_eq!(deserialized, pubkey);

        // Deserializing invalid base64 should produce an error
        let bad_json = "\"not-a-valid-key\"";
        let result: std::result::Result<AsfaloadPublicKeys, _> = serde_json::from_str(bad_json);
        assert!(result.is_err());

        Ok(())
    }

    #[test]
    fn test_add_to_aggregate_rejects_revoked_file() -> Result<()> {
        // Create a temporary directory and a file to sign
        let temp_dir = tempfile::tempdir()?;
        let signed_file_path = create_file_to_sign(temp_dir.path().to_path_buf())?;

        // Load a key pair and create a valid signature
        let (pubkey, seckey) = get_key_pair()?;
        let data = common::sha512_for_file(&signed_file_path)?;
        let signature = seckey.sign(&data)?;

        // Create a completed revocation file (filename.revocation.json)
        let revocation_path = common::fs::names::revocation_path_for(&signed_file_path)?;
        fs::write(&revocation_path, r#"{"revoked": true}"#)?;

        // Attempting to add a signature should fail with FileRevoked
        let result = add_to_aggregate_for_file(&signature, &signed_file_path, &pubkey);
        assert!(result.is_err());
        match result.unwrap_err() {
            SignatureError::FileRevoked(path) => {
                assert_eq!(path, signed_file_path);
            }
            other => panic!("Expected FileRevoked error, got: {:?}", other),
        }

        Ok(())
    }

    #[test]
    fn test_add_to_aggregate_allows_pending_revocation() -> Result<()> {
        // Create a temporary directory and a file to sign
        let temp_dir = tempfile::tempdir()?;
        let signed_file_path = create_file_to_sign(temp_dir.path().to_path_buf())?;

        // Load a key pair and create a valid signature
        let (pubkey, seckey) = get_key_pair()?;
        let data = common::sha512_for_file(&signed_file_path)?;
        let signature = seckey.sign(&data)?;

        // Create a PENDING revocation file (should NOT block)
        let revocation_path = common::fs::names::revocation_path_for(&signed_file_path)?;
        let pending_revocation_path = PathBuf::from(format!(
            "{}.{}",
            revocation_path.to_string_lossy(),
            constants::PENDING_SUFFIX
        ));
        fs::write(&pending_revocation_path, r#"{"revoked": true}"#)?;

        // Attempting to add a signature should succeed
        let result = add_to_aggregate_for_file(&signature, &signed_file_path, &pubkey);
        assert!(
            result.is_ok(),
            "Pending revocation should not block signature addition, but got: {:?}",
            result.unwrap_err()
        );

        Ok(())
    }

    #[test]
    fn test_add_to_aggregate_works_without_revocation_file() -> Result<()> {
        // Create a temporary directory and a file to sign
        let temp_dir = tempfile::tempdir()?;
        let signed_file_path = create_file_to_sign(temp_dir.path().to_path_buf())?;

        // Load a key pair and create a valid signature
        let (pubkey, seckey) = get_key_pair()?;
        let data = common::sha512_for_file(&signed_file_path)?;
        let signature = seckey.sign(&data)?;

        // No revocation file exists — signature should succeed
        let revocation_path = common::fs::names::revocation_path_for(&signed_file_path)?;
        assert!(
            !revocation_path.exists(),
            "Revocation file should not exist in this test"
        );

        let result = add_to_aggregate_for_file(&signature, &signed_file_path, &pubkey);
        assert!(
            result.is_ok(),
            "Signature should succeed when no revocation file exists, but got: {:?}",
            result.unwrap_err()
        );

        Ok(())
    }

    //------------------------------------------------------------
    // Asfaload tests
    //------------------------------------------------------------

    #[test]
    fn test_asfaload_new_with_format() -> Result<()> {
        let kp = AsfaloadKeyPairs::new_with_format_and_argon2_params(
            "mypass",
            &KeyFormat::Asfaload,
            Argon2Params::TEST,
        )?;
        let temp_dir = tempfile::tempdir()?;
        kp.save(temp_dir.path())?;
        assert!(temp_dir.path().join("key").exists());
        assert!(temp_dir.path().join("key.pub").exists());

        let sk = AsfaloadSecretKeys::from_file(temp_dir.path().join("key"), "mypass")?;
        let pk = AsfaloadPublicKeys::from_file(temp_dir.path().join("key.pub"))?;
        assert_eq!(pk.key_format(), KeyFormat::Asfaload);

        let data = common::sha512_for_content(b"asfaload test".to_vec())?;
        let sig = sk.sign(&data)?;
        pk.verify(&sig, &data)?;

        Ok(())
    }

    #[test]
    fn test_asfaload_openssh_new_returns_error() {
        let result = AsfaloadKeyPairs::new_with_format("pw", &KeyFormat::OpenSsh);
        assert!(result.is_err(), "generating OpenSSH keys should fail");
        match result.unwrap_err() {
            KeyError::ImportOnlyFormat(msg) => {
                assert!(
                    msg.contains("OpenSSH") || msg.contains("SSH") || msg.contains("read-only"),
                    "error should mention OpenSSH / read-only: {msg}"
                );
            }
            other => panic!("expected ImportOnlyFormat, got {other:?}"),
        }
    }

    #[test]
    fn test_asfaload_fixture_sign_and_verify() -> Result<()> {
        let (_dir, pk, sk) = get_asfaload_key_pair()?;
        assert_eq!(pk.key_format(), KeyFormat::Asfaload);

        let data = common::sha512_for_content(b"asfaload fixture test".to_vec())?;
        let sig = sk.sign(&data)?;
        pk.verify(&sig, &data)?;
        Ok(())
    }

    #[test]
    fn test_asfaload_base64_round_trip() -> Result<()> {
        let (_dir, pk, _) = get_asfaload_key_pair()?;
        let b64 = pk.to_base64();
        assert!(b64.starts_with("asfaload-pub:"));
        let pk2 = AsfaloadPublicKeys::from_base64(&b64)?;
        assert_eq!(pk, pk2);
        Ok(())
    }

    #[test]
    fn test_asfaload_signature_serialisation() -> Result<()> {
        let (_dir, pk, sk) = get_asfaload_key_pair()?;
        let data = common::sha512_for_content(b"serialise me asfaload".to_vec())?;
        let sig = sk.sign(&data)?;

        // Base64 round-trip
        let b64 = sig.to_base64();
        let sig2 = AsfaloadSignatures::from_base64(&b64)?;
        pk.verify(&sig2, &data)?;

        // File round-trip
        let temp_dir = TempDir::new()?;
        let sig_path = temp_dir.path().join("asfaload_sig");
        sig.to_file(&sig_path)?;
        let sig3 = AsfaloadSignatures::from_file(&sig_path)?;
        pk.verify(&sig3, &data)?;

        Ok(())
    }

    #[test]
    fn test_asfaload_public_key_from_secret_key() -> Result<()> {
        let (_dir, pk, sk) = get_asfaload_key_pair()?;
        let derived = AsfaloadPublicKeys::from_secret_key(&sk)?;
        assert_eq!(derived.to_base64(), pk.to_base64());
        Ok(())
    }

    #[test]
    fn test_asfaload_public_key_serde_round_trip() -> Result<()> {
        let (_dir, pk, _) = get_asfaload_key_pair()?;
        let json = serde_json::to_string(&pk)?;
        let expected_json = format!("\"{}\"", pk.to_base64());
        assert_eq!(json, expected_json);

        let deserialized: AsfaloadPublicKeys = serde_json::from_str(&json)?;
        assert_eq!(deserialized, pk);
        Ok(())
    }

    #[test]
    fn test_asfaload_add_to_aggregate() -> Result<()> {
        let temp_dir = tempfile::tempdir()?;
        let signed_file_path = create_file_to_sign(temp_dir.path().to_path_buf())?;
        fs::write(&signed_file_path, "asfaload aggregate test")?;

        let (_kdir, pk1, sk1, pk2, sk2) = get_two_asfaload_key_pairs()?;
        let data = common::sha512_for_content(b"asfaload aggregate test".to_vec())?;
        let sig1 = sk1.sign(&data)?;
        let sig2 = sk2.sign(&data)?;

        add_to_aggregate_for_file(&sig1, &signed_file_path, &pk1)?;
        add_to_aggregate_for_file(&sig2, &signed_file_path, &pk2)?;

        let sig_file_path = signed_file_path.with_file_name(format!(
            "{}.{}",
            signed_file_path.to_string_lossy(),
            PENDING_SIGNATURES_SUFFIX
        ));
        let content = fs::read_to_string(&sig_file_path)?;
        let sig_file: SignaturesFile = serde_json::from_str(&content)?;
        assert_eq!(sig_file.entries.len(), 2);
        assert!(sig_file.entries.contains_key(&pk1.to_base64()));
        assert!(sig_file.entries.contains_key(&pk2.to_base64()));
        assert_eq!(
            sig_file.entries.get(&pk1.to_base64()).unwrap().format,
            KeyFormat::Asfaload
        );

        Ok(())
    }
}
