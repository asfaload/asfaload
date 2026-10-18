//! Test helpers for creating signers configurations and files.
//!
//! These functions simplify test setup by providing reusable utilities
//! for creating signers configs, artifact files, and signature files.

use std::fs;
use std::path::{Path, PathBuf};

use common::errors::SignersConfigError;
use common::sha512_for_file;
use constants::{PENDING_SIGNERS_DIR, SIGNATURES_SUFFIX, SIGNERS_DIR, SIGNERS_FILE};
use signatures::keys::{AsfaloadPublicKeyTrait, AsfaloadSecretKeyTrait, AsfaloadSignatureTrait};
use signatures::signatures_file::{SignaturesFile, TaggedSignature};
use signers_file_types::{
    Signer, SignerData, SignerGroup, SignerKind, SignersConfig, SignersConfigProposal,
};
use tempfile::TempDir;

use crate::TestKeys;

/// Create a Signer from a TestKeys instance at the given index.
/// The format is inferred from the public key's algorithm.
pub fn create_signer(test_keys: &TestKeys, index: usize) -> Signer {
    let pubkey = test_keys.pub_key(index).unwrap().clone();
    Signer {
        kind: SignerKind::Key,
        data: SignerData { pubkey },
    }
}

/// Create a SignerGroup from a vector of signer indices.
pub fn create_group(test_keys: &TestKeys, indices: Vec<usize>, threshold: u32) -> SignerGroup {
    let signers = indices
        .into_iter()
        .map(|i| create_signer(test_keys, i))
        .collect();
    SignerGroup { signers, threshold }
}

/// Create a signers config on disk at `root/SIGNERS_DIR/SIGNERS_FILE`.
///
/// Returns the path to the signers file.
pub fn write_signers_config(root: &Path, config: &SignersConfig) -> PathBuf {
    let sig_dir = root.join(SIGNERS_DIR);
    fs::create_dir_all(&sig_dir).unwrap();
    let signers_file = sig_dir.join(SIGNERS_FILE);
    let json = serde_json::to_string_pretty(config).unwrap();
    fs::write(&signers_file, json).unwrap();
    signers_file
}

/// Create a pending signers config on disk at `root/PENDING_SIGNERS_DIR/SIGNERS_FILE`.
///
/// Returns the path to the pending signers file.
pub fn write_pending_signers_config(root: &Path, config: &SignersConfig) -> PathBuf {
    let pending_dir = root.join(PENDING_SIGNERS_DIR);
    fs::create_dir_all(&pending_dir).unwrap();
    let signers_file = pending_dir.join(SIGNERS_FILE);
    let json = serde_json::to_string_pretty(config).unwrap();
    fs::write(&signers_file, json).unwrap();
    signers_file
}

/// Build a signers config whose only group is the artifact signers group,
/// built from the public keys of `test_keys` at `indices`, requiring
/// `threshold` signatures from that group.
///
/// An empty `indices` slice produces a config with no artifact signers, for
/// tests exercising the absence of authorised signers.
pub fn artifact_signers_only_config(
    test_keys: &TestKeys,
    indices: &[usize],
    threshold: u32,
) -> Result<SignersConfig, SignersConfigError> {
    let keys = indices
        .iter()
        .map(|i| test_keys.pub_key(*i).unwrap().clone())
        .collect::<Vec<_>>();
    SignersConfig::with_artifact_signers_only(1, (keys, threshold))
}

/// Build an artifact-signers-only config with
/// `artifact_signers_only_config` and write it to
/// `root/SIGNERS_DIR/SIGNERS_FILE`.
///
/// Returns the path to the written signers file.
pub fn write_artifact_signers_config(
    root: &Path,
    test_keys: &TestKeys,
    indices: &[usize],
    threshold: u32,
) -> Result<PathBuf, SignersConfigError> {
    let config = artifact_signers_only_config(test_keys, indices, threshold)?;
    Ok(write_signers_config(root, &config))
}

/// Create an artifact file at `root/nested/artifact.txt` with dummy content.
///
/// Returns the path to the artifact file.
pub fn write_artifact_file(root: &Path) -> PathBuf {
    let artifact_path = root.join("nested/artifact.txt");
    fs::create_dir_all(artifact_path.parent().unwrap()).unwrap();
    fs::write(&artifact_path, "content").unwrap();
    artifact_path
}

/// Write a pending signatures file for the given file path.
///
/// `signed_keys` contains (pubkey, secret_key) pairs that should have valid signatures.
pub fn write_pending_signatures(
    file_path: &Path,
    signed_keys: &[(
        signatures::types::AsfaloadPublicKeys,
        signatures::types::AsfaloadSecretKeys,
    )],
) {
    use common::fs::names::pending_signatures_path_for;

    let file_hash = sha512_for_file(file_path).unwrap();
    let mut sig_file = SignaturesFile::new();
    for (pubkey, seckey) in signed_keys {
        let sig = seckey.sign(&file_hash).unwrap();
        sig_file.entries.insert(
            pubkey.to_base64(),
            TaggedSignature {
                format: pubkey.key_format(),
                signature: sig.to_base64(),
            },
        );
    }
    let sig_path = pending_signatures_path_for(file_path).unwrap();
    let json = serde_json::to_string_pretty(&sig_file).unwrap();
    fs::write(sig_path, json).unwrap();
}

/// Create a complete signers file setup with signatures.
///
/// Creates a signers directory with a signed signers config file.
/// Artifact signers are always keys 0 and 1 (threshold 2).
/// Admin, master, and revocation keys are configurable.
///
/// Returns `(signers_file_path, signatures_file_path)`.
pub fn create_complete_signers_setup(
    temp_dir: &TempDir,
    test_keys: &TestKeys,
    admin_key_indices: Option<Vec<usize>>,
    master_key_indices: Option<Vec<usize>>,
    revocation_key_indices: Option<Vec<usize>>,
) -> Result<(PathBuf, PathBuf), Box<dyn std::error::Error>> {
    let root = temp_dir.path();

    let signers_dir = root.join(SIGNERS_DIR);
    fs::create_dir_all(&signers_dir)?;
    let signers_file = signers_dir.join(SIGNERS_FILE);

    let signer_at = |i: usize| -> Signer {
        let pubkey = test_keys.pub_key(i).unwrap().clone();
        Signer {
            kind: SignerKind::Key,
            data: SignerData { pubkey },
        }
    };

    let artifact_signers = vec![signer_at(0), signer_at(1)];

    let master_keys = master_key_indices.clone().map(|indices| {
        vec![SignerGroup {
            signers: indices.iter().map(|&i| signer_at(i)).collect(),
            threshold: indices.len() as u32,
        }]
    });

    let admin_keys = admin_key_indices.clone().map(|indices| {
        vec![SignerGroup {
            signers: indices.iter().map(|&i| signer_at(i)).collect(),
            threshold: indices.len() as u32,
        }]
    });

    let revocation_keys = revocation_key_indices.map(|indices| {
        vec![SignerGroup {
            signers: indices.iter().map(|&i| signer_at(i)).collect(),
            threshold: indices.len() as u32,
        }]
    });

    let signers_config_proposal = SignersConfigProposal {
        timestamp: chrono::Utc::now(),
        version: 1,
        artifact_signers: vec![SignerGroup {
            signers: artifact_signers,
            threshold: 2,
        }],
        master_keys: master_keys.clone(),
        admin_keys: admin_keys.clone(),
        revocation_keys,
    };

    let signers_config = signers_config_proposal.build()?;

    let config_json = serde_json::to_string_pretty(&signers_config)?;
    fs::write(&signers_file, config_json)?;

    let hash = sha512_for_file(&signers_file)?;

    let mut sig_file = SignaturesFile::new();

    if let Some(indices) = master_key_indices {
        for &index in &indices {
            let pubkey = test_keys.pub_key(index).unwrap();
            let seckey = test_keys.sec_key(index).unwrap();
            let signature = seckey.sign(&hash)?;
            sig_file.entries.insert(
                pubkey.to_base64(),
                TaggedSignature {
                    format: pubkey.key_format(),
                    signature: signature.to_base64(),
                },
            );
        }
    } else {
        for i in 0..2 {
            let pubkey = test_keys.pub_key(i).unwrap();
            let seckey = test_keys.sec_key(i).unwrap();
            let signature = seckey.sign(&hash)?;
            sig_file.entries.insert(
                pubkey.to_base64(),
                TaggedSignature {
                    format: pubkey.key_format(),
                    signature: signature.to_base64(),
                },
            );
        }
    }

    let signatures_file = signers_file.with_file_name(format!(
        "{}.{}",
        signers_file.file_name().unwrap().to_string_lossy(),
        SIGNATURES_SUFFIX
    ));
    fs::write(&signatures_file, serde_json::to_string_pretty(&sig_file)?)?;

    Ok((signers_file, signatures_file))
}

/// Write a revocation file (RevocationInfo JSON) for the given artifact path.
///
/// The revocation file is placed at `{artifact_path}.{REVOCATION_SUFFIX}`.
/// Returns the path to the revocation file.
pub fn write_revocation_file(
    artifact_path: &Path,
    initiator: &signatures::types::AsfaloadPublicKeys,
) -> PathBuf {
    use common::fs::names::revocation_path_for;
    use signers_file_types::revocation::RevocationInfo;

    let subject_digest = sha512_for_file(artifact_path).unwrap();
    let revocation_info = RevocationInfo {
        timestamp: chrono::Utc::now(),
        subject_digest,
        initiator: initiator.clone(),
    };
    let json = serde_json::to_string_pretty(&revocation_info).unwrap();
    let revocation_path = revocation_path_for(artifact_path).unwrap();
    fs::write(&revocation_path, json).unwrap();
    revocation_path
}
