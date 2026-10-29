use crate::file_auth::actors::git_actor::{CommitFile, GitActor};
use crate::handlers::map_to_user_error;
use common::errors::{AggregateSignatureError, SignersFileError};
use common::fs::names::signatures_path_for;
use constants::SIGNERS_DIR;
use features_lib::{
    AsfaloadPublicKeys, AsfaloadSignatures, SignatureWithState, SignedFileLoader, sha512_for_file,
};
use kameo::actor::ActorRef;
use kameo::message::Context;
use kameo::prelude::{Actor, Message};
use rest_api_types::errors::{ApiError, map_aggregate_signature_error};
use rest_api_types::path_validation::NormalisedPaths;
use signers_file_types::revocation::RevocationInfo;
use std::collections::HashMap;
use std::path::{Path, PathBuf};

/// Request to collect a signature for a specific file.
///
/// This request is sent to the SignatureCollector actor to add an individual
/// signature to a file's aggregate signature collection.
#[derive(Debug, Clone)]
pub struct CollectSignatureRequest {
    /// Normalised path to the primary file being signed
    pub file_path: NormalisedPaths,
    /// Public key of the signer
    pub public_key: AsfaloadPublicKeys,
    /// Map of relative file paths to their signatures.
    /// Must contain at least the primary file's signature.
    /// For signers files, also contains the metadata file signature.
    pub signatures: HashMap<PathBuf, AsfaloadSignatures>,
    /// Request ID for tracing and logging
    pub request_id: String,
}

/// Result of a signature collection operation.
///
/// Returns the completion status of the aggregate signature after adding
/// the individual signature.
#[derive(Debug, Clone)]
pub struct CollectSignatureResult {
    /// Whether the aggregate signature is now complete
    pub is_complete: bool,
    /// Request ID from the original request
    pub request_id: String,
}

/// Request to query the current status of a file's signature collection.
#[derive(Debug, Clone)]
pub struct GetSignatureStatusRequest {
    /// Normalised path to the file
    pub file_path: NormalisedPaths,
    /// Request ID for tracing and logging
    pub request_id: String,
}

/// Status of signature collection for a file.
#[derive(Debug, Clone)]
pub struct SignatureStatus {
    /// Whether the aggregate signature is complete
    pub is_complete: bool,
}

/// Request to revoke a signed file.
///
/// Routed through the SignatureCollector actor to serialize revocation
/// alongside signature operations, preventing race conditions.
#[derive(Debug, Clone)]
pub struct RevokeFileMessage {
    pub file_path: NormalisedPaths,
    pub revocation_json: String,
    pub signature: AsfaloadSignatures,
    pub public_key: AsfaloadPublicKeys,
    pub request_id: String,
}

/// Result of a revocation operation.
#[derive(Debug, Clone)]
pub struct RevokeFileResult();

/// Actor responsible for collecting individual signatures for aggregate signatures.
///
/// The SignatureCollector handles the generic collection of signatures for any type
/// of aggregate signature (initial signers files, signers file updates, or artifact files).
/// It delegates to the AggregateSignature API for validation and storage, and automatically
/// transitions signatures from pending to complete state when the threshold is reached.
pub struct SignatureCollector {
    git_actor: ActorRef<GitActor>,
}

const ACTOR_NAME: &str = "SignatureCollector";

impl Actor for SignatureCollector {
    type Args = ActorRef<GitActor>;
    type Error = String;

    async fn on_start(
        args: Self::Args,
        _actor_ref: kameo::prelude::ActorRef<Self>,
    ) -> Result<Self, Self::Error> {
        tracing::info!(actor = ACTOR_NAME, "starting");
        Ok(Self { git_actor: args })
    }
}

impl Message<CollectSignatureRequest> for SignatureCollector {
    type Reply = Result<CollectSignatureResult, ApiError>;

    #[tracing::instrument(skip(self, msg, _ctx))]
    async fn handle(
        &mut self,
        msg: CollectSignatureRequest,
        _ctx: &mut Context<Self, Self::Reply>,
    ) -> Self::Reply {
        tracing::info!(
            actor = ACTOR_NAME,
            request_id = %msg.request_id,
            file_path = %msg.file_path.absolute_path().display(),
            "received signature collection request"
        );

        if !msg.file_path.absolute_path().exists() {
            return Err(ApiError::InvalidRequestBody(format!(
                "File not found: {}",
                msg.file_path.absolute_path().display()
            )));
        }

        let rel_path = msg.file_path.relative_path();
        let rel_parent = rel_path.parent();
        // We do not support signatures for files in the repo's root.
        // This can be fixed (eg the signers_initialiser would need to be
        // updated to not call parent on the signed file), but is currently not
        // a priority as all files are in subdirectories.
        if rel_parent.is_none() || rel_parent == Some(Path::new("")) {
            return Err(ApiError::InvalidRequestBody(
                "Files at git repository root cannot have signatures. Files must be in a subdirectory.".to_string()
            ));
        }

        let file_path = msg.file_path.absolute_path();

        let authorized_signers =
            features_lib::aggregate_signature_helpers::get_authorized_signers_for_file(&file_path)
                .map_err(|e| {
                    tracing::error!(
                        actor = ACTOR_NAME,
                        request_id = %msg.request_id,
                        error = %e,
                        "failed to get authorized signers"
                    );
                    match e {
                        AggregateSignatureError::FileRevoked => {
                            ApiError::FileRevoked("Cannot sign a revoked file".to_string())
                        }
                        _ => ApiError::InternalServerError(
                            "Failed to get authorized signers".to_string(),
                        ),
                    }
                })?;

        if !authorized_signers.contains(&msg.public_key) {
            return Err(ApiError::InvalidRequestBody(
                "Public key is not an authorized signer".to_string(),
            ));
        }

        // Determine file type to choose the right signing path
        let signed_file = SignedFileLoader::load(&msg.file_path).map_err(|e| {
            tracing::error!(
                actor = ACTOR_NAME,
                request_id = %msg.request_id,
                error = %e,
                "failed to load signed file"
            );
            ApiError::InternalServerError(format!("Failed to load signed file: {}", e))
        })?;

        let is_signers_file = signed_file.is_initial_signers() || signed_file.is_signers();

        let new_state = if is_signers_file {
            let primary_path = msg.file_path.relative_path();
            let signature = msg.signatures.get(&primary_path).ok_or_else(|| {
                ApiError::InvalidRequestBody(format!(
                    "No signature provided for primary file: {}",
                    primary_path.display()
                ))
            })?;
            let metadata_rel_path =
                common::fs::names::metadata_path_for(&primary_path).map_err(|e| {
                    ApiError::InternalServerError(format!("Failed to compute metadata path: {}", e))
                })?;
            let metadata_sig = msg.signatures.get(&metadata_rel_path).ok_or_else(|| {
                ApiError::InvalidRequestBody(
                    "Metadata signature required for signers files".to_string(),
                )
            })?;
            signers_file::sign_signers_and_metadata_file(
                msg.file_path.absolute_path(),
                signature,
                &msg.public_key,
                metadata_sig,
            )
            .map_err(|e| {
                tracing::error!(
                    actor = ACTOR_NAME,
                    request_id = %msg.request_id,
                    error = %e,
                    "failed to sign signers file"
                );
                map_signers_file_error(e)
            })?
        } else {
            // For non-signers files, use the existing add_individual_signature flow
            let signature_with_state =
                SignatureWithState::load_for_file(&msg.file_path).map_err(|e| {
                    tracing::error!(
                        actor = ACTOR_NAME,
                        request_id = %msg.request_id,
                        error = %e,
                        "failed to load aggregate signature"
                    );
                    ApiError::InternalServerError("Failed to load aggregate signature".to_string())
                })?;

            let pending_agg = signature_with_state.get_pending().ok_or_else(|| {
                ApiError::SignatureAlreadyComplete(
                    "Cannot accept additional signatures".to_string(),
                )
            })?;

            let primary_path = msg.file_path.relative_path();
            let signature = msg.signatures.get(&primary_path).ok_or_else(|| {
                ApiError::InvalidRequestBody(format!(
                    "No signature provided for file: {}",
                    primary_path.display()
                ))
            })?;
            pending_agg
                .add_individual_signature(signature, &msg.public_key)
                .map_err(|e| {
                    tracing::error!(
                        actor = ACTOR_NAME,
                        request_id = %msg.request_id,
                        error = %e,
                        "failed to add individual signature"
                    );
                    map_aggregate_signature_error(e)
                })?
        };

        let is_complete = new_state.is_complete();

        let commit_msg = if is_complete {
            if is_signers_file {
                // Signers file was already activated by sign_signers_and_metadata_file.
                // The dirname changes for a signers file, which influences
                // the git commit.
                tracing::info!(
                    actor = ACTOR_NAME,
                    request_id = %msg.request_id,
                    file_path = %msg.file_path.absolute_path().display(),
                    "Successfully activated signers file"
                );

                let project_dir = msg.file_path.parent().parent();
                let new_dir = project_dir.join(SIGNERS_DIR).await?;

                // Include the history file in the commit if it exists (created
                // by move_current_signers_to_history during signers rotation).
                let mut paths = vec![new_dir.clone()];
                let history_file = project_dir.join(constants::SIGNERS_HISTORY_FILE).await?;
                if history_file.absolute_path().exists() {
                    paths.push(history_file);
                }

                let commit_message = format!(
                    "completed signature collection for {}",
                    new_dir.relative_path().display()
                );
                CommitFile {
                    file_paths: paths,
                    commit_message,
                    request_id: msg.request_id.to_string(),
                }
            } else {
                // For an artifact file, the dir name doesn't change
                let commit_message = format!(
                    "completed signature collection for {}",
                    msg.file_path.relative_path().display(),
                );
                CommitFile {
                    file_paths: vec![msg.file_path.parent()],
                    commit_message,
                    request_id: msg.request_id.to_string(),
                }
            }
        } else {
            // If the signature is still partial, the dirname doesn't change,
            // even for signers files
            let commit_message = format!(
                "added partial signature for {}",
                msg.file_path.relative_path().display(),
            );
            CommitFile {
                file_paths: vec![msg.file_path.parent()],
                commit_message,
                request_id: msg.request_id.to_string(),
            }
        };

        self.git_actor.ask(commit_msg).await.map_err(|e| {
            tracing::error!(
                actor = ACTOR_NAME,
                error = %e,
                "Request to git actor failed: Failed to commit signature changes"
            );
            map_to_user_error(e, "Failed to commit signature changes")
        })?;
        // Handle both complete and incomplete states appropriately
        tracing::info!(
            actor = ACTOR_NAME,
            request_id = %msg.request_id,
            file_path = %msg.file_path.absolute_path().display(),
            is_complete = %is_complete,
            "Added individual signature to aggregate signature"
        );

        Ok(CollectSignatureResult {
            is_complete,
            request_id: msg.request_id.clone(),
        })
    }
}

impl Message<GetSignatureStatusRequest> for SignatureCollector {
    type Reply = Result<SignatureStatus, ApiError>;

    #[tracing::instrument(skip(self, msg, _ctx))]
    async fn handle(
        &mut self,
        msg: GetSignatureStatusRequest,
        _ctx: &mut Context<Self, Self::Reply>,
    ) -> Self::Reply {
        tracing::debug!(
            actor = ACTOR_NAME,
            request_id = %msg.request_id,
            file_path = %msg.file_path.absolute_path().display(),
            "received status request"
        );

        // Load the aggregate signature
        let signature_with_state =
            SignatureWithState::load_for_file(&msg.file_path).map_err(|e| {
                tracing::error!(
                    actor = ACTOR_NAME,
                    request_id = %msg.request_id,
                    error = %e,
                    "failed to load aggregate signature"
                );
                ApiError::InternalServerError("Failed to load aggregate signature".to_string())
            })?;

        let is_complete = signature_with_state.is_complete();

        Ok(SignatureStatus { is_complete })
    }
}

impl Message<RevokeFileMessage> for SignatureCollector {
    type Reply = Result<RevokeFileResult, ApiError>;

    #[tracing::instrument(skip(self, msg, _ctx))]
    async fn handle(
        &mut self,
        msg: RevokeFileMessage,
        _ctx: &mut Context<Self, Self::Reply>,
    ) -> Self::Reply {
        tracing::info!(
            actor = ACTOR_NAME,
            request_id = %msg.request_id,
            file_path = %msg.file_path.absolute_path().display(),
            "received revocation request"
        );

        let abs_path = msg.file_path.absolute_path();

        // Check validity of path for revocation
        let rel_path = msg.file_path.relative_path();
        let rel_parent = rel_path.parent();
        if rel_parent.is_none() || rel_parent == Some(Path::new("")) {
            return Err(ApiError::InvalidRequestBody(
                "Files at git repository root cannot be revoked. Files must be in a subdirectory."
                    .to_string(),
            ));
        }
        // Validate file exists
        if !abs_path.exists() {
            return Err(ApiError::InvalidRequestBody(format!(
                "File not found: {}",
                abs_path.display()
            )));
        }

        // Spec check #3: Check file has a complete aggregate signature
        let sig_path = signatures_path_for(&abs_path).map_err(|e| {
            ApiError::InternalServerError(format!("Failed to compute signatures path: {}", e))
        })?;
        if !sig_path.exists() {
            return Err(ApiError::FileNotFullySigned(format!(
                "No complete signature found for {}",
                msg.file_path.relative_path().display()
            )));
        }

        // Spec check #4: Parse revocation JSON, compute sha512 of the file,
        // compare with subject_digest
        let revocation_info = RevocationInfo::from_json(&msg.revocation_json)
            .map_err(|e| ApiError::InvalidRequestBody(format!("Invalid revocation JSON: {}", e)))?;

        let file_digest = sha512_for_file(&abs_path).map_err(|e| {
            ApiError::InternalServerError(format!("Failed to compute file digest: {}", e))
        })?;

        if revocation_info.subject_digest != file_digest {
            return Err(ApiError::DigestMismatch(format!(
                "Revocation subject_digest does not match actual file digest for {}",
                msg.file_path.relative_path().display()
            )));
        }

        // Delegate to core revocation logic (validates signature, authorization, creates files)
        aggregate_signature::revocation::revoke_signed_file(
            &abs_path,
            &msg.revocation_json,
            &msg.signature,
            &msg.public_key,
        )
        .map_err(|e| ApiError::RevocationError(e.to_string()))?;

        // Commit changes via git actor
        let commit_msg = CommitFile {
            file_paths: vec![msg.file_path.parent()],
            commit_message: format!("revoked {}", msg.file_path.relative_path().display()),
            request_id: msg.request_id.clone(),
        };
        self.git_actor.ask(commit_msg).await.map_err(|e| {
            tracing::error!(
                actor = ACTOR_NAME,
                error = %e,
                "Request to git actor failed: Failed to commit revocation changes"
            );
            map_to_user_error(e, "Failed to commit revocation changes")
        })?;

        tracing::info!(
            actor = ACTOR_NAME,
            request_id = %msg.request_id,
            file_path = %msg.file_path.absolute_path().display(),
            "Successfully revoked signed file"
        );

        Ok(RevokeFileResult())
    }
}

/// Map a `SignersFileError` to the appropriate `ApiError`, preserving the same
/// error responses as the previous direct `add_individual_signature` + `activate_signers_file` flow.
fn map_signers_file_error(e: SignersFileError) -> ApiError {
    match e {
        SignersFileError::AggregateSignatureError(agg_err) => match agg_err {
            AggregateSignatureError::SignatureAlreadyComplete => {
                ApiError::SignatureAlreadyComplete(
                    "Cannot accept additional signatures".to_string(),
                )
            }
            other => map_aggregate_signature_error(other),
        },
        SignersFileError::IoError(io) => ApiError::InternalServerError(format!("IO error: {}", io)),
        SignersFileError::SignatureVerificationFailed(_) => ApiError::SignatureVerificationFailed,
        _ => ApiError::InternalServerError(e.to_string()),
    }
}

#[cfg(all(test, not(feature = "test-utils")))]
mod tests {
    use rest_api_types::git_backend::{GitBackend, GitBackendKind, Sha256GitBackend};

    use super::*;
    use common::fs::names::{metadata_path_for, pending_signatures_path_for};
    use constants::{PENDING_SIGNERS_DIR, SIGNATURES_SUFFIX, SIGNERS_DIR, SIGNERS_FILE};
    use features_lib::{AsfaloadSecretKeyTrait, SignaturesFile, sha512_for_file};
    use kameo::actor::Spawn;
    use rest_api_test_helpers::init_git_repo;
    use signers_file_types::SignersConfig;
    use std::sync::Arc;
    use std::{
        path::{Path, PathBuf},
        str::FromStr,
    };
    use tempfile::TempDir;

    fn spawn_test_git_actor(
        repo_path: &std::path::Path,
        kind: GitBackendKind,
    ) -> kameo::actor::ActorRef<crate::file_auth::actors::git_actor::GitActor> {
        let key = test_helpers::git_signing_pub_key_path();
        let backend: Arc<dyn GitBackend> = match kind {
            GitBackendKind::Sha256 => Arc::new(Sha256GitBackend::new(repo_path, &key)),
        };
        crate::file_auth::actors::git_actor::GitActor::spawn(backend)
    }

    /// Set up a pending signers file with all required companion files:
    /// - The signers JSON content
    /// - An empty pending signatures file for the signers file
    /// - A metadata file
    /// - An empty pending signatures file for the metadata file
    ///
    /// Returns the path to the pending signers file.
    fn setup_pending_signers_with_metadata(
        pending_dir: &Path,
        signers_json: &str,
    ) -> anyhow::Result<PathBuf> {
        std::fs::create_dir_all(pending_dir)?;
        let pending_signers_path = pending_dir.join(SIGNERS_FILE);
        std::fs::write(&pending_signers_path, signers_json)?;

        // Create empty pending signatures for the signers file
        let pending_sig_path = pending_signatures_path_for(&pending_signers_path)?;
        let empty_sigs = SignaturesFile::new();
        std::fs::write(
            &pending_sig_path,
            serde_json::to_string_pretty(&empty_sigs)?,
        )?;

        // Create metadata file
        let metadata_path = metadata_path_for(&pending_signers_path)?;
        let metadata = test_helpers::test_metadata();
        let metadata_file = std::fs::File::create(&metadata_path)?;
        serde_json::to_writer_pretty(&metadata_file, &metadata)?;

        // Create empty pending signatures for the metadata file
        let metadata_pending_sig_path = pending_signatures_path_for(&metadata_path)?;
        std::fs::write(
            metadata_pending_sig_path,
            serde_json::to_string_pretty(&empty_sigs)?,
        )?;

        Ok(pending_signers_path)
    }

    /// Compute a metadata signature for a signers file.
    fn compute_metadata_signature(
        signers_file_path: &Path,
        test_keys: &test_helpers::TestKeys,
        key_index: usize,
    ) -> anyhow::Result<AsfaloadSignatures> {
        let metadata_path = metadata_path_for(signers_file_path)?;
        let metadata_hash = sha512_for_file(&metadata_path)?;
        Ok(test_keys.sec_key(key_index).unwrap().sign(&metadata_hash)?)
    }

    /// Read the git backend from the `ASFALOAD_GIT_BACKEND` environment variable.
    /// Duplicated in tests module that need it. Moving it to a test helpers crate implies
    /// too much code to move due to its return type GitBackendType
    /// Only accepts sha256 since sha1 backend was removed
    pub fn backend_kind_from_env() -> GitBackendKind {
        match std::env::var("ASFALOAD_GIT_BACKEND").as_deref() {
            Ok("sha256") => GitBackendKind::Sha256,
            Ok(other) => panic!("Unrecognised value for ASFALOAD_GIT_BACKEND {other}"),
            Err(_e) => GitBackendKind::Sha256,
        }
    }

    // Helper function to create NormalisedPaths for testing
    async fn make_normalised_paths<P: AsRef<Path>>(
        base: &tempfile::TempDir,
        relative: P,
    ) -> NormalisedPaths {
        NormalisedPaths::new(base.path(), relative).await.unwrap()
    }

    #[tokio::test]
    async fn test_collect_signature_for_signers_file() -> anyhow::Result<()> {
        let temp_dir = TempDir::new()?;
        init_git_repo(temp_dir.path())?;

        let project_dir = temp_dir.path().join("github.com/test/repo");
        let pending_dir = project_dir.join(PENDING_SIGNERS_DIR);

        // Create test keys
        let test_keys = test_helpers::TestKeys::new(1);
        let public_key = test_keys.pub_key(0).unwrap();

        // Create signers config with 1 signer, threshold 1
        let signers_config =
            SignersConfig::with_artifact_signers_only(1, (vec![public_key.clone()], 1))?;

        let signers_json = serde_json::to_string_pretty(&signers_config)?;
        let pending_signers_path =
            setup_pending_signers_with_metadata(&pending_dir, &signers_json)?;

        // Create the signature for the signers file
        let digest = sha512_for_file(&pending_signers_path)?;
        let secret_key = test_keys.sec_key(0).unwrap();
        let signature = secret_key.sign(&digest)?;

        // Create the metadata signature
        let metadata_sig = compute_metadata_signature(&pending_signers_path, &test_keys, 0)?;

        // Create NormalisedPaths
        let file_path =
            make_normalised_paths(&temp_dir, &pending_signers_path.strip_prefix(&temp_dir)?).await;

        // Spawn git actor and signature collector
        let git_actor = spawn_test_git_actor(temp_dir.path(), backend_kind_from_env());

        let actor_ref = SignatureCollector::spawn(git_actor);

        let rel_path = file_path.relative_path();
        let metadata_rel_path = metadata_path_for(&rel_path).unwrap();
        let mut signatures = HashMap::new();
        signatures.insert(rel_path, signature);
        signatures.insert(metadata_rel_path, metadata_sig);

        let request = CollectSignatureRequest {
            file_path,
            public_key: public_key.clone(),
            signatures,
            request_id: "test-123".to_string(),
        };

        let result = actor_ref.ask(request).await;

        // Note: With 1 signer at threshold 1, the signature becomes complete
        assert!(result.is_ok());
        let collect_result = result.unwrap();

        assert!(collect_result.is_complete);

        // After activation, the signers file should be in the active directory
        let active_dir = project_dir.join(SIGNERS_DIR);
        let active_signers_path = active_dir.join(SIGNERS_FILE);

        // The signers file should have been moved to the active directory
        assert!(active_signers_path.exists());

        // The signature path is {file_path}.signatures.json for a complete signature
        let complete_sig_path = format!("{}.{}", active_signers_path.display(), SIGNATURES_SUFFIX);
        let complete_sig_path = std::path::PathBuf::from(complete_sig_path);

        // The signature file should exist in the active directory
        assert!(complete_sig_path.exists());

        // The pending directory should no longer exist
        assert!(!pending_dir.exists());

        Ok(())
    }

    #[tokio::test]
    async fn test_collect_signature_for_artifact_file() -> anyhow::Result<()> {
        let temp_dir = TempDir::new()?;
        init_git_repo(temp_dir.path())?;

        let signers_dir = temp_dir.path().join(SIGNERS_DIR);
        std::fs::create_dir_all(&signers_dir)?;

        // Create signers config
        let test_keys = test_helpers::TestKeys::new(1);
        let signers_config = SignersConfig::with_artifact_signers_only(
            1,
            (vec![test_keys.pub_key(0).unwrap().clone()], 1),
        )?;
        let signers_json = serde_json::to_string_pretty(&signers_config)?;
        std::fs::write(signers_dir.join(SIGNERS_FILE), signers_json)?;

        // Create artifact file
        let artifact_path = "my/nested/dir/with/release.txt";
        std::fs::create_dir_all(
            temp_dir
                .path()
                .join(PathBuf::from_str(artifact_path)?.parent().unwrap()),
        )?;
        let artifact_file = temp_dir.path().join(artifact_path);
        std::fs::write(&artifact_file, "artifact content")?;

        // Create the signature
        let public_key = test_keys.pub_key(0).unwrap();
        let digest = sha512_for_file(&artifact_file)?;
        let secret_key = test_keys.sec_key(0).unwrap();
        let signature = secret_key.sign(&digest)?;

        let file_path = make_normalised_paths(&temp_dir, &artifact_path).await;

        // Spawn git actor and signature collector
        let git_actor = spawn_test_git_actor(temp_dir.path(), backend_kind_from_env());

        let actor_ref = SignatureCollector::spawn(git_actor);

        let mut signatures = HashMap::new();
        signatures.insert(file_path.relative_path(), signature);

        let request = CollectSignatureRequest {
            file_path,
            public_key: public_key.clone(),
            signatures,
            request_id: "test-456".to_string(),
        };

        let result = actor_ref.ask(request).await;

        assert!(result.is_ok());
        let collect_result = result.unwrap();

        assert!(collect_result.is_complete);

        Ok(())
    }

    #[tokio::test]
    async fn test_collect_signature_second_attempt_after_complete() -> anyhow::Result<()> {
        let temp_dir = TempDir::new()?;
        init_git_repo(temp_dir.path())?;

        let project_dir = temp_dir.path().join("github.com/test/repo");
        let pending_dir = project_dir.join(PENDING_SIGNERS_DIR);

        // Create key pair
        let test_keys = test_helpers::TestKeys::new(1);
        let signers_config = SignersConfig::with_artifact_signers_only(
            1,
            (vec![test_keys.pub_key(0).unwrap().clone()], 1),
        )?;
        let signers_json = serde_json::to_string_pretty(&signers_config)?;
        let pending_signers_path =
            setup_pending_signers_with_metadata(&pending_dir, &signers_json)?;

        // Create a signature
        let digest = sha512_for_file(&pending_signers_path)?;
        let secret_key = test_keys.sec_key(0).unwrap();
        let signature = secret_key.sign(&digest)?;
        let public_key = test_keys.pub_key(0).unwrap();

        // Create the metadata signature
        let metadata_sig = compute_metadata_signature(&pending_signers_path, &test_keys, 0)?;

        let file_path =
            make_normalised_paths(&temp_dir, pending_signers_path.strip_prefix(&temp_dir)?).await;

        let git_actor = spawn_test_git_actor(temp_dir.path(), backend_kind_from_env());
        let actor_ref = SignatureCollector::spawn(git_actor);

        // Add the signature first time - should succeed and complete
        let rel_path = file_path.relative_path();
        let metadata_rel_path = metadata_path_for(&rel_path).unwrap();
        let mut signatures1 = HashMap::new();
        signatures1.insert(rel_path, signature.clone());
        signatures1.insert(metadata_rel_path.clone(), metadata_sig.clone());

        let result1 = actor_ref
            .ask(CollectSignatureRequest {
                file_path: file_path.clone(),
                public_key: public_key.clone(),
                signatures: signatures1,
                request_id: "first-sign".to_string(),
            })
            .await;
        assert!(result1.is_ok());
        assert!(result1.unwrap().is_complete);

        // After activation, the file path changes from pending to active directory
        let active_signers_path = project_dir.join(SIGNERS_DIR).join(SIGNERS_FILE);
        let active_file_path =
            make_normalised_paths(&temp_dir, active_signers_path.strip_prefix(&temp_dir)?).await;

        // Try to add the same signature again - should fail with "already complete"
        // (because after first signature, the signature file is now complete and activated)
        let active_rel_path = active_file_path.relative_path();
        let active_metadata_rel_path = metadata_path_for(&active_rel_path).unwrap();
        let mut signatures2 = HashMap::new();
        signatures2.insert(active_rel_path, signature);
        signatures2.insert(active_metadata_rel_path, metadata_sig);

        let result2 = actor_ref
            .ask(CollectSignatureRequest {
                file_path: active_file_path,
                public_key: public_key.clone(),
                signatures: signatures2,
                request_id: "duplicate-sign".to_string(),
            })
            .await;

        assert!(result2.is_err());
        match result2.unwrap_err() {
            kameo::error::SendError::HandlerError(ApiError::SignatureAlreadyComplete(msg)) => {
                if msg.contains("Cannot accept additional signature") {
                } else {
                    panic!(
                        "Expected Cannot accept additional signature message, but got {}",
                        msg
                    )
                };
            }
            e => panic!(
                "Expected SignatureAlreadyComplete with 'already complete', got {:?}",
                e
            ),
        }

        Ok(())
    }

    #[tokio::test]
    async fn test_collect_signature_partial_completion() -> anyhow::Result<()> {
        let temp_dir = TempDir::new()?;
        init_git_repo(temp_dir.path())?;

        let project_dir = temp_dir.path().join("github.com/test/repo");
        let pending_dir = project_dir.join(PENDING_SIGNERS_DIR);

        // Create test keys - we'll need 2 for threshold > 1
        let test_keys = test_helpers::TestKeys::new(2);

        // Create signers config with 2 signers, threshold 2
        let signers_config = SignersConfig::with_artifact_signers_only(
            2,
            (
                vec![
                    test_keys.pub_key(0).unwrap().clone(),
                    test_keys.pub_key(1).unwrap().clone(),
                ],
                2,
            ),
        )?;

        let signers_json = serde_json::to_string_pretty(&signers_config)?;
        let pending_signers_path =
            setup_pending_signers_with_metadata(&pending_dir, &signers_json)?;

        // Create first signature
        let digest = sha512_for_file(&pending_signers_path)?;
        let secret_key1 = test_keys.sec_key(0).unwrap();
        let signature1 = secret_key1.sign(&digest)?;
        let public_key1 = test_keys.pub_key(0).unwrap();

        // Create metadata signatures
        let metadata_sig1 = compute_metadata_signature(&pending_signers_path, &test_keys, 0)?;

        let file_path =
            make_normalised_paths(&temp_dir, pending_signers_path.strip_prefix(&temp_dir)?).await;

        let git_actor = spawn_test_git_actor(temp_dir.path(), backend_kind_from_env());
        let actor_ref = SignatureCollector::spawn(git_actor);

        // Add first signature - should return is_complete: false
        let rel_path = file_path.relative_path();
        let metadata_rel_path = metadata_path_for(&rel_path).unwrap();
        let mut signatures1 = HashMap::new();
        signatures1.insert(rel_path.clone(), signature1);
        signatures1.insert(metadata_rel_path.clone(), metadata_sig1);

        let result1 = actor_ref
            .ask(CollectSignatureRequest {
                file_path: file_path.clone(),
                public_key: public_key1.clone(),
                signatures: signatures1,
                request_id: "first-sign".to_string(),
            })
            .await;

        assert!(result1.is_ok());
        let collect_result1 = result1.unwrap();
        assert!(!collect_result1.is_complete); // Should be false - threshold not met yet

        // Add second signature to complete aggregate signature
        let secret_key2 = test_keys.sec_key(1).unwrap();
        let signature2 = secret_key2.sign(&digest)?;
        let public_key2 = test_keys.pub_key(1).unwrap();
        let metadata_sig2 = compute_metadata_signature(&pending_signers_path, &test_keys, 1)?;
        let mut signatures2 = HashMap::new();
        signatures2.insert(rel_path, signature2);
        signatures2.insert(metadata_rel_path, metadata_sig2);

        let result2 = actor_ref
            .ask(CollectSignatureRequest {
                file_path: file_path.clone(),
                public_key: public_key2.clone(),
                signatures: signatures2,
                request_id: "second-sign".to_string(),
            })
            .await;

        assert!(result2.is_ok());
        let collect_result2 = result2.unwrap();
        assert!(collect_result2.is_complete);

        Ok(())
    }

    #[tokio::test]
    async fn test_collect_signature_rejects_root_level_file() -> anyhow::Result<()> {
        let temp_dir = TempDir::new()?;
        init_git_repo(temp_dir.path())?;

        // Create signers config
        let test_keys = test_helpers::TestKeys::new(1);
        let signers_config = SignersConfig::with_artifact_signers_only(
            1,
            (vec![test_keys.pub_key(0).unwrap().clone()], 1),
        )?;

        let signers_json = serde_json::to_string_pretty(&signers_config)?;

        // Create signers directory and file
        let signers_dir = temp_dir.path().join(SIGNERS_DIR);
        std::fs::create_dir_all(&signers_dir)?;
        std::fs::write(signers_dir.join(SIGNERS_FILE), signers_json)?;

        // Create artifact file at repo root
        let artifact_file = temp_dir.path().join("release.txt");
        std::fs::write(&artifact_file, "artifact content")?;

        // Create the signature
        let public_key = test_keys.pub_key(0).unwrap();
        let digest = sha512_for_file(&artifact_file)?;
        let secret_key = test_keys.sec_key(0).unwrap();
        let signature = secret_key.sign(&digest)?;

        let file_path = make_normalised_paths(&temp_dir, Path::new("release.txt")).await;

        let git_actor = spawn_test_git_actor(temp_dir.path(), backend_kind_from_env());
        let actor_ref = SignatureCollector::spawn(git_actor);

        let mut signatures = HashMap::new();
        signatures.insert(file_path.relative_path(), signature);

        let result = actor_ref
            .ask(CollectSignatureRequest {
                file_path,
                public_key: public_key.clone(),
                signatures,
                request_id: "test-root-file".to_string(),
            })
            .await;

        assert!(result.is_err());
        match result.unwrap_err() {
            kameo::error::SendError::HandlerError(ApiError::InvalidRequestBody(msg))
                if msg.contains("Files at git repository root cannot have signatures") => {}
            e => panic!(
                "Expected InvalidRequestBody with root rejection, got {:?}",
                e
            ),
        }

        Ok(())
    }

    #[tokio::test]
    async fn test_collect_signature_rejects_first_unauthorized_signature() -> anyhow::Result<()> {
        let temp_dir = TempDir::new()?;
        init_git_repo(temp_dir.path())?;

        let test_keys = test_helpers::TestKeys::new(3);

        let signers_config = SignersConfig::with_artifact_signers_only(
            2,
            (
                vec![
                    test_keys.pub_key(0).unwrap().clone(),
                    test_keys.pub_key(1).unwrap().clone(),
                ],
                2,
            ),
        )?;

        let signers_dir = temp_dir.path().join(SIGNERS_DIR);
        std::fs::create_dir_all(&signers_dir)?;
        std::fs::write(signers_dir.join(SIGNERS_FILE), signers_config.to_json()?)?;

        let artifact_path = "nested/artifact.txt";
        std::fs::create_dir_all(temp_dir.path().join("nested"))?;
        let artifact_full_path = temp_dir.path().join(artifact_path);
        std::fs::write(&artifact_full_path, "content")?;

        let file_path = make_normalised_paths(&temp_dir, artifact_path).await;
        let digest = sha512_for_file(&artifact_full_path)?;
        let signature = test_keys.sec_key(2).unwrap().sign(&digest)?;

        let git_actor = spawn_test_git_actor(&artifact_full_path, backend_kind_from_env());
        let actor_ref = SignatureCollector::spawn(git_actor);

        let mut signatures = HashMap::new();
        signatures.insert(file_path.relative_path(), signature);

        let result = actor_ref
            .ask(CollectSignatureRequest {
                file_path,
                public_key: test_keys.pub_key(2).unwrap().clone(),
                signatures,
                request_id: "test-unauth-1".to_string(),
            })
            .await;

        assert!(result.is_err());
        match result.unwrap_err() {
            kameo::error::SendError::HandlerError(ApiError::InvalidRequestBody(msg))
                if msg.contains("not an authorized signer") => {}
            e => panic!("Expected unauthorized signer error, got {:?}", e),
        }

        let pending_sig_path = common::fs::names::pending_signatures_path_for(&artifact_full_path)?;
        assert!(
            !pending_sig_path.exists(),
            "Pending signatures should not be created when signature is unauthorized"
        );

        Ok(())
    }

    #[tokio::test]
    async fn test_collect_signature_rejects_unauthorized_for_signers_update() -> anyhow::Result<()>
    {
        let temp_dir = TempDir::new()?;
        init_git_repo(temp_dir.path())?;

        // Create old signers config with admin (key 0) and master (key 1)
        let test_keys = test_helpers::TestKeys::new(4);

        // First, establish the current signers configuration
        // We create a config with admin and master signers (existing signers for the signers file)
        let old_config = SignersConfig::with_keys(
            1,
            (vec![], 1),
            Some((vec![test_keys.pub_key(0).unwrap().clone()], 1)),
            Some((vec![test_keys.pub_key(1).unwrap().clone()], 1)),
            None,
        )?;

        let signers_dir = temp_dir.path().join(SIGNERS_DIR);
        std::fs::create_dir_all(&signers_dir)?;
        std::fs::write(
            signers_dir.join(SIGNERS_FILE),
            serde_json::to_string_pretty(&old_config)?,
        )?;

        // Create new signers config (in pending) that adds key 3 as artifact signer
        let new_config = SignersConfig::with_keys(
            2,
            (vec![test_keys.pub_key(3).unwrap().clone()], 1),
            Some((vec![test_keys.pub_key(0).unwrap().clone()], 1)),
            Some((vec![test_keys.pub_key(1).unwrap().clone()], 1)),
            None,
        )?;
        let pending_dir = temp_dir.path().join(PENDING_SIGNERS_DIR);
        std::fs::create_dir_all(&pending_dir)?;
        std::fs::write(
            pending_dir.join(SIGNERS_FILE),
            serde_json::to_string_pretty(&new_config)?,
        )?;

        // Try to sign the pending signers file with unauthorized key
        // The relative path should be "asfaload.signers.pending/index.json"
        let relative_path = format!("{}/{}", PENDING_SIGNERS_DIR, SIGNERS_FILE);
        let file_path = make_normalised_paths(&temp_dir, &relative_path).await;

        let digest = sha512_for_file(pending_dir.join(SIGNERS_FILE))?;
        let signature = test_keys.sec_key(2).unwrap().sign(&digest)?;

        let git_actor = spawn_test_git_actor(temp_dir.path(), backend_kind_from_env());
        let actor_ref = SignatureCollector::spawn(git_actor);

        let mut signatures = HashMap::new();
        signatures.insert(file_path.relative_path(), signature);

        let result = actor_ref
            .ask(CollectSignatureRequest {
                file_path,
                public_key: test_keys.pub_key(2).unwrap().clone(),
                signatures,
                request_id: "test-unauth-signers".to_string(),
            })
            .await;

        // Should fail - key_pair_unauth is not authorized
        assert!(result.is_err());
        match result.unwrap_err() {
            kameo::error::SendError::HandlerError(ApiError::InvalidRequestBody(msg))
                if msg.contains("not an authorized signer") => {}
            e => panic!("Expected unauthorized signer error, got {:?}", e),
        }

        Ok(())
    }

    #[tokio::test]
    async fn test_collect_signature_rejects_unauthorized_for_initial_signers() -> anyhow::Result<()>
    {
        let temp_dir = TempDir::new()?;
        init_git_repo(temp_dir.path())?;

        // Create initial signers config
        let test_keys = test_helpers::TestKeys::new(3);

        let config = SignersConfig::with_artifact_signers_only(
            2,
            (
                vec![
                    test_keys.pub_key(0).unwrap().clone(),
                    test_keys.pub_key(1).unwrap().clone(),
                ],
                2,
            ),
        )?;

        let pending_dir = temp_dir.path().join(PENDING_SIGNERS_DIR);
        std::fs::create_dir_all(&pending_dir)?;
        std::fs::write(
            pending_dir.join(SIGNERS_FILE),
            serde_json::to_string_pretty(&config)?,
        )?;

        // Try to sign with unauthorized key
        let relative_path = format!("{}/{}", PENDING_SIGNERS_DIR, SIGNERS_FILE);
        let file_path = make_normalised_paths(&temp_dir, &relative_path).await;

        let digest = sha512_for_file(pending_dir.join(SIGNERS_FILE))?;
        let signature = test_keys.sec_key(2).unwrap().sign(&digest)?;

        let git_actor = spawn_test_git_actor(temp_dir.path(), backend_kind_from_env());
        let actor_ref = SignatureCollector::spawn(git_actor);

        let mut signatures = HashMap::new();
        signatures.insert(file_path.relative_path(), signature);

        let result = actor_ref
            .ask(CollectSignatureRequest {
                file_path,
                public_key: test_keys.pub_key(2).unwrap().clone(),
                signatures,
                request_id: "test-unauth-initial".to_string(),
            })
            .await;

        // Should fail
        assert!(result.is_err());
        match result.unwrap_err() {
            kameo::error::SendError::HandlerError(ApiError::InvalidRequestBody(msg))
                if msg.contains("not an authorized signer") => {}
            e => panic!("Expected unauthorized signer error, got {:?}", e),
        }

        Ok(())
    }
}
