use constants::{PENDING_SIGNERS_DIR, SIGNERS_DIR, SIGNERS_FILE, SIGNERS_HISTORY_FILE};
use features_lib::AsfaloadSignatures;
use kameo::message::Context;
use kameo::prelude::{Actor, Message};
use rest_api_types::errors::ApiError;
use signatures::keys::AsfaloadPublicKeyTrait;
use signatures::types::AsfaloadPublicKeys;
use signers_file_types::{HistoryFile, SignersConfigMetadata};
use std::path::PathBuf;

use crate::file_auth::actors::forge_signers_validator::SignersInfo;
use rest_api_types::path_validation::NormalisedPaths;

const ACTOR_NAME: &str = "signers_initialiser";
#[derive(Debug)]
pub struct InitialiseSignersRequest {
    pub project_path: NormalisedPaths,
    pub signers_info: SignersInfo,
    pub signers_signature: AsfaloadSignatures,
    pub metadata: SignersConfigMetadata,
    pub metadata_signature: AsfaloadSignatures,
    pub git_repo_path: PathBuf,
    pub request_id: String,
    pub pubkey: AsfaloadPublicKeys,
}

#[derive(Debug, Clone)]
pub struct InitialiseSignersResult {
    pub project_path: NormalisedPaths,
    pub required_signers: Vec<String>,
    pub signers_file_path: NormalisedPaths,
    pub history_file_path: NormalisedPaths,
    pub request_id: String,
}

#[derive(Debug, Clone)]
pub struct CleanupSignersRequest {
    pub signers_file_path: NormalisedPaths,
    /// `None` when cleaning up after a failed update (the history file
    /// already existed and must not be removed).
    pub history_file_path: Option<NormalisedPaths>,
    pub pending_dir: NormalisedPaths,
    pub request_id: String,
}

#[derive(Debug)]
pub struct ProposeSignersRequest {
    pub project_path: NormalisedPaths,
    pub signers_info: SignersInfo,
    pub signers_signature: AsfaloadSignatures,
    pub metadata: SignersConfigMetadata,
    pub metadata_signature: AsfaloadSignatures,
    pub request_id: String,
    pub pubkey: AsfaloadPublicKeys,
}

#[derive(Debug, Clone)]
pub struct ProposeSignersResult {
    pub project_path: NormalisedPaths,
    pub required_signers: Vec<String>,
    pub request_id: String,
}

pub struct SignersInitialiser;

impl Actor for SignersInitialiser {
    type Args = ();
    type Error = String;

    async fn on_start(
        _args: Self::Args,
        _actor_ref: kameo::prelude::ActorRef<Self>,
    ) -> Result<Self, Self::Error> {
        tracing::info!("SignersInitialiser starting");
        Ok(Self)
    }
}

impl Message<InitialiseSignersRequest> for SignersInitialiser {
    type Reply = Result<InitialiseSignersResult, ApiError>;

    #[tracing::instrument(skip(self, msg, _ctx))]
    async fn handle(
        &mut self,
        msg: InitialiseSignersRequest,
        _ctx: &mut Context<Self, Self::Reply>,
    ) -> Self::Reply {
        let project_id = msg
            .project_path
            .relative_path()
            .to_string_lossy()
            .to_string();
        tracing::info!(
            request_id = %msg.request_id,
            project_id = %project_id,
            "SignersInitialiser received initialisation request"
        );

        let project_normalised_paths = msg.project_path;
        //
        // Even though the handler checks the existence, we need to test it here
        // just in case the handler gets the second request before we create the
        // directory here. The second message the handler sends us will detect
        // here that the project dir was already created.
        let project_dir = project_normalised_paths.absolute_path();
        if tokio::fs::try_exists(&project_dir).await? {
            tracing::warn!(
                request_id = %msg.request_id,
                project_id = %project_id,
                "Project directory structure already exists, indicating a pending or completed registration."
            );
            return Err(ApiError::ProjectAlreadyRegistered(format!(
                "Project '{}' is already registered or registration is in progress.",
                project_id
            )));
        }

        tracing::debug!(
                request_id = %msg.request_id,
                project_id = %project_id,
            project_normalised_paths_relative = %project_normalised_paths.relative_path().display(),
            project_normalised_paths_absolute = %project_normalised_paths.absolute_path().display(),
            "Computed normalised paths for project"
        );

        let signers_normalised_paths = project_normalised_paths
            .join(PENDING_SIGNERS_DIR)
            .await?
            .join(SIGNERS_FILE)
            .await?;
        let history_normalised_paths = project_normalised_paths.join(SIGNERS_HISTORY_FILE).await?;

        // Create the project directory (initialize_signers_file will create PENDING_SIGNERS_DIR inside it)
        tokio::fs::create_dir_all(&project_dir).await.map_err(|e| {
            tracing::error!(
                request_id = %msg.request_id,
                error = %e,
                path = %project_dir.display(),
                "Failed to create project directory"
            );
            ApiError::DirectoryCreationFailed(format!(
                "Failed to create directory {}: {}",
                project_dir.display(),
                e
            ))
        })?;

        // Use initialize_signers_file from signers_file crate to create the
        // pending signers directory, write the signers file, and metadata.
        let dir = project_dir.clone();
        let json = msg.signers_info.json();
        let meta = msg.metadata;
        let pubkey = msg.pubkey.clone();
        tokio::task::spawn_blocking(move || {
            signers_file::initialize_signers_file(&dir, &json, meta, &pubkey)
        })
        .await??;

        // Record the client-provided signatures
        let signature_with_state = {
            let signers_path = signers_normalised_paths.absolute_path().to_path_buf();
            let signature = msg.signers_signature.clone();
            let metadata_signature = msg.metadata_signature.clone();
            let pubkey = msg.pubkey.clone();
            tokio::task::spawn_blocking(move || {
                signers_file::sign_signers_and_metadata_file(
                    &signers_path,
                    &signature,
                    &pubkey,
                    &metadata_signature,
                )
            })
            .await??
        };

        // Write the history file (initialize_signers_file does not create this)
        let history_json = HistoryFile::new().to_json()?;
        tokio::fs::write(&history_normalised_paths, history_json)
            .await
            .map_err(|e| {
                tracing::error!(
                    request_id = %msg.request_id,
                    error = %e,
                    path = %history_normalised_paths,
                    "Failed to write history file"
                );
                ApiError::FileWriteFailed(format!(
                    "Failed to write history file {}: {}",
                    history_normalised_paths, e
                ))
            })?;

        tracing::debug!(
            request_id = %msg.request_id,
            file_path = %history_normalised_paths,
            "Wrote history file to disk"
        );

        let (required_signers, signers_updated_normalised_paths): (Vec<String>, NormalisedPaths) =
            if signature_with_state.is_complete() {
                // If the signature is complete, the signers file has been activated, hence renamed
                // dropping the pending suffix
                let signers_file_path = project_normalised_paths
                    .join(SIGNERS_DIR)
                    .await?
                    .join(SIGNERS_FILE)
                    .await?;
                (vec![], signers_file_path)
            } else {
                let pending_signers_path = signers_normalised_paths.absolute_path().to_path_buf();
                let missing_signers = tokio::task::spawn_blocking(move || {
                    features_lib::aggregate_signature_helpers::get_missing_signers(
                        &pending_signers_path,
                    )
                })
                .await?
                .map_err(|e| {
                    tracing::error!(
                        request_id = %msg.request_id,
                        error = %e,
                        path = %signers_normalised_paths,
                        "Failed to compute missing signers"
                    );
                    ApiError::ActorOperationFailed(format!(
                        "Failed to compute missing signers: {}",
                        e
                    ))
                })?
                .into_iter()
                .map(|key: AsfaloadPublicKeys| key.to_base64())
                .collect();
                (missing_signers, signers_normalised_paths)
            };

        tracing::info!(
            request_id = %msg.request_id,
            project_id = %project_id,
            required_signers_count = required_signers.len(),
            "Successfully initialised signers"
        );

        Ok(InitialiseSignersResult {
            project_path: project_normalised_paths,
            required_signers,
            signers_file_path: signers_updated_normalised_paths,
            history_file_path: history_normalised_paths,
            request_id: msg.request_id,
        })
    }
}

impl Message<ProposeSignersRequest> for SignersInitialiser {
    type Reply = Result<ProposeSignersResult, ApiError>;

    #[tracing::instrument(skip(self, msg, _ctx))]
    async fn handle(
        &mut self,
        msg: ProposeSignersRequest,
        _ctx: &mut Context<Self, Self::Reply>,
    ) -> Self::Reply {
        let project_id = msg
            .project_path
            .relative_path()
            .to_string_lossy()
            .to_string();
        tracing::info!(
            actor = %ACTOR_NAME,
            request_id = %msg.request_id,
            project_id = %project_id,
            "SignersInitialiser received propose signers request"
        );

        let project_dir = msg.project_path.absolute_path();

        // For updates, the project directory must already exist
        if !tokio::fs::try_exists(&project_dir).await? {
            tracing::error!(
                actor = %ACTOR_NAME,
                request_id = %msg.request_id,
                project_id = %project_id,
                "Project is not registered yet, which is required for a signers update."
            );
            return Err(ApiError::InvalidRequestBody(format!(
                "Project '{}' is not registered. Register the repo first.",
                project_id
            )));
        }

        let json = msg.signers_info.json();
        let meta = msg.metadata;
        let dir = project_dir.clone();
        let pubkey = msg.pubkey.clone();
        tokio::task::spawn_blocking(move || {
            signers_file::propose_signers_file(&dir, &json, meta, &pubkey)
        })
        .await
        .map_err(|e| {
            tracing::error!(
                actor = %ACTOR_NAME,
                request_id = %msg.request_id,
                project_id = %project_id,
                error = %e,
                "Spawn error"
            );
            e
        })?
        .map_err(|e| {
            tracing::error!(
                actor = %ACTOR_NAME,
                request_id = %msg.request_id,
                project_id = %project_id,
                error = %e,
                "propose_signers_file error"
            );
            e
        })?;

        tracing::info!(
            request_id = %msg.request_id,
            project_id = %project_id,
            "Successfully proposed signers file update"
        );
        let project_normalised_paths = msg.project_path.clone();
        let signers_normalised_paths = project_normalised_paths
            .join(PENDING_SIGNERS_DIR)
            .await?
            .join(SIGNERS_FILE)
            .await?;

        // Record the client-provided signatures
        let signature_with_state = {
            let signers_path = signers_normalised_paths.absolute_path().to_path_buf();
            let signature = msg.signers_signature.clone();
            let metadata_signature = msg.metadata_signature.clone();
            let pubkey = msg.pubkey.clone();
            tokio::task::spawn_blocking(move || {
                signers_file::sign_signers_and_metadata_file(
                    &signers_path,
                    &signature,
                    &pubkey,
                    &metadata_signature,
                )
            })
            .await??
        };

        let required_signers: Vec<String> = if signature_with_state.is_complete() {
            // If the signature is complete, the signers file has been activated: the
            // previous active signers file was moved to the history, and the proposed
            // file renamed, dropping the pending suffix.
            vec![]
        } else {
            // Collect required signers from the *proposed* config
            // (these are the admin/master keys that need to sign to activate)
            let pending_signers_path = signers_normalised_paths.absolute_path().to_path_buf();
            tokio::task::spawn_blocking(move || {
                features_lib::aggregate_signature_helpers::get_missing_signers(
                    &pending_signers_path,
                )
            })
            .await?
            .map_err(|e| {
                tracing::error!(
                    request_id = %msg.request_id,
                    error = %e,
                    path = %signers_normalised_paths,
                    "Failed to compute missing signers"
                );
                ApiError::ActorOperationFailed(format!("Failed to compute missing signers: {}", e))
            })?
            .into_iter()
            .map(|key: AsfaloadPublicKeys| key.to_base64())
            .collect()
        };

        Ok(ProposeSignersResult {
            project_path: msg.project_path,
            required_signers,
            request_id: msg.request_id,
        })
    }
}

impl Message<CleanupSignersRequest> for SignersInitialiser {
    type Reply = Result<(), ApiError>;

    #[tracing::instrument(skip(self, msg, _ctx))]
    async fn handle(
        &mut self,
        msg: CleanupSignersRequest,
        _ctx: &mut Context<Self, Self::Reply>,
    ) -> Self::Reply {
        tracing::info!(
            request_id = %msg.request_id,
            signers_file_path = %msg.signers_file_path,
            history_file_path = ?msg.history_file_path,
            pending_dir = %msg.pending_dir,
            "Cleaning up signers files"
        );

        let mut had_error = false;

        if let Some(ref history_file_path) = msg.history_file_path
            && let Err(e) = tokio::fs::remove_file(history_file_path).await
        {
            had_error = true;
            tracing::warn!(
                request_id = %msg.request_id,
                path = %history_file_path,
                error = %e,
                "Failed to remove history file during cleanup"
            );
        }

        if let Err(e) = tokio::fs::remove_dir_all(&msg.pending_dir).await {
            had_error = true;
            tracing::warn!(
                request_id = %msg.request_id,
                path = %msg.pending_dir,
                error = %e,
                "Failed to remove pending directory during cleanup"
            );
        }

        tracing::info!(
            request_id = %msg.request_id,
            "Cleanup completed"
        );

        if had_error {
            Err(ApiError::ActorOperationFailed("Cleanup failed".to_string()))
        } else {
            Ok(())
        }
    }
}

#[cfg(all(test, not(feature = "test-utils")))]
mod tests {
    use crate::file_auth::github::get_project_normalised_paths;

    use super::*;
    use anyhow::Result;
    use common::fs::names::metadata_path_for;
    use features_lib::SignersConfig;
    use kameo::actor::Spawn;
    use signers_file_types::{Forge, VerifiedForgeContent};

    /// Helper to create test InitialiseSignersRequest.
    fn build_test_init_request(
        project_path: NormalisedPaths,
        config: &SignersConfig,
        test_keys: &test_helpers::TestKeys,
        git_repo_path: std::path::PathBuf,
        request_id: &str,
    ) -> InitialiseSignersRequest {
        let signers_json = serde_json::to_string_pretty(config).unwrap();
        let signers_info = SignersInfo::from_string(&signers_json).unwrap();
        let metadata = SignersConfigMetadata::new(
            Forge::Github,
            "https://github.com/test/repo/blob/main/signers.json".to_string(),
            VerifiedForgeContent::new_for_test(
                "https://github.com/test/repo/blob/main/signers.json".to_string(),
                "test_hash_placeholder".to_string(),
            ),
            chrono::Utc::now(),
        );
        InitialiseSignersRequest {
            project_path,
            signers_info,
            metadata,
            git_repo_path,
            request_id: request_id.to_string(),
            pubkey: test_keys.pub_key(0).unwrap().clone(),
        }
    }

    #[tokio::test]
    async fn test_signers_initialiser_creates_directory_structure() -> Result<()> {
        let temp = tempfile::TempDir::new().unwrap();
        let git_path = temp.path().to_path_buf();

        // Use 2 signers so the signature stays pending after init (only key 0 signs).
        // With 1 signer, initialize_signers_file completes the signature immediately
        // and activates the signers file, renaming pending -> active.
        let test_keys = test_helpers::TestKeys::new(2);

        let config = SignersConfig::with_artifact_signers_only(
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

        let project_path = get_project_normalised_paths(&git_path, "github.com/test/repo").await?;
        let request = build_test_init_request(
            project_path,
            &config,
            &test_keys,
            git_path.clone(),
            "test-123",
        );

        let actor_ref = SignersInitialiser::spawn(());
        let result = actor_ref.ask(request).await;

        assert!(result.is_ok());
        let init_result = result.unwrap();

        let project_dir = git_path.join("github.com/test/repo");
        let signers_pending_dir = project_dir.join("asfaload.signers.pending");
        assert!(signers_pending_dir.exists());
        assert!(init_result.signers_file_path.absolute_path().exists());
        assert!(init_result.history_file_path.absolute_path().exists());

        // Verify metadata file was created
        let metadata_path = metadata_path_for(init_result.signers_file_path.absolute_path())
            .expect("Failed to build metadata path");
        assert!(metadata_path.exists(), "metadata file should exist");

        let history_content =
            tokio::fs::read_to_string(&init_result.history_file_path.absolute_path())
                .await
                .unwrap();
        let history =
            HistoryFile::from_json(&history_content).expect("History file should be valid JSON");
        assert!(
            history.entries().is_empty(),
            "History file should have no entries"
        );

        let signers_content =
            tokio::fs::read_to_string(&init_result.signers_file_path.absolute_path())
                .await
                .unwrap();
        let parsed_config: SignersConfig = serde_json::from_str(&signers_content).unwrap();
        assert_eq!(parsed_config.artifact_signers().len(), 1);
        Ok(())
    }

    #[tokio::test]
    async fn test_signers_initialiser_extract_public_keys() -> Result<()> {
        let temp = tempfile::TempDir::new().unwrap();
        let git_path = temp.path().to_path_buf();

        let test_keys = test_helpers::TestKeys::new(2);

        let config = SignersConfig::with_artifact_signers_only(
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
        let project_path = get_project_normalised_paths(&git_path, "github.com/test/repo").await?;

        let request = build_test_init_request(
            project_path,
            &config,
            &test_keys,
            git_path.clone(),
            "test-456",
        );

        let actor_ref = SignersInitialiser::spawn(());
        let result = actor_ref.ask(request).await;

        assert!(result.is_ok());
        let init_result = result.unwrap();

        // No signing during initialization, so both keys should be missing
        assert_eq!(init_result.required_signers.len(), 2);
        assert!(
            init_result
                .required_signers
                .contains(&test_keys.pub_key(0).unwrap().to_base64()),
            "Key 0 should be in required_signers"
        );
        assert!(
            init_result
                .required_signers
                .contains(&test_keys.pub_key(1).unwrap().to_base64()),
            "Key 1 should be in required_signers"
        );
        Ok(())
    }

    #[tokio::test]
    async fn test_signers_initialiser_handles_existing_directory() -> Result<()> {
        let temp = tempfile::TempDir::new().unwrap();
        let git_path = temp.path().to_path_buf();

        let project_dir = git_path.join("github.com/test/existing");
        let signers_pending_dir = project_dir.join("asfaload.signers.pending");
        tokio::fs::create_dir_all(&project_dir).await.unwrap();
        tokio::fs::write(&signers_pending_dir, "").await.unwrap();

        let test_keys = test_helpers::TestKeys::new(1);
        let public_key = test_keys.pub_key(0).unwrap().clone();

        let config = SignersConfig::with_artifact_signers_only(1, (vec![public_key], 1)).unwrap();
        let project_path =
            get_project_normalised_paths(&git_path, "github.com/test/existing").await?;

        let request = build_test_init_request(
            project_path,
            &config,
            &test_keys,
            git_path.clone(),
            "test-exists-001",
        );

        let actor_ref = SignersInitialiser::spawn(());
        let result = actor_ref.ask(request).await;

        match result {
            Ok(_) => panic!("Expected error for existing directory"),
            Err(send_error) => match send_error {
                kameo::error::SendError::HandlerError(api_error) => match api_error {
                    ApiError::ProjectAlreadyRegistered(msg) => {
                        assert!(msg.contains("already registered"));
                    }
                    _ => panic!("Expected ProjectAlreadyRegistered error for existing directory"),
                },
                _ => panic!("Expected HandlerError for existing directory"),
            },
        }
        Ok(())
    }

    /// Helper to create test ProposeSignersRequest.
    fn build_test_propose_request(
        project_path: NormalisedPaths,
        config: &SignersConfig,
        test_keys: &test_helpers::TestKeys,
        signer_index: usize,
        request_id: &str,
    ) -> ProposeSignersRequest {
        let signers_json = serde_json::to_string_pretty(config).unwrap();
        let signers_info = SignersInfo::from_string(&signers_json).unwrap();
        let metadata = SignersConfigMetadata::new(
            Forge::Github,
            "https://github.com/test/repo/blob/main/signers.json".to_string(),
            VerifiedForgeContent::new_for_test(
                "https://github.com/test/repo/blob/main/signers.json".to_string(),
                "test_hash_placeholder".to_string(),
            ),
            chrono::Utc::now(),
        );
        ProposeSignersRequest {
            project_path,
            signers_info,
            metadata,
            request_id: request_id.to_string(),
            pubkey: test_keys.pub_key(signer_index).unwrap().clone(),
        }
    }

    #[tokio::test]
    async fn test_propose_signers_returns_missing_signers() -> Result<()> {
        use features_lib::{AsfaloadSecretKeyTrait, sha512_for_file};

        let temp = tempfile::TempDir::new().unwrap();
        let git_path = temp.path().to_path_buf();

        let test_keys = test_helpers::TestKeys::new(3);

        // Step 1: Initialize with a 1-signer config.
        let init_config = SignersConfig::with_artifact_signers_only(
            1,
            (vec![test_keys.pub_key(0).unwrap().clone()], 1),
        )
        .unwrap();

        let project_path = get_project_normalised_paths(&git_path, "github.com/test/repo").await?;
        let init_request = build_test_init_request(
            project_path,
            &init_config,
            &test_keys,
            git_path.clone(),
            "init-001",
        );

        let actor_ref = SignersInitialiser::spawn(());
        let init_result = actor_ref.ask(init_request).await;
        assert!(
            init_result.is_ok(),
            "Init should succeed: {:?}",
            init_result
        );

        // Step 1b: Sign the signers file and metadata to activate them.
        let init_res = init_result.unwrap();
        let signers_file_path = init_res.signers_file_path.absolute_path();
        let metadata_path = metadata_path_for(&signers_file_path)?;

        // Sign the signers file and metadata to activate
        let signers_digest = sha512_for_file(&signers_file_path)?;
        let signers_sig = test_keys.sec_key(0).unwrap().sign(&signers_digest)?;
        let metadata_digest = sha512_for_file(&metadata_path)?;
        let metadata_sig = test_keys.sec_key(0).unwrap().sign(&metadata_digest)?;
        signers_file::sign_signers_and_metadata_file(
            &signers_file_path,
            &signers_sig,
            test_keys.pub_key(0).unwrap(),
            &metadata_sig,
        )?;

        // Step 2: Propose an update with 3 signers, signed by key0.
        // key0 is valid for updates because admin_keys() falls back to
        // artifact_signers when no explicit admin keys are set.
        let propose_config = SignersConfig::with_artifact_signers_only(
            2,
            (
                vec![
                    test_keys.pub_key(0).unwrap().clone(),
                    test_keys.pub_key(1).unwrap().clone(),
                    test_keys.pub_key(2).unwrap().clone(),
                ],
                2,
            ),
        )
        .unwrap();

        // Re-obtain project_path (the original was moved into init_request)
        let project_path = get_project_normalised_paths(&git_path, "github.com/test/repo").await?;
        let propose_request = build_test_propose_request(
            project_path,
            &propose_config,
            &test_keys,
            0, // key0 signs the proposal
            "propose-001",
        );

        let result = actor_ref.ask(propose_request).await;
        assert!(result.is_ok(), "Propose should succeed: {:?}", result);
        let propose_result = result.unwrap();

        // Step 3: Verify required_signers.
        // No signing during propose_signers_file, so all 3 signers should be missing.
        let key0_b64 = test_keys.pub_key(0).unwrap().to_base64();
        let key1_b64 = test_keys.pub_key(1).unwrap().to_base64();
        let key2_b64 = test_keys.pub_key(2).unwrap().to_base64();

        assert_eq!(
            propose_result.required_signers.len(),
            3,
            "Should have 3 missing signers (all keys), got: {:?}",
            propose_result.required_signers
        );
        assert!(
            propose_result.required_signers.contains(&key0_b64),
            "key0 has not signed yet, should be in required_signers"
        );
        assert!(
            propose_result.required_signers.contains(&key1_b64),
            "key1 has not signed yet, should be in required_signers"
        );
        assert!(
            propose_result.required_signers.contains(&key2_b64),
            "key2 has not signed yet, should be in required_signers"
        );

        Ok(())
    }
}
