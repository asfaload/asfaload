use common::fs::names::{
    find_global_signers_for, revocation_path_for, revocation_signatures_path_for,
    revocation_signers_path_for, subject_path_from_pending_signatures,
};
use common::sha512_for_file;
use constants::SIGNERS_DIR;
use features_lib::{AsfaloadPublicKeyTrait, AsfaloadSignatureTrait, SignersConfig};
use rest_api_types::models::{
    GetArtifactInfoResponse, PendingFile, UpdateRepoSignersRequest, UpdateRepoSignersResponse,
};
use rest_api_types::{
    FilesToSignResponse, GetSignatureStatusResponse, GetSignersChainResponse, ListPendingResponse,
    PingAuthStatus, PingResponse, RegisterRepoRequest, RegisterRepoResponse, RevokeFileRequest,
    RevokeFileResponse, SubmitSignatureRequest, SubmitSignatureResponse,
};
use std::{collections::HashMap, path::PathBuf, str::FromStr};

use crate::auth_middleware::{AuthOutcome, validate_auth};
use crate::file_auth::forges::ForgeInfo;
use crate::file_auth::forges::ForgeTrait;
use crate::file_auth::github::get_project_normalised_paths;
use crate::state::AppState;
use axum::{Json, extract::State, http::HeaderMap};
use constants::PENDING_SIGNERS_DIR;
use forge_url::ForgesPathMethods;
use forge_url::forges::{Forges, get_forge};
use forge_url::github::GITHUB_HOSTS;
use rest_api_auth::HEADER_PUBLIC_KEY;
use rest_api_types::errors::ApiError;
use rest_api_types::path_validation::NormalisedPaths;
pub fn map_to_user_error<M>(
    error: kameo::error::SendError<M, ApiError>,
    context: &str,
) -> ApiError {
    match error {
        kameo::error::SendError::HandlerError(api_error) => api_error,
        other => {
            tracing::error!(internal_error = %other, "{}", context);
            ApiError::InternalServerError(
                "Operation failed. Please check your request and try again.".to_string(),
            )
        }
    }
}

pub async fn register_repo_handler(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<RegisterRepoRequest>,
) -> Result<Json<RegisterRepoResponse>, ApiError> {
    let request_id = headers
        .get("x-request-id")
        .and_then(|h| h.to_str().ok())
        .unwrap_or("unknown");

    tracing::info!(
        request_id = %request_id,
        signers_file_url = %request.signers_file_url,
        "Received register_repo request"
    );

    let parsed_url = url::Url::parse(&request.signers_file_url)
        .map_err(|e| ApiError::InvalidRequestBody(e.to_string()))?;
    let repo_info = ForgeInfo::new(&parsed_url).map_err(|e| {
        tracing::error!(
            request_id = %request_id,
            url = %request.signers_file_url,
            error = %e,
            "Failed to parse GitHub URL"
        );
        ApiError::InvalidRequestBody(format!("Invalid GitHub URL: {}", e))
    })?;

    let project_id = repo_info.project_id();
    let project_normalised_paths = get_project_normalised_paths(&state.git_repo_path, &project_id)
        .await
        .map_err(|e| {
            tracing::error!(
                request_id = %request_id,
                project_id = %project_id,
                error = %e,
                "Failed to get normalised paths in handlers"
            );
            e
        })?;

    let project_dir = project_normalised_paths.absolute_path();
    if tokio::fs::try_exists(&project_dir).await? {
        tracing::warn!(
            request_id = %request_id,
            project_id = %project_id,
            "Project directory structure already exists, indicating a pending or completed registration."
        );
        return Err(ApiError::ProjectAlreadyRegistered(format!(
            "Project '{}' is already registered or registration is in progress.",
            project_id
        )));
    }
    let auth_request = crate::file_auth::actors::forge_signers_validator::ValidateProjectRequest {
        signers_file_url: parsed_url,
        request_id: request_id.to_string(),
    };

    let signers_proposal = state
        .forge_project_validator
        .ask(auth_request)
        .await
        .map_err(|e| map_to_user_error(e, "Project authentication failed"))?;

    // Construct metadata from forge information
    let forge_kind = match &repo_info {
        ForgeInfo::Github(_) => signers_file_types::Forge::Github,
        ForgeInfo::Gitlab(_) => signers_file_types::Forge::Gitlab,
        ForgeInfo::FileServer(_) => signers_file_types::Forge::FileServer,
    };
    let metadata = signers_file_types::SignersConfigMetadata::from_forge(
        signers_file_types::ForgeOrigin::new(
            forge_kind,
            request.signers_file_url.clone(),
            signers_proposal.verified_content,
            chrono::Utc::now(),
        ),
    );

    // Parse the submitter's public key for authorization
    let pubkey = features_lib::AsfaloadPublicKeys::from_base64(&request.public_key)
        .map_err(|e| ApiError::InvalidRequestBody(format!("Invalid public key: {}", e)))?;

    // Step 2: Initialise signers - create directory structure and files
    let init_request = crate::file_auth::actors::signers_initialiser::InitialiseSignersRequest {
        project_path: project_normalised_paths,
        signers_info: signers_proposal.signers_info,
        metadata,
        git_repo_path: state.git_repo_path.clone(),
        request_id: request_id.to_string(),
        pubkey,
    };

    let init_result = state
        .signers_initialiser
        .ask(init_request)
        .await
        .map_err(|e| map_to_user_error(e, "Signers initialisation failed"))?;

    // Step 3: Write and commit files via Git actor
    let write_commit_request = crate::file_auth::actors::git_actor::CommitFile {
        file_paths: vec![init_result.project_path.clone()],
        commit_message: format!(
            "Adding {}",
            init_result.project_path.relative_path().display()
        ),
        request_id: request_id.to_string(),
    };

    let git_actor_result = state.git_actor.ask(write_commit_request).await;

    if let Err(e) = git_actor_result {
        tracing::error!(
            request_id = %request_id,
            error = %e,
            "Git actor commit failed, initiating cleanup"
        );

        match init_result.project_path.join(PENDING_SIGNERS_DIR).await {
            Ok(pending_dir) => {
                let cleanup_request =
                    crate::file_auth::actors::signers_initialiser::CleanupSignersRequest {
                        signers_file_path: init_result.signers_file_path.clone(),
                        history_file_path: Some(init_result.history_file_path.clone()),
                        pending_dir,
                        request_id: request_id.to_string(),
                    };

                if let Err(cleanup_err) = state.signers_initialiser.ask(cleanup_request).await {
                    tracing::error!(
                        request_id = %request_id,
                        error = %cleanup_err,
                        "Cleanup also failed"
                    );
                }
            }
            Err(join_err) => {
                tracing::error!(
                    request_id = %request_id,
                    error = %join_err,
                    "Failed to construct pending_dir path for cleanup"
                );
            }
        }

        return Err(map_to_user_error(
            e,
            "Git write and commit operation failed",
        ));
    }

    tracing::info!(
        request_id = %request_id,
        project_id = %signers_proposal.project_id,
        "Repo handler write and commit succeeded"
    );

    tracing::info!(
        request_id = %request_id,
        project_id = %signers_proposal.project_id,
        "Project registration completed successfully"
    );

    Ok(Json(RegisterRepoResponse {
        success: true,
        project_id: signers_proposal.project_id,
        message: "Project registered successfully. Collect signatures to activate.".to_string(),
        required_signers: init_result.required_signers.into_iter().collect(),
        signature_submission_url: "/v1/signatures".to_string(),
    }))
}

pub async fn update_signers_handler(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<UpdateRepoSignersRequest>,
) -> Result<Json<UpdateRepoSignersResponse>, ApiError> {
    let request_id = headers
        .get("x-request-id")
        .and_then(|h| h.to_str().ok())
        .unwrap_or("unknown");

    tracing::info!(
        request_id = %request_id,
        signers_file_url = %request.signers_file_url,
        "Received update_signers request"
    );

    let parsed_url = url::Url::parse(&request.signers_file_url)
        .map_err(|e| ApiError::InvalidRequestBody(e.to_string()))?;
    let repo_info = ForgeInfo::new(&parsed_url).map_err(|e| {
        tracing::error!(
            request_id = %request_id,
            url = %request.signers_file_url,
            error = %e,
            "Failed to parse forge URL"
        );
        ApiError::InvalidRequestBody(format!("Invalid forge URL: {}", e))
    })?;

    let project_id = repo_info.project_id();
    let project_normalised_paths = get_project_normalised_paths(&state.git_repo_path, &project_id)
        .await
        .map_err(|e| {
            tracing::error!(
                request_id = %request_id,
                project_id = %project_id,
                error = %e,
                "Failed to get normalised paths"
            );
            e
        })?;

    // For updates, the project directory must already exist
    let project_dir = project_normalised_paths.absolute_path();
    if !tokio::fs::try_exists(&project_dir).await? {
        return Err(ApiError::InvalidRequestBody(format!(
            "Project '{}' is not registered. Register the repo first.",
            project_id
        )));
    }

    // The signers directory must also exist (project fully initialized)
    let signers_dir = project_dir.join(SIGNERS_DIR);
    if !tokio::fs::try_exists(&signers_dir).await? {
        return Err(ApiError::InvalidRequestBody(format!(
            "Project '{}' has no active signers file. Complete initial registration first.",
            project_id
        )));
    }

    // Validate the signers file from the forge
    let auth_request = crate::file_auth::actors::forge_signers_validator::ValidateProjectRequest {
        signers_file_url: parsed_url,
        request_id: request_id.to_string(),
    };

    let signers_proposal = state
        .forge_project_validator
        .ask(auth_request)
        .await
        .map_err(|e| map_to_user_error(e, "Project validation failed"))?;

    // Construct metadata from forge information
    let forge_kind = match &repo_info {
        ForgeInfo::Github(_) => signers_file_types::Forge::Github,
        ForgeInfo::Gitlab(_) => signers_file_types::Forge::Gitlab,
        ForgeInfo::FileServer(_) => signers_file_types::Forge::FileServer,
    };
    let metadata = signers_file_types::SignersConfigMetadata::from_forge(
        signers_file_types::ForgeOrigin::new(
            forge_kind,
            request.signers_file_url.clone(),
            signers_proposal.verified_content,
            chrono::Utc::now(),
        ),
    );

    // Parse the submitter's public key for authorization
    let pubkey = features_lib::AsfaloadPublicKeys::from_base64(&request.public_key)
        .map_err(|e| ApiError::InvalidRequestBody(format!("Invalid public key: {}", e)))?;

    // Propose signers file update
    let propose_request = crate::file_auth::actors::signers_initialiser::ProposeSignersRequest {
        project_path: project_normalised_paths.clone(),
        signers_info: signers_proposal.signers_info,
        metadata,
        request_id: request_id.to_string(),
        pubkey,
    };

    let propose_result = state
        .signers_initialiser
        .ask(propose_request)
        .await
        .map_err(|e| map_to_user_error(e, "Signers proposal failed"))?;

    // Commit the changes via Git actor
    let write_commit_request = crate::file_auth::actors::git_actor::CommitFile {
        file_paths: vec![propose_result.project_path.clone()],
        commit_message: format!(
            "Proposed signers update for {}",
            propose_result.project_path.relative_path().display()
        ),
        request_id: request_id.to_string(),
    };

    let git_actor_result = state.git_actor.ask(write_commit_request).await;

    if let Err(e) = git_actor_result {
        tracing::error!(
            request_id = %request_id,
            error = %e,
            "Git actor commit failed, initiating cleanup"
        );

        match propose_result.project_path.join(PENDING_SIGNERS_DIR).await {
            Ok(pending_dir) => {
                let cleanup_request =
                    crate::file_auth::actors::signers_initialiser::CleanupSignersRequest {
                        signers_file_path: propose_result.project_path.clone(),
                        history_file_path: None,
                        pending_dir,
                        request_id: request_id.to_string(),
                    };

                if let Err(cleanup_err) = state.signers_initialiser.ask(cleanup_request).await {
                    tracing::error!(
                        request_id = %request_id,
                        error = %cleanup_err,
                        "Cleanup also failed"
                    );
                }
            }
            Err(join_err) => {
                tracing::error!(
                    request_id = %request_id,
                    error = %join_err,
                    "Failed to construct pending_dir path for cleanup"
                );
            }
        }

        return Err(map_to_user_error(
            e,
            "Git write and commit operation failed",
        ));
    }

    tracing::info!(
        request_id = %request_id,
        project_id = %signers_proposal.project_id,
        "Signers update proposal completed successfully"
    );

    Ok(Json(UpdateRepoSignersResponse {
        success: true,
        project_id: signers_proposal.project_id,
        message: "Signers update proposed successfully. Collect signatures to activate."
            .to_string(),
        required_signers: propose_result.required_signers,
        signature_submission_url: "/v1/signatures".to_string(),
    }))
}

/// Handle signature submission for a specific file.
///
/// This endpoint accepts individual signatures for any file that has an aggregate signature.
/// The signature is validated and added to the collection. Changes are committed to Git after
/// each signature is collected to prevent data loss.
///
/// # Arguments
/// * `state` - Application state containing actor references
/// * `headers` - HTTP headers (must include x-request-id for tracing)
/// * `request` - Signature submission with file_path, public_key, and signature
///
/// # Returns
/// Returns a response indicating whether signature collection is complete
///
/// # Errors
/// Returns `ApiError` if:
/// - File path is invalid or file doesn't exist
/// - Public key or signature format is invalid
/// - Signature verification fails
/// - Git commit fails
pub async fn submit_signature_handler(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<SubmitSignatureRequest>,
) -> Result<Json<SubmitSignatureResponse>, ApiError> {
    let request_id = headers
        .get("x-request-id")
        .and_then(|h| h.to_str().ok())
        .unwrap_or("unknown");

    tracing::info!(
        request_id = %request_id,
        file_path = %request.pending_file,
        "Received submit_signature request"
    );

    // Normalize and validate the file path
    let file_path = NormalisedPaths::new(
        state.git_repo_path.clone(),
        PathBuf::from(request.pending_file.path()),
    )
    .await?;

    // Check if the file exists
    if !file_path.absolute_path().exists() {
        return Err(ApiError::InvalidRequestBody(format!(
            "File not found: {}",
            request.pending_file
        )));
    }

    // Consistency check of digest sent
    let digest_on_disk = sha512_for_file(file_path.absolute_path())?;
    if *request.pending_file.digest() != digest_on_disk {
        return Err(ApiError::DigestMismatch(
            "Digest sent is different from digest of file on disk at path sent.".into(),
        ));
    }
    // Parse public key from base64 string
    let public_key = features_lib::AsfaloadPublicKeys::from_base64(&request.public_key)
        .map_err(|_| ApiError::InvalidRequestBody("Invalid public key format".to_string()))?;

    // Parse all signatures from the request map
    let mut parsed_signatures = std::collections::HashMap::new();
    for (path_str, sig_b64) in &request.signatures {
        let sig = features_lib::AsfaloadSignatures::from_base64(sig_b64).map_err(|_| {
            ApiError::InvalidRequestBody(format!("Invalid signature format for path: {}", path_str))
        })?;
        parsed_signatures.insert(PathBuf::from(path_str), sig);
    }

    // Verify the primary file has a signature
    let primary_path = PathBuf::from(&request.pending_file.path());
    if !parsed_signatures.contains_key(&primary_path) {
        return Err(ApiError::InvalidRequestBody(format!(
            "No signature provided for primary file: {}",
            request.pending_file
        )));
    }

    // Send signature collection request to the actor
    let collector_request =
        crate::file_auth::actors::signature_collector::CollectSignatureRequest {
            file_path: file_path.clone(),
            public_key,
            signatures: parsed_signatures,
            request_id: request_id.to_string(),
        };

    let collector_result = state
        .signature_collector
        .ask(collector_request)
        .await
        .map_err(|e| map_to_user_error(e, "Signature collection failed"))?;

    tracing::info!(
        request_id = %request_id,
        file_path = %request.pending_file,
        is_complete = collector_result.is_complete,
        "Signature collection result"
    );

    Ok(Json(SubmitSignatureResponse {
        is_complete: collector_result.is_complete,
    }))
}

/// Query the current signature status for a specific file.
///
/// Returns information about the aggregate signature for a file, including
/// whether it's complete and how many signatures have been collected.
///
/// # Arguments
/// * `state` - Application state containing actor references
/// * `headers` - HTTP headers (must include x-request-id for tracing)
/// * `file_path` - Path to the file from the URL path parameter
///
/// # Returns
/// Returns the current status of signature collection including completion
/// status and count of collected signatures
///
/// # Errors
/// Returns `ApiError` if:
/// - File path is invalid or file doesn't exist
/// - Failed to load signature status from disk
pub async fn get_signature_status_handler(
    State(state): State<AppState>,
    headers: HeaderMap,
    axum::extract::Path(file_path): axum::extract::Path<String>,
) -> Result<Json<GetSignatureStatusResponse>, ApiError> {
    let request_id = headers
        .get("x-request-id")
        .and_then(|h| h.to_str().ok())
        .unwrap_or("unknown");

    tracing::info!(
        request_id = %request_id,
        file_path = %file_path,
        "Received get_signature_status request"
    );

    if file_path.is_empty() {
        return Err(ApiError::InvalidRequestBody(
            "File path cannot be empty".to_string(),
        ));
    }

    // Normalize and validate the file path
    let file_path = NormalisedPaths::new(
        state.git_repo_path.clone(),
        PathBuf::from_str(file_path.as_ref()).unwrap(),
    )
    .await?;

    if !file_path.absolute_path().exists() {
        return Err(ApiError::FileNotFound(format!(
            "File not found: {}",
            file_path.relative_path().to_string_lossy()
        )));
    }

    // Verify caller is an authorized signer for this file
    // Note that we look at the current global signers file, not the local copy taken when the
    // signature was completed. If a key has been removed from the signers file, we might have the
    // situation where a key that signed the file can't check its status. This seems sensible, as
    // the key might have been removed for security reasons.
    let public_key = extract_public_key_from_headers(&headers)?;
    let signers_config = tokio::task::spawn_blocking({
        let file_path = file_path.clone();
        let request_id = request_id.to_string();
        move || -> Result<SignersConfig, ApiError> {
            let signers_path =
                find_global_signers_for(&file_path.absolute_path()).map_err(|e| {
                    tracing::error!(
                        request_id = %request_id,
                        error = %e,
                        "No signers file found"
                    );
                    ApiError::FileNotFound(format!(
                        "No signers file found for: {}",
                        file_path.relative_path().display()
                    ))
                })?;
            Ok(SignersConfig::from_file(&signers_path)?)
        }
    })
    .await
    // First '?': JoinError (mapped above)
    // Second '?': ApiError returned from the closure
    .map_err(|e| ApiError::InternalServerError(format!("Task join error: {}", e)))??;
    if !signers_config.all_signer_keys().contains(&public_key) {
        return Err(ApiError::NotAuthorized(format!(
            "caller is not an authorized signer for {}",
            file_path.relative_path().display()
        )));
    }

    // Send status request to the actor
    let status_request = crate::file_auth::actors::signature_collector::GetSignatureStatusRequest {
        file_path: file_path.clone(),
        request_id: request_id.to_string(),
    };

    let status = state
        .signature_collector
        .ask(status_request)
        .await
        .map_err(|e| map_to_user_error(e, "Signature status query failed"))?;

    Ok(Json(GetSignatureStatusResponse {
        file_path: file_path.relative_path().display().to_string(),
        is_complete: status.is_complete,
    }))
}

/// Handler to list all pending signature files for a specific signer.
///
/// Returns a list of file paths where the authenticated signer is authorized
/// to sign but has not yet submitted their signature.
///
/// # Arguments
/// * `state` - Application state with git repo path and actors
/// * `headers` - HTTP headers (must include authentication headers signed by the signer)
///
/// # Returns
/// Returns JSON response with list of file paths needing the signer's signature
///
/// # Errors
/// Returns `ApiError` if:
/// - Authentication headers are missing or invalid
/// - Failed to scan repository for pending files
/// - Failed to check signer authorization
pub async fn get_pending_signatures_handler(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<ListPendingResponse>, ApiError> {
    use crate::pending_discovery;
    use rest_api_types::path_validation::build_normalised_absolute_path;

    let request_id = headers
        .get("x-request-id")
        .and_then(|h| h.to_str().ok())
        .unwrap_or("unknown");

    tracing::info!(
        request_id = %request_id,
        "Received list_pending_signatures request"
    );

    // Extract public key from authentication headers
    let public_key = extract_public_key_from_headers(&headers)?;

    // Create base path NormalisedPaths for scanning from repo root
    let base_path = build_normalised_absolute_path(state.git_repo_path.clone(), PathBuf::from("."))
        .map_err(|e| ApiError::InvalidFilePath(format!("Failed to normalize base path: {}", e)))?;

    // Find pending files for this signer
    let discovery = pending_discovery::create_default_discovery();
    let pending_files = discovery
        .find_pending_for_signer(&base_path, &public_key)
        .map_err(|e| {
            tracing::error!(
                request_id = %request_id,
                error = %e,
                "Failed to find pending signatures"
            );
            ApiError::InternalServerError("Failed to find pending signatures".to_string())
        })?;

    // Extract relative paths and convert from pending signature files to artifact files
    let file_paths: Vec<PendingFile> = pending_files
        .iter()
        .map(|np| {
            let pending_sig_path = np.relative_path();
            let artifact_relative = subject_path_from_pending_signatures(&pending_sig_path)?;
            let artifact_np = build_normalised_absolute_path(np.base_dir(), artifact_relative)?;
            let r = PendingFile::try_new(&artifact_np)?;
            Ok(r)
        })
        .collect::<Result<Vec<_>, ApiError>>()?;

    tracing::info!(
        request_id = %request_id,
        count = %file_paths.len(),
        "Returning pending signatures list"
    );

    Ok(Json(ListPendingResponse {
        pending_files: file_paths,
    }))
}

/// Helper to extract public key from authentication headers.
fn extract_public_key_from_headers(
    headers: &HeaderMap,
) -> Result<features_lib::AsfaloadPublicKeys, ApiError> {
    let pub_key_header = headers
        .get(HEADER_PUBLIC_KEY)
        .ok_or_else(|| ApiError::MissingAuthenticationHeaders)?
        .to_str()
        .map_err(|_| ApiError::InvalidAuthenticationHeaders)?;

    features_lib::AsfaloadPublicKeys::from_base64(pub_key_header)
        .map_err(|_| ApiError::InvalidAuthenticationHeaders)
}

/// Handler to fetch a file's raw content from the repository.
///
/// Returns the raw file content as bytes. Used by client CLI to fetch files
/// that need to be signed (e.g., in the sign-pending workflow).
///
/// # Arguments
/// * `state` - Application state with git repo path
/// * `axum::extract::Path(file_path)` - URL path parameter containing the file path
///
/// # Returns
/// The raw file content as bytes with appropriate content-type header
///
/// # Errors
/// Returns `ApiError` if:
/// - File path is invalid or contains traversal attempts
/// - File does not exist
/// - File cannot be read
pub async fn get_file_handler(
    State(state): State<AppState>,
    headers: HeaderMap,
    axum::extract::Path(file_path): axum::extract::Path<String>,
) -> Result<(axum::http::StatusCode, axum::http::HeaderMap, Vec<u8>), ApiError> {
    use axum::http::header;

    let request_id = headers
        .get("x-request-id")
        .and_then(|h| h.to_str().ok())
        .unwrap_or("unknown");

    tracing::info!(
        request_id = %request_id,
        file_path = %file_path,
        "Received file fetch request"
    );

    // The file_path we get is sanitised, and making it normalised
    // further validates it against path traversals
    let normalised_paths = NormalisedPaths::new(state.git_repo_path, PathBuf::from(&file_path))
        .await
        .map_err(|e| ApiError::InvalidFilePath(format!("Invalid file path: {}", e)))?;

    let absolute_path = normalised_paths.absolute_path();

    // Verify the file exists
    if !absolute_path.exists() {
        tracing::warn!(
            request_id = %request_id,
            file_path = %file_path,
            absolute_path = %absolute_path.display(),
            "File not found"
        );
        return Err(ApiError::FileNotFound(format!(
            "File not found: {}",
            file_path
        )));
    }

    // Verify it's a file (not a directory)
    if !absolute_path.is_file() {
        tracing::warn!(
            request_id = %request_id,
            file_path = %file_path,
            absolute_path = %absolute_path.display(),
            "Path requested is not a file"
        );
        return Err(ApiError::InvalidFilePath(format!(
            "Path is not a file: {}",
            file_path
        )));
    }

    // Read the file content
    let content = tokio::fs::read(&absolute_path).await.map_err(|e| {
        tracing::error!(
            request_id = %request_id,
            file_path = %file_path,
            error = %e,
            "Failed to read file"
        );
        ApiError::InternalServerError(format!("Failed to read file: {}", e))
    })?;

    tracing::info!(
        request_id = %request_id,
        file_path = %file_path,
        size = content.len(),
        "Successfully read file"
    );

    // Build response headers
    let mut headers = axum::http::HeaderMap::new();
    headers.insert(
        header::CONTENT_TYPE,
        header::HeaderValue::from_static("application/octet-stream"),
    );
    headers.insert(
        header::CONTENT_LENGTH,
        header::HeaderValue::from_str(&content.len().to_string())
            .unwrap_or_else(|_| header::HeaderValue::from_static("0")),
    );

    Ok((axum::http::StatusCode::OK, headers, content))
}

/// Handler to return all files that need to be signed for a given file path.
///
/// For signers files, this includes both the signers file itself and
/// its metadata file. For other files, only the primary file is returned.
/// File contents are base64-encoded in the response.
///
/// # Arguments
/// * `state` - Application state with git repo path
/// * `file_path` - URL path parameter containing the file path
///
/// # Returns
/// A map of relative file paths to their base64-encoded contents
///
/// # Errors
/// Returns `ApiError` if:
/// - File path is invalid
/// - File does not exist
/// - File cannot be read
pub async fn get_files_to_sign_handler(
    State(state): State<AppState>,
    headers: HeaderMap,
    axum::extract::Path(file_path): axum::extract::Path<String>,
) -> Result<Json<FilesToSignResponse>, ApiError> {
    use base64::Engine;

    let normalised_paths =
        NormalisedPaths::new(state.git_repo_path.clone(), PathBuf::from(&file_path))
            .await
            .map_err(|e| ApiError::InvalidFilePath(format!("Invalid file path: {}", e)))?;

    let absolute_path = normalised_paths.absolute_path();

    if !absolute_path.exists() || !absolute_path.is_file() {
        return Err(ApiError::FileNotFound(format!(
            "File not found: {}",
            file_path
        )));
    }

    // Extract and validate the signer's public key from auth headers
    let _public_key = extract_public_key_from_headers(&headers)?;

    let mut files = HashMap::new();

    // Read the primary file
    let content = tokio::fs::read(&absolute_path)
        .await
        .map_err(|e| ApiError::InternalServerError(format!("Failed to read file: {}", e)))?;
    let relative_path = normalised_paths
        .relative_path()
        .to_string_lossy()
        .to_string();
    files.insert(
        relative_path.clone(),
        base64::engine::general_purpose::STANDARD.encode(&content),
    );

    // If it's a signers file, also include the metadata file
    let signed_file = common::SignedFileLoader::load(&absolute_path).map_err(|e| {
        ApiError::InternalServerError(format!("Failed to determine file type: {}", e))
    })?;
    if signed_file.is_initial_signers() || signed_file.is_signers() {
        let metadata_path = common::fs::names::metadata_path_for(&absolute_path).map_err(|e| {
            ApiError::InternalServerError(format!("Failed to compute metadata path: {}", e))
        })?;
        if metadata_path.exists() {
            let metadata_content = tokio::fs::read(&metadata_path).await.map_err(|e| {
                ApiError::InternalServerError(format!("Failed to read metadata file: {}", e))
            })?;
            let metadata_relative =
                common::fs::names::metadata_path_for(&relative_path).map_err(|e| {
                    ApiError::InternalServerError(format!(
                        "Failed to compute metadata relative path: {}",
                        e
                    ))
                })?;
            files.insert(
                metadata_relative.to_string_lossy().to_string(),
                base64::engine::general_purpose::STANDARD.encode(&metadata_content),
            );
        } else {
            return Err(ApiError::InternalServerError(format!(
                "Metadata file not found for signers file: {}",
                metadata_path.display()
            )));
        }
    }

    Ok(Json(FilesToSignResponse { files }))
}

/// Handler to fetch the signers file for a given file path.
///
/// This endpoint takes a file path and returns the signers configuration
/// that applies to that file. It uses find_global_signers_for to locate
/// the appropriate signers file by traversing parent directories.
///
/// # Arguments
/// * `state` - Application state with git repo path
/// * `axum::extract::Path(file_path)` - URL path parameter containing the file path
///
/// # Returns
/// The signers file content as JSON
///
/// # Errors
/// Returns `ApiError` if:
/// - File path is invalid or contains traversal attempts
/// - No signers file found for the given path
/// - Signers file cannot be read
pub async fn get_signers_handler(
    State(state): State<AppState>,
    headers: HeaderMap,
    axum::extract::Path(file_path): axum::extract::Path<String>,
) -> Result<(axum::http::StatusCode, axum::http::HeaderMap, Vec<u8>), ApiError> {
    use axum::http::header;
    use common::fs::names::find_global_signers_for;

    let request_id = headers
        .get("x-request-id")
        .and_then(|h| h.to_str().ok())
        .unwrap_or("unknown");

    tracing::info!(
        request_id = %request_id,
        file_path = %file_path,
        "Received get_signers request"
    );

    // Normalize the file path
    let normalised_paths =
        NormalisedPaths::new(state.git_repo_path.clone(), PathBuf::from(&file_path))
            .await
            .map_err(|e| ApiError::InvalidFilePath(format!("Invalid file path: {}", e)))?;

    let absolute_path = normalised_paths.absolute_path();

    // Find the global signers file for this path
    let signers_path = find_global_signers_for(&absolute_path).map_err(|e| {
        tracing::warn!(
            request_id = %request_id,
            file_path = %file_path,
            absolute_path = %absolute_path.display(),
            error = %e,
            "No signers file found for path"
        );
        ApiError::FileNotFound(format!(
            "No signers file found for: {}. Error: {}",
            file_path, e
        ))
    })?;

    // Read the signers file content
    let content = tokio::fs::read(&signers_path).await.map_err(|e| {
        tracing::error!(
            request_id = %request_id,
            signers_path = %signers_path.display(),
            error = %e,
            "Failed to read signers file"
        );
        ApiError::InternalServerError(format!("Failed to read signers file: {}", e))
    })?;

    tracing::info!(
        request_id = %request_id,
        file_path = %file_path,
        signers_path = %signers_path.display(),
        size = content.len(),
        "Successfully retrieved signers file"
    );

    // Build response headers
    let mut response_headers = axum::http::HeaderMap::new();
    response_headers.insert(
        header::CONTENT_TYPE,
        header::HeaderValue::from_static("application/json"),
    );
    response_headers.insert(
        header::CONTENT_LENGTH,
        header::HeaderValue::from_str(&content.len().to_string())
            .unwrap_or_else(|_| header::HeaderValue::from_static("0")),
    );

    Ok((axum::http::StatusCode::OK, response_headers, content))
}

/// Handle a revocation request for a signed file.
///
/// Validates the HTTP request, then delegates to the SignatureCollector
/// actor which serializes revocation alongside signature operations.
///
/// # Arguments
/// * `state` - Application state containing actor references
/// * `headers` - HTTP headers (must include x-request-id for tracing)
/// * `request` - Revocation request with file_path, revocation_json, signature, public_key
///
/// # Returns
/// Returns a response indicating whether revocation succeeded
///
/// # Errors
/// Returns `ApiError` if:
/// - File path is invalid or file doesn't exist
/// - Public key or signature format is invalid
/// - File has no complete aggregate signature
/// - Digest mismatch between revocation JSON and actual file
/// - Revocation authorization fails
pub async fn revoke_handler(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<RevokeFileRequest>,
) -> Result<Json<RevokeFileResponse>, ApiError> {
    let request_id = headers
        .get("x-request-id")
        .and_then(|h| h.to_str().ok())
        .unwrap_or("unknown");

    tracing::info!(
        request_id = %request_id,
        file_path = %request.file_path,
        "Received revoke request"
    );

    // Validate the file path
    if request.file_path.is_empty() {
        return Err(ApiError::InvalidRequestBody(
            "File path cannot be empty".to_string(),
        ));
    }

    // Normalize and validate the file path
    let file_path = NormalisedPaths::new(
        state.git_repo_path.clone(),
        PathBuf::from_str(request.file_path.as_ref()).unwrap(),
    )
    .await?;

    // Check if the file exists
    if !file_path.absolute_path().exists() {
        return Err(ApiError::FileNotFound(format!(
            "File not found: {}",
            request.file_path
        )));
    }

    // Parse public key and signature from base64 strings
    let public_key = features_lib::AsfaloadPublicKeys::from_base64(&request.public_key)
        .map_err(|_| ApiError::InvalidRequestBody("Invalid public key format".to_string()))?;

    let signature = features_lib::AsfaloadSignatures::from_base64(&request.signature)
        .map_err(|_| ApiError::InvalidRequestBody("Invalid signature format".to_string()))?;

    // Send revocation request to the SignatureCollector actor
    let _result = state
        .signature_collector
        .ask(
            crate::file_auth::actors::signature_collector::RevokeFileMessage {
                file_path: file_path.clone(),
                revocation_json: request.revocation_json,
                signature,
                public_key,
                request_id: request_id.to_string(),
            },
        )
        .await
        .map_err(|e| map_to_user_error(e, "Revocation failed"))?;

    tracing::info!(
        request_id = %request_id,
        file_path = %request.file_path,
        "Revocation completed successfully"
    );

    Ok(Json(RevokeFileResponse {
        // If we get here we are successful
        success: true,
        message: "File revoked successfully".to_string(),
    }))
}

/// Handle asset registration — either a GitHub release or checksums files.
///
/// Validates the request (exactly one of `github_release_url` or `csum_files` must be set),
/// then dispatches to the appropriate actor:
/// - `github_release_url`: delegates to the release actor (existing GitHub flow)
/// - `csum_files`: delegates to the checksums actor
pub async fn register_assets_handler(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<rest_api_types::RegisterAssetsRequest>,
) -> Result<Json<rest_api_types::RegisterAssetsResponse>, ApiError> {
    let request_id = headers
        .get("x-request-id")
        .and_then(|h| h.to_str().ok())
        .unwrap_or("unknown");

    match (&request.github_release_url, &request.csum_files) {
        (Some(url), None) => register_github_release(&state, request_id, url).await,
        (None, Some(csum_urls)) => register_checksums(&state, request_id, csum_urls).await,
        (Some(_), Some(_)) => Err(ApiError::InvalidRequestBody(
            "github_release_url and csum_files are mutually exclusive".to_string(),
        )),
        (None, None) => Err(ApiError::InvalidRequestBody(
            "Either github_release_url or csum_files must be provided".to_string(),
        )),
    }
}

async fn register_github_release(
    state: &AppState,
    request_id: &str,
    github_release_url: &str,
) -> Result<Json<rest_api_types::RegisterAssetsResponse>, ApiError> {
    tracing::info!(
        request_id = %request_id,
        github_release_url = %github_release_url,
        "Received register-assets request (GitHub mode)"
    );

    let parsed_url = url::Url::parse(github_release_url)
        .map_err(|e| ApiError::InvalidRequestBody(format!("Invalid release URL: {}", e)))?;

    let host = parsed_url
        .host_str()
        .ok_or_else(|| ApiError::InvalidRequestBody("Release URL missing host".to_string()))?;
    if !GITHUB_HOSTS.contains(&host) {
        return Err(ApiError::InvalidRequestBody(format!(
            "github_release_url must be a GitHub URL. Host '{}' is not a known GitHub host",
            host
        )));
    }

    let result = state
        .release_actor
        .ask(crate::file_auth::actors::release_actor::ProcessRelease {
            request_id: request_id.to_string(),
            release_url: parsed_url,
        })
        .await
        .map_err(|e| map_to_user_error(e, "Release registration failed"))?;

    Ok(Json(rest_api_types::RegisterAssetsResponse {
        success: true,
        message: "Release registered successfully".to_string(),
        index_file_path: Some(
            result
                .index_file_path
                .relative_path()
                .to_string_lossy()
                .to_string(),
        ),
    }))
}

async fn register_checksums(
    state: &AppState,
    request_id: &str,
    csum_urls: &[String],
) -> Result<Json<rest_api_types::RegisterAssetsResponse>, ApiError> {
    tracing::info!(
        request_id = %request_id,
        url_count = %csum_urls.len(),
        "Received register-assets request (checksums mode)"
    );

    let urls: Vec<url::Url> = csum_urls
        .iter()
        .map(|s| {
            url::Url::parse(s)
                .map_err(|e| ApiError::InvalidRequestBody(format!("Invalid URL '{}': {}", s, e)))
        })
        .collect::<Result<Vec<_>, _>>()?;

    let result = state
        .checksums_actor
        .ask(
            crate::file_auth::actors::checksums_actor::ProcessChecksums {
                request_id: request_id.to_string(),
                urls,
            },
        )
        .await
        .map_err(|e| map_to_user_error(e, "Checksums registration failed"))?;

    Ok(Json(rest_api_types::RegisterAssetsResponse {
        success: true,
        message: "Assets registered successfully".to_string(),
        index_file_path: Some(
            result
                .index_file_path
                .relative_path()
                .to_string_lossy()
                .to_string(),
        ),
    }))
}

/// Trace a "local signers copy" file (an artifact's `.signers.json` copy OR
/// a revocation's `.signers.json` copy) back to the original signers file
/// that introduced it, and build the `SignersChain` as of that source
/// commit. Returns the chain plus the commit metadata so callers that need
/// extra files from the same commit (e.g. the index JSON) can fetch them
/// without re-tracing.
async fn build_chain_from_local_signers_copy(
    state: &AppState,
    request_id: &str,
    local_signers: NormalisedPaths,
) -> Result<
    (
        signers_file_types::SignersChain,
        String,                        /* commit */
        chrono::DateTime<chrono::Utc>, /* commit_time */
    ),
    ApiError,
> {
    use common::fs::names::{
        history_file_path_for, metadata_path_for, metadata_signatures_path_for, signatures_path_for,
    };

    // Trace back to the original signers file source
    let backend = state.git_backend.clone();
    let source = tokio::task::spawn_blocking({
        let local_signers = local_signers.clone();
        move || backend.artifact_signers_source(local_signers)
    })
    .await
    .map_err(|e| ApiError::InternalServerError(format!("Task join error: {}", e)))?
    .map_err(|e| {
        tracing::error!(
            request_id = %request_id,
            local_signers = %local_signers,
            error = %e,
            "Could not identify signers source"
        );
        ApiError::InvalidFilePath(format!("Could not identify signers source: {}", e))
    })?;

    let commit = source.commit().to_string();
    let commit_time = source.commit_time();

    // source.path() points to the original signers file,
    // e.g. "asfaload.signers/asfaload.signers.json"
    // The parent is the signers directory
    let source_signers_file = source.path().relative_path();
    let signers_dir = source_signers_file.parent().ok_or_else(|| {
        ApiError::InternalServerError("Signers file has no parent directory".to_string())
    })?;

    // Build relative paths for files to read at the commit
    let history_rel = history_file_path_for(signers_dir);
    let signatures_rel = signatures_path_for(&source_signers_file).map_err(|e| {
        tracing::error!(
            request_id = %request_id,
            signers_file = %source_signers_file.display(),
            error = %e,
            "Cannot derive signatures path"
        );
        ApiError::InternalServerError(format!("Cannot derive signatures path: {}", e))
    })?;
    let metadata_rel = metadata_path_for(&source_signers_file).map_err(|e| {
        tracing::error!(
            request_id = %request_id,
            signers_file = %source_signers_file.display(),
            error = %e,
            "Cannot derive metadata path"
        );
        ApiError::InternalServerError(format!("Cannot derive metadata path: {}", e))
    })?;
    let metadata_signatures_rel =
        metadata_signatures_path_for(&source_signers_file).map_err(|e| {
            tracing::error!(
                request_id = %request_id,
                signers_file = %source_signers_file.display(),
                error = %e,
                "Cannot derive metadata signatures path"
            );
            ApiError::InternalServerError(format!("Cannot derive metadata signatures path: {}", e))
        })?;

    // Read all needed files from git history
    type GitReadResult = (Result<String, ApiError>, String, String, String, String);
    let backend = state.git_backend.clone();
    let (
        history_result,
        active_signers_json,
        active_signatures_json,
        active_metadata_json,
        active_metadata_signatures_json,
    ) = tokio::task::spawn_blocking({
        let commit = commit.clone();
        let history_rel = history_rel.clone();
        let signatures_rel = signatures_rel.clone();
        let metadata_rel = metadata_rel.clone();
        let metadata_signatures_rel = metadata_signatures_rel.clone();
        move || -> Result<GitReadResult, ApiError> {
            // History file may not exist if no rotations happened
            let history = backend.file_content_at_commit(&commit, &history_rel);
            let signers = backend.file_content_at_commit(&commit, &source_signers_file)?;
            let sigs = backend.file_content_at_commit(&commit, &signatures_rel)?;
            let meta = backend.file_content_at_commit(&commit, &metadata_rel)?;
            let meta_sigs = backend.file_content_at_commit(&commit, &metadata_signatures_rel)?;
            Ok((history, signers, sigs, meta, meta_sigs))
        }
    })
    .await
    .map_err(|e| ApiError::InternalServerError(format!("Task join error: {}", e)))??;

    // Parse history (may be empty if no rotations happened)
    let history = match history_result {
        Ok(history_json) => signers_file_types::parse_history_file(&history_json).map_err(|e| {
            ApiError::InternalServerError(format!("Failed to parse history file: {}", e))
        })?,
        Err(_) => signers_file_types::HistoryFile::new(),
    };

    let active_signatures: signatures::signatures_file::SignaturesFile =
        serde_json::from_str(&active_signatures_json).map_err(|e| {
            ApiError::InternalServerError(format!("Failed to parse signatures file: {}", e))
        })?;
    let active_metadata_signatures: signatures::signatures_file::SignaturesFile =
        serde_json::from_str(&active_metadata_signatures_json).map_err(|e| {
            ApiError::InternalServerError(format!(
                "Failed to parse metadata signatures file: {}",
                e
            ))
        })?;

    // Build the filtered chain
    let chain = signers_file::signers_chain_for_artifact(
        // Data from the history file on disk
        &history,
        // The artifact's signers copy which is not included in the history.
        &active_signers_json,
        &active_signatures,
        &active_metadata_json,
        &active_metadata_signatures,
        commit_time,
    )
    .map_err(|e| ApiError::InternalServerError(format!("Failed to build signers chain: {}", e)))?;

    Ok((chain, commit, commit_time))
}

/// Returns the signers chain for a signed artifact.
pub async fn get_artifact_signers_chain_handler(
    State(state): State<AppState>,
    headers: HeaderMap,
    axum::extract::Path(artifact_path_in): axum::extract::Path<String>,
) -> Result<Json<GetSignersChainResponse>, ApiError> {
    use common::fs::names::local_signers_path_for;

    let request_id = headers
        .get("x-request-id")
        .and_then(|h| h.to_str().ok())
        .unwrap_or("unknown");

    tracing::info!(
        request_id = %request_id,
        artifact_path = %artifact_path_in,
        "Received get_artifact_signers_chain request"
    );

    let artifact_path = NormalisedPaths::new(&state.git_repo_path, &artifact_path_in)
        .await
        .map_err(|e| {
            tracing::error!(
                request_id = %request_id,
                artifact_path = %artifact_path_in,
                error = %e,
                "Invalid artifact path"
            );
            ApiError::InvalidFilePath(format!("Invalid artifact path: {}", e))
        })?;

    // Derive the local signers copy path from the artifact path
    let local_signers_relative =
        local_signers_path_for(artifact_path.relative_path()).map_err(|e| {
            tracing::error!(
                request_id = %request_id,
                artifact_path = %artifact_path,
                error = %e,
                "Cannot derive signers path for artifact"
            );
            ApiError::InvalidFilePath(format!("Cannot derive signers path for artifact: {}", e))
        })?;

    let local_signers = NormalisedPaths::new(state.git_repo_path.clone(), local_signers_relative)
        .await
        .map_err(|e| {
            tracing::error!(
                request_id = %request_id,
                artifact_path = %artifact_path,
                error = %e,
                "Invalid signers path"
            );
            ApiError::InvalidFilePath(format!("Invalid signers path: {}", e))
        })?;

    let (chain, _commit, _commit_time) =
        build_chain_from_local_signers_copy(&state, request_id, local_signers).await?;

    tracing::info!(
        request_id = %request_id,
        artifact_path = %artifact_path,
        chain_length = chain.entries().len(),
        "Successfully built signers chain"
    );

    Ok(Json(GetSignersChainResponse { chain }))
}

// Helper to build index path from artifact url and forge type.

async fn index_paths_for(
    state: &AppState,
    url: url::Url,
    forge_kind: Option<String>,
) -> Result<NormalisedPaths, ApiError> {
    // Map the artifact download URL to the index file's repository path using
    // the shared forge-url layer (GitHub /releases/download/ -> /releases/tag/,
    // other forges use the path as-is), then validate it as a repo-relative path.
    let forge = match forge_kind {
        Some(ft) => Forges::from_type_str(&ft)
            .map_err(|e| ApiError::InvalidRequestBody(format!("Invalid forge type: {}", e)))?,
        None => get_forge(&url).map_err(|e| {
            ApiError::InvalidRequestBody(format!(
                "Forge type could not be extracted from URL: {}",
                e
            ))
        })?,
    };

    let index_file_path = forge
        .construct_index_file_path(&url)
        .map_err(|e| ApiError::InvalidRequestBody(format!("Invalid artifact URL: {}", e)))?;
    let index_file_paths = NormalisedPaths::new(&state.git_repo_path, &index_file_path).await?;
    Ok(index_file_paths)
}

/// Handler to fetch everything a client needs to verify a signed artifact.
///
/// Bundles the artifact's index JSON, its signatures envelope, and the
/// signers chain anchored at the artifact-signature commit. The client
/// validates the chain (realm + trust anchor), then verifies the index
/// signatures against the chain head — never trusting the backend-served
/// local `.signers.json` copy.
pub async fn get_artifact_info_handler(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<rest_api_types::models::GetArtifactInfoRequest>,
) -> Result<Json<GetArtifactInfoResponse>, ApiError> {
    use common::fs::names::{local_signers_path_for, signatures_path_for};

    let request_id = headers
        .get("x-request-id")
        .and_then(|h| h.to_str().ok())
        .unwrap_or("unknown");

    tracing::info!(
        request_id = %request_id,
        url = %request.artifact_url,
        "Received get_artifact_info request"
    );

    let url = request.artifact_url;

    let logged_url = url.clone();
    let index_file_paths = index_paths_for(&state, url, request.forge_kind)
        .await
        .map_err(|e| {
            tracing::error!(
                request_id = %request_id,
                url = %logged_url,
                error = %e,
                "Cannot derive signers path for artifact"
            );
            ApiError::InvalidFilePath(format!("Cannot derive signers path for artifact: {}", e))
        })?;

    // The chain is built from the artifact's local `.signers.json` copy, taken
    // when the artifact's signature completed. The commit that introduced that
    // copy is the same commit the index and its signatures were committed at,
    // so all three are read consistently from it.
    let local_signers_relative =
        local_signers_path_for(index_file_paths.relative_path()).map_err(|e| {
            tracing::error!(
                request_id = %request_id,
                artifact_path = %index_file_paths,
                error = %e,
                "Cannot derive signers path for artifact"
            );
            ApiError::InvalidFilePath(format!("Cannot derive signers path for artifact: {}", e))
        })?;

    let local_signers = NormalisedPaths::new(state.git_repo_path.clone(), local_signers_relative)
        .await
        .map_err(|e| {
            tracing::error!(
                request_id = %request_id,
                artifact_path = %index_file_paths,
                error = %e,
                "Invalid signers path"
            );
            ApiError::InvalidFilePath(format!("Invalid signers path: {}", e))
        })?;

    let (chain, commit, _commit_time) =
        build_chain_from_local_signers_copy(&state, request_id, local_signers).await?;

    // Read the index and its signatures at the same commit the chain is
    // anchored to.
    let index_relative = index_file_paths.relative_path();
    let index_signatures_relative = signatures_path_for(&index_relative).map_err(|e| {
        tracing::error!(
            request_id = %request_id,
            artifact_path = %index_file_paths,
            error = %e,
            "Cannot derive index signatures path"
        );
        ApiError::InternalServerError(format!("Cannot derive index signatures path: {}", e))
    })?;

    let backend = state.git_backend.clone();
    let (index_json, index_signatures_json) =
        tokio::task::spawn_blocking(move || -> Result<(String, String), ApiError> {
            let index = backend.file_content_at_commit(&commit, &index_relative)?;
            let signatures = backend.file_content_at_commit(&commit, &index_signatures_relative)?;
            Ok((index, signatures))
        })
        .await
        .map_err(|e| ApiError::InternalServerError(format!("Task join error: {}", e)))??;

    tracing::info!(
        request_id = %request_id,
        artifact_path = %index_file_paths,
        chain_length = chain.entries().len(),
        "Successfully built artifact info response"
    );

    Ok(Json(GetArtifactInfoResponse {
        index_json,
        index_signatures_raw: index_signatures_json,
        signers_chain: chain,
    }))
}

/// Handler to fetch the revocation status of a signed artifact.
///
/// Returns 404 if no revocation exists. Otherwise returns the revocation
/// payload (raw JSON + signatures) bundled with the signers chain anchored
/// at the revocation commit, so the client can validate the chain (realm +
/// trust anchor) before trusting the revocation's authorization.
pub async fn get_revocation_handler(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<rest_api_types::models::GetRevocationRequest>,
) -> Result<Json<rest_api_types::models::GetRevocationResponse>, ApiError> {
    let request_id = headers
        .get("x-request-id")
        .and_then(|h| h.to_str().ok())
        .unwrap_or("unknown");

    tracing::info!(
        request_id = %request_id,
        url = %request.artifact_url,
        "Received get_revocation request"
    );

    let url = request.artifact_url;

    let logged_url = url.clone();
    let index_file_paths = index_paths_for(&state, url, request.forge_kind)
        .await
        .map_err(|e| {
            tracing::error!(
                request_id = %request_id,
                url = %logged_url,
                error = %e,
                "Cannot derive signers path for artifact"
            );
            ApiError::InvalidFilePath(format!("Cannot derive signers path for artifact: {}", e))
        })?;

    let revocation_path = revocation_path_for(index_file_paths.relative_path()).map_err(|e| {
        tracing::error!(
            request_id = %request_id,
            index_path = %index_file_paths,
            error = %e,
            "Cannot derive revocation path"
        );
        ApiError::InvalidFilePath(format!("Cannot derive revocation path: {}", e))
    })?;
    let revocation_paths = NormalisedPaths::new(&state.git_repo_path, revocation_path)
        .await
        .map_err(|e| {
            tracing::error!(
                request_id = %request_id,
                index_path = %index_file_paths,
                error = %e,
                "Invalid revocation path"
            );
            ApiError::InvalidFilePath(format!("Invalid revocation path: {}", e))
        })?;
    if !revocation_paths.absolute_path().exists() {
        tracing::info!(
            request_id = %request_id,
            index_path = %index_file_paths,
            "No revocation file present"
        );
        return Err(ApiError::FileNotFound(format!(
            "No revocation for: {}",
            index_file_paths.relative_path().display()
        )));
    }

    let revocation_local_signers_rel =
        revocation_signers_path_for(index_file_paths.relative_path()).map_err(|e| {
            tracing::error!(
                request_id = %request_id,
                index_path = %index_file_paths,
                error = %e,
                "Cannot derive revocation signers path"
            );
            ApiError::InvalidFilePath(format!("Cannot derive revocation signers path: {}", e))
        })?;

    let revocation_local_signers =
        NormalisedPaths::new(state.git_repo_path.clone(), revocation_local_signers_rel)
            .await
            .map_err(|e| {
                tracing::error!(
                    request_id = %request_id,
                    index_path = %index_file_paths,
                    error = %e,
                    "Invalid revocation signers path"
                );
                ApiError::InvalidFilePath(format!("Invalid revocation signers path: {}", e))
            })?;

    let (chain, commit, _commit_time) =
        build_chain_from_local_signers_copy(&state, request_id, revocation_local_signers).await?;

    let revocation_signatures_relative =
        revocation_signatures_path_for(index_file_paths.relative_path()).map_err(|e| {
            tracing::error!(
                request_id = %request_id,
                revocation_path = %revocation_paths,
                error = %e,
                "Cannot derive revocation signatures path"
            );
            ApiError::InvalidFilePath(format!("Cannot derive revocation signatures path: {}", e))
        })?;

    let backend = state.git_backend.clone();
    let (revocation_json, revocation_signatures_json) =
        tokio::task::spawn_blocking(move || -> Result<(String, String), ApiError> {
            let rev = backend.file_content_at_commit(&commit, &revocation_paths.relative_path())?;
            let sigs = backend.file_content_at_commit(&commit, &revocation_signatures_relative)?;
            Ok((rev, sigs))
        })
        .await
        .map_err(|e| ApiError::InternalServerError(format!("Task join error: {}", e)))??;

    tracing::info!(
        request_id = %request_id,
        index_path = %index_file_paths,
        chain_length = chain.entries().len(),
        "Successfully built revocation response"
    );

    Ok(Json(rest_api_types::models::GetRevocationResponse {
        revocation_json,
        revocation_signatures: revocation_signatures_json,
        signers_chain: chain,
    }))
}

/// Handler answering ping requests with authentication diagnostics.
///
/// Always returns 200. Reports whether the request carried authentication
/// headers, whether the full validation (headers, nonce, timestamp,
/// signature) passed, and which public key was authenticated. Failed
/// validation is reported in the body instead of rejecting the request,
/// making this endpoint a connectivity and credentials diagnostic tool.
///
/// A successful validation consumes the nonce, like any authenticated
/// request.
pub async fn ping_handler(State(state): State<AppState>, headers: HeaderMap) -> Json<PingResponse> {
    let request_id = headers
        .get("x-request-id")
        .and_then(|h| h.to_str().ok())
        .unwrap_or("unknown");

    tracing::info!(
        request_id = %request_id,
        "Received ping request"
    );

    // Ping is a GET request: the signed payload is the empty string.
    let auth = match validate_auth(state, &headers, "", request_id).await {
        AuthOutcome::NotAttempted => PingAuthStatus::Unauthenticated,
        AuthOutcome::Success { public_key } => PingAuthStatus::Success { public_key },
        AuthOutcome::Failed { public_key, error } => {
            // Auth-failure reasons are deliberate diagnostics, but internal
            // server errors must not leak details to unauthenticated callers.
            let reason = if error.to_http_status().is_server_error() {
                "Internal error during authentication validation".to_string()
            } else {
                error.to_string()
            };
            PingAuthStatus::Failed { public_key, reason }
        }
    };

    Json(PingResponse {
        message: "pong".to_string(),
        auth,
    })
}
