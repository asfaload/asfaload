use std::collections::HashMap;

use crate::error::Result;
use common::fs::names::{is_pending_signers_file_path, metadata_path_for};
use features_lib::{
    AsfaloadPublicKeyTrait, AsfaloadPublicKeys, AsfaloadSecretKeyTrait, AsfaloadSecretKeys,
    AsfaloadSignatures, SignersConfigMetadata, sha512_for_content,
};
use rest_api_types::{SubmitSignatureResponse, models::ClientPendingFile};

/// Handle the sign-pending command.
///
/// Translates a file path from list-pending into a signed submission to the backend.
/// This is a one-step command for the user that:
/// 1. Fetches all files that need signing from backend
/// 2. Computes hash and signs each file with user's key
/// 3. Submits all signatures to backend in one request
///
/// # Arguments
/// * `file_path` - Path to the file (as returned by list-pending)
/// * `backend_url` - Backend API URL
/// * `secret_key_path` - Path to the user's secret key file
/// * `password` - Password to unlock secret key
///
/// # Workflow
/// * Load secret key and derive public key
/// * Fetch all files to sign from backend
/// * Compute SHA512 hash and sign each file
/// * Submit all signatures to backend
/// * Display result (whether signature is now complete)
pub async fn handle_sign_pending_command(
    pending_file: ClientPendingFile,
    backend_url: &str,
    secret_key_path: &std::path::PathBuf,
    password: &str,
    json: bool,
) -> Result<SubmitSignatureResponse> {
    // Load secret key and derive public key
    let secret_key = AsfaloadSecretKeys::from_file(secret_key_path, password)?;
    handle_sign_pending_sec_key(pending_file, backend_url, &secret_key, json).await
}

pub async fn handle_sign_pending_sec_key(
    pending_file: ClientPendingFile,
    backend_url: &str,
    secret_key: &AsfaloadSecretKeys,
    json: bool,
) -> Result<SubmitSignatureResponse> {
    let public_key = AsfaloadPublicKeys::from_secret_key(secret_key)?;
    // Create REST client
    let client = admin_lib::v1::Client::new(backend_url);

    // Fetch all files that need signing
    let files_to_sign = client
        .fetch_files_to_sign(pending_file.path(), secret_key)
        .await?;

    // A pending signers file must be byte-identical to the forge source its
    // metadata points at. A compromised backend could otherwise have us sign a
    // config that differs from the one the forge URL serves. The source is
    // fetched from the retrieval URL recorded in the metadata and compared by
    // SHA-512.
    if is_pending_signers_file_path(pending_file.path()) {
        let metadata_key = metadata_path_for(pending_file.path())?
            .to_string_lossy()
            .to_string();
        // We get both the signers file and its metadata file (their respective paths are the keys
        // of the HashMap)
        let signers_content = files_to_sign.get(pending_file.path()).ok_or_else(|| {
            crate::error::ClientCliError::InvalidInput(format!(
                "Missing content for pending signers file: {}",
                pending_file.path()
            ))
        })?;
        // Extract the metadata json from the HashMap
        let metadata_content = files_to_sign.get(&metadata_key).ok_or_else(|| {
            crate::error::ClientCliError::InvalidInput(format!(
                "Missing metadata required to validate pending signers file: {}",
                metadata_key
            ))
        })?;

        let metadata: SignersConfigMetadata = serde_json::from_slice(metadata_content)?;
        // Retrieves file from publishing platform to assess validity.
        client_lib::verify_signers_file_matches_metadata_source(signers_content, &metadata)
            .await
            .map_err(|e| crate::error::signers_metadata_verification_error(&metadata, e))?;
    }

    // Sign each file
    let mut signatures: HashMap<String, AsfaloadSignatures> = HashMap::new();
    for (path, content) in &files_to_sign {
        // content is &Vec<u8>, as_slice() give a &[u8] and avoids cloning
        let hash = sha512_for_content(content.as_slice())?;
        // Only verify the digest for the primary file; associated files (e.g. metadata)
        // are signed without digest pre-verification since pending_file.digest() covers
        // only the primary file.
        if *path == pending_file.path() && hash != *pending_file.digest() {
            return Err(crate::error::ClientCliError::ServerDigestError(
                hash.to_string(),
                pending_file.digest().clone(),
            ));
        }
        let signature = secret_key.sign(&hash)?;
        signatures.insert(path.clone(), signature);
    }

    // Submit all signatures to backend
    let response = client
        .submit_signatures(pending_file, &public_key, &signatures, secret_key)
        .await?;

    // Display result
    if json {
        println!("{}", serde_json::to_string(&response)?);
    } else if response.is_complete {
        println!(
            "Success! Your signature has been included and the aggregate signature is now complete. No further signature will be included in this aggregate signature."
        );
    } else {
        println!(
            "Success! Your signature has been included, but the aggregate signature is not yet complete. Other signers must still provide their signatures."
        );
    }

    Ok(response)
}
