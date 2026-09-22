use common::fs::names::{is_pending_signers_file_path, metadata_path_for};
use features_lib::{SignersConfigMetadata, SignersConfigOrigin, sha512_for_content};

use crate::error::{ClientCliError, Result, signers_metadata_verification_error};
use crate::utils::{bishop_art, bishop_plain};

/// Handle the check-pending-signers command.
///
/// Fetches the pending signers file at `signers_path` from the backend mirror
/// together with its metadata file, and verifies that the file is
/// byte-identical to the content served at the retrieval URL recorded in the
/// metadata. The command is unauthenticated because the files endpoint is
/// public and verification needs no identity.
///
/// # Arguments
/// * `signers_path` - Mirror-relative path of the pending signers file, as displayed by `list-pending`
/// * `backend_url` - Backend API URL
/// * `json` - Emit output as JSON instead of human-readable text
///
/// # Errors
/// * `InvalidInput` when the path is not a pending signers file path
/// * `AdminLib` when the file or its metadata cannot be fetched
/// * `BackendDataError` when the file differs from the content served at the retrieval URL
pub async fn handle_check_pending_signers_command(
    signers_path: &str,
    backend_url: &str,
    json: bool,
) -> Result<()> {
    // Reject any other path before any network call: the command only makes
    // sense for the file type it is named after.
    if !is_pending_signers_file_path(signers_path) {
        return Err(ClientCliError::InvalidInput(format!(
            "Not a pending signers file path: {signers_path}"
        )));
    }

    let client = admin_lib::v1::Client::new(backend_url);
    let signers_content = client.fetch_file(signers_path).await?;
    let metadata_path = metadata_path_for(signers_path)?;
    let metadata_content = client.fetch_file(&metadata_path.to_string_lossy()).await?;

    client_lib::verify_signers_file_matches_metadata_source(&signers_content, &metadata_content)
        .await
        .map_err(|e| signers_metadata_verification_error(&metadata_content, e))?;

    // The verification passed, so the metadata parsed successfully during
    // verification; parsing it here only extracts the retrieval URL for output.
    let metadata: SignersConfigMetadata = serde_json::from_slice(&metadata_content)?;
    let retrieval_url = match metadata.origin() {
        SignersConfigOrigin::Forge(origin) => origin.verified_content().retrieval_url(),
    };
    let hash = sha512_for_content(signers_content.as_slice())?;

    if json {
        let output = crate::output::CheckPendingSignersOutput {
            signers_path: signers_path.to_string(),
            retrieval_url: retrieval_url.to_string(),
            hash: hash.to_string(),
            bishop_art: bishop_plain(&hash),
        };
        println!("{}", serde_json::to_string(&output)?);
    } else {
        println!("✓ Pending signers file matches the content published at {retrieval_url}");
        println!("{hash}");
        println!("{}", bishop_art(&hash));
    }

    Ok(())
}
