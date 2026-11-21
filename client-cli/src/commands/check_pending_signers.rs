use client_lib::config::ConfigAccessor;
use common::fs::names::{is_pending_signers_file_path, metadata_path_for};
use features_lib::{SignersConfigMetadata, parse_signers_config, sha512_for_content};

use crate::commands::signers_config_output::signer_groups_lines;
use crate::commands::signers_submission_output::BOLD;
use crate::utils::config_for_display;

use crate::error::{
    ClientCliError, Result, signers_metadata_parse_error, signers_metadata_verification_error,
};

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
/// * `config_accessor` - Gives access to the configuration file holding the key aliases
///
/// # Errors
/// * `InvalidInput` when the path is not a pending signers file path
/// * `AdminLib` when the file or its metadata cannot be fetched
/// * `BackendDataError` when the file differs from the content served at the retrieval URL
/// * `SignersFile` when the content is not a valid signers file
pub async fn handle_check_pending_signers_command(
    signers_path: &str,
    backend_url: &str,
    json: bool,
    config_accessor: &ConfigAccessor,
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
    let metadata: SignersConfigMetadata =
        serde_json::from_slice(&metadata_content).map_err(signers_metadata_parse_error)?;

    client_lib::verify_signers_file_matches_metadata_source(
        &signers_content,
        signers_path,
        &metadata,
    )
    .await
    .map_err(|e| signers_metadata_verification_error(&metadata, e))?;

    let retrieval_url = metadata.verified_content().retrieval_url();
    let hash = sha512_for_content(signers_content.as_slice())?;

    // The user signs this file next, so content that is not a signers file is an error.
    let signers_config = std::str::from_utf8(&signers_content)
        .map_err(|e| e.to_string())
        .and_then(|s| parse_signers_config(s).map_err(|e| e.to_string()))
        .map_err(|e| {
            ClientCliError::SignersFile(format!(
                "Pending signers file is not a valid signers file: {e}"
            ))
        })?;

    if json {
        let output = crate::output::CheckPendingSignersOutput {
            signers_path: signers_path.to_string(),
            retrieval_url: retrieval_url.to_string(),
            hash: hash.to_string(),
        };
        println!("{}", serde_json::to_string(&output)?);
    } else {
        println!("✓ Pending signers file matches the content published at {retrieval_url}");
        println!("{hash}");
        let cli_config = config_for_display(config_accessor);
        println!();
        // anstream removes the styles when stdout is not a terminal.
        for line in signer_groups_lines(&signers_config, &cli_config, BOLD) {
            anstream::println!("{line}");
        }
    }

    Ok(())
}
