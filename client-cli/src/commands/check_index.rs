use crate::error::{ClientCliError, Result, index_digest_source_error};
use client_lib::index_verification::extract_parsed_checksums_from_index;
use client_lib::signers_metadata::verify_remote_url_in_path_realm;
use common::index_types::AsfaloadIndex;
use features_lib::validate_index_against_digests;

/// Handle the check-index command.
///
/// Fetches the index file at `index_path` from the backend mirror and validates
/// every digest it records against its original digest source. The command is
/// unauthenticated because the files endpoint is public and validation needs no
/// identity.
///
/// # Arguments
/// * `index_path` - Mirror-relative path of the index, as displayed by `list-pending`
/// * `backend_url` - Backend API URL
/// * `json` - Emit output as JSON instead of human-readable text
///
/// # Errors
/// * `AdminLib` when the index cannot be fetched (e.g. unknown path)
/// * `InvalidInput` when the fetched body is not a valid index
/// * `IndexValidation` when a digest source cannot be fetched, parsed, or disagrees with the index
pub async fn handle_check_index_command(
    index_path: &str,
    backend_url: &str,
    json: bool,
) -> Result<()> {
    let client = admin_lib::v1::Client::new(backend_url);
    let content = client.fetch_file(index_path).await?;

    // A corrupt index body almost always means the wrong path was given, so the
    // error names the path rather than exposing a bare serde message.
    let index: AsfaloadIndex = serde_json::from_slice(&content).map_err(|e| {
        ClientCliError::InvalidInput(format!(
            "Body at {index_path} is not valid JSON for an index file: {e}"
        ))
    })?;

    let files_checked = index.published_files.len();

    // Validate all digest sources are in the realm of the index file's path on the backend.
    // Could be improved as we do it in two steps and iterate twice: first here, then in
    // validate_index_against_digests. But the realm check needs the index path on the backend,
    // which validate_index_against_digests does not know, and this still seems a reasonable way
    // to implement as the number of sources should be small (often even 1).
    for published_file in &index.published_files {
        verify_remote_url_in_path_realm(index_path, &published_file.source)
            .map_err(index_digest_source_error)?;
    }

    // Extract all parsed digests from index so we can pass it to the validation function
    let digests = extract_parsed_checksums_from_index(&index).await?;

    // Validate the index against the digests that were retrieved (no network op here)
    validate_index_against_digests(index.clone(), digests)?;

    if json {
        let output = crate::output::CheckIndexOutput {
            index_path: index_path.to_string(),
            files_checked,
            index,
        };
        println!("{}", serde_json::to_string(&output)?);
    } else {
        println!("✓ Index valid: {files_checked} file(s) verified against their digest sources");
    }

    Ok(())
}
