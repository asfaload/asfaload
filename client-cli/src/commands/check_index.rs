use crate::error::{ClientCliError, Result};
use common::index_types::AsfaloadIndex;
use common::index_validation::file_auth::validate_index_hash_files;

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
    validate_index_hash_files(index).await?;

    // JSON success output is added in the next task; the `json` flag only
    // affects error reporting (handled by main.rs) until then.
    let _ = json;
    println!("✓ Index valid: {files_checked} file(s) verified against their digest sources");

    Ok(())
}
