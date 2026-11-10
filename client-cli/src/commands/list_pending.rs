use crate::error::{ClientCliError, Result};
use common::AsfaloadHashes;
use features_lib::AsfaloadSecretKeyTrait;
use features_lib::AsfaloadSecretKeys;
use rest_api_types::models::PendingFile;

/// Handle the list-pending command.
///
/// Lists all files from the backend that require the user's signature.
///
/// # Arguments
///
/// * `backend_url` - Backend API URL
/// * `secret_key_path` - Path to the user's secret key file
/// * `password` - Password for the secret key
///
/// # Workflow
///
/// 1. Load secret key
/// 2. Make authenticated request to backend
/// 3. Display list of pending files
pub async fn handle_list_pending_command(
    backend_url: &str,
    secret_key_path: &std::path::PathBuf,
    password: &str,
    digest_filter: Option<String>,
    json: bool,
) -> Result<Vec<PendingFile>> {
    // 1. Load secret key
    let secret_key = AsfaloadSecretKeys::from_file(secret_key_path, password)?;

    // 2. Make authenticated request to backend (derives public key from auth headers)
    let client = admin_lib::v1::Client::new(backend_url);
    let response = client.get_pending_signatures(&secret_key).await?;

    let filtered_response = match digest_filter {
        Some(filter) => {
            let parsed = filter
                .parse::<AsfaloadHashes>()
                .map_err(ClientCliError::InvalidInput)?;
            response.filter(&parsed)
        }
        None => response,
    };

    // 3. Display results
    if json {
        println!("{}", serde_json::to_string(&filtered_response)?);
    } else if filtered_response.pending_files.is_empty() {
        println!("No pending signatures found.");
    } else {
        println!("Files requiring your signature:");
        for path in &filtered_response.pending_files {
            println!("  - {}", path);
        }
    }

    Ok(filtered_response.pending_files)
}
