use crate::error::{ClientCliError, Result};
use common::AsfaloadHashes;
use features_lib::AsfaloadSecretKeys;
use rest_api_types::models::SafeListPendingResponse;
use rest_api_types::models::SafePendingFile;

/// Lists all files from the backend that require the user's signature.
pub async fn handle_list_pending_command(
    backend_url: &str,
    secret_key: &AsfaloadSecretKeys,
    digest_filter: Option<String>,
    json: bool,
) -> Result<Vec<SafePendingFile>> {
    let client = admin_lib::v1::Client::new(backend_url);
    let response = client.get_pending_signatures(secret_key).await?;

    let filtered_response: SafeListPendingResponse = match digest_filter {
        Some(filter) => {
            let parsed = filter
                .parse::<AsfaloadHashes>()
                .map_err(ClientCliError::InvalidInput)?;
            response.filter(&parsed).into()
        }
        None => response.into(),
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
