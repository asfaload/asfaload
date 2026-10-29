use crate::error::Result;

use super::prepare_signed_submission;

pub async fn handle_update_signers_command(
    backend_url: &str,
    signers_file_url: &str,
    secret_key_path: &std::path::PathBuf,
    password: &str,
    json: bool,
) -> Result<()> {
    let sub = prepare_signed_submission(backend_url, secret_key_path, password).await?;

    let response = sub
        .client
        .update_signers(signers_file_url, &sub.public_key, &sub.secret_key)
        .await?;

    if json {
        println!("{}", serde_json::to_string(&response)?);
    } else if response.success {
        println!("Signers update proposed successfully!");
        println!("Project ID: {}", response.project_id);
        println!(
            "Required signers ({}): {}",
            response.required_signers.len(),
            response.required_signers.join(", ")
        );
        println!("Success: {}", response.message);
    } else {
        println!("Signers update failed: {}", response.message);
    }

    Ok(())
}
