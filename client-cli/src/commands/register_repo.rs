use crate::commands::prepare_signed_submission;
use crate::error::Result;
use common::AsfaloadHashes;

pub async fn handle_register_repo_command(
    backend_url: &str,
    signers_file_url: &str,
    expected_digest: &AsfaloadHashes,
    secret_key_path: &std::path::PathBuf,
    password: &str,
    json: bool,
) -> Result<()> {
    // All failable local steps happen before any network request
    let sub = prepare_signed_submission(backend_url, secret_key_path, password).await?;

    let response = sub
        .client
        .register_repo(
            signers_file_url,
            expected_digest,
            &sub.public_key,
            &sub.secret_key,
        )
        .await?;

    if json {
        println!("{}", serde_json::to_string(&response)?);
    } else if response.success {
        println!("Repository registered successfully!");
        println!("Project ID: {}", response.project_id);
        println!(
            "Required signers ({}): {}",
            response.required_signers.len(),
            response.required_signers.join(", ")
        );
        println!("Success! {}", response.message);
    } else {
        println!("Repository registration failed: {}", response.message);
    }

    Ok(())
}
