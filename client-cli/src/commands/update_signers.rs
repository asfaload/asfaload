use common::AsfaloadHashes;

use crate::commands::signers_submission_output::print_submission_overview;
use crate::error::{ClientCliError, Result, ensure_backend_success};

use super::prepare_signed_submission;

pub async fn handle_update_signers_command(
    backend_url: &str,
    signers_file_url: &str,
    expected_digest: &AsfaloadHashes,
    secret_key_path: &std::path::PathBuf,
    password: &str,
    json: bool,
) -> Result<()> {
    let sub = prepare_signed_submission(backend_url, secret_key_path, password).await?;

    let response = sub
        .client
        .update_signers(
            signers_file_url,
            expected_digest,
            &sub.public_key,
            &sub.secret_key,
        )
        .await?;

    ensure_backend_success(
        response.success,
        &response.message,
        ClientCliError::SignersUpdateFailed,
    )?;

    if json {
        println!("{}", serde_json::to_string(&response)?);
    } else {
        print_submission_overview(
            "Signers update proposed",
            &response,
            expected_digest,
            backend_url,
        );
    }

    Ok(())
}
