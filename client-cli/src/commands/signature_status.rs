use crate::commands::signers_submission_output::{BOLD, keys_that_can_sign_lines};
use crate::error::Result;
use crate::utils::strip_control_chars;
use anstyle::Style;
use features_lib::AsfaloadSecretKeyTrait;
use features_lib::AsfaloadSecretKeys;
use rest_api_types::GetSignatureStatusResponse;

/// Build the human output of signature-status. For a pending signature, it
/// also lists the keys that can still sign.
pub fn signature_status_overview(response: &GetSignatureStatusResponse, with_ansi: bool) -> String {
    let bold = if with_ansi { BOLD } else { Style::new() };
    let file_path = strip_control_chars(&response.file_path);
    if response.is_complete {
        return format!("{file_path}: complete\n");
    }
    let mut lines = vec![format!("{file_path}: pending"), String::new()];
    lines.extend(keys_that_can_sign_lines(&response.required_signers, bold));
    let mut output = lines.join("\n");
    output.push('\n');
    output
}

/// Handle the signature-status command.
///
/// Queries the backend for the signature collection status of a file.
/// The caller must be an authorized signer for the file.
pub async fn handle_signature_status_command(
    file_path: &str,
    backend_url: &str,
    secret_key_path: &std::path::PathBuf,
    password: &str,
    json: bool,
) -> Result<()> {
    let secret_key = AsfaloadSecretKeys::from_file(secret_key_path, password)?;

    let client = admin_lib::v1::Client::new(backend_url);
    let response = client.get_signature_status(file_path, &secret_key).await?;

    if json {
        println!("{}", serde_json::to_string(&response)?);
    } else {
        // anstream removes the styles when stdout is not a terminal.
        anstream::print!("{}", signature_status_overview(&response, true));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn response(is_complete: bool, required_signers: &[&str]) -> GetSignatureStatusResponse {
        GetSignatureStatusResponse {
            file_path: "project/asfaload.index.json".to_string(),
            is_complete,
            required_signers: required_signers.iter().map(|k| k.to_string()).collect(),
        }
    }

    #[test]
    fn complete_status() {
        assert_eq!(
            signature_status_overview(&response(true, &[]), false),
            "project/asfaload.index.json: complete\n"
        );
    }

    #[test]
    fn pending_status_lists_keys() {
        assert_eq!(
            signature_status_overview(&response(false, &["key1", "key2"]), false),
            "project/asfaload.index.json: pending\n\nKeys that can still sign\n  key1\n  key2\n"
        );
    }

    #[test]
    fn control_chars_are_removed_from_path() {
        let mut status = response(true, &[]);
        status.file_path = "pro\x1b[2Kject".to_string();
        assert_eq!(
            signature_status_overview(&status, false),
            "pro[2Kject: complete\n"
        );
    }
}
