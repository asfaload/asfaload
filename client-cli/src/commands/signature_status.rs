use crate::commands::signers_submission_output::{
    BOLD, command_tail, is_safe_project_id, keys_that_can_sign_lines,
};
use crate::error::Result;
use crate::utils::{config_for_display, strip_control_chars};
use anstyle::Style;
use client_lib::config::{CliConfig, ConfigAccessor};
use features_lib::AsfaloadSecretKeys;
use rest_api_types::GetSignatureStatusResponse;

/// Build the human output of signature-status. For a pending signature, it
/// also lists the keys that can still sign.
pub fn signature_status_overview(
    response: &GetSignatureStatusResponse,
    config: &CliConfig,
    with_ansi: bool,
) -> String {
    let bold = if with_ansi { BOLD } else { Style::new() };
    let file_path = strip_control_chars(&response.file_path);
    if response.is_complete {
        return format!("{file_path}: complete\n");
    }
    let mut lines = vec![format!("{file_path}: pending"), String::new()];
    lines.extend(keys_that_can_sign_lines(
        &response.required_signers,
        config,
        bold,
    ));
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
    secret_key: &AsfaloadSecretKeys,
    json: bool,
    config_accessor: &ConfigAccessor,
) -> Result<()> {
    let client = admin_lib::v1::Client::new(backend_url);
    let response = client.get_signature_status(file_path, secret_key).await?;

    if json {
        println!("{}", serde_json::to_string(&response)?);
    } else {
        let config = config_for_display(config_accessor);
        // anstream removes the styles when stdout is not a terminal.
        anstream::print!("{}", signature_status_overview(&response, &config, true));
    }

    Ok(())
}

/// Build the hint, shown after a signature, about how to follow the status
/// of the signature. The command is shown only when `file_path` is safe to
/// put in a shell command.
///
/// `backend_url` is `Some` only when the user did not use the default backend.
pub fn signature_status_hint(
    file_path: &str,
    backend_url: Option<&str>,
    executable: &str,
) -> String {
    if !is_safe_project_id(file_path) {
        return "To follow the status of the signature, use the signature-status command.\n"
            .to_string();
    }
    let mut lines = vec![
        "To follow the status of the signature, run this command:".to_string(),
        String::new(),
    ];
    lines.extend(signature_status_command_lines(
        file_path,
        backend_url,
        executable,
    ));
    let mut output = lines.join("\n");
    output.push('\n');
    output
}

/// The signature-status command for `file_path`, as shown in a hint.
/// `file_path` must be safe to put in a shell command.
///
/// `backend_url` is `Some` only when the user did not use the default backend.
pub(crate) fn signature_status_command_lines(
    file_path: &str,
    backend_url: Option<&str>,
    executable: &str,
) -> Vec<String> {
    let mut lines = vec![
        format!("     {executable} signature-status \\"),
        format!("       {file_path} \\"),
    ];
    lines.extend(command_tail(backend_url));
    lines
}

#[cfg(test)]
mod tests {
    use super::*;
    use features_lib::AsfaloadPublicKeyTrait;

    #[test]
    fn status_hint_with_default_backend() {
        assert_eq!(
            signature_status_hint("project/asfaload.index.json", None, "asfaload"),
            "To follow the status of the signature, run this command:\n\
             \n     asfaload signature-status \\\n       project/asfaload.index.json \\\n       --secret-key <secret-key>\n"
        );
    }

    #[test]
    fn status_hint_with_other_backend() {
        let hint = signature_status_hint(
            "project/asfaload.index.json",
            Some("https://asfaload.example.com"),
            "asfaload",
        );
        assert!(hint.contains("       --backend-url https://asfaload.example.com \\\n"));
        assert!(hint.ends_with("       --secret-key <secret-key>\n"));
    }

    #[test]
    fn status_hint_without_command_for_unsafe_path() {
        for path in ["../project/file", "project/a b", "pro\x1bject"] {
            assert_eq!(
                signature_status_hint(path, None, "asfaload"),
                "To follow the status of the signature, use the signature-status command.\n"
            );
        }
    }

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
            signature_status_overview(&response(true, &[]), &CliConfig::default(), false),
            "project/asfaload.index.json: complete\n"
        );
    }

    #[test]
    fn pending_status_lists_keys() {
        assert_eq!(
            signature_status_overview(
                &response(false, &["key1", "key2"]),
                &CliConfig::default(),
                false
            ),
            "project/asfaload.index.json: pending\n\nKeys that can still sign\n  key1\n  key2\n"
        );
    }

    #[test]
    fn pending_status_shows_aliases() {
        let keys = test_helpers::TestKeys::new(1);
        let key_0 = keys.pub_key(0).unwrap();
        let mut config = CliConfig::default();
        config.add_alias(key_0, "alice", false).unwrap();
        let status = response(false, &[&key_0.to_base64()]);
        assert_eq!(
            signature_status_overview(&status, &config, false),
            format!(
                "project/asfaload.index.json: pending\n\nKeys that can still sign\n  {} (alice)\n",
                key_0.to_base64()
            )
        );
    }

    #[test]
    fn control_chars_are_removed_from_path() {
        let mut status = response(true, &[]);
        status.file_path = "pro\x1b[2Kject".to_string();
        assert_eq!(
            signature_status_overview(&status, &CliConfig::default(), false),
            "pro[2Kject: complete\n"
        );
    }
}
