use anstyle::Style;
use common::AsfaloadHashes;
use common::fs::names::{is_pending_revocation_file_path, pending_revocation_path_for};
use rest_api_types::RevokeFileResponse;

use crate::cli::DEFAULT_BACKEND;
use crate::commands::signers_submission_output::{
    BOLD, SignaturesToCollect, is_safe_project_id, signatures_to_collect_lines, strip_control_chars,
};
use crate::utils::program_name;

/// Shown when the revocation is complete.
pub const REVOCATION_COMPLETE_MESSAGE: &str =
    "The revocation is complete. Downloads of this file now fail.";
/// Shown when the revocation is pending.
pub const REVOCATION_PENDING_MESSAGE: &str =
    "Users can still download the file until the revocation is complete.";

/// The note to show after a signature of `file_path`. `None` when the file is
/// not a pending revocation.
pub fn revocation_note(file_path: &str, is_complete: bool) -> Option<&'static str> {
    is_pending_revocation_file_path(file_path).then_some(if is_complete {
        REVOCATION_COMPLETE_MESSAGE
    } else {
        REVOCATION_PENDING_MESSAGE
    })
}

/// The path of the pending revocation file that the other signers must
/// sign. `None` when the path is not safe to put in a command for them.
fn safe_pending_revocation_path(file_path: &str) -> Option<String> {
    pending_revocation_path_for(file_path)
        .ok()
        .and_then(|path| path.to_str().map(String::from))
        .filter(|path| is_safe_project_id(path))
}

/// Print the output of a successful revoke.
pub fn print_revocation_overview(
    response: &RevokeFileResponse,
    file_path: &str,
    digest: &AsfaloadHashes,
    backend_url: &str,
) {
    let non_default_backend = (backend_url != DEFAULT_BACKEND).then_some(backend_url);
    // anstream removes the styles when stdout is not a terminal.
    anstream::print!(
        "{}",
        revocation_overview(
            response,
            file_path,
            digest,
            non_default_backend,
            &program_name(),
            true,
        )
    );
}

/// Build the human output after a successful revoke.
///
/// `digest` is the digest of the revocation document, which the other
/// revocation signers must give to sign-pending.
/// `backend_url` is `Some` only when the user did not use the default backend.
/// Signers must then contact the same backend, so the command shows it.
pub fn revocation_overview(
    response: &RevokeFileResponse,
    file_path: &str,
    digest: &AsfaloadHashes,
    backend_url: Option<&str>,
    executable: &str,
    with_ansi: bool,
) -> String {
    let bold = if with_ansi { BOLD } else { Style::new() };
    let is_complete = response.required_signers.is_empty();
    let headline = if is_complete {
        "File revoked:"
    } else {
        "Revocation started:"
    };
    let mut lines = vec![
        format!(
            "{bold}{headline}{bold:#} {}",
            strip_control_chars(file_path)
        ),
        "Your signature is included.".to_string(),
    ];
    if !is_complete {
        lines.push(REVOCATION_PENDING_MESSAGE.to_string());
    }
    lines.push(String::new());
    let pending_revocation_path = safe_pending_revocation_path(file_path);
    lines.extend(signatures_to_collect_lines(
        &SignaturesToCollect {
            required_signers: &response.required_signers,
            file_path: pending_revocation_path.as_deref(),
            digest,
            complete_message: REVOCATION_COMPLETE_MESSAGE,
            unexpected_data_warning: "The path of the revoked file contains unexpected characters.",
        },
        backend_url,
        executable,
        bold,
    ));
    let mut output = lines.join("\n");
    output.push('\n');
    output
}

#[cfg(test)]
mod tests {
    use super::*;
    use features_lib::constants::{PENDING_REVOCATION_SUFFIX, PENDING_SIGNERS_DIR, SIGNERS_FILE};

    const FILE_PATH: &str = "https/github.com/443/acme/tool/releases/tag/v1.0/asfaload.index.json";

    fn response(required_signers: Vec<&str>) -> RevokeFileResponse {
        RevokeFileResponse {
            success: true,
            message: "unused".to_string(),
            required_signers: required_signers.into_iter().map(String::from).collect(),
        }
    }

    fn digest() -> AsfaloadHashes {
        common::sha512_for_content(&b"revocation document"[..]).unwrap()
    }

    fn overview_for(response: &RevokeFileResponse, file_path: &str) -> String {
        revocation_overview(response, file_path, &digest(), None, "asfaload-cli", false)
    }

    #[test]
    fn overview_when_pending_shows_keys_and_sign_command() {
        let output = overview_for(
            &response(vec!["asfaload-pub:key-a", "asfaload-pub:key-b"]),
            FILE_PATH,
        );
        let expected = format!(
            "Revocation started: {FILE_PATH}\n\
             Your signature is included.\n\
             Users can still download the file until the revocation is complete.\n\
             \n\
             Keys that can still sign\n  \
             asfaload-pub:key-a\n  \
             asfaload-pub:key-b\n\
             \n\
             Next step\n  \
             Send this command to the signers. Each signer replaces <secret-key>\n  \
             with their secret key file:\n\
             \n     \
             asfaload-cli sign-pending \\\n       \
             --digest {} \\\n       \
             {FILE_PATH}.{PENDING_REVOCATION_SUFFIX} \\\n       \
             --secret-key <secret-key>\n",
            digest()
        );
        assert_eq!(output, expected);
    }

    #[test]
    fn overview_when_complete_has_no_sign_command() {
        assert_eq!(
            overview_for(&response(vec![]), FILE_PATH),
            format!(
                "File revoked: {FILE_PATH}\n\
                 Your signature is included.\n\
                 \n\
                 The revocation is complete. Downloads of this file now fail.\n"
            )
        );
    }

    #[test]
    fn overview_with_non_default_backend_adds_backend_url_before_secret_key() {
        let output = revocation_overview(
            &response(vec!["asfaload-pub:key-a"]),
            FILE_PATH,
            &digest(),
            Some("http://localhost:3000"),
            "asfaload-cli",
            false,
        );
        assert!(
            output.ends_with(
                "       --backend-url http://localhost:3000 \\\n       \
                 --secret-key <secret-key>\n"
            ),
            "unexpected output:\n{output}"
        );
    }

    #[test]
    fn overview_with_unsafe_file_path_shows_warning_instead_of_command() {
        let unsafe_path = "releases/my file.json";
        assert_eq!(
            overview_for(&response(vec!["asfaload-pub:key-a"]), unsafe_path),
            format!(
                "Revocation started: {unsafe_path}\n\
                 Your signature is included.\n\
                 Users can still download the file until the revocation is complete.\n\
                 \n\
                 Keys that can still sign\n  \
                 asfaload-pub:key-a\n\
                 \n\
                 Warning\n  \
                 The path of the revoked file contains unexpected characters.\n  \
                 For security, the command for the signers is not shown.\n  \
                 Signers can find the file with list-pending.\n"
            )
        );
    }

    #[test]
    fn overview_removes_control_chars_from_headline() {
        let output = overview_for(&response(vec![]), "releases/a\x1b[31mb.json");
        assert!(
            output.starts_with("File revoked: releases/a[31mb.json\n"),
            "unexpected output:\n{output}"
        );
    }

    #[test]
    fn revocation_note_for_revocation_and_other_files() {
        let revocation = format!("{FILE_PATH}.{PENDING_REVOCATION_SUFFIX}");
        assert_eq!(
            revocation_note(&revocation, true),
            Some(REVOCATION_COMPLETE_MESSAGE)
        );
        assert_eq!(
            revocation_note(&revocation, false),
            Some(REVOCATION_PENDING_MESSAGE)
        );
        assert_eq!(revocation_note(FILE_PATH, true), None);
        let signers = format!("project/{PENDING_SIGNERS_DIR}/{SIGNERS_FILE}");
        assert_eq!(revocation_note(&signers, false), None);
    }
}
