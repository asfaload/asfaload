use std::path::Path;

use anstyle::Style;
use common::index_types::AsfaloadIndex;
use features_lib::constants::INDEX_FILE;
use forge_url::artifacts_url_prefix_for_index_path;

use crate::cli::DEFAULT_BACKEND;
use crate::commands::signers_submission_output::BOLD;
use crate::utils::program_name;

/// True when `file_path` is the index of a release.
pub fn is_release_index_path(file_path: &str) -> bool {
    Path::new(file_path)
        .file_name()
        .is_some_and(|name| name == INDEX_FILE)
}

/// A URL is safe in a shell command when it is an http or https URL with only
/// ASCII letters, digits and `:`, `/`, `.`, `-`, `_`, `~`, `%`, `+`.
fn is_safe_url_for_command(url: &str) -> bool {
    (url.starts_with("https://") || url.starts_with("http://"))
        && url.chars().all(|c| {
            c.is_ascii_alphanumeric() || matches!(c, ':' | '/' | '.' | '-' | '_' | '~' | '%' | '+')
        })
}

/// The URL of the directory with the artifacts of the release, when it is
/// safe to put in a command.
fn safe_artifacts_url_prefix(index_path: &str) -> Option<String> {
    artifacts_url_prefix_for_index_path(index_path)
        .ok()
        .map(String::from)
        .filter(|prefix| is_safe_url_for_command(prefix))
}

/// The URL of the first artifact listed in the index, when it is safe to put
/// in a command.
///
/// The file name comes from the index, so it must not change the directory
/// of the URL.
fn first_artifact_url(prefix: &str, index_content: &[u8]) -> Option<String> {
    let index: AsfaloadIndex = serde_json::from_slice(index_content).ok()?;
    let file_name = &index.published_files.first()?.file_name;
    let is_plain_name = !matches!(file_name.as_str(), "." | "..")
        && !file_name.contains('/')
        && !file_name.contains(':');
    let url = format!("{prefix}{file_name}");
    (is_plain_name && is_safe_url_for_command(&url)).then_some(url)
}

/// Print the next step after a signature completed a release index.
///
/// `index_content` is the content of the index that the user signed.
pub fn print_release_download_next_step(
    index_path: &str,
    index_content: Option<&[u8]>,
    backend_url: &str,
) {
    let non_default_backend = (backend_url != DEFAULT_BACKEND).then_some(backend_url);
    // anstream removes the styles when stdout is not a terminal.
    anstream::print!(
        "{}",
        release_download_next_step(
            index_path,
            index_content,
            non_default_backend,
            &program_name(),
            true,
        )
    );
}

/// Build the next step after a signature completed a release index: an
/// example command to download an artifact of the release with verification.
///
/// The example uses the first artifact listed in the index. When the artifact
/// URL is not available or not safe in a shell, the example has the
/// placeholder `<download-url>`.
///
/// `backend_url` is `Some` only when the user did not use the default backend.
/// Users must then download with the same backend, so the command shows it.
pub fn release_download_next_step(
    index_path: &str,
    index_content: Option<&[u8]>,
    backend_url: Option<&str>,
    executable: &str,
    with_ansi: bool,
) -> String {
    let bold = if with_ansi { BOLD } else { Style::new() };
    let prefix = safe_artifacts_url_prefix(index_path);
    let artifact_url = prefix
        .as_deref()
        .zip(index_content)
        .and_then(|(prefix, content)| first_artifact_url(prefix, content));

    let mut lines = vec![
        format!("{bold}Next step{bold:#}"),
        "  The release is now signed. Users can download its artifacts with".to_string(),
    ];
    match (&artifact_url, &prefix) {
        (Some(_), _) => lines.push("  signature verification. Example:".to_string()),
        (None, Some(prefix)) => {
            lines.push(
                "  signature verification. Replace <download-url> with the URL of an".to_string(),
            );
            lines.push("  artifact, which starts with".to_string());
            lines.push(format!("  {prefix}"));
        }
        (None, None) => {
            lines.push(
                "  signature verification. Replace <download-url> with the URL of an".to_string(),
            );
            lines.push("  artifact of the release:".to_string());
        }
    }
    lines.push(String::new());
    lines.push(format!("     {executable} download \\"));
    if let Some(url) = backend_url {
        lines.push(format!("       --backend-url {url} \\"));
    }
    lines.push(format!(
        "       {}",
        artifact_url.as_deref().unwrap_or("<download-url>")
    ));
    lines.push(String::new());
    if let (Some(_), Some(prefix)) = (&artifact_url, &prefix) {
        lines.push("  The artifacts of this release are at".to_string());
        lines.push(format!("  {prefix}"));
    }
    lines
        .push("  You can also download them with asfald, our dedicated download tool.".to_string());
    let mut output = lines.join("\n");
    output.push('\n');
    output
}

#[cfg(test)]
mod tests {
    use super::*;
    use common::index_types::{ChecksumSourceFormat, FileChecksum, HashAlgorithm};

    const INDEX_PATH: &str = "https/github.com/443/acme/tool/releases/tag/v1.0/asfaload.index.json";
    const PREFIX: &str = "https://github.com/acme/tool/releases/download/v1.0/";

    fn index_content(file_names: &[&str]) -> Vec<u8> {
        let index = AsfaloadIndex {
            mirrored_on: chrono::Utc::now(),
            published_on: chrono::Utc::now(),
            version: 1,
            published_files: file_names
                .iter()
                .map(|name| FileChecksum {
                    file_name: name.to_string(),
                    algo: HashAlgorithm::Sha256,
                    source: "https://api.github.com/repos/acme/tool/releases/1".to_string(),
                    source_format: ChecksumSourceFormat::GithubRelease,
                    hash: "a".repeat(64),
                })
                .collect(),
        };
        index.to_json().unwrap().into_bytes()
    }

    fn next_step(index_path: &str, content: Option<&[u8]>) -> String {
        release_download_next_step(index_path, content, None, "asfaload", false)
    }

    #[test]
    fn is_release_index_path_cases() {
        let cases = [
            (INDEX_PATH, true),
            ("asfaload.index.json", true),
            (
                "https/github.com/443/acme/tool/asfaload.signers.pending/index.json",
                false,
            ),
            (
                "https/github.com/443/acme/tool/releases/tag/v1.0/asfaload.index.json.revocation.json.pending",
                false,
            ),
            ("", false),
        ];
        for (path, expected) in cases {
            assert_eq!(is_release_index_path(path), expected, "path {path:?}");
        }
    }

    #[test]
    fn next_step_with_artifact_shows_its_download_command() {
        let content = index_content(&["tool-linux-amd64.tar.gz", "tool-macos.zip"]);

        let output = next_step(INDEX_PATH, Some(&content));

        assert_eq!(
            output,
            format!(
                "Next step\n\
                 \x20 The release is now signed. Users can download its artifacts with\n\
                 \x20 signature verification. Example:\n\
                 \n     asfaload download \\\n       {PREFIX}tool-linux-amd64.tar.gz\n\
                 \n  The artifacts of this release are at\n  {PREFIX}\n\
                 \x20 You can also download them with asfald, our dedicated download tool.\n"
            )
        );
    }

    #[test]
    fn next_step_without_usable_artifact_shows_prefix_and_placeholder() {
        let empty_index = index_content(&[]);
        let unsafe_names = [
            "a b.tar.gz",
            "a;rm -rf.tar.gz",
            "../other.tar.gz",
            "sub/file.tar.gz",
            "https:evil",
            "..",
        ]
        .map(|name| index_content(&[name]));
        let contents: Vec<Option<&[u8]>> =
            [None, Some(b"not an index".as_slice()), Some(&empty_index)]
                .into_iter()
                .chain(unsafe_names.iter().map(|c| Some(c.as_slice())))
                .collect();

        for content in contents {
            let output = next_step(INDEX_PATH, content);

            assert!(
                output.contains(&format!(
                    "Replace <download-url> with the URL of an\n  artifact, which starts with\n  {PREFIX}\n"
                )),
                "content {content:?}: {output}"
            );
            assert!(
                output.contains("     asfaload download \\\n       <download-url>\n"),
                "content {content:?}: {output}"
            );
        }
    }

    #[test]
    fn next_step_without_prefix_shows_only_placeholder() {
        let content = index_content(&["tool.tar.gz"]);
        for index_path in [
            "asfaload.index.json",
            "https/example.com/443/a b/asfaload.index.json",
            "https/example.com/443/a;b/asfaload.index.json",
        ] {
            let output = next_step(index_path, Some(&content));

            assert!(
                output.contains(
                    "Replace <download-url> with the URL of an\n  artifact of the release:\n"
                ),
                "index path {index_path:?}: {output}"
            );
            assert!(
                output.contains("       <download-url>\n"),
                "index path {index_path:?}: {output}"
            );
            assert!(
                !output.contains("https://"),
                "index path {index_path:?}: {output}"
            );
        }
    }

    #[test]
    fn next_step_with_non_default_backend_adds_backend_url() {
        let content = index_content(&["tool.tar.gz"]);

        let output = release_download_next_step(
            INDEX_PATH,
            Some(&content),
            Some("https://asfaload.example.com"),
            "asfaload",
            false,
        );

        assert!(output.contains(&format!(
            "     asfaload download \\\n       --backend-url https://asfaload.example.com \\\n       {PREFIX}tool.tar.gz\n"
        )));
    }

    #[test]
    fn next_step_without_ansi_has_no_escape_codes_and_with_ansi_has_some() {
        let render =
            |with_ansi| release_download_next_step(INDEX_PATH, None, None, "asfaload", with_ansi);

        assert!(!render(false).contains('\x1b'));
        assert!(render(true).contains('\x1b'));
    }
}
