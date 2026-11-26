use crate::cli::DEFAULT_BACKEND;
use crate::commands::signers_submission_output::{BOLD, is_safe_project_id};
use crate::error::{ClientCliError, Result};
use crate::utils::{executable_name, strip_control_chars};
use anstyle::Style;
use common::AsfaloadHashes;
use features_lib::AsfaloadSecretKeys;
use rest_api_types::models::SafeListPendingResponse;
use rest_api_types::models::SafePendingFile;
use std::path::Path;

/// Maximum width of the wrapped text lines, indentation included.
const TEXT_WIDTH: usize = 74;

/// True when the user's argument can go in a command to copy without quotes.
fn is_plain_shell_word(word: &str) -> bool {
    !word.is_empty()
        && !word.starts_with('-')
        && word
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '/' | '.' | '_' | '-' | '~'))
}

/// The key arguments of the sign-pending example: the ones that the user gave
/// to list-pending. `None` when they are not plain shell words.
fn key_arguments(secret_key: &str, keys_dir: Option<&Path>) -> Option<Vec<String>> {
    let keys_dir = match keys_dir {
        Some(dir) => Some(dir.to_str().filter(|d| is_plain_shell_word(d))?),
        None => None,
    };
    if !is_plain_shell_word(secret_key) {
        return None;
    }
    Some(
        keys_dir
            .map(|dir| format!("--keys-dir {dir}"))
            .into_iter()
            .chain(std::iter::once(format!("--secret-key {secret_key}")))
            .collect(),
    )
}

/// Wrap `text` in lines indented by two spaces.
fn wrap_text(text: &str) -> Vec<String> {
    let mut lines = Vec::new();
    let mut line = String::from(" ");
    for word in text.split_whitespace() {
        if line.len() > 1 && line.len() + 1 + word.len() > TEXT_WIDTH {
            lines.push(line);
            line = String::from(" ");
        }
        line.push(' ');
        line.push_str(word);
    }
    lines.push(line);
    lines
}

/// Build the human output of list-pending: the pending files, and how to sign one.
///
/// `backend_url` is `Some` only when the user did not use the default backend.
/// `secret_key` and `keys_dir` are the values given to list-pending. The
/// sign-pending example uses them.
pub fn pending_files_overview(
    files: &[SafePendingFile],
    backend_url: Option<&str>,
    secret_key: &str,
    keys_dir: Option<&Path>,
    executable: &str,
    with_ansi: bool,
) -> String {
    if files.is_empty() {
        return "No pending signatures found.\n".to_string();
    }
    let bold = if with_ansi { BOLD } else { Style::new() };
    let mut lines = vec![format!("{bold}Files requiring your signature{bold:#}")];
    // Right-align the numbers, so that the paths and digests stay in one column.
    let width = files.len().to_string().len();
    for (index, file) in files.iter().enumerate() {
        if index > 0 {
            lines.push(String::new());
        }
        lines.push(format!(
            "  {:>width$}. path:   {}",
            index + 1,
            strip_control_chars(file.path())
        ));
        lines.push(format!(
            "  {:width$}  digest: {}",
            "",
            strip_control_chars(file.digest())
        ));
    }
    // Only a safe path goes in the command. Else the user fills it in.
    let example = files
        .iter()
        .enumerate()
        .find(|(_, file)| is_safe_project_id(file.path()));
    lines.extend([
        String::new(),
        format!("{bold}Before you sign{bold:#}"),
        "  The digests above are shortened. Get the full digest of the file from".to_string(),
        "  the user who started the signature process. Use the full digest to".to_string(),
        "  sign. Make sure that it starts and ends like the shortened digest.".to_string(),
        String::new(),
        format!("{bold}Next step{bold:#}"),
    ]);
    let key_args = key_arguments(secret_key, keys_dir);
    lines.extend(wrap_text(&next_step_intro(
        example.map(|(index, _)| index + 1),
        files.len(),
        key_args.is_none(),
    )));
    let mut args = vec![
        "--digest <full-digest>".to_string(),
        example
            .map_or("<file-path>", |(_, file)| file.path())
            .to_string(),
    ];
    args.extend(backend_url.map(|url| format!("--backend-url {url}")));
    args.extend(key_args.unwrap_or_else(|| vec!["--secret-key <secret-key>".to_string()]));
    lines.push(String::new());
    lines.push(format!("     {executable} sign-pending \\"));
    let last = args.len() - 1;
    lines.extend(args.iter().enumerate().map(|(i, arg)| {
        let continuation = if i == last { "" } else { " \\" };
        format!("       {arg}{continuation}")
    }));
    let mut output = lines.join("\n");
    output.push('\n');
    output
}

/// The text before the sign-pending example. `example_number` is the number
/// of the file in the example, `None` when the example has no path.
fn next_step_intro(
    example_number: Option<usize>,
    file_count: usize,
    key_placeholder: bool,
) -> String {
    let mut replacements = Vec::new();
    if example_number.is_none() {
        replacements.push("<file-path> with the path of the file");
    }
    replacements.push("<full-digest> with the full digest");
    if key_placeholder {
        replacements.push("<secret-key> with your secret key file");
    }
    let replace = match replacements.split_last() {
        Some((last, [])) => last.to_string(),
        Some((last, others)) => format!("{}, and {last}", others.join(", ")),
        None => String::new(),
    };
    match example_number {
        Some(number) if file_count > 1 => format!(
            "To sign pending file {number}, run this command. Replace {replace}. \
             To sign a different file, replace the path:"
        ),
        Some(number) => {
            format!("To sign pending file {number}, run this command. Replace {replace}:")
        }
        None => format!("To sign a pending file, run this command. Replace {replace}:"),
    }
}

/// Lists all files from the backend that require the user's signature.
///
/// `secret_key_arg` and `keys_dir` are the values that the user gave, shown
/// in the sign-pending example.
pub async fn handle_list_pending_command(
    backend_url: &str,
    secret_key: &AsfaloadSecretKeys,
    secret_key_arg: &str,
    keys_dir: Option<&Path>,
    digest_filter: Option<String>,
    json: bool,
) -> Result<Vec<SafePendingFile>> {
    let client = admin_lib::v1::Client::new(backend_url);
    let response = client.get_pending_signatures(secret_key).await?;

    let filtered_response: SafeListPendingResponse = match digest_filter {
        Some(filter) => {
            let parsed = filter
                .parse::<AsfaloadHashes>()
                .map_err(ClientCliError::InvalidInput)?;
            response.filter(&parsed).into()
        }
        None => response.into(),
    };

    // 3. Display results
    if json {
        println!("{}", serde_json::to_string(&filtered_response)?);
    } else {
        let non_default_backend = (backend_url != DEFAULT_BACKEND).then_some(backend_url);
        // anstream removes the styles when stdout is not a terminal.
        anstream::print!(
            "{}",
            pending_files_overview(
                &filtered_response.pending_files,
                non_default_backend,
                secret_key_arg,
                keys_dir,
                &executable_name(),
                true,
            )
        );
    }

    Ok(filtered_response.pending_files)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rest_api_types::models::PendingFile;

    const DIGEST: &str = concat!(
        "sha512:",
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    );

    fn pending_file(path: &str) -> SafePendingFile {
        let file: PendingFile =
            serde_json::from_str(&format!(r#"{{"path":"{path}","digest":"{DIGEST}"}}"#)).unwrap();
        SafePendingFile::from(&file)
    }

    #[test]
    fn overview_without_files() {
        assert_eq!(
            pending_files_overview(&[], None, "my key", None, "asfaload", false),
            "No pending signatures found.\n"
        );
    }

    #[test]
    fn overview_with_default_backend() {
        let files = [
            pending_file("github.com/o/r/asfaload.signers.pending/index.json"),
            pending_file("github.com/o/r/v1/asfaload.index.json"),
        ];
        assert_eq!(
            pending_files_overview(&files, None, "my key", None, "asfaload", false),
            "Files requiring your signature\n\
             \x20 1. path:   github.com/o/r/asfaload.signers.pending/index.json\n\
             \x20    digest: sha512:aaaaaaaa....aaaaaaaa\n\
             \n\
             \x20 2. path:   github.com/o/r/v1/asfaload.index.json\n\
             \x20    digest: sha512:aaaaaaaa....aaaaaaaa\n\
             \n\
             Before you sign\n\
             \x20 The digests above are shortened. Get the full digest of the file from\n\
             \x20 the user who started the signature process. Use the full digest to\n\
             \x20 sign. Make sure that it starts and ends like the shortened digest.\n\
             \n\
             Next step\n\
             \x20 To sign pending file 1, run this command. Replace <full-digest> with the\n\
             \x20 full digest, and <secret-key> with your secret key file. To sign a\n\
             \x20 different file, replace the path:\n\
             \n\
             \x20    asfaload sign-pending \\\n\
             \x20      --digest <full-digest> \\\n\
             \x20      github.com/o/r/asfaload.signers.pending/index.json \\\n\
             \x20      --secret-key <secret-key>\n"
        );
    }

    #[test]
    fn overview_with_other_backend_shows_backend_url() {
        let files = [pending_file("github.com/o/r/v1/asfaload.index.json")];
        let output = pending_files_overview(
            &files,
            Some("http://localhost:3000"),
            "my key",
            None,
            "a",
            false,
        );
        assert!(
            output.ends_with(
                "       github.com/o/r/v1/asfaload.index.json \\\n\
                 \x20      --backend-url http://localhost:3000 \\\n\
                 \x20      --secret-key <secret-key>\n"
            ),
            "got: {output}"
        );
    }

    #[test]
    fn overview_example_skips_unsafe_path() {
        let files = [
            pending_file("-rf/asfaload.index.json"),
            pending_file("github.com/o/r/v1/asfaload.index.json"),
        ];
        let output = pending_files_overview(&files, None, "my key", None, "a", false);
        assert!(output.contains("To sign pending file 2,"), "got: {output}");
        assert!(
            output.contains("       github.com/o/r/v1/asfaload.index.json \\\n"),
            "got: {output}"
        );
        assert!(!output.contains("       -rf/"), "got: {output}");
    }

    #[test]
    fn overview_example_uses_placeholder_without_safe_path() {
        let files = [pending_file("o/r/../asfaload.index.json")];
        let output = pending_files_overview(&files, None, "my key", None, "a", false);
        assert!(
            output.contains(
                "  To sign a pending file, run this command. Replace <file-path> with the\n"
            ),
            "got: {output}"
        );
        assert!(output.contains("       <file-path> \\\n"), "got: {output}");
    }

    #[test]
    fn overview_with_one_file_does_not_mention_other_files() {
        let files = [pending_file("github.com/o/r/v1/asfaload.index.json")];
        let output = pending_files_overview(&files, None, "my key", None, "a", false);
        assert!(
            output.contains(
                "  To sign pending file 1, run this command. Replace <full-digest> with the\n\
                 \x20 full digest, and <secret-key> with your secret key file:\n"
            ),
            "got: {output}"
        );
        assert!(!output.contains("different file"), "got: {output}");
    }

    #[test]
    fn overview_aligns_numbers_from_ten_files() {
        let files: Vec<_> = (0..10)
            .map(|i| pending_file(&format!("o/r/v{i}/asfaload.index.json")))
            .collect();
        let output = pending_files_overview(&files, None, "my key", None, "a", false);
        assert!(
            output.contains(
                "   9. path:   o/r/v8/asfaload.index.json\n\
                 \x20     digest: sha512:aaaaaaaa....aaaaaaaa\n\
                 \n\
                 \x20 10. path:   o/r/v9/asfaload.index.json\n\
                 \x20     digest: sha512:aaaaaaaa....aaaaaaaa\n"
            ),
            "got: {output}"
        );
    }

    #[test]
    fn overview_uses_secret_key_and_keys_dir_of_the_user() {
        let files = [
            pending_file("github.com/o/r/v1/asfaload.index.json"),
            pending_file("github.com/o/r/v2/asfaload.index.json"),
        ];
        let output = pending_files_overview(
            &files,
            Some("http://localhost:3000"),
            "mykey",
            Some(Path::new("/home/me/keys")),
            "a",
            false,
        );
        assert!(
            output.ends_with(
                "Next step\n\
                 \x20 To sign pending file 1, run this command. Replace <full-digest> with the\n\
                 \x20 full digest. To sign a different file, replace the path:\n\
                 \n\
                 \x20    a sign-pending \\\n\
                 \x20      --digest <full-digest> \\\n\
                 \x20      github.com/o/r/v1/asfaload.index.json \\\n\
                 \x20      --backend-url http://localhost:3000 \\\n\
                 \x20      --keys-dir /home/me/keys \\\n\
                 \x20      --secret-key mykey\n"
            ),
            "got: {output}"
        );
    }

    #[test]
    fn overview_uses_secret_key_without_keys_dir() {
        let files = [pending_file("github.com/o/r/v1/asfaload.index.json")];
        let output = pending_files_overview(&files, None, "keys/key_0", None, "a", false);
        assert!(
            output.ends_with(
                "  To sign pending file 1, run this command. Replace <full-digest> with the\n\
                 \x20 full digest:\n\
                 \n\
                 \x20    a sign-pending \\\n\
                 \x20      --digest <full-digest> \\\n\
                 \x20      github.com/o/r/v1/asfaload.index.json \\\n\
                 \x20      --secret-key keys/key_0\n"
            ),
            "got: {output}"
        );
    }

    #[test]
    fn overview_uses_placeholder_for_unsafe_keys_dir() {
        let files = [pending_file("github.com/o/r/v1/asfaload.index.json")];
        let output = pending_files_overview(
            &files,
            None,
            "mykey",
            Some(Path::new("/home/me/my keys")),
            "a",
            false,
        );
        assert!(!output.contains("--keys-dir"), "got: {output}");
        assert!(
            output.ends_with("       --secret-key <secret-key>\n"),
            "got: {output}"
        );
        assert!(
            output.contains("<secret-key> with your secret key"),
            "got: {output}"
        );
    }

    /// Secret key, keys dir, and the expected key arguments.
    type KeyArgumentsCase<'a> = (&'a str, Option<&'a str>, Option<Vec<&'a str>>);

    #[test]
    fn key_arguments_cases() {
        let cases: Vec<KeyArgumentsCase> = vec![
            ("mykey", None, Some(vec!["--secret-key mykey"])),
            (
                "~/.keys/key_0",
                Some("/k"),
                Some(vec!["--keys-dir /k", "--secret-key ~/.keys/key_0"]),
            ),
            ("my key", None, None),
            ("-rf", None, None),
            ("", None, None),
            ("key$(id)", None, None),
            ("mykey", Some("-d"), None),
            ("mykey", Some("a;b"), None),
        ];
        for (secret_key, keys_dir, expected) in cases {
            let expected: Option<Vec<String>> =
                expected.map(|args| args.into_iter().map(String::from).collect());
            assert_eq!(
                key_arguments(secret_key, keys_dir.map(Path::new)),
                expected,
                "unexpected result for {secret_key:?} {keys_dir:?}"
            );
        }
    }

    #[test]
    fn overview_removes_control_chars_from_path() {
        let files = [pending_file(r"o/r/\u001b[2Jx")];
        let output = pending_files_overview(&files, None, "my key", None, "a", false);
        assert!(!output.contains('\u{1b}'), "got: {output}");
        assert!(output.contains("  1. path:   o/r/[2Jx\n"), "got: {output}");
    }
}
