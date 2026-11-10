use ClientCliError::PasswordStrengthError;
use std::io::Read;
use std::io::{Error, ErrorKind};
use std::path::Path;
use std::process::Command;
use std::str::FromStr;
use zxcvbn::{Score, zxcvbn};

use crate::error::{ClientCliError, Result};
use clap::CommandFactory;
use common::{AsfaloadHashes, sha512_for_file};

/// Ensures a directory exists, creating it if necessary
pub fn ensure_dir_exists(path: &Path) -> Result<()> {
    if !path.exists() {
        std::fs::create_dir_all(path).map_err(ClientCliError::Io)?;
    }
    Ok(())
}

/// Validates that a threshold is valid for the given number of keys
pub fn validate_threshold(threshold: u32, key_count: usize) -> Result<()> {
    if threshold == 0 {
        return Err(ClientCliError::InvalidInput(
            "Threshold cannot be zero".to_string(),
        ));
    }

    if threshold as usize > key_count {
        return Err(ClientCliError::InvalidInput(format!(
            "Threshold ({}) cannot be greater than the number of keys ({})",
            threshold, key_count
        )));
    }

    Ok(())
}

/// Name of the program as defined in the command line parser.
/// Use it in hints that other people run. Use `executable_name()` in hints
/// that the same user runs.
pub fn program_name() -> String {
    crate::cli::Cli::command().get_name().to_string()
}

/// Name of the executable as started by the user, like `$0` in a shell.
/// Use it in command hints, so that the user can copy them.
pub fn executable_name() -> String {
    executable_name_from(std::env::args_os().next())
}

/// Uses the clap command name when `argv[0]` is missing or empty.
fn executable_name_from(arg0: Option<std::ffi::OsString>) -> String {
    arg0.filter(|a| !a.is_empty())
        .map(|a| a.to_string_lossy().into_owned())
        .unwrap_or_else(program_name)
}

/// Removes control characters, so that text from the backend cannot
/// use terminal escape sequences to hide or change the output.
pub(crate) fn strip_control_chars(text: &str) -> String {
    text.chars().filter(|c| !c.is_control()).collect()
}

/// Reads password from a file
pub fn read_password_from_file(file_path: &Path) -> Result<String> {
    let mut file = std::fs::File::open(file_path).map_err(ClientCliError::Io)?;
    let mut password = String::new();
    file.read_to_string(&mut password)
        .map_err(ClientCliError::Io)?;
    Ok(password.trim_end().to_string())
}

/// Gets password from various sources with the following priority:
/// 1. Direct password argument
/// 2. Password file argument
/// 3. Environment variable ASFALOAD_NEW_KEYS_PASSWORD
/// 4. Environment variable ASFALOAD_NEW_KEYS_PASSWORD_FILE
/// 5. Interactive prompt
fn get_unvalidated_password(
    password_arg: Option<String>,
    password_file_arg: Option<&Path>,
    password_command_arg: Option<String>,
    env_var_password: &str,
    env_var_password_file: &str,
    password_confirmation: PasswordConfirmation,
    prompt_message: &str,
) -> Result<String> {
    if let Some(password) = password_arg {
        return Ok(password);
    }

    if let Some(command) = password_command_arg {
        return read_password_from_command(&command);
    }

    if let Some(file_path) = password_file_arg {
        return read_password_from_file(file_path);
    }

    // Check environment variable for password
    if let Ok(password) = std::env::var(env_var_password) {
        return Ok(password);
    }

    // Check environment variable for password file
    if let Ok(file_path) = std::env::var(env_var_password_file) {
        return read_password_from_file(Path::new(&file_path));
    }

    // If none found, prompt the user
    let password = rpassword::prompt_password(prompt_message)
        .map_err(|e| ClientCliError::InvalidInput(format!("Failed to read password: {}", e)))?;

    match password_confirmation {
        PasswordConfirmation::RequireConfirmation => {
            let password_confirmation =
                rpassword::prompt_password("Confirmation:").map_err(|e| {
                    ClientCliError::InvalidInput(format!("Failed to read password: {}", e))
                })?;

            if password_confirmation == password {
                Ok(password)
            } else {
                Err(ClientCliError::PasswordConfirmationError)
            }
        }
        PasswordConfirmation::WithoutConfirmation => Ok(password),
    }
}

fn validate_password(password: &str) -> Result<String> {
    let estimate = zxcvbn(password, &[]);

    // Check score
    match estimate.score() {
        Score::Zero | Score::One | Score::Two => {
            return Err(PasswordStrengthError("Password is too weak".to_string()));
        }
        // The enum is marked non-exhaustive, so we only match on the weaker ones, the rest is ok
        _ => {}
    }

    // Check warnings
    if let Some(feedback) = estimate.feedback() {
        if let Some(warning) = feedback.warning() {
            return Err(PasswordStrengthError(format!(
                "Password warning: {}",
                warning
            )));
        }
        if !feedback.suggestions().is_empty() {
            for suggestion in feedback.suggestions() {
                eprintln!("  • {}", suggestion);
            }
        }
    }

    Ok(password.to_string())
}
pub enum PasswordConfirmation {
    RequireConfirmation,
    WithoutConfirmation,
}
#[allow(clippy::too_many_arguments)]
pub fn get_password(
    password_arg: Option<String>,
    password_file_arg: Option<&Path>,
    password_command_arg: Option<String>,
    env_var_password: &str,
    env_var_password_file: &str,
    prompt_message: &str,
    password_confirmation: PasswordConfirmation,
    accept_weak_password: bool,
) -> Result<String> {
    let unvalidated_password = get_unvalidated_password(
        password_arg,
        password_file_arg,
        password_command_arg,
        env_var_password,
        env_var_password_file,
        password_confirmation,
        prompt_message,
    )?;
    if accept_weak_password {
        Ok(unvalidated_password)
    } else {
        let validated_password = validate_password(unvalidated_password.as_str())?;
        Ok(validated_password)
    }
}

fn read_password_from_command(command_str: &str) -> Result<String> {
    // shell_words::split handles quotes and escapes properly
    let words = shell_words::split(command_str).map_err(|e| {
        Error::new(
            ErrorKind::InvalidInput,
            format!("Invalid shell quoting in command: {}", e),
        )
    })?;

    if words.is_empty() {
        return Err(Error::new(ErrorKind::InvalidInput, "Command string is empty").into());
    }

    // args[0] is the executable, the rest are arguments
    let output = Command::new(&words[0]).args(&words[1..]).output()?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(Error::other(format!("Command failed: {}", stderr.trim())).into());
    }

    let password =
        String::from_utf8(output.stdout).map_err(|e| Error::new(ErrorKind::InvalidData, e))?;

    Ok(password.trim_end_matches(['\r', '\n']).to_string())
}

/// Resolve the expected digest of the signers file from the command flags.
///
/// The user gives either the digest value itself (`--digest`, format
/// `sha512:<hex>` as printed by get-digest) or the path of a local copy
/// of the signers file whose digest becomes the expected value.
/// clap enforces that the two flags are mutually exclusive, but we also
/// reject the impossible pair here.
pub fn expected_digest(
    digest: Option<String>,
    local_copy: Option<String>,
) -> Result<AsfaloadHashes> {
    match (digest, local_copy) {
        (Some(value), None) => AsfaloadHashes::from_str(value.trim())
            .map_err(|e| ClientCliError::InvalidInput(format!("Invalid --digest value: {e}"))),
        (None, Some(path)) => sha512_for_file(&path).map_err(|e| match e.kind() {
            std::io::ErrorKind::NotFound => ClientCliError::InvalidInput(format!(
                "Invalid --local-copy: File not found at {path}"
            )),
            // sha512_for_file returns InvalidData only for an empty file.
            std::io::ErrorKind::InvalidData => ClientCliError::InvalidInput(format!(
                "Invalid --local-copy: File is empty at {path}"
            )),
            _ => ClientCliError::from(e),
        }),
        // clap enforces the conflict; handle the impossible pair anyway.
        (Some(_), Some(_)) => Err(ClientCliError::InvalidInput(
            "--digest and --local-copy are mutually exclusive".to_string(),
        )),
        (None, None) => Err(ClientCliError::InvalidInput(
            "One of --digest or --local-copy is required".to_string(),
        )),
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use common::AsfaloadHashes;

    #[test]
    fn program_name_is_the_clap_command_name() {
        assert_eq!(program_name(), "asfaload-cli");
    }

    #[test]
    fn executable_name_from_cases() {
        use std::ffi::OsString;

        let clap_name = crate::cli::Cli::command().get_name().to_string();
        let cases = [
            (
                Some(OsString::from("./target/debug/asfaload-cli")),
                "./target/debug/asfaload-cli".to_string(),
            ),
            (None, clap_name.clone()),
            (Some(OsString::new()), clap_name),
        ];
        for (arg0, expected) in cases {
            assert_eq!(
                executable_name_from(arg0.clone()),
                expected,
                "unexpected executable name for argv[0] {arg0:?}"
            );
        }
    }

    #[test]
    fn strip_control_chars_removes_only_control_chars() {
        assert_eq!(strip_control_chars("a\x1b[2Kb\nc\u{7}"), "a[2Kbc");
    }

    // test expected_digest
    // --------------------
    const SIGNERS_CONTENT: &[u8] = b"{\"version\": 1}";

    fn signers_hash() -> AsfaloadHashes {
        common::sha512_for_content(SIGNERS_CONTENT).unwrap()
    }

    fn assert_invalid_input(result: Result<AsfaloadHashes>, expected_start: &str, case: &str) {
        match result {
            Err(ClientCliError::InvalidInput(msg)) => assert!(
                msg.starts_with(expected_start),
                "case {case}: unexpected message {msg:?}"
            ),
            other => panic!("case {case}: expected InvalidInput, got {other:?}"),
        }
    }

    #[test]
    fn expected_digest_accepts_valid_digest_values() {
        let hex = signers_hash().to_hex();
        let cases = vec![
            ("canonical", format!("sha512:{hex}")),
            ("uppercase hex", format!("sha512:{}", hex.to_uppercase())),
            ("uppercase algorithm", format!("SHA512:{hex}")),
            ("surrounding whitespace", format!("  sha512:{hex}\n")),
        ];
        for (case, value) in cases {
            let result = expected_digest(Some(value), None);
            assert_eq!(result.ok(), Some(signers_hash()), "case {case}");
        }
    }

    #[test]
    fn expected_digest_rejects_invalid_digest_values() {
        let hex = signers_hash().to_hex();
        let cases = vec![
            ("bare hex", hex.clone()),
            ("sha256 algorithm", format!("sha256:{hex}")),
            ("hex too short", format!("sha512:{}", &hex[..hex.len() - 2])),
            ("hex too long", format!("sha512:{hex}00")),
            (
                "odd hex length",
                format!("sha512:{}", &hex[..hex.len() - 1]),
            ),
            (
                "non hex character",
                format!("sha512:{}zz", &hex[..hex.len() - 2]),
            ),
            ("whitespace in value", format!("sha512: {hex}")),
            ("empty", String::new()),
        ];
        for (case, value) in cases {
            let result = expected_digest(Some(value), None);
            assert_invalid_input(result, "Invalid --digest value", case);
        }
    }

    #[test]
    fn expected_digest_uses_digest_of_local_copy() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("signers.json");
        std::fs::write(&path, SIGNERS_CONTENT).unwrap();

        let result = expected_digest(None, Some(path.to_string_lossy().into_owned()));

        assert_eq!(result.ok(), Some(signers_hash()));
    }

    #[test]
    fn expected_digest_rejects_missing_local_copy() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("missing.json");

        let result = expected_digest(None, Some(path.to_string_lossy().into_owned()));

        assert_invalid_input(
            result,
            "Invalid --local-copy: File not found at",
            "missing file",
        );
    }

    #[test]
    fn expected_digest_rejects_empty_local_copy() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("empty.json");
        std::fs::write(&path, b"").unwrap();

        let result = expected_digest(None, Some(path.to_string_lossy().into_owned()));

        assert_invalid_input(
            result,
            "Invalid --local-copy: File is empty at",
            "empty file",
        );
    }

    #[test]
    fn expected_digest_requires_exactly_one_flag() {
        let value = format!("sha512:{}", signers_hash().to_hex());
        assert_invalid_input(
            expected_digest(Some(value), Some("signers.json".to_string())),
            "--digest and --local-copy are mutually exclusive",
            "both flags",
        );
        assert_invalid_input(
            expected_digest(None, None),
            "One of --digest or --local-copy is required",
            "no flag",
        );
    }
}
