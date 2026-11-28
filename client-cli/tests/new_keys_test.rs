use features_lib::{AsfaloadSecretKeyTrait, AsfaloadSecretKeys};
use predicates::prelude::*;
use tempfile::TempDir;

const TEST_PASSWORD: &str = "test_password_123";

// Verifies that a key created via --password-command can be loaded with the
// password the command printed -- i.e. it is equivalent to passing the same
// string via --password.
#[test]
fn test_new_keys_password_command_produces_loadable_key() {
    let temp_dir = TempDir::new().unwrap();
    let key_path = temp_dir.path().join("mykey");

    // `printf %s` outputs the password with no trailing newline.
    let cmd_str = format!("sh -c 'printf %s {TEST_PASSWORD}'");

    let mut cmd = assert_cmd::cargo_bin_cmd!("asfaload-cli");
    cmd.arg("new-keys")
        .arg("-n")
        .arg("mykey")
        .arg("--keys-dir")
        .arg(temp_dir.path())
        .arg("-C")
        .arg(&cmd_str)
        .arg("--accept-weak-password");
    cmd.assert().success();

    AsfaloadSecretKeys::from_file(&key_path, TEST_PASSWORD)
        .expect("key generated with --password-command should load with the printed password");
}

// `echo` appends a trailing newline; the implementation must strip it so the
// effective password matches what the user (or another command using --password)
// would type.
#[test]
fn test_new_keys_password_command_trims_trailing_newline() {
    let temp_dir = TempDir::new().unwrap();
    let key_path = temp_dir.path().join("mykey");

    let cmd_str = format!("sh -c 'echo {TEST_PASSWORD}'");

    let mut cmd = assert_cmd::cargo_bin_cmd!("asfaload-cli");
    cmd.arg("new-keys")
        .arg("-n")
        .arg("mykey")
        .arg("--keys-dir")
        .arg(temp_dir.path())
        .arg("-C")
        .arg(&cmd_str)
        .arg("--accept-weak-password");
    cmd.assert().success();

    AsfaloadSecretKeys::from_file(&key_path, TEST_PASSWORD)
        .expect("trailing newline from echo should be trimmed before the password is used");
}

#[test]
fn test_new_keys_message_suggests_alias() {
    let temp_dir = TempDir::new().unwrap();

    let mut cmd = assert_cmd::cargo_bin_cmd!("asfaload-cli");
    cmd.arg("new-keys")
        .arg("-n")
        .arg("mykey")
        .arg("--keys-dir")
        .arg(temp_dir.path())
        .arg("-p")
        .arg(TEST_PASSWORD)
        .arg("--accept-weak-password");
    let assert = cmd.assert().success();

    let pub_key = std::fs::read_to_string(temp_dir.path().join("mykey.pub")).unwrap();
    assert.stdout(predicate::str::contains(format!(
        "asfaload-cli alias --key {} <name>",
        pub_key.trim()
    )));
}

// Without --keys-dir, keys go to the user's data dir. XDG_DATA_HOME is set on the child process
// only, so the test never writes in the data dir of the developer.
#[cfg(unix)]
#[test]
fn test_new_keys_defaults_to_user_data_dir() {
    let temp_dir = TempDir::new().unwrap();
    let data_dir = temp_dir.path().join("data");

    let mut cmd = assert_cmd::cargo_bin_cmd!("asfaload-cli");
    cmd.arg("new-keys")
        .arg("-n")
        .arg("mykey")
        .arg("-p")
        .arg(TEST_PASSWORD)
        .arg("--accept-weak-password")
        .env_remove("ASFALOAD_KEYS_DIR")
        .env("HOME", temp_dir.path())
        .env("XDG_DATA_HOME", &data_dir);
    cmd.assert().success();

    let keys_dir = data_dir.join("asfaload-cli");
    assert!(keys_dir.join("mykey").is_file());
    assert!(keys_dir.join("mykey.pub").is_file());
}

#[cfg(unix)]
#[test]
fn test_new_keys_creates_output_dir_readable_by_owner_only() {
    use std::os::unix::fs::PermissionsExt;

    let temp_dir = TempDir::new().unwrap();
    let output_dir = temp_dir.path().join("new").join("keys");

    let mut cmd = assert_cmd::cargo_bin_cmd!("asfaload-cli");
    cmd.arg("new-keys")
        .arg("-n")
        .arg("mykey")
        .arg("--keys-dir")
        .arg(&output_dir)
        .arg("-p")
        .arg(TEST_PASSWORD)
        .arg("--accept-weak-password");
    cmd.assert().success();

    let mode = std::fs::metadata(&output_dir).unwrap().permissions().mode();
    assert_eq!(mode & 0o777, 0o700, "unexpected keys dir mode {mode:o}");
}

// new-keys writes in the keys dir that the other commands use to find a key name.
#[test]
fn test_new_keys_writes_in_keys_dir_env_var() {
    let temp_dir = TempDir::new().unwrap();
    let keys_dir = temp_dir.path().join("keys");

    let mut cmd = assert_cmd::cargo_bin_cmd!("asfaload-cli");
    cmd.arg("new-keys")
        .arg("-n")
        .arg("mykey")
        .arg("-p")
        .arg(TEST_PASSWORD)
        .arg("--accept-weak-password")
        .env("ASFALOAD_KEYS_DIR", &keys_dir);
    cmd.assert().success();

    assert!(keys_dir.join("mykey").is_file());
    assert!(keys_dir.join("mykey.pub").is_file());
}

#[test]
fn test_new_keys_reports_existing_key_before_asking_password() {
    let temp_dir = TempDir::new().unwrap();
    std::fs::write(temp_dir.path().join("mykey.pub"), "existing").unwrap();

    let mut cmd = assert_cmd::cargo_bin_cmd!("asfaload-cli");
    cmd.arg("new-keys")
        .arg("-n")
        .arg("mykey")
        .arg("--keys-dir")
        .arg(temp_dir.path())
        .arg("--password-command")
        .arg("sh -c 'echo PASSWORD_ASKED 1>&2; exit 1'")
        .assert()
        .failure()
        .stderr(predicate::str::contains(
            "Refusing to write key to existing file",
        ))
        .stderr(predicate::str::contains("PASSWORD_ASKED").not());
}

// Clap shows the options set from environment variables in the usage of an error.
// They must not look required.
#[test]
fn test_new_keys_error_usage_omits_options_set_from_env() {
    let temp_dir = TempDir::new().unwrap();

    let mut cmd = assert_cmd::cargo_bin_cmd!("asfaload-cli");
    cmd.arg("new-keys")
        .env("ASFALOAD_KEYS_DIR", temp_dir.path())
        .env("ASFALOAD_PASSWORD_FILE", temp_dir.path().join("password"));
    cmd.assert().code(2).stderr(predicate::str::contains(
        "Usage: asfaload-cli new-keys [OPTIONS] --name <NAME>\n",
    ));
}
