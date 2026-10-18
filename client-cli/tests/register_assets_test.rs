use features_lib::{AsfaloadKeyPairTrait, AsfaloadKeyPairs};
use predicates::prelude::*;

#[test]
fn test_register_assets_cli_help() {
    let mut cmd = assert_cmd::cargo_bin_cmd!("asfaload-cli");
    cmd.arg("register-assets").arg("--help");
    cmd.assert()
        .success()
        .stdout(predicate::str::contains("github-release-url"))
        .stdout(predicate::str::contains("csum-file"))
        .stdout(predicate::str::contains("secret-key"))
        .stdout(predicate::str::contains("backend-url"));
}

#[test]
fn test_register_assets_requires_mode() {
    let mut cmd = assert_cmd::cargo_bin_cmd!("asfaload-cli");
    cmd.arg("register-assets");
    cmd.assert()
        .failure()
        .stderr(predicate::str::contains("required"));
}

#[test]
fn test_register_assets_requires_secret_key_for_github_release() {
    let mut cmd = assert_cmd::cargo_bin_cmd!("asfaload-cli");
    cmd.arg("register-assets")
        .arg("--github-release-url")
        .arg("https://github.com/testowner/testrepo/releases/tag/v1.0.0");
    cmd.assert()
        .failure()
        .stderr(predicate::str::contains("required"));
}

#[test]
fn test_register_assets_requires_secret_key_for_csum_file() {
    let mut cmd = assert_cmd::cargo_bin_cmd!("asfaload-cli");
    cmd.arg("register-assets")
        .arg("--csum-file")
        .arg("https://files.example.com/releases/v1.0/SHA256SUMS");
    cmd.assert()
        .failure()
        .stderr(predicate::str::contains("required"));
}

// Without the test-utils mock fetcher the CLI would query the real github
// rest-api: this test runs only when the test-utils feature is enabled.
#[cfg(feature = "test-utils")]
#[test]
fn test_register_assets_github_release_network_error_without_server() {
    let temp_dir = tempfile::TempDir::new().unwrap();
    let key_path = temp_dir.path().join("test_key.json");

    let secret_key = AsfaloadKeyPairs::new("test_password_123").unwrap();
    secret_key.save(&key_path).unwrap();

    let mut cmd = assert_cmd::cargo_bin_cmd!("asfaload-cli");
    cmd.arg("register-assets")
        .arg("--github-release-url")
        .arg("https://github.com/testowner/testrepo/releases/tag/v1.0.0")
        .arg("-K")
        .arg(&key_path)
        .arg("-u")
        .arg("http://127.0.0.1:9")
        .env("ASFALOAD_REGISTER_ASSETS_PASSWORD", "test_password_123");

    cmd.assert().failure().stderr(
        predicate::str::contains("connection")
            .or(predicate::str::contains("Connection"))
            .or(predicate::str::contains("error sending request")),
    );
}

#[test]
fn test_register_assets_csum_file_network_error_without_server() {
    let temp_dir = tempfile::TempDir::new().unwrap();
    let key_path = temp_dir.path().join("test_key.json");

    let secret_key = AsfaloadKeyPairs::new("test_password_123").unwrap();
    secret_key.save(&key_path).unwrap();

    let mut cmd = assert_cmd::cargo_bin_cmd!("asfaload-cli");
    cmd.arg("register-assets")
        .arg("--csum-file")
        .arg("https://files.example.com/releases/v1.0/SHA256SUMS")
        .arg("-K")
        .arg(&key_path)
        .arg("-u")
        .arg("http://127.0.0.1:9")
        .env("ASFALOAD_REGISTER_ASSETS_PASSWORD", "test_password_123");

    cmd.assert().failure().stderr(
        predicate::str::contains("connection")
            .or(predicate::str::contains("Connection"))
            .or(predicate::str::contains("error sending request")),
    );
}
