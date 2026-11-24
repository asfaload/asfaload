// Binary-level tests verifying that the clap arguments wired to environment
// variables in the last release effectively pick up their value from the env
// when the corresponding flag is not given on the command line.
//
// Each test spawns the real binary so the environment is isolated per child
// process (no global env mutation, no cross-test races). Every test also has a
// counterpart "env absent" behaviour documented inline: that is what makes the
// assertion meaningful — it only passes because the value came from the env.

use predicates::prelude::*;

// -------------------------------------------------------------------
// ASFALOAD_BACKEND_URL -> BackendUrlArgs::backend_url
// -------------------------------------------------------------------

// `ping` echoes the backend url it used. We point a mock server at it through
// the env var (no `-u` flag) and assert the request lands on the mock and the
// output names that url. Without the env var the command would hit the default
// backend (https://backend.asfaload.com) and never touch the mock.
#[test]
fn test_backend_url_taken_from_env() {
    let mut server = mockito::Server::new();
    let mock = server
        .mock("GET", "/v1/ping")
        .with_status(200)
        .with_body(r#"{"message":"pong","auth":{"status":"unauthenticated"}}"#)
        .create();

    let mut cmd = assert_cmd::cargo_bin_cmd!("asfaload-cli");
    cmd.arg("ping").env("ASFALOAD_BACKEND_URL", server.url());

    cmd.assert().success().stdout(
        predicate::str::contains(format!("from {}", server.url()))
            .and(predicate::str::contains("unauthenticated")),
    );

    mock.assert();
}

// NOTE: `ping` is also wired to ASFALOAD_SECRET_KEY (keeping its own optional
// key field). Proving it *authenticates* with that key is done end-to-end in
// tests/e2e_tests/basic_flow_local.sh against a real backend that validates the
// request signature — a mock here could only check that headers were sent, not
// that the signature is accepted.

// -------------------------------------------------------------------
// ASFALOAD_SECRET_KEY -> SecretKeyArgs::secret_key
// -------------------------------------------------------------------

// `--secret-key` is a required argument. Without it (and without the env var)
// clap refuses to run. This is the baseline proving the env var is what
// satisfies the requirement in the next test.
#[test]
fn test_secret_key_required_without_env() {
    let mut cmd = assert_cmd::cargo_bin_cmd!("asfaload-cli");
    cmd.arg("list-pending").arg("--password").arg("whatever");

    cmd.assert()
        .failure()
        .stderr(predicate::str::contains("required"))
        .stderr(predicate::str::contains("--secret-key"));
}

// With the env var set, clap is satisfied without `-K`/`--secret-key` and the
// command proceeds past argument parsing to actually load the key. We point it
// at a non-existent path so it fails at key loading rather than the clap
// required-argument error — proving the value came from the env.
#[test]
fn test_secret_key_taken_from_env() {
    let mut cmd = assert_cmd::cargo_bin_cmd!("asfaload-cli");
    cmd.arg("list-pending")
        .arg("--password")
        .arg("whatever")
        .arg("-u")
        .arg("http://127.0.0.1:9")
        .env("ASFALOAD_SECRET_KEY", "/nonexistent/key_from_env.json");

    cmd.assert()
        .failure()
        // Got past clap: this is no longer the required-argument error.
        .stderr(predicate::str::contains("required").not())
        // Reached key loading with the env-provided path.
        .stderr(predicate::str::contains("/nonexistent/key_from_env.json"));
}

// -------------------------------------------------------------------
// ASFALOAD_PASSWORD_COMMAND -> PasswordArgs::password_command
// -------------------------------------------------------------------

// The password command is run to obtain the password. We set it through the env
// var to a command that prints a recognisable marker and fails; the marker
// surfaces verbatim in the error, proving the command string came from the env.
// Without the env var, `new-keys` would prompt interactively and fail to read
// the password instead.
#[test]
fn test_password_command_taken_from_env() {
    let temp_dir = tempfile::TempDir::new().unwrap();

    let mut cmd = assert_cmd::cargo_bin_cmd!("asfaload-cli");
    cmd.arg("new-keys")
        .arg("--name")
        .arg("envkey")
        .arg("--keys-dir")
        .arg(temp_dir.path())
        .env(
            "ASFALOAD_PASSWORD_COMMAND",
            "sh -c 'echo CMD_MARKER_XYZ 1>&2; exit 1'",
        );

    cmd.assert()
        .failure()
        .stderr(predicate::str::contains("Command failed: CMD_MARKER_XYZ"));
}

// -------------------------------------------------------------------
// ASFALOAD_PASSWORD_FILE -> PasswordArgs::password_file
// -------------------------------------------------------------------

// The password file is read to obtain the password. We write a strong password
// to a file and pass its path only through the env var (no `--password-file`
// flag). `new-keys` succeeds, which can only happen if the password was read
// from the env-provided file — otherwise it would prompt interactively and fail.
#[test]
fn test_password_file_taken_from_env() {
    let temp_dir = tempfile::TempDir::new().unwrap();
    let password_file = temp_dir.path().join("password.txt");
    std::fs::write(&password_file, "correct horse battery staple 9z!").unwrap();

    let mut cmd = assert_cmd::cargo_bin_cmd!("asfaload-cli");
    cmd.arg("new-keys")
        .arg("--name")
        .arg("envkey")
        .arg("--keys-dir")
        .arg(temp_dir.path())
        .env("ASFALOAD_PASSWORD_FILE", &password_file);

    cmd.assert()
        .success()
        .stdout(predicate::str::contains("Generated keypair"));
}
