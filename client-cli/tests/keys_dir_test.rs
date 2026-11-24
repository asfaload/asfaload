// Binary-level tests for loading a secret key by its name in the keys dir. The mock backend only
// answers when the request is signed with the expected key, so a success proves which key file
// the command read.

use std::path::Path;

use features_lib::{AsfaloadPublicKeyTrait, AsfaloadPublicKeys};
use predicates::prelude::*;
use tempfile::TempDir;

const FIXTURE_PASSWORD: &str = "password";

fn fixture_public_key(n: usize) -> String {
    AsfaloadPublicKeys::from_file(test_helpers::fixtures_pub_key(n))
        .unwrap()
        .to_base64()
}

// Copy fixture key `n` in `dir`, under `name`.
fn copy_fixture_key(n: usize, dir: &Path, name: &str) {
    std::fs::create_dir_all(dir).unwrap();
    std::fs::copy(
        test_helpers::fixtures_keys_dir().join(format!("key_{n}")),
        dir.join(name),
    )
    .unwrap();
}

fn mock_ping_signed_by(server: &mut mockito::Server, n: usize) -> mockito::Mock {
    server
        .mock("GET", "/v1/ping")
        .match_header(
            rest_api_auth::HEADER_PUBLIC_KEY,
            fixture_public_key(n).as_str(),
        )
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(format!(
            r#"{{"message":"pong","auth":{{"status":"success","public_key":"{}"}}}}"#,
            fixture_public_key(n)
        ))
        .create()
}

// A ping with -K `name`, isolated from key settings in the environment of the developer.
fn ping_command(server: &mockito::Server, name: &str, home: &Path) -> assert_cmd::Command {
    let mut cmd = assert_cmd::cargo_bin_cmd!("asfaload-cli");
    cmd.arg("ping")
        .arg("-u")
        .arg(server.url())
        .arg("-K")
        .arg(name)
        .arg("-p")
        .arg(FIXTURE_PASSWORD)
        .env_remove("ASFALOAD_KEYS_DIR")
        .env_remove("ASFALOAD_SECRET_KEY")
        .env("HOME", home)
        .env("XDG_DATA_HOME", home.join("data"));
    cmd
}

#[test]
fn ping_reads_key_name_in_keys_dir_flag() {
    let temp_dir = TempDir::new().unwrap();
    let keys_dir = temp_dir.path().join("keys");
    copy_fixture_key(0, &keys_dir, "mykey");
    let mut server = mockito::Server::new();
    let mock = mock_ping_signed_by(&mut server, 0);

    ping_command(&server, "mykey", temp_dir.path())
        .arg("--keys-dir")
        .arg(&keys_dir)
        .current_dir(temp_dir.path())
        .assert()
        .success();

    mock.assert();
}

#[test]
fn ping_reads_key_name_in_keys_dir_env_var() {
    let temp_dir = TempDir::new().unwrap();
    let keys_dir = temp_dir.path().join("keys");
    copy_fixture_key(1, &keys_dir, "mykey");
    let mut server = mockito::Server::new();
    let mock = mock_ping_signed_by(&mut server, 1);

    ping_command(&server, "mykey", temp_dir.path())
        .env("ASFALOAD_KEYS_DIR", &keys_dir)
        .current_dir(temp_dir.path())
        .assert()
        .success();

    mock.assert();
}

#[test]
fn ping_keys_dir_flag_overrides_env_var() {
    let temp_dir = TempDir::new().unwrap();
    let flag_dir = temp_dir.path().join("flag");
    let env_dir = temp_dir.path().join("env");
    copy_fixture_key(0, &flag_dir, "mykey");
    copy_fixture_key(1, &env_dir, "mykey");
    let mut server = mockito::Server::new();
    let mock = mock_ping_signed_by(&mut server, 0);

    ping_command(&server, "mykey", temp_dir.path())
        .arg("--keys-dir")
        .arg(&flag_dir)
        .env("ASFALOAD_KEYS_DIR", &env_dir)
        .current_dir(temp_dir.path())
        .assert()
        .success();

    mock.assert();
}

// The default keys dir is the one where new-keys writes keys by default.
#[cfg(unix)]
#[test]
fn ping_reads_key_name_in_default_keys_dir() {
    let temp_dir = TempDir::new().unwrap();
    copy_fixture_key(
        2,
        &temp_dir.path().join("data").join("asfaload-cli"),
        "mykey",
    );
    let mut server = mockito::Server::new();
    let mock = mock_ping_signed_by(&mut server, 2);

    ping_command(&server, "mykey", temp_dir.path())
        .current_dir(temp_dir.path())
        .assert()
        .success();

    mock.assert();
}

// A relative path to an existing file keeps working as before keys dirs existed.
#[test]
fn ping_prefers_file_in_current_dir_over_keys_dir() {
    let temp_dir = TempDir::new().unwrap();
    let work_dir = temp_dir.path().join("work");
    let keys_dir = temp_dir.path().join("keys");
    copy_fixture_key(0, &work_dir, "mykey");
    copy_fixture_key(1, &keys_dir, "mykey");
    let mut server = mockito::Server::new();
    let mock = mock_ping_signed_by(&mut server, 0);

    ping_command(&server, "mykey", temp_dir.path())
        .arg("--keys-dir")
        .arg(&keys_dir)
        .current_dir(&work_dir)
        .assert()
        .success();

    mock.assert();
}

#[test]
fn ping_fails_when_key_name_is_not_found() {
    let temp_dir = TempDir::new().unwrap();
    let keys_dir = temp_dir.path().join("keys");
    std::fs::create_dir_all(&keys_dir).unwrap();
    let mut server = mockito::Server::new();
    let mock = server.mock("GET", "/v1/ping").expect(0).create();

    ping_command(&server, "missing_key", temp_dir.path())
        .arg("--keys-dir")
        .arg(&keys_dir)
        .current_dir(temp_dir.path())
        .assert()
        .failure();

    mock.assert();
}

// The other commands get -K and --keys-dir from a shared struct, which ping does not use.
#[test]
fn list_pending_reads_key_name_in_keys_dir() {
    let temp_dir = TempDir::new().unwrap();
    let keys_dir = temp_dir.path().join("keys");
    copy_fixture_key(3, &keys_dir, "mykey");
    let mut server = mockito::Server::new();
    let mock = server
        .mock("GET", "/v1/pending_signatures")
        .match_header(
            rest_api_auth::HEADER_PUBLIC_KEY,
            fixture_public_key(3).as_str(),
        )
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(r#"{"pending_files":[]}"#)
        .create();

    let mut cmd = assert_cmd::cargo_bin_cmd!("asfaload-cli");
    cmd.arg("list-pending")
        .arg("-u")
        .arg(server.url())
        .arg("-K")
        .arg("mykey")
        .arg("--keys-dir")
        .arg(&keys_dir)
        .arg("-p")
        .arg(FIXTURE_PASSWORD)
        .env_remove("ASFALOAD_KEYS_DIR")
        .env_remove("ASFALOAD_SECRET_KEY")
        .current_dir(temp_dir.path())
        .assert()
        .success()
        .stdout(predicate::str::is_empty().not());

    mock.assert();
}
