use predicates::prelude::*;
use sha2::{Digest, Sha512};
use std::io::Write;
use tempfile::NamedTempFile;

fn expected_sha512(content: &[u8]) -> String {
    let hash = Sha512::digest(content);
    format!("sha512:{}", hex::encode(hash))
}

// ---------------------------------------------------------------------------
// File-path branch
// ---------------------------------------------------------------------------

#[test]
fn get_digest_file_prints_sha512_prefix() {
    let mut file = NamedTempFile::new().unwrap();
    file.write_all(b"test content").unwrap();
    file.flush().unwrap();

    let mut cmd = assert_cmd::cargo_bin_cmd!("asfaload-cli");
    cmd.arg("get-digest").arg(file.path());

    cmd.assert()
        .success()
        .stdout(predicate::str::starts_with("sha512:"));
}

#[test]
fn get_digest_file_hash_is_correct() {
    let content = b"known content for hash verification";
    let mut file = NamedTempFile::new().unwrap();
    file.write_all(content).unwrap();
    file.flush().unwrap();

    let mut cmd = assert_cmd::cargo_bin_cmd!("asfaload-cli");
    cmd.arg("get-digest").arg(file.path());

    cmd.assert()
        .success()
        .stdout(predicate::str::contains(expected_sha512(content)));
}

#[test]
fn get_digest_file_json_output() {
    let content = b"json test content";
    let mut file = NamedTempFile::new().unwrap();
    file.write_all(content).unwrap();
    file.flush().unwrap();

    let output = assert_cmd::cargo_bin_cmd!("asfaload-cli")
        .arg("get-digest")
        .arg("--json")
        .arg(file.path())
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout).unwrap();
    let json: serde_json::Value =
        serde_json::from_str(&stdout).expect("stdout should be valid JSON");
    assert_eq!(json["digest"].as_str().unwrap(), expected_sha512(content));
}

#[test]
fn get_digest_nonexistent_file_fails() {
    let mut cmd = assert_cmd::cargo_bin_cmd!("asfaload-cli");
    cmd.arg("get-digest").arg("/nonexistent/path/file.bin");
    cmd.assert().failure().stderr(predicate::str::contains(
        "File not found at /nonexistent/path/file.bin",
    ));
}

// ---------------------------------------------------------------------------
// URL branch
// ---------------------------------------------------------------------------

#[test]
fn get_digest_url_prints_correct_hash() {
    let content = b"content served via url";
    let mut server = mockito::Server::new();
    let _m = server
        .mock("GET", "/file.bin")
        .with_status(200)
        .with_body(content.as_ref())
        .create();

    let url = format!("{}/file.bin", server.url());

    let mut cmd = assert_cmd::cargo_bin_cmd!("asfaload-cli");
    cmd.arg("get-digest").arg(&url);

    cmd.assert()
        .success()
        .stdout(predicate::str::contains(expected_sha512(content)));
}

#[test]
fn get_digest_url_json_output() {
    let content = b"json url content";
    let mut server = mockito::Server::new();
    let _m = server
        .mock("GET", "/file.bin")
        .with_status(200)
        .with_body(content.as_ref())
        .create();

    let url = format!("{}/file.bin", server.url());

    let output = assert_cmd::cargo_bin_cmd!("asfaload-cli")
        .arg("get-digest")
        .arg("--json")
        .arg(&url)
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout).unwrap();
    let json: serde_json::Value =
        serde_json::from_str(&stdout).expect("stdout should be valid JSON");
    assert_eq!(json["digest"].as_str().unwrap(), expected_sha512(content));
}

#[test]
fn get_digest_url_http_error_fails() {
    let mut server = mockito::Server::new();
    let _m = server
        .mock("GET", "/file.bin")
        .with_status(404)
        .with_body("not found")
        .create();

    let url = format!("{}/file.bin", server.url());

    let mut cmd = assert_cmd::cargo_bin_cmd!("asfaload-cli");
    cmd.arg("get-digest").arg(&url);
    cmd.assert().failure();
    cmd.assert()
        .failure()
        .stderr(predicate::str::contains("HTTP 404 Not Found:"));
}

#[test]
fn get_digest_url_empty_body_fails() {
    let mut server = mockito::Server::new();
    let _m = server
        .mock("GET", "/empty")
        .with_status(200)
        .with_body("")
        .create();

    let url = format!("{}/empty", server.url());

    let mut cmd = assert_cmd::cargo_bin_cmd!("asfaload-cli");
    cmd.arg("get-digest").arg(&url);
    cmd.assert().failure();
}

// ---------------------------------------------------------------------------
// Consistency: file and URL with same content must produce identical output
// ---------------------------------------------------------------------------

#[test]
fn get_digest_file_and_url_same_content_produce_same_hash() {
    let content = b"consistent content";

    let mut file = NamedTempFile::new().unwrap();
    file.write_all(content).unwrap();
    file.flush().unwrap();

    let mut server = mockito::Server::new();
    let _m = server
        .mock("GET", "/file.bin")
        .with_status(200)
        .with_body(content.as_ref())
        .create();

    let url = format!("{}/file.bin", server.url());

    let file_out = assert_cmd::cargo_bin_cmd!("asfaload-cli")
        .arg("get-digest")
        .arg(file.path())
        .output()
        .unwrap();

    let url_out = assert_cmd::cargo_bin_cmd!("asfaload-cli")
        .arg("get-digest")
        .arg(&url)
        .output()
        .unwrap();

    assert!(file_out.status.success());
    assert!(url_out.status.success());
    assert_eq!(file_out.stdout, url_out.stdout);
}

#[test]
fn get_digest_file_default_output_is_digest_only() {
    let content = b"digest only content";
    let mut file = NamedTempFile::new().unwrap();
    file.write_all(content).unwrap();
    file.flush().unwrap();

    let mut cmd = assert_cmd::cargo_bin_cmd!("asfaload-cli");
    cmd.arg("get-digest").arg(file.path());

    cmd.assert()
        .success()
        .stdout(format!("{}\n", expected_sha512(content)));
}

#[test]
fn get_digest_json_output_contains_only_digest() {
    let content = b"json digest only content";
    let mut file = NamedTempFile::new().unwrap();
    file.write_all(content).unwrap();
    file.flush().unwrap();

    let output = assert_cmd::cargo_bin_cmd!("asfaload-cli")
        .arg("get-digest")
        .arg("--json")
        .arg(file.path())
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout).unwrap();
    let json: serde_json::Value =
        serde_json::from_str(&stdout).expect("stdout should be valid JSON");
    assert_eq!(
        json,
        serde_json::json!({ "digest": expected_sha512(content) }),
        "JSON output must contain only the digest"
    );
}
