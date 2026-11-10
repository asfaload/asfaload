use features_lib::{AsfaloadKeyPairTrait, AsfaloadKeyPairs};
use predicates::prelude::*;
use serde_json::Value;
use tempfile::TempDir;

const TEST_PASSWORD: &str = "test_password_123";

const DIGEST_A: &str = concat!(
    "sha512:",
    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
);
const DIGEST_B: &str = concat!(
    "sha512:",
    "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
    "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
);
const DIGEST_NON_MATCHING: &str = concat!(
    "sha512:",
    "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
    "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
);

fn generate_test_keypair() -> (TempDir, std::path::PathBuf) {
    let temp_dir = TempDir::new().unwrap();
    let key_path = temp_dir.path().join("test_key");
    let kp = AsfaloadKeyPairs::new(TEST_PASSWORD).unwrap();
    kp.save(&key_path).unwrap();
    (temp_dir, key_path)
}

fn pending_response_json(files: &[(&str, &str)]) -> String {
    let items: Vec<String> = files
        .iter()
        .map(|(path, digest)| format!(r#"{{"path":"{}","digest":"{}"}}"#, path, digest))
        .collect();
    format!(r#"{{"pending_files":[{}]}}"#, items.join(","))
}

// ---------------------------------------------------------------------------
// --help wiring
// ---------------------------------------------------------------------------

#[test]
fn list_pending_help_shows_digest_filter_option() {
    let mut cmd = assert_cmd::cargo_bin_cmd!("asfaload-cli");
    cmd.arg("list-pending").arg("--help");
    cmd.assert()
        .success()
        .stdout(predicate::str::contains("digest-filter"));
}

// ---------------------------------------------------------------------------
// no filter: all pending files are shown
// ---------------------------------------------------------------------------

#[test]
fn list_pending_no_filter_shows_all_files() {
    let (_key_dir, key_path) = generate_test_keypair();
    let mut server = mockito::Server::new();
    let _m = server
        .mock("GET", "/v1/pending_signatures")
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(pending_response_json(&[
            ("releases/v1/file-a.tar.gz", DIGEST_A),
            ("releases/v1/file-b.tar.gz", DIGEST_B),
        ]))
        .create();

    let mut cmd = assert_cmd::cargo_bin_cmd!("asfaload-cli");
    cmd.arg("list-pending")
        .arg("-K")
        .arg(&key_path)
        .arg("-u")
        .arg(server.url())
        .env("ASFALOAD_LIST_PENDING_PASSWORD", TEST_PASSWORD);

    cmd.assert()
        .success()
        .stdout(predicate::str::contains("file-a.tar.gz"))
        .stdout(predicate::str::contains("file-b.tar.gz"));
}

#[test]
fn list_pending_output_shows_only_paths_and_digests() {
    let mut server = mockito::Server::new();
    let _m = server
        .mock("GET", "/v1/pending_signatures")
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(pending_response_json(&[
            ("releases/v1/file-a.tar.gz", DIGEST_A),
            ("releases/v1/file-b.tar.gz", DIGEST_B),
        ]))
        .create();

    let mut cmd = assert_cmd::cargo_bin_cmd!("asfaload-cli");
    cmd.arg("list-pending")
        .arg("-K")
        .arg(test_helpers::fixtures_keys_dir().join("key_0"))
        .arg("-u")
        .arg(server.url())
        .env("ASFALOAD_LIST_PENDING_PASSWORD", "password");

    let expected = format!(
        "Files requiring your signature:\n  - path: releases/v1/file-a.tar.gz\ndigest: {DIGEST_A}\n\n  - path: releases/v1/file-b.tar.gz\ndigest: {DIGEST_B}\n\n"
    );
    cmd.assert().success().stdout(expected);
}

// ---------------------------------------------------------------------------
// --digest-filter: only the matching file is returned
// ---------------------------------------------------------------------------

#[test]
fn list_pending_digest_filter_keeps_matching_file() {
    let (_key_dir, key_path) = generate_test_keypair();
    let mut server = mockito::Server::new();
    let _m = server
        .mock("GET", "/v1/pending_signatures")
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(pending_response_json(&[
            ("releases/v1/file-a.tar.gz", DIGEST_A),
            ("releases/v1/file-b.tar.gz", DIGEST_B),
        ]))
        .create();

    let mut cmd = assert_cmd::cargo_bin_cmd!("asfaload-cli");
    cmd.arg("list-pending")
        .arg("-K")
        .arg(&key_path)
        .arg("-u")
        .arg(server.url())
        .arg("--digest-filter")
        .arg(DIGEST_A)
        .env("ASFALOAD_LIST_PENDING_PASSWORD", TEST_PASSWORD);

    cmd.assert()
        .success()
        .stdout(predicate::str::contains("file-a.tar.gz"))
        .stdout(predicate::str::contains("file-b.tar.gz").not());
}

#[test]
fn list_pending_digest_filter_excludes_non_matching_file() {
    let (_key_dir, key_path) = generate_test_keypair();
    let mut server = mockito::Server::new();
    let _m = server
        .mock("GET", "/v1/pending_signatures")
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(pending_response_json(&[
            ("releases/v1/file-a.tar.gz", DIGEST_A),
            ("releases/v1/file-b.tar.gz", DIGEST_B),
        ]))
        .create();

    let mut cmd = assert_cmd::cargo_bin_cmd!("asfaload-cli");
    cmd.arg("list-pending")
        .arg("-K")
        .arg(&key_path)
        .arg("-u")
        .arg(server.url())
        .arg("--digest-filter")
        .arg(DIGEST_B)
        .env("ASFALOAD_LIST_PENDING_PASSWORD", TEST_PASSWORD);

    cmd.assert()
        .success()
        .stdout(predicate::str::contains("file-b.tar.gz"))
        .stdout(predicate::str::contains("file-a.tar.gz").not());
}

// ---------------------------------------------------------------------------
// --digest-filter with no match: empty result
// ---------------------------------------------------------------------------

#[test]
fn list_pending_digest_filter_no_match_shows_empty_message() {
    let (_key_dir, key_path) = generate_test_keypair();
    let mut server = mockito::Server::new();
    let _m = server
        .mock("GET", "/v1/pending_signatures")
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(pending_response_json(&[(
            "releases/v1/file-a.tar.gz",
            DIGEST_A,
        )]))
        .create();

    let mut cmd = assert_cmd::cargo_bin_cmd!("asfaload-cli");
    cmd.arg("list-pending")
        .arg("-K")
        .arg(&key_path)
        .arg("-u")
        .arg(server.url())
        .arg("--digest-filter")
        .arg(DIGEST_NON_MATCHING)
        .env("ASFALOAD_LIST_PENDING_PASSWORD", TEST_PASSWORD);

    cmd.assert()
        .success()
        .stdout(predicate::str::contains("No pending signatures found"));
}

// ---------------------------------------------------------------------------
// --digest-filter with --json
// ---------------------------------------------------------------------------

#[test]
fn list_pending_digest_filter_json_contains_only_matching_file() {
    let (_key_dir, key_path) = generate_test_keypair();
    let mut server = mockito::Server::new();
    let _m = server
        .mock("GET", "/v1/pending_signatures")
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(pending_response_json(&[
            ("releases/v1/file-a.tar.gz", DIGEST_A),
            ("releases/v1/file-b.tar.gz", DIGEST_B),
        ]))
        .create();

    let output = assert_cmd::cargo_bin_cmd!("asfaload-cli")
        .arg("list-pending")
        .arg("-K")
        .arg(&key_path)
        .arg("-u")
        .arg(server.url())
        .arg("--digest-filter")
        .arg(DIGEST_A)
        .arg("--json")
        .env("ASFALOAD_LIST_PENDING_PASSWORD", TEST_PASSWORD)
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout).unwrap();
    let json: Value = serde_json::from_str(&stdout).expect("stdout should be valid JSON");

    let files = json["pending_files"]
        .as_array()
        .expect("pending_files should be array");
    assert_eq!(files.len(), 1);
    assert_eq!(files[0]["digest"].as_str().unwrap(), DIGEST_A);
    assert!(files[0]["path"].as_str().unwrap().contains("file-a.tar.gz"));
}

#[test]
fn list_pending_digest_filter_no_match_json_returns_empty_array() {
    let (_key_dir, key_path) = generate_test_keypair();
    let mut server = mockito::Server::new();
    let _m = server
        .mock("GET", "/v1/pending_signatures")
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(pending_response_json(&[(
            "releases/v1/file-a.tar.gz",
            DIGEST_A,
        )]))
        .create();

    let output = assert_cmd::cargo_bin_cmd!("asfaload-cli")
        .arg("list-pending")
        .arg("-K")
        .arg(&key_path)
        .arg("-u")
        .arg(server.url())
        .arg("--digest-filter")
        .arg(DIGEST_NON_MATCHING)
        .arg("--json")
        .env("ASFALOAD_LIST_PENDING_PASSWORD", TEST_PASSWORD)
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout).unwrap();
    let json: Value = serde_json::from_str(&stdout).expect("stdout should be valid JSON");

    let files = json["pending_files"]
        .as_array()
        .expect("pending_files should be array");
    assert!(files.is_empty());
}
