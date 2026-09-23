use client_cli::utils::label_for_hash;
use common::fs::names::metadata_path_for;
use features_lib::HashAlgorithm;
use predicates::prelude::*;
use serde_json::Value;
use sha2::{Digest, Sha512};

const SIGNERS_PATH: &str = "acme/tool/asfaload.signers.pending/index.json";
const SOURCE_CONTENT: &[u8] = br#"{"version":1}"#;
const PENDING_CONTENT: &[u8] = br#"{"version":2}"#;

const SOURCE_PATH: &str = "/acme/tool/asfaload.signers/index.json";

fn signers_metadata_json(source_url: &str) -> String {
    format!(
        r#"{{"data":{{"Forge":{{"kind":"Github","url":"https://github.com/acme/tool/raw/main/asfaload.signers/index.json","verified_content":{{"retrieval_url":"{source_url}","content_hash":"000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"}},"retrieved_at":"2024-01-01T00:00:00Z"}}}}}}"#
    )
}

fn sha512_digest_str(content: &[u8]) -> String {
    format!("sha512:{}", hex::encode(Sha512::digest(content)))
}

// Serves the pending signers file and its metadata from the backend mirror.
// `signers_content` is what the mirror holds; the metadata always points at
// `source_url` on the (distinct) file server.
fn mock_backend_files(
    backend: &mut mockito::Server,
    signers_content: &[u8],
    source_url: &str,
) -> (mockito::Mock, mockito::Mock) {
    let metadata_path = metadata_path_for(SIGNERS_PATH)
        .unwrap()
        .to_string_lossy()
        .to_string();
    let signers = backend
        .mock("GET", format!("/v1/files/{SIGNERS_PATH}").as_str())
        .with_status(200)
        .with_body(signers_content)
        .create();
    let metadata = backend
        .mock("GET", format!("/v1/files/{metadata_path}").as_str())
        .with_status(200)
        .with_body(signers_metadata_json(source_url))
        .create();
    (signers, metadata)
}

// Serves the signers file as published on the forge, at the path the
// metadata's retrieval_url points at.
fn mock_source(file_server: &mut mockito::Server, content: &[u8]) -> mockito::Mock {
    file_server
        .mock("GET", SOURCE_PATH)
        .with_status(200)
        .with_body(content)
        .create()
}

fn check_pending_cmd(backend: &mockito::Server) -> assert_cmd::Command {
    let mut cmd = assert_cmd::cargo_bin_cmd!("asfaload-cli");
    cmd.arg("check-pending-signers")
        .arg(SIGNERS_PATH)
        .arg("-u")
        .arg(backend.url());
    cmd
}

#[test]
fn check_pending_signers_help_lists_flags() {
    let mut cmd = assert_cmd::cargo_bin_cmd!("asfaload-cli");
    cmd.arg("check-pending-signers").arg("--help");
    cmd.assert()
        .success()
        .stdout(predicate::str::contains("--backend-url"))
        .stdout(predicate::str::contains("--json"));
}

#[test]
fn check_pending_signers_matching_source_succeeds() {
    let mut backend = mockito::Server::new();
    let mut file_server = mockito::Server::new();
    let source_url = format!("{}{SOURCE_PATH}", file_server.url());
    let _mocks = mock_backend_files(&mut backend, SOURCE_CONTENT, &source_url);
    let _source = mock_source(&mut file_server, SOURCE_CONTENT);

    check_pending_cmd(&backend)
        .assert()
        .success()
        .stdout(predicate::str::contains("matches the content published at"))
        .stdout(predicate::str::contains(&source_url))
        .stdout(predicate::str::contains(sha512_digest_str(SOURCE_CONTENT)))
        .stdout(predicate::str::contains(format!(
            "[{}]",
            label_for_hash(HashAlgorithm::Sha512)
        )));
}

#[test]
fn check_pending_signers_json_output() {
    let mut backend = mockito::Server::new();
    let mut file_server = mockito::Server::new();
    let source_url = format!("{}{SOURCE_PATH}", file_server.url());
    let _mocks = mock_backend_files(&mut backend, SOURCE_CONTENT, &source_url);
    let _source = mock_source(&mut file_server, SOURCE_CONTENT);

    let output = check_pending_cmd(&backend).arg("--json").assert().success();
    let stdout = String::from_utf8(output.get_output().stdout.clone()).unwrap();
    let v: Value = serde_json::from_str(stdout.trim()).unwrap();
    assert_eq!(v["signers_path"], SIGNERS_PATH);
    assert_eq!(v["retrieval_url"], source_url);
    assert_eq!(v["hash"], sha512_digest_str(SOURCE_CONTENT));
    let bishop_art = v["bishop_art"]
        .as_str()
        .expect("bishop_art field should be a string");
    assert!(
        !bishop_art.contains('\x1b'),
        "bishop art in JSON must not contain ANSI codes"
    );
    assert!(
        bishop_art.contains(format!("[{}]", label_for_hash(HashAlgorithm::Sha512)).as_str()),
        "bishop art should be rendered, got: {bishop_art}"
    );
}

#[test]
fn check_pending_signers_mismatch_fails_naming_source() {
    let mut backend = mockito::Server::new();
    let mut file_server = mockito::Server::new();
    let source_url = format!("{}{SOURCE_PATH}", file_server.url());
    let _mocks = mock_backend_files(&mut backend, PENDING_CONTENT, &source_url);
    let _source = mock_source(&mut file_server, SOURCE_CONTENT);

    check_pending_cmd(&backend)
        .assert()
        .failure()
        .stderr(predicate::str::contains("Hash mismatch"))
        .stderr(predicate::str::contains(&source_url));
}

#[test]
fn check_pending_signers_mismatch_json_error() {
    let mut backend = mockito::Server::new();
    let mut file_server = mockito::Server::new();
    let source_url = format!("{}{SOURCE_PATH}", file_server.url());
    let _mocks = mock_backend_files(&mut backend, PENDING_CONTENT, &source_url);
    let _source = mock_source(&mut file_server, SOURCE_CONTENT);

    let output = check_pending_cmd(&backend).arg("--json").assert().failure();
    let stderr = String::from_utf8(output.get_output().stderr.clone()).unwrap();
    let v: Value = serde_json::from_str(stderr.trim()).unwrap();
    assert!(
        v["error"]
            .as_str()
            .expect("error field must be a string")
            .contains(&source_url),
        "expected error naming the retrieval url, got: {stderr}"
    );
}

// Metadata JSON is parsed by the command itself, before the retrieval URL is
// contacted: malformed metadata must fail the command without any fetch.
#[test]
fn check_pending_signers_fails_on_malformed_metadata() {
    let mut backend = mockito::Server::new();
    let metadata_path = metadata_path_for(SIGNERS_PATH)
        .unwrap()
        .to_string_lossy()
        .to_string();
    let _signers = backend
        .mock("GET", format!("/v1/files/{SIGNERS_PATH}").as_str())
        .with_status(200)
        .with_body(SOURCE_CONTENT)
        .create();
    let _metadata = backend
        .mock("GET", format!("/v1/files/{metadata_path}").as_str())
        .with_status(200)
        .with_body("not json")
        .create();

    check_pending_cmd(&backend)
        .assert()
        .failure()
        .stderr(predicate::str::contains("JSON serialization error"));
}

// A path that is not a pending signers file must be rejected before any
// network call: the files endpoint mock expects zero hits.
#[test]
fn check_pending_signers_rejects_non_pending_path() {
    let mut backend = mockito::Server::new();
    let not_signers = backend
        .mock("GET", "/v1/files/releases/v1/file.tar.gz")
        .with_status(200)
        .expect(0)
        .create();

    let mut cmd = assert_cmd::cargo_bin_cmd!("asfaload-cli");
    cmd.arg("check-pending-signers")
        .arg("releases/v1/file.tar.gz")
        .arg("-u")
        .arg(backend.url());

    cmd.assert()
        .failure()
        .stderr(predicate::str::contains("Not a pending signers file path"));
    not_signers.assert();
}

#[test]
fn check_pending_signers_missing_signers_file_fails() {
    let mut backend = mockito::Server::new();
    let _signers = backend
        .mock("GET", format!("/v1/files/{SIGNERS_PATH}").as_str())
        .with_status(404)
        .with_body("File not found")
        .create();

    check_pending_cmd(&backend)
        .assert()
        .failure()
        .stderr(predicate::str::contains("404"));
}
