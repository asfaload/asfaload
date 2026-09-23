use client_cli::utils::label_for_hash;
use common::fs::names::metadata_path_for;
use features_lib::HashAlgorithm;
use predicates::prelude::*;
use serde_json::Value;
use sha2::{Digest, Sha512};

const SIGNERS_REL_PATH: &str = "acme/tool/asfaload.signers.pending/index.json";

const SOURCE_CONTENT: &[u8] = br#"{"version":1}"#;
const PENDING_CONTENT: &[u8] = br#"{"version":2}"#;

const SOURCE_PATH: &str = "/acme/tool/asfaload.signers/index.json";

// Build backend path, which include scheme, host and port as prefix.
fn signers_path(file_server: &mockito::Server) -> String {
    let parsed = url::Url::parse(&file_server.url()).unwrap();
    format!(
        "{}/{}",
        forge_url::path_prefix_from_url(&parsed).unwrap(),
        SIGNERS_REL_PATH
    )
}

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
    signers_path: &str,
) -> (mockito::Mock, mockito::Mock) {
    let metadata_path = metadata_path_for(signers_path)
        .unwrap()
        .to_string_lossy()
        .to_string();
    let signers = backend
        .mock("GET", format!("/v1/files/{signers_path}").as_str())
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

fn check_pending_cmd(backend: &mockito::Server, signers_path: &str) -> assert_cmd::Command {
    let mut cmd = assert_cmd::cargo_bin_cmd!("asfaload-cli");
    cmd.arg("check-pending-signers")
        .arg(signers_path)
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
    let signers_path = signers_path(&file_server);
    let source_url = format!("{}{SOURCE_PATH}", file_server.url());
    let _mocks = mock_backend_files(&mut backend, SOURCE_CONTENT, &source_url, &signers_path);
    let _source = mock_source(&mut file_server, SOURCE_CONTENT);

    check_pending_cmd(&backend, &signers_path)
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
    let signers_path = signers_path(&file_server);
    let source_url = format!("{}{SOURCE_PATH}", file_server.url());
    let _mocks = mock_backend_files(&mut backend, SOURCE_CONTENT, &source_url, &signers_path);
    let _source = mock_source(&mut file_server, SOURCE_CONTENT);

    let output = check_pending_cmd(&backend, &signers_path)
        .arg("--json")
        .assert()
        .success();
    let stdout = String::from_utf8(output.get_output().stdout.clone()).unwrap();
    let v: Value = serde_json::from_str(stdout.trim()).unwrap();
    assert_eq!(v["signers_path"], signers_path);
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
    let signers_path = signers_path(&file_server);
    let source_url = format!("{}{SOURCE_PATH}", file_server.url());
    let _mocks = mock_backend_files(&mut backend, PENDING_CONTENT, &source_url, &signers_path);
    let _source = mock_source(&mut file_server, SOURCE_CONTENT);

    check_pending_cmd(&backend, &signers_path)
        .assert()
        .failure()
        .stderr(predicate::str::contains("Hash mismatch"))
        .stderr(predicate::str::contains(&source_url));
}

#[test]
fn check_pending_signers_mismatch_json_error() {
    let mut backend = mockito::Server::new();
    let mut file_server = mockito::Server::new();
    let signers_path = signers_path(&file_server);
    let source_url = format!("{}{SOURCE_PATH}", file_server.url());
    let _mocks = mock_backend_files(&mut backend, PENDING_CONTENT, &source_url, &signers_path);
    let _source = mock_source(&mut file_server, SOURCE_CONTENT);

    let output = check_pending_cmd(&backend, &signers_path)
        .arg("--json")
        .assert()
        .failure();
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
// contacted: malformed metadata must fail the command on parsing alone. The
// file server exists only to derive the mirror path prefix and has no routes.
#[test]
fn check_pending_signers_fails_on_malformed_metadata() {
    let mut backend = mockito::Server::new();
    let file_server = mockito::Server::new();
    let signers_path = signers_path(&file_server);
    let metadata_path = metadata_path_for(&signers_path)
        .unwrap()
        .to_string_lossy()
        .to_string();
    let _signers = backend
        .mock("GET", format!("/v1/files/{signers_path}").as_str())
        .with_status(200)
        .with_body(SOURCE_CONTENT)
        .create();
    let _metadata = backend
        .mock("GET", format!("/v1/files/{metadata_path}").as_str())
        .with_status(200)
        .with_body("not json")
        .create();

    check_pending_cmd(&backend, &signers_path)
        .assert()
        .failure()
        .stderr(predicate::str::contains("Failed to parse metadata"));
}

// The metadata's retrieval_url serves content identical to the pending file,
// but sits outside the file's realm: a hash comparison alone accepts, so the
// rejection must come from the location check. It must also happen before
// any fetch of the out-of-realm source, and name the url, the project it
// resolves to and the backend path, so the user can compare them.
#[test]
fn check_pending_signers_rejects_source_outside_realm() {
    let mut backend = mockito::Server::new();
    let file_server = mockito::Server::new();
    let mut attacker_server = mockito::Server::new();
    let signers_path = signers_path(&file_server);
    let attacker_url = format!("{}{SOURCE_PATH}", attacker_server.url());
    // The forge project the attacker url resolves to: its origin plus the
    // owner/repo segments of the source route.
    let attacker_project = {
        let parsed = url::Url::parse(&attacker_server.url()).unwrap();
        format!(
            "{}/acme/tool",
            forge_url::path_prefix_from_url(&parsed).unwrap()
        )
    };
    let _mocks = mock_backend_files(&mut backend, SOURCE_CONTENT, &attacker_url, &signers_path);
    let fake_source = attacker_server
        .mock("GET", SOURCE_PATH)
        .with_status(200)
        .with_body(SOURCE_CONTENT)
        .expect(0)
        .create();

    check_pending_cmd(&backend, &signers_path)
        .assert()
        .failure()
        .stderr(predicate::str::contains(
            "does not match the file's backend path",
        ))
        .stderr(predicate::str::contains(&attacker_url))
        .stderr(predicate::str::contains(&attacker_project))
        .stderr(predicate::str::contains(&signers_path))
        .stderr(predicate::str::contains("tampered"));

    fake_source.assert();
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
    let file_server = mockito::Server::new();
    let signers_path = signers_path(&file_server);
    let _signers = backend
        .mock("GET", format!("/v1/files/{signers_path}").as_str())
        .with_status(404)
        .with_body("File not found")
        .create();

    check_pending_cmd(&backend, &signers_path)
        .assert()
        .failure()
        .stderr(predicate::str::contains("404"));
}
