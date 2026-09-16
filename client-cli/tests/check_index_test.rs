use features_lib::constants::INDEX_FILE;
use predicates::prelude::*;
use serde_json::Value;

const SHA256_HASH: &str = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
const SHA256_OTHER: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
fn index_path() -> String {
    format!("project/releases/v0.5/{INDEX_FILE}")
}

fn index_json(source_url: &str, hash: &str) -> String {
    format!(
        concat!(
            r#"{{"mirroredOn":"2026-09-12T12:00:00Z","publishedOn":"2026-09-12T12:00:00Z","#,
            r#""version":1,"publishedFiles":[{{"fileName":"file-a.tar.gz","#,
            r#""algo":"Sha256","source":"{}","hash":"{}"}}]}}"#
        ),
        source_url, hash
    )
}

#[test]
fn check_index_help_lists_flags() {
    let mut cmd = assert_cmd::cargo_bin_cmd!("asfaload-cli");
    cmd.arg("check-index").arg("--help");
    cmd.assert()
        .success()
        .stdout(predicate::str::contains("--backend-url"))
        .stdout(predicate::str::contains("--json"));
}

// Mocks the index endpoint on the backend server, with an index body whose
// digest source points at the distinct file server, which is also mocked as
// matching. Keeping the two on separate servers proves the CLI fetches the
// absolute `source` URL from the index rather than resolving it against the
// backend URL.
fn mock_valid_index(
    backend: &mut mockito::Server,
    file_server: &mut mockito::Server,
) -> (mockito::Mock, mockito::Mock) {
    let source_url = format!("{}/checksums.txt", file_server.url());
    let index = backend
        .mock("GET", format!("/v1/files/{}", index_path()).as_str())
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(index_json(&source_url, SHA256_HASH))
        .create();
    let source = file_server
        .mock("GET", "/checksums.txt")
        .with_status(200)
        .with_body(format!("{SHA256_HASH}  file-a.tar.gz"))
        .create();
    (index, source)
}

fn check_index_cmd(backend: &mockito::Server) -> assert_cmd::Command {
    let mut cmd = assert_cmd::cargo_bin_cmd!("asfaload-cli");
    cmd.arg("check-index")
        .arg(index_path())
        .arg("-u")
        .arg(backend.url());
    cmd
}

#[test]
fn check_index_matching_digests_succeeds() {
    let mut backend = mockito::Server::new();
    let mut file_server = mockito::Server::new();
    let _mocks = mock_valid_index(&mut backend, &mut file_server);

    check_index_cmd(&backend)
        .assert()
        .success()
        .stdout(predicate::str::contains("Index valid"))
        .stdout(predicate::str::contains("1 file"));
}

#[test]
fn check_index_digest_mismatch_fails() {
    let mut backend = mockito::Server::new();
    let mut file_server = mockito::Server::new();
    let source_url = format!("{}/checksums.txt", file_server.url());
    let _index = backend
        .mock("GET", format!("/v1/files/{}", index_path()).as_str())
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(index_json(&source_url, SHA256_HASH))
        .create();
    let _source = file_server
        .mock("GET", "/checksums.txt")
        .with_status(200)
        .with_body(format!("{SHA256_OTHER}  file-a.tar.gz"))
        .create();

    check_index_cmd(&backend)
        .assert()
        .failure()
        .stderr(predicate::str::contains("digest mismatch"));
}

#[test]
fn check_index_missing_index_fails() {
    let mut backend = mockito::Server::new();
    let _index = backend
        .mock("GET", format!("/v1/files/{}", index_path()).as_str())
        .with_status(404)
        .with_body("File not found")
        .create();

    check_index_cmd(&backend)
        .assert()
        .failure()
        .stderr(predicate::str::contains("404"));
}

#[test]
fn check_index_invalid_json_body_fails() {
    let mut backend = mockito::Server::new();
    let _index = backend
        .mock("GET", format!("/v1/files/{}", index_path()).as_str())
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body("this is not an index")
        .create();

    check_index_cmd(&backend)
        .assert()
        .failure()
        .stderr(predicate::str::contains("not valid JSON"));
}

#[test]
fn check_index_json_error_on_mismatch() {
    let mut backend = mockito::Server::new();
    let mut file_server = mockito::Server::new();
    let source_url = format!("{}/checksums.txt", file_server.url());
    let _index = backend
        .mock("GET", format!("/v1/files/{}", index_path()).as_str())
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(index_json(&source_url, SHA256_HASH))
        .create();
    let _source = file_server
        .mock("GET", "/checksums.txt")
        .with_status(200)
        .with_body(format!("{SHA256_OTHER}  file-a.tar.gz"))
        .create();

    let output = check_index_cmd(&backend).arg("--json").assert().failure();
    let stderr = String::from_utf8(output.get_output().stderr.clone()).unwrap();
    let v: Value = serde_json::from_str(stderr.trim()).unwrap();
    assert!(
        v["error"]
            .as_str()
            .expect("error field must be a string")
            .contains("digest mismatch"),
        "expected digest mismatch message, got: {stderr}"
    );
}

#[test]
fn check_index_json_output() {
    let mut backend = mockito::Server::new();
    let mut file_server = mockito::Server::new();
    let _mocks = mock_valid_index(&mut backend, &mut file_server);
    let source_url = format!("{}/checksums.txt", file_server.url());

    let output = check_index_cmd(&backend).arg("--json").assert().success();
    let stdout = String::from_utf8(output.get_output().stdout.clone()).unwrap();
    let v: Value = serde_json::from_str(stdout.trim()).unwrap();
    assert_eq!(v["index_path"], index_path().as_str());
    assert_eq!(v["files_checked"], 1);
    // The whole validated index is embedded under "index", serialized camelCase.
    // These literals are hand-derived from the fixture body served above.
    let index = &v["index"];
    assert_eq!(index["version"], 1);
    assert_eq!(index["mirrored_on"], Value::Null);
    assert_eq!(index["mirroredOn"], "2026-09-12T12:00:00Z");
    assert_eq!(index["publishedFiles"][0]["fileName"], "file-a.tar.gz");
    assert_eq!(index["publishedFiles"][0]["algo"], "Sha256");
    assert_eq!(index["publishedFiles"][0]["source"], source_url);
    assert_eq!(index["publishedFiles"][0]["hash"], SHA256_HASH);
}
