use features_lib::constants::INDEX_FILE;
use predicates::prelude::*;
use serde_json::Value;

const SHA256_HASH: &str = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
const SHA256_OTHER: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

// The backend path of the index, derived from the digest source server URL:
// the mockito url as scheme/host/port, plus a project path. The realm check
// must hold under both parsings of the source URL: with the file server
// parser the project is the scheme/host/port prefix; with the test-utils
// GitHub parser (active in a workspace-wide test run) the first path segments
// are owner and repo. The `acme/tool/main/releases` prefix satisfies both.
fn index_path_for(file_server_url: &str) -> String {
    let parsed = url::Url::parse(file_server_url).unwrap();
    format!(
        "{}/acme/tool/main/releases/v0.5/{INDEX_FILE}",
        forge_url::path_prefix_from_url(&parsed).unwrap()
    )
}

fn index_json(source_url: &str, hash: &str) -> String {
    format!(
        concat!(
            r#"{{"mirroredOn":"2026-09-12T12:00:00Z","publishedOn":"2026-09-12T12:00:00Z","#,
            r#""version":1,"publishedFiles":[{{"fileName":"file-a.tar.gz","#,
            r#""algo":"Sha256","source":"{}","sourceFormat":"ShaSum","hash":"{}"}}]}}"#
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
    let index_path = index_path_for(&file_server.url());
    let source_url = format!(
        "{}/acme/tool/main/releases/checksums.txt",
        file_server.url()
    );
    let index = backend
        .mock("GET", format!("/v1/files/{index_path}").as_str())
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(index_json(&source_url, SHA256_HASH))
        .create();
    let source = file_server
        .mock("GET", "/acme/tool/main/releases/checksums.txt")
        .with_status(200)
        .with_body(format!("{SHA256_HASH}  file-a.tar.gz"))
        .create();
    (index, source)
}

fn check_index_cmd(backend: &mockito::Server, index_path: &str) -> assert_cmd::Command {
    let mut cmd = assert_cmd::cargo_bin_cmd!("asfaload-cli");
    cmd.arg("check-index")
        .arg(index_path)
        .arg("-u")
        .arg(backend.url());
    cmd
}

#[test]
fn check_index_matching_digests_succeeds() {
    let mut backend = mockito::Server::new();
    let mut file_server = mockito::Server::new();
    let _mocks = mock_valid_index(&mut backend, &mut file_server);

    check_index_cmd(&backend, &index_path_for(&file_server.url()))
        .assert()
        .success()
        .stdout(predicate::str::contains("Index valid"))
        .stdout(predicate::str::contains("1 file"));
}

#[test]
fn check_index_digest_mismatch_fails() {
    let mut backend = mockito::Server::new();
    let mut file_server = mockito::Server::new();
    let index_path = index_path_for(&file_server.url());
    let source_url = format!(
        "{}/acme/tool/main/releases/checksums.txt",
        file_server.url()
    );
    let _index = backend
        .mock("GET", format!("/v1/files/{index_path}").as_str())
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(index_json(&source_url, SHA256_HASH))
        .create();
    let _source = file_server
        .mock("GET", "/acme/tool/main/releases/checksums.txt")
        .with_status(200)
        .with_body(format!("{SHA256_OTHER}  file-a.tar.gz"))
        .create();

    check_index_cmd(&backend, &index_path)
        .assert()
        .failure()
        .stderr(predicate::str::contains("digest mismatch"));
}

// Mocks the file server so it rejects any request. Asserting the returned
// mocks after the command proves the command fetched no digest source: a
// request to the file server would panic in an assert. One mock per method
// as mockito cannot match any method in one mock.
fn mock_no_source_fetch(file_server: &mut mockito::Server) -> Vec<mockito::Mock> {
    ["GET", "HEAD", "POST", "PUT", "DELETE"]
        .iter()
        .map(|method| {
            file_server
                .mock(method, mockito::Matcher::Any)
                .expect(0)
                .create()
        })
        .collect()
}

fn assert_no_source_fetch(mocks: &[mockito::Mock]) {
    for mock in mocks {
        mock.assert();
    }
}

#[test]
fn check_index_missing_index_fails() {
    let mut backend = mockito::Server::new();
    // The file server only provides the URL the index path is derived from;
    // the index fetch fails before any digest source is fetched.
    let mut file_server = mockito::Server::new();
    let no_source = mock_no_source_fetch(&mut file_server);
    let index_path = index_path_for(&file_server.url());
    let _index = backend
        .mock("GET", format!("/v1/files/{index_path}").as_str())
        .with_status(404)
        .with_body("File not found")
        .create();

    check_index_cmd(&backend, &index_path)
        .assert()
        .failure()
        .stderr(predicate::str::contains("404"));
    assert_no_source_fetch(&no_source);
}

#[test]
fn check_index_invalid_json_body_fails() {
    let mut backend = mockito::Server::new();
    // The file server only provides the URL the index path is derived from;
    // index parsing fails before any digest source is fetched.
    let mut file_server = mockito::Server::new();
    let no_source = mock_no_source_fetch(&mut file_server);
    let index_path = index_path_for(&file_server.url());
    let _index = backend
        .mock("GET", format!("/v1/files/{index_path}").as_str())
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body("this is not an index")
        .create();

    check_index_cmd(&backend, &index_path)
        .assert()
        .failure()
        .stderr(predicate::str::contains("not valid JSON"));
    assert_no_source_fetch(&no_source);
}

#[test]
fn check_index_json_error_on_mismatch() {
    let mut backend = mockito::Server::new();
    let mut file_server = mockito::Server::new();
    let index_path = index_path_for(&file_server.url());
    let source_url = format!(
        "{}/acme/tool/main/releases/checksums.txt",
        file_server.url()
    );
    let _index = backend
        .mock("GET", format!("/v1/files/{index_path}").as_str())
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(index_json(&source_url, SHA256_HASH))
        .create();
    let _source = file_server
        .mock("GET", "/acme/tool/main/releases/checksums.txt")
        .with_status(200)
        .with_body(format!("{SHA256_OTHER}  file-a.tar.gz"))
        .create();

    let output = check_index_cmd(&backend, &index_path)
        .arg("--json")
        .assert()
        .failure();
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
    let index_path = index_path_for(&file_server.url());
    let source_url = format!(
        "{}/acme/tool/main/releases/checksums.txt",
        file_server.url()
    );

    let output = check_index_cmd(&backend, &index_path)
        .arg("--json")
        .assert()
        .success();
    let stdout = String::from_utf8(output.get_output().stdout.clone()).unwrap();
    let v: Value = serde_json::from_str(stdout.trim()).unwrap();
    assert_eq!(v["index_path"], index_path.as_str());
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
    assert_eq!(index["publishedFiles"][0]["sourceFormat"], "ShaSum");
    assert_eq!(index["publishedFiles"][0]["hash"], SHA256_HASH);
}

// An index with no published files has nothing to contradict, so validation
// succeeds trivially. Pinning that behavior: exit 0, "0 file(s) verified",
// and no digest source is fetched.
#[test]
fn check_index_empty_index_succeeds() {
    let mut backend = mockito::Server::new();
    // The file server only provides the URL the index path is derived from;
    // the empty index lists no digest source to fetch.
    let mut file_server = mockito::Server::new();
    let no_source = mock_no_source_fetch(&mut file_server);
    let index_path = index_path_for(&file_server.url());
    let _index = backend
        .mock("GET", format!("/v1/files/{index_path}").as_str())
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(
            r#"{"mirroredOn":"2026-09-12T12:00:00Z","publishedOn":"2026-09-12T12:00:00Z","version":1,"publishedFiles":[]}"#,
        )
        .create();

    check_index_cmd(&backend, &index_path)
        .assert()
        .success()
        .stdout(predicate::str::contains("0 file(s)"));
    assert_no_source_fetch(&no_source);
}
