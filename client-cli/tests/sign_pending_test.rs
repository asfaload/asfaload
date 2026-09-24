use client_cli::utils::label_for_hash;
use features_lib::HashAlgorithm;
use predicates::prelude::*;
use sha2::{Digest, Sha512};

const FIXTURE_PASSWORD: &str = "password";

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

fn fixture_key_path() -> std::path::PathBuf {
    test_helpers::fixtures_keys_dir().join("key_0")
}

fn pending_response_json(files: &[(&str, &str)]) -> String {
    let items: Vec<String> = files
        .iter()
        .map(|(path, digest)| format!(r#"{{"path":"{}","digest":"{}"}}"#, path, digest))
        .collect();
    format!(r#"{{"pending_files":[{}]}}"#, items.join(","))
}

fn sha512_digest_str(content: &[u8]) -> String {
    format!("sha512:{}", hex::encode(Sha512::digest(content)))
}

fn files_response_json(files: &[(&str, &[u8])]) -> String {
    use base64::Engine;
    let items: Vec<String> = files
        .iter()
        .map(|(path, content)| {
            format!(
                r#""{}":"{}""#,
                path,
                base64::engine::general_purpose::STANDARD.encode(content)
            )
        })
        .collect();
    format!(r#"{{"files":{{{}}}}}"#, items.join(","))
}

fn signers_metadata_json(source_url: &str) -> String {
    format!(
        r#"{{"data":{{"Forge":{{"kind":"Github","url":"https://github.com/acme/tool/raw/main/asfaload.signers/index.json","verified_content":{{"retrieval_url":"{source_url}","content_hash":"00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"}},"retrieved_at":"2024-01-01T00:00:00Z"}}}}}}"#
    )
}

// ---------------------------------------------------------------------------
// --help wiring
// ---------------------------------------------------------------------------

#[test]
fn sign_pending_help_shows_digest_filter_option() {
    let mut cmd = assert_cmd::cargo_bin_cmd!("asfaload-cli");
    cmd.arg("sign-pending").arg("--help");
    cmd.assert()
        .success()
        .stdout(predicate::str::contains("digest-filter"));
}

// ---------------------------------------------------------------------------
// --digest-filter with no match: no pending signature error
// ---------------------------------------------------------------------------

#[test]
fn sign_pending_digest_filter_no_match_fails_with_no_pending() {
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
    cmd.arg("sign-pending")
        .arg("-K")
        .arg(fixture_key_path())
        .arg("-u")
        .arg(server.url())
        .arg("--digest-filter")
        .arg(DIGEST_NON_MATCHING)
        .env("ASFALOAD_SIGN_PENDING_PASSWORD", FIXTURE_PASSWORD);

    cmd.assert()
        .failure()
        .stderr(predicate::str::contains("No pending signature found"));
}

// ---------------------------------------------------------------------------
// --digest-filter leaves only the non-targeted file → NoPendingSignature,
// not "Not a tty", proving the filter ran before the TTY check.
// ---------------------------------------------------------------------------

#[test]
fn sign_pending_digest_filter_excludes_non_matching_digest() {
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
    cmd.arg("sign-pending")
        .arg("-K")
        .arg(fixture_key_path())
        .arg("-u")
        .arg(server.url())
        .arg("--digest-filter")
        .arg(DIGEST_NON_MATCHING)
        .env("ASFALOAD_SIGN_PENDING_PASSWORD", FIXTURE_PASSWORD);

    cmd.assert()
        .failure()
        .stderr(predicate::str::contains("No pending signature found"))
        .stderr(predicate::str::contains("Not a tty").not());
}

#[test]
fn sign_pending_explicit_path_no_bishop_art() {
    use base64::Engine;

    let content = b"test file content for json signing";
    let hash_bytes = Sha512::digest(content);
    let digest_str = format!("sha512:{}", hex::encode(hash_bytes));
    let b64_content = base64::engine::general_purpose::STANDARD.encode(content);
    let file_path = "releases/v1/file-json.tar.gz";

    let mut server = mockito::Server::new();

    let files_body = format!(r#"{{"files":{{"{}":{:?}}}}}"#, file_path, b64_content);
    let _m1 = server
        .mock("GET", format!("/v1/files-to-sign/{}", file_path).as_str())
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(&files_body)
        .create();

    let _m2 = server
        .mock("POST", "/v1/signatures")
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(r#"{"is_complete":false}"#)
        .create();

    let output = assert_cmd::cargo_bin_cmd!("asfaload-cli")
        .arg("sign-pending")
        .arg("-K")
        .arg(test_helpers::fixtures_keys_dir().join("key_0"))
        .arg("-u")
        .arg(server.url())
        .arg(file_path)
        .arg("--digest")
        .arg(&digest_str)
        .arg("--json")
        .env("ASFALOAD_SIGN_PENDING_PASSWORD", FIXTURE_PASSWORD)
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout).unwrap();
    let label_bracket = format!("[{}]", label_for_hash(HashAlgorithm::Sha512));
    assert!(
        !stdout.contains(&label_bracket),
        "explicit-path mode must not contain bishop art framing"
    );
}

// ---------------------------------------------------------------------------
// Pending signers files must be byte-identical to the source vouched for by
// their metadata before the client signs them.
// ---------------------------------------------------------------------------

const SIGNERS_REL_PATH: &str = "acme/tool/asfaload.signers.pending/index.json";

// Build on disk path, which includes scheme, host, port and path.
fn signers_path(file_server: &mockito::Server) -> String {
    let parsed = url::Url::parse(&file_server.url()).unwrap();
    format!(
        "{}/{}",
        forge_url::path_prefix_from_url(&parsed).unwrap(),
        SIGNERS_REL_PATH
    )
}

#[test]
fn sign_pending_rejects_signers_file_not_matching_metadata() {
    let source_content = br#"{"version":1}"#;
    let pending_content = br#"{"version":2}"#;

    // Use distinct mocks for the user's file server and the Asfaload backend.
    let mut file_server = mockito::Server::new();
    let mut backend = mockito::Server::new();
    let signers_path = signers_path(&file_server);

    let metadata_path = common::fs::names::metadata_path_for(&signers_path)
        .unwrap()
        .to_string_lossy()
        .to_string();

    let source_path = "/acme/tool/asfaload.signers/index.json";
    // Mock file server where users publish their files
    // This serves the user's source_content
    let source = file_server
        .mock("GET", source_path)
        .with_status(200)
        .with_body(source_content.as_slice())
        .create();

    let metadata = signers_metadata_json(&format!("{}{}", file_server.url(), source_path));

    // mock handler returning files to sign for a path
    // this returns the pending_content, not matching the file server's content
    let _files = backend
        .mock(
            "GET",
            format!("/v1/files-to-sign/{}", signers_path).as_str(),
        )
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(files_response_json(&[
            (signers_path.as_str(), pending_content.as_slice()),
            (metadata_path.as_str(), metadata.as_bytes()),
        ]))
        .create();

    // mock handler of submitted signatures
    let submit = backend
        .mock("POST", "/v1/signatures")
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(r#"{"is_complete":false}"#)
        .expect(0)
        .create();

    let mut cmd = assert_cmd::cargo_bin_cmd!("asfaload-cli");
    cmd.arg("sign-pending")
        .arg("-K")
        .arg(fixture_key_path())
        .arg("-u")
        .arg(backend.url())
        .arg(&signers_path)
        .arg("--digest")
        .arg(sha512_digest_str(pending_content))
        .env("ASFALOAD_SIGN_PENDING_PASSWORD", FIXTURE_PASSWORD);

    cmd.assert()
        .failure()
        .stderr(predicate::str::contains("Hash mismatch"));
    submit.assert();
    source.assert();
}

#[test]
fn sign_pending_accepts_signers_file_matching_metadata() {
    let signers_content = br#"{"version":1}"#;

    // Use distinct mocks for the user's file server and the Asfaload backend.
    let mut file_server = mockito::Server::new();
    let mut backend = mockito::Server::new();
    let signers_path = signers_path(&file_server);

    let metadata_path = common::fs::names::metadata_path_for(&signers_path)
        .unwrap()
        .to_string_lossy()
        .to_string();

    let source_path = "/acme/tool/asfaload.signers/index.json";
    // Mock file server where users publish their files
    // This serves the user's signers_content
    let source = file_server
        .mock("GET", source_path)
        .with_status(200)
        .with_body(signers_content.as_slice())
        .create();

    let metadata = signers_metadata_json(&format!("{}{}", file_server.url(), source_path));

    // mock handler returning files to sign for a path
    // this returns the pending_content, identical to what is found on the file_server
    let _files = backend
        .mock(
            "GET",
            format!("/v1/files-to-sign/{}", signers_path).as_str(),
        )
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(files_response_json(&[
            (signers_path.as_str(), signers_content.as_slice()),
            (metadata_path.as_str(), metadata.as_bytes()),
        ]))
        .create();

    let submit = backend
        .mock("POST", "/v1/signatures")
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(r#"{"is_complete":false}"#)
        .create();

    let mut cmd = assert_cmd::cargo_bin_cmd!("asfaload-cli");
    cmd.arg("sign-pending")
        .arg("-K")
        .arg(fixture_key_path())
        .arg("-u")
        .arg(backend.url())
        .arg(&signers_path)
        .arg("--digest")
        .arg(sha512_digest_str(signers_content))
        .env("ASFALOAD_SIGN_PENDING_PASSWORD", FIXTURE_PASSWORD);

    cmd.assert().success();
    submit.assert();
    source.assert();
}
