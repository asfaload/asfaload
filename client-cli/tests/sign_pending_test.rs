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

const FORGE_URL: &str = "https://github.com/acme/tool/raw/main/asfaload.signers/index.json";

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

    let source_url = format!("{}{}", file_server.url(), source_path);
    let metadata =
        test_helpers::signers_metadata_json(FORGE_URL, &source_url, source_content.as_slice());

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

    let source_url = format!("{}{}", file_server.url(), source_path);
    let metadata =
        test_helpers::signers_metadata_json(FORGE_URL, &source_url, signers_content.as_slice());

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

// ---------------------------------------------------------------------------
// The client signs the hash of each file it gets from the backend, and the
// signature is not bound to a path. A compromised backend must not be able to
// add files to the set to sign, nor remove the file the user asked for.
// ---------------------------------------------------------------------------

#[test]
fn sign_pending_rejects_unexpected_files_to_sign() {
    let content = b"legitimate release index";
    let injected_content = b"index injected by the backend";
    let file_path = "releases/v1/asfaload.index.json";
    let injected_path = "releases/v2/asfaload.index.json";

    let mut backend = mockito::Server::new();
    let _files = backend
        .mock("GET", format!("/v1/files-to-sign/{}", file_path).as_str())
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(files_response_json(&[
            (file_path, content.as_slice()),
            (injected_path, injected_content.as_slice()),
        ]))
        .create();

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
        .arg(file_path)
        .arg("--digest")
        .arg(sha512_digest_str(content))
        .env("ASFALOAD_SIGN_PENDING_PASSWORD", FIXTURE_PASSWORD);

    cmd.assert()
        .failure()
        .stderr(predicate::str::contains(injected_path));
    submit.assert();
}

#[test]
fn sign_pending_rejects_files_to_sign_without_requested_file() {
    let injected_content = b"index injected by the backend";
    let file_path = "releases/v1/asfaload.index.json";
    let injected_path = "releases/v2/asfaload.index.json";

    let mut backend = mockito::Server::new();
    let _files = backend
        .mock("GET", format!("/v1/files-to-sign/{}", file_path).as_str())
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(files_response_json(&[(
            injected_path,
            injected_content.as_slice(),
        )]))
        .create();

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
        .arg(file_path)
        .arg("--digest")
        .arg(sha512_digest_str(b"legitimate release index"))
        .env("ASFALOAD_SIGN_PENDING_PASSWORD", FIXTURE_PASSWORD);

    cmd.assert()
        .failure()
        .stderr(predicate::str::contains(file_path));
    submit.assert();
}

#[test]
fn sign_pending_rejects_unexpected_file_next_to_signers_metadata() {
    let signers_content = br#"{"version":1}"#;
    let injected_content = b"index injected by the backend";
    let injected_path = "releases/v2/asfaload.index.json";

    let mut file_server = mockito::Server::new();
    let mut backend = mockito::Server::new();
    let signers_path = signers_path(&file_server);

    let metadata_path = common::fs::names::metadata_path_for(&signers_path)
        .unwrap()
        .to_string_lossy()
        .to_string();

    let source_path = "/acme/tool/asfaload.signers/index.json";
    let _source = file_server
        .mock("GET", source_path)
        .with_status(200)
        .with_body(signers_content.as_slice())
        .create();

    let source_url = format!("{}{}", file_server.url(), source_path);
    let metadata =
        test_helpers::signers_metadata_json(FORGE_URL, &source_url, signers_content.as_slice());

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
            (injected_path, injected_content.as_slice()),
        ]))
        .create();

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
        .arg(sha512_digest_str(signers_content))
        .env("ASFALOAD_SIGN_PENDING_PASSWORD", FIXTURE_PASSWORD);

    cmd.assert()
        .failure()
        .stderr(predicate::str::contains(injected_path));
    submit.assert();
}

// ---------------------------------------------------------------------------
// Signers metadata is signed without a digest given by the user. A
// compromised backend must not be able to hide other content in it, such as
// the fields of an index, to get a signature for that content.
// ---------------------------------------------------------------------------

#[test]
fn sign_pending_rejects_metadata_that_is_also_an_index() {
    let signers_content = br#"{"version":1}"#;

    let mut file_server = mockito::Server::new();
    let mut backend = mockito::Server::new();
    let signers_path = signers_path(&file_server);

    let metadata_path = common::fs::names::metadata_path_for(&signers_path)
        .unwrap()
        .to_string_lossy()
        .to_string();

    let source_path = "/acme/tool/asfaload.signers/index.json";
    let _source = file_server
        .mock("GET", source_path)
        .with_status(200)
        .with_body(signers_content.as_slice())
        .create();

    let source_url = format!("{}{}", file_server.url(), source_path);
    let legitimate_metadata =
        test_helpers::signers_metadata_json(FORGE_URL, &source_url, signers_content.as_slice());

    // Add the fields of an index to the legitimate metadata. The field names
    // of both types do not overlap, so these bytes would parse as both if
    // unknown fields were accepted.
    let mut polyglot: serde_json::Value = serde_json::from_str(&legitimate_metadata).unwrap();
    let index_fields = serde_json::json!({
        "mirroredOn": "2026-01-01T00:00:00Z",
        "publishedOn": "2026-01-01T00:00:00Z",
        "version": 1,
        "publishedFiles": [{
            "fileName": "tool",
            "algo": "Sha256",
            "source": "https://github.com/acme/tool/releases/download/v1/checksums.txt",
            "sourceFormat": "ShaSum",
            "hash": "0000000000000000000000000000000000000000000000000000000000000000"
        }]
    });
    polyglot
        .as_object_mut()
        .unwrap()
        .extend(index_fields.as_object().unwrap().clone());
    let polyglot_metadata = common::to_posix_json(&polyglot).unwrap();

    let _files = backend
        .mock(
            "GET",
            format!("/v1/files-to-sign/{}", signers_path).as_str(),
        )
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(files_response_json(&[
            (signers_path.as_str(), signers_content.as_slice()),
            (metadata_path.as_str(), polyglot_metadata.as_bytes()),
        ]))
        .create();

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
        .arg(sha512_digest_str(signers_content))
        .env("ASFALOAD_SIGN_PENDING_PASSWORD", FIXTURE_PASSWORD);

    cmd.assert()
        .failure()
        .stderr(predicate::str::contains("Backend data error"));
    submit.assert();
}

// ---------------------------------------------------------------------------
// A complete release index shows how to download its artifacts.
// ---------------------------------------------------------------------------

#[test]
fn sign_pending_complete_release_index_shows_download_command() {
    let index_path = "https/github.com/443/acme/tool/releases/tag/v1.0/asfaload.index.json";
    let index_content = br#"{"mirroredOn":"2026-01-01T00:00:00Z","publishedOn":"2026-01-01T00:00:00Z","version":1,"publishedFiles":[{"fileName":"tool-linux-amd64.tar.gz","algo":"Sha256","source":"https://api.github.com/repos/acme/tool/releases/1","sourceFormat":"GithubRelease","hash":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}]}"#;

    let mut server = mockito::Server::new();
    let _files_mock = server
        .mock("GET", format!("/v1/files-to-sign/{index_path}").as_str())
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(files_response_json(&[(index_path, index_content)]))
        .create();
    let _signatures_mock = server
        .mock("POST", "/v1/signatures")
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(r#"{"is_complete":true}"#)
        .create();

    let output = assert_cmd::cargo_bin_cmd!("asfaload-cli")
        .arg("sign-pending")
        .arg("-K")
        .arg(fixture_key_path())
        .arg("-u")
        .arg(server.url())
        .arg(index_path)
        .arg("--digest")
        .arg(sha512_digest_str(index_content))
        .env("ASFALOAD_SIGN_PENDING_PASSWORD", FIXTURE_PASSWORD)
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(
        stdout.contains(&format!("--backend-url {} \\\n", server.url())),
        "stdout: {stdout}"
    );
    assert!(
        stdout.contains(
            "       https://github.com/acme/tool/releases/download/v1.0/tool-linux-amd64.tar.gz\n"
        ),
        "stdout: {stdout}"
    );
    assert!(stdout.contains("asfald"), "stdout: {stdout}");
}

// ---------------------------------------------------------------------------
// A pending signers file that was activated with the signature of the user.
// ---------------------------------------------------------------------------

/// Mock a files-to-sign response that reports an activated signers file, and
/// run sign-pending on its pending path with `extra_args`. Returns the output
/// and the URL of the mock backend.
fn run_sign_pending_on_activated_signers(extra_args: &[&str]) -> (std::process::Output, String) {
    // The host is in no forge host list, also with test-utils, so the example
    // is the same in all builds. The CLI does not contact it.
    let pending_signers =
        "http/files.example.com/8080/acme/tool/asfaload.signers.pending/index.json";
    let body = serde_json::to_string(&rest_api_types::models::ErrorResponse {
        error: rest_api_types::errors::ApiError::SignatureAlreadyCollected(
            pending_signers.to_string(),
        )
        .to_string(),
    })
    .unwrap();

    let mut server = mockito::Server::new();
    let _files_mock = server
        .mock(
            "GET",
            format!("/v1/files-to-sign/{pending_signers}").as_str(),
        )
        .with_status(409)
        .with_header("content-type", "application/json")
        .with_body(body)
        .create();
    // No signature is submitted.
    let signatures_mock = server.mock("POST", "/v1/signatures").expect(0).create();

    let output = assert_cmd::cargo_bin_cmd!("asfaload-cli")
        .arg("sign-pending")
        .arg("-K")
        .arg(fixture_key_path())
        .arg("-u")
        .arg(server.url())
        .arg(pending_signers)
        .arg("--digest")
        .arg(DIGEST_A)
        .args(extra_args)
        .env("ASFALOAD_SIGN_PENDING_PASSWORD", FIXTURE_PASSWORD)
        .output()
        .unwrap();
    signatures_mock.assert();
    (output, server.url())
}

#[test]
fn sign_pending_activated_signers_file_reports_collected_signature() {
    let (output, server_url) = run_sign_pending_on_activated_signers(&[]);

    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert_eq!(
        stdout,
        format!(
            "The signers file http/files.example.com/8080/acme/tool/asfaload.signers.pending/index.json was activated. Your signature was collected. You do not need to sign it again.\n\
             \n\
             Next step\n  \
             The signers file is now active. An artifact signer can register a release\n  \
             with its checksums files. Replace <checksums-file-url> and <secret-key>:\n\
             \n     \
             asfaload-cli register-assets \\\n       \
             --csum-file <checksums-file-url> \\\n       \
             --backend-url {} \\\n       \
             --secret-key <secret-key>\n\
             \n  \
             --csum-file can be repeated. For a GitHub release, use --github-release-url.\n",
            server_url
        )
    );
}

#[test]
fn sign_pending_activated_signers_file_json_reports_complete() {
    let (output, _) = run_sign_pending_on_activated_signers(&["--json"]);

    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert_eq!(stdout, "{\"is_complete\":true}\n");
}
