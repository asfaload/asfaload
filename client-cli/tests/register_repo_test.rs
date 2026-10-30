use predicates::prelude::*;

#[test]
fn test_register_repo_missing_url_shows_error() {
    let mut cmd = assert_cmd::cargo_bin_cmd!("asfaload-cli");
    cmd.arg("register-repo");
    cmd.assert().failure();
}

#[test]
fn test_register_repo_help_shows_usage() {
    let mut cmd = assert_cmd::cargo_bin_cmd!("asfaload-cli");
    cmd.args(["register-repo", "--help"]);
    cmd.assert()
        .success()
        .stdout(predicate::str::contains("SIGNERS_FILE_URL"))
        .stdout(predicate::str::contains("backend-url"))
        .stdout(predicate::str::contains("secret-key"));
}

#[test]
fn test_register_repo_requires_digest_or_local_copy() {
    // -K is a required clap arg (SecretKeyArgs.secret_key is a bare PathBuf),
    // so pass a fixture key to reach the digest validation.
    // expected_digest runs before get_password, so no password is needed.
    let key = test_helpers::fixtures_sec_key(0);
    let mut cmd = assert_cmd::cargo_bin_cmd!("asfaload-cli");
    cmd.arg("register-repo")
        .arg("https://example.com/signers.json")
        .arg("-K")
        .arg(&key);
    cmd.assert()
        .failure()
        .stderr(predicate::str::contains("--digest"));
}

#[test]
fn test_register_repo_rejects_both_flags() {
    let key = test_helpers::fixtures_sec_key(0);
    let mut cmd = assert_cmd::cargo_bin_cmd!("asfaload-cli");
    cmd.arg("register-repo")
        .arg("https://example.com/signers.json")
        .arg("-K")
        .arg(&key)
        .arg("--digest")
        .arg("sha512:23df2513136fbee784517241e40b4222e9a5679b2f7b462e3b7aa3042739dcf28444ce26561fd2b088a70bd1d8012d7324eb96fa1ce37c906c6fa1e677c02a00")
        .arg("--local-copy")
        .arg("/tmp/signers.json");
    cmd.assert()
        .failure()
        .stderr(predicate::str::contains("cannot be used with"));
}

const FIXTURE_PASSWORD: &str = "password";

#[test]
fn test_register_repo_rejects_bare_hex_digest() {
    let key = test_helpers::fixtures_sec_key(0);
    let mut cmd = assert_cmd::cargo_bin_cmd!("asfaload-cli");
    // No colon: from_str error surfaces before any key/password network use.
    cmd.arg("register-repo")
        .arg("https://example.com/signers.json")
        .arg("--digest")
        .arg("abcd")
        .arg("-K")
        .arg(&key)
        .arg("-p")
        .arg(FIXTURE_PASSWORD);
    cmd.assert()
        .failure()
        .stderr(predicate::str::contains("Invalid --digest value"));
}

#[test]
fn test_register_repo_rejects_sha256_digest() {
    let key = test_helpers::fixtures_sec_key(0);
    let mut cmd = assert_cmd::cargo_bin_cmd!("asfaload-cli");
    let wrong_len = format!("sha256:{}", "ab".repeat(64));
    cmd.arg("register-repo")
        .arg("https://example.com/signers.json")
        .arg("--digest")
        .arg(wrong_len.as_str())
        .arg("-K")
        .arg(&key)
        .arg("-p")
        .arg(FIXTURE_PASSWORD);
    cmd.assert()
        .failure()
        .stderr(predicate::str::contains("Unsupported hash algorithm"));
}

#[test]
fn test_register_repo_local_copy_missing_file() {
    let key = test_helpers::fixtures_sec_key(0);
    let mut cmd = assert_cmd::cargo_bin_cmd!("asfaload-cli");
    cmd.arg("register-repo")
        .arg("https://example.com/signers.json")
        .arg("--local-copy")
        .arg("/tmp/nonexistent.signers.json")
        .arg("-K")
        .arg(&key)
        .arg("-p")
        .arg(FIXTURE_PASSWORD);
    cmd.assert()
        .failure()
        .stderr(predicate::str::contains("Invalid --local-copy"));
}

const SIGNERS_CONTENT: &[u8] = b"signers file served by the mock server";
const OTHER_DIGEST: &str = "sha512:23df2513136fbee784517241e40b4222e9a5679b2f7b462e3b7aa3042739dcf28444ce26561fd2b088a70bd1d8012d7324eb96fa1ce37c906c6fa1e677c02a00";

fn expected_sha512(content: &[u8]) -> String {
    use sha2::{Digest, Sha512};
    format!("sha512:{}", hex::encode(Sha512::digest(content)))
}

#[test]
fn test_register_repo_digest_mismatch_aborts() {
    let mut server = mockito::Server::new();
    let _m = server
        .mock("GET", "/signers.json")
        .with_status(200)
        .with_body(SIGNERS_CONTENT)
        .create();
    let url = format!("{}/signers.json", server.url());

    // A separate backend stub proves the backend saw zero requests even if
    // the pre-flight ordering regresses.
    let mut backend = mockito::Server::new();
    let m = backend
        .mock("POST", mockito::Matcher::Any)
        .expect(0)
        .create();

    let key = test_helpers::fixtures_sec_key(0);
    let mut cmd = assert_cmd::cargo_bin_cmd!("asfaload-cli");
    cmd.arg("register-repo")
        .arg(url.as_str())
        .arg("--digest")
        .arg(OTHER_DIGEST)
        .arg("-K")
        .arg(&key)
        .arg("-p")
        .arg(FIXTURE_PASSWORD)
        .arg("-u")
        .arg(backend.url());
    cmd.assert()
        .failure()
        .stderr(predicate::str::contains("Digest mismatch"))
        .stderr(predicate::str::contains(OTHER_DIGEST))
        .stderr(predicate::str::contains(expected_sha512(SIGNERS_CONTENT)));
    m.assert();
}

#[test]
fn test_register_repo_remote_fetch_failure_does_not_register() {
    let mut server = mockito::Server::new();
    let _m = server
        .mock("GET", "/signers.json")
        .with_status(404)
        .create();
    let url = format!("{}/signers.json", server.url());

    // A separate backend stub proves the backend saw zero requests even if
    // the pre-flight ordering regresses.
    let mut backend = mockito::Server::new();
    let m = backend
        .mock("POST", mockito::Matcher::Any)
        .expect(0)
        .create();

    let key = test_helpers::fixtures_sec_key(0);
    let mut cmd = assert_cmd::cargo_bin_cmd!("asfaload-cli");
    cmd.arg("register-repo")
        .arg(url.as_str())
        .arg("--digest")
        .arg(OTHER_DIGEST)
        .arg("-K")
        .arg(&key)
        .arg("-p")
        .arg(FIXTURE_PASSWORD)
        .arg("-u")
        .arg(backend.url());
    cmd.assert()
        .failure()
        .stderr(predicate::str::contains("HTTP 404"))
        .stderr(predicate::str::contains("Digest mismatch").not());
    m.assert();
}

#[test]
fn test_register_repo_matching_digest_passes_pre_flight() {
    let mut server = mockito::Server::new();
    let signers_mock = server
        .mock("GET", "/signers.json")
        .with_status(200)
        .with_body(SIGNERS_CONTENT)
        .expect_at_least(1)
        .create();
    let url = format!("{}/signers.json", server.url());
    let digest = expected_sha512(SIGNERS_CONTENT);

    // The handler decrypts the key first, then fetches the signers file and
    // checks its digest, and only then contacts the backend. The fetch happens
    // only after decryption, so it proves the flow got past the password check
    // and the digest matched. It is fetched again later when admin-lib signs
    // the metadata, hence "at least one".
    let key = test_helpers::fixtures_sec_key(0);
    let mut cmd = assert_cmd::cargo_bin_cmd!("asfaload-cli");
    cmd.arg("register-repo")
        .arg(url.as_str())
        .arg("--digest")
        .arg(digest.as_str())
        .arg("-K")
        .arg(&key)
        .arg("-p")
        .arg(FIXTURE_PASSWORD)
        .arg("-u")
        .arg("http://127.0.0.1:1");
    cmd.assert()
        .failure()
        .stderr(predicate::str::contains("Digest mismatch").not());
    signers_mock.assert();
}

#[test]
fn test_register_repo_local_copy_matches_remote_passes_pre_flight() {
    let mut server = mockito::Server::new();
    let signers_mock = server
        .mock("GET", "/signers.json")
        .with_status(200)
        .with_body(SIGNERS_CONTENT)
        .expect_at_least(1)
        .create();
    let url = format!("{}/signers.json", server.url());

    let dir = tempfile::TempDir::new().unwrap();
    let copy = dir.path().join("register_repo_local_copy_match.json");
    std::fs::write(&copy, SIGNERS_CONTENT).unwrap();
    let copy_path = copy.to_string_lossy().into_owned();

    // The signers-file fetch happens only after the local copy was hashed and
    // matched, so a fetch pins that the pre-flight check passed.
    let key = test_helpers::fixtures_sec_key(0);
    let mut cmd = assert_cmd::cargo_bin_cmd!("asfaload-cli");
    cmd.arg("register-repo")
        .arg(url.as_str())
        .arg("--local-copy")
        .arg(copy_path.as_str())
        .arg("-K")
        .arg(&key)
        .arg("-p")
        .arg(FIXTURE_PASSWORD)
        .arg("-u")
        .arg("http://127.0.0.1:1");
    cmd.assert()
        .failure()
        .stderr(predicate::str::contains("Digest mismatch").not());
    signers_mock.assert();
}

#[test]
fn test_register_repo_local_copy_mismatch_aborts() {
    let mut server = mockito::Server::new();
    let _m = server
        .mock("GET", "/signers.json")
        .with_status(200)
        .with_body(SIGNERS_CONTENT)
        .create();
    let url = format!("{}/signers.json", server.url());

    let mut backend = mockito::Server::new();
    let m = backend
        .mock("POST", mockito::Matcher::Any)
        .expect(0)
        .create();

    let different_bytes = b"a different signers file";
    let dir = tempfile::TempDir::new().unwrap();
    let copy = dir.path().join("register_repo_local_copy_mismatch.json");
    std::fs::write(&copy, different_bytes).unwrap();
    let copy_path = copy.to_string_lossy().into_owned();

    let key = test_helpers::fixtures_sec_key(0);
    let mut cmd = assert_cmd::cargo_bin_cmd!("asfaload-cli");
    cmd.arg("register-repo")
        .arg(url.as_str())
        .arg("--local-copy")
        .arg(copy_path.as_str())
        .arg("-K")
        .arg(&key)
        .arg("-p")
        .arg(FIXTURE_PASSWORD)
        .arg("-u")
        .arg(backend.url());
    cmd.assert()
        .failure()
        .stderr(predicate::str::contains("Digest mismatch"))
        .stderr(predicate::str::contains(expected_sha512(different_bytes)))
        .stderr(predicate::str::contains(expected_sha512(SIGNERS_CONTENT)));
    m.assert();
}

/// A wrong password must abort before any network request: the signers
/// fetch at the forge must see zero hits. `expect(0)` + `m.assert()` pins
/// that: mockito 1.x has no hits() accessor, `assert()` enforces the count.
#[test]
fn test_register_repo_wrong_password_fails_before_fetch() {
    let mut server = mockito::Server::new();
    let m = server
        .mock("GET", "/signers.json")
        .with_status(200)
        .with_body(SIGNERS_CONTENT)
        .expect(0)
        .create();
    let url = format!("{}/signers.json", server.url());

    let key = test_helpers::fixtures_sec_key(0);
    let mut cmd = assert_cmd::cargo_bin_cmd!("asfaload-cli");
    cmd.arg("register-repo")
        .arg(url.as_str())
        .arg("--digest")
        .arg(OTHER_DIGEST)
        .arg("-K")
        .arg(&key)
        .arg("-p")
        .arg("wrong-password");
    cmd.assert()
        .failure()
        .stderr(predicate::str::contains("Digest mismatch").not());
    m.assert();
}
