use predicates::prelude::*;

const FIXTURE_PASSWORD: &str = "password";

const SIGNERS_CONTENT: &[u8] = b"new signers file served by the mock server";
const OTHER_DIGEST: &str = "sha512:23df2513136fbee784517241e40b4222e9a5679b2f7b462e3b7aa3042739dcf28444ce26561fd2b088a70bd1d8012d7324eb96fa1ce37c906c6fa1e677c02a00";

fn expected_sha512(content: &[u8]) -> String {
    use sha2::{Digest, Sha512};
    format!("sha512:{}", hex::encode(Sha512::digest(content)))
}

#[test]
fn test_update_signers_requires_digest_or_local_copy() {
    // -K is a required clap arg (SecretKeyArgs.secret_key is a bare PathBuf),
    // so pass a fixture key. Then only the missing digest flags cause the
    // clap usage error.
    let key = test_helpers::fixtures_sec_key(0);
    let mut cmd = assert_cmd::cargo_bin_cmd!("asfaload-cli");
    cmd.arg("update-signers")
        .arg("https://example.com/signers.json")
        .arg("-K")
        .arg(&key);
    cmd.assert()
        .code(2)
        .stderr(predicate::str::contains(
            "required arguments were not provided",
        ))
        .stderr(predicate::str::contains("--digest"))
        .stderr(predicate::str::contains("--local-copy"));
}

#[test]
fn test_update_signers_rejects_both_flags() {
    let key = test_helpers::fixtures_sec_key(0);
    let mut cmd = assert_cmd::cargo_bin_cmd!("asfaload-cli");
    cmd.arg("update-signers")
        .arg("https://example.com/signers.json")
        .arg("-K")
        .arg(&key)
        .arg("--digest")
        .arg(OTHER_DIGEST)
        .arg("--local-copy")
        .arg("/tmp/signers.json");
    cmd.assert()
        .failure()
        .stderr(predicate::str::contains("cannot be used with"));
}

#[test]
fn test_update_signers_rejects_bare_hex_digest() {
    let key = test_helpers::fixtures_sec_key(0);
    let mut cmd = assert_cmd::cargo_bin_cmd!("asfaload-cli");
    // No colon: from_str error surfaces before any key/password network use.
    cmd.arg("update-signers")
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
fn test_update_signers_rejects_sha256_digest() {
    let key = test_helpers::fixtures_sec_key(0);
    let mut cmd = assert_cmd::cargo_bin_cmd!("asfaload-cli");
    let wrong_algo = format!("sha256:{}", "ab".repeat(64));
    cmd.arg("update-signers")
        .arg("https://example.com/signers.json")
        .arg("--digest")
        .arg(wrong_algo.as_str())
        .arg("-K")
        .arg(&key)
        .arg("-p")
        .arg(FIXTURE_PASSWORD);
    cmd.assert()
        .failure()
        .stderr(predicate::str::contains("Unsupported hash algorithm"));
}

#[test]
fn test_update_signers_local_copy_missing_file() {
    let key = test_helpers::fixtures_sec_key(0);
    let mut cmd = assert_cmd::cargo_bin_cmd!("asfaload-cli");
    cmd.arg("update-signers")
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

#[test]
fn test_update_signers_digest_mismatch_aborts() {
    let mut server = mockito::Server::new();
    let _m = server
        .mock("GET", "/owner/repo/main/signers.json")
        .with_status(200)
        .with_body(SIGNERS_CONTENT)
        .create();
    let url = format!("{}/owner/repo/main/signers.json", server.url());

    // A separate backend stub proves the backend saw zero requests even if
    // the pre-flight ordering regresses.
    let mut backend = mockito::Server::new();
    let m = backend
        .mock("POST", mockito::Matcher::Any)
        .expect(0)
        .create();

    let key = test_helpers::fixtures_sec_key(0);
    let mut cmd = assert_cmd::cargo_bin_cmd!("asfaload-cli");
    cmd.arg("update-signers")
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
fn test_update_signers_remote_fetch_failure_does_not_update() {
    let mut server = mockito::Server::new();
    let _m = server
        .mock("GET", "/owner/repo/main/signers.json")
        .with_status(404)
        .create();
    let url = format!("{}/owner/repo/main/signers.json", server.url());

    // A separate backend stub proves the backend saw zero requests even if
    // the pre-flight ordering regresses.
    let mut backend = mockito::Server::new();
    let m = backend
        .mock("POST", mockito::Matcher::Any)
        .expect(0)
        .create();

    let key = test_helpers::fixtures_sec_key(0);
    let mut cmd = assert_cmd::cargo_bin_cmd!("asfaload-cli");
    cmd.arg("update-signers")
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
fn test_update_signers_matching_digest_passes_pre_flight() {
    let mut server = mockito::Server::new();
    let signers_mock = server
        .mock("GET", "/owner/repo/main/signers.json")
        .with_status(200)
        .with_body(SIGNERS_CONTENT)
        .expect_at_least(1)
        .create();
    let url = format!("{}/owner/repo/main/signers.json", server.url());
    let digest = expected_sha512(SIGNERS_CONTENT);

    // The handler decrypts the key, fetches the new signers file, checks its
    // digest, then contacts the backend. The backend is unreachable, so
    // failing on the connection to 127.0.0.1:1 proves the flow got past the
    // digest check. The forge URL must have at least four path segments, or
    // admin-lib rejects it before any request. The forge is fetched again
    // when admin-lib signs the metadata, hence "at least one".
    let key = test_helpers::fixtures_sec_key(0);
    let mut cmd = assert_cmd::cargo_bin_cmd!("asfaload-cli");
    cmd.arg("update-signers")
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
        .stderr(predicate::str::contains("127.0.0.1:1"))
        .stderr(predicate::str::contains("Digest mismatch").not());
    signers_mock.assert();
}

#[test]
fn test_update_signers_local_copy_matches_remote_passes_pre_flight() {
    let mut server = mockito::Server::new();
    let signers_mock = server
        .mock("GET", "/owner/repo/main/signers.json")
        .with_status(200)
        .with_body(SIGNERS_CONTENT)
        .expect_at_least(1)
        .create();
    let url = format!("{}/owner/repo/main/signers.json", server.url());

    let dir = tempfile::TempDir::new().unwrap();
    let copy = dir.path().join("update_signers_local_copy_match.json");
    std::fs::write(&copy, SIGNERS_CONTENT).unwrap();
    let copy_path = copy.to_string_lossy().into_owned();

    // The backend is unreachable, so failing on the connection to
    // 127.0.0.1:1 proves the flow got past the digest check computed from
    // the local copy. See test_update_signers_matching_digest_passes_pre_flight
    // for why the forge URL needs four path segments.
    let key = test_helpers::fixtures_sec_key(0);
    let mut cmd = assert_cmd::cargo_bin_cmd!("asfaload-cli");
    cmd.arg("update-signers")
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
        .stderr(predicate::str::contains("127.0.0.1:1"))
        .stderr(predicate::str::contains("Digest mismatch").not());
    signers_mock.assert();
}

#[test]
fn test_update_signers_local_copy_mismatch_aborts() {
    let mut server = mockito::Server::new();
    let _m = server
        .mock("GET", "/owner/repo/main/signers.json")
        .with_status(200)
        .with_body(SIGNERS_CONTENT)
        .create();
    let url = format!("{}/owner/repo/main/signers.json", server.url());

    let mut backend = mockito::Server::new();
    let m = backend
        .mock("POST", mockito::Matcher::Any)
        .expect(0)
        .create();

    let different_bytes = b"a different new signers file";
    let dir = tempfile::TempDir::new().unwrap();
    let copy = dir.path().join("update_signers_local_copy_mismatch.json");
    std::fs::write(&copy, different_bytes).unwrap();
    let copy_path = copy.to_string_lossy().into_owned();

    let key = test_helpers::fixtures_sec_key(0);
    let mut cmd = assert_cmd::cargo_bin_cmd!("asfaload-cli");
    cmd.arg("update-signers")
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
fn test_update_signers_wrong_password_fails_before_fetch() {
    let mut server = mockito::Server::new();
    let m = server
        .mock("GET", "/owner/repo/main/signers.json")
        .with_status(200)
        .with_body(SIGNERS_CONTENT)
        .expect(0)
        .create();
    let url = format!("{}/owner/repo/main/signers.json", server.url());

    let key = test_helpers::fixtures_sec_key(0);
    let mut cmd = assert_cmd::cargo_bin_cmd!("asfaload-cli");
    cmd.arg("update-signers")
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
