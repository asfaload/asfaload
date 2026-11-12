use predicates::prelude::*;
use sha2::{Digest, Sha512};

const FIXTURE_PASSWORD: &str = "password";
const FILE_PATH: &str = "github.com/acme/tool/releases/download/v1.0.0/asfaload.index.json";
const CONTENT: &[u8] = b"content served by the backend";
const DIGEST_NON_MATCHING: &str = concat!(
    "sha512:",
    "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
    "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
);

fn sha512_digest_str(content: &[u8]) -> String {
    format!("sha512:{}", hex::encode(Sha512::digest(content)))
}

// Mock the file fetch and the revoke endpoint. The revoke mock expects
// `revoke_calls` requests, check it with `assert()`.
fn mock_revoke(
    server: &mut mockito::Server,
    revoke_calls: usize,
) -> (mockito::Mock, mockito::Mock) {
    let file = server
        .mock("GET", format!("/v1/files/{}", FILE_PATH).as_str())
        .with_status(200)
        .with_body(CONTENT)
        .create();
    let revoke = server
        .mock("POST", "/v1/revoke")
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(r#"{"success":true,"message":"revoked","required_signers":[]}"#)
        .expect(revoke_calls)
        .create();
    (file, revoke)
}

fn revoke_cmd(server: &mockito::Server) -> assert_cmd::Command {
    let mut cmd = assert_cmd::cargo_bin_cmd!("asfaload-cli");
    cmd.arg("revoke")
        .arg("-K")
        .arg(test_helpers::fixtures_sec_key(0))
        .arg("-u")
        .arg(server.url())
        .arg(FILE_PATH)
        .env("ASFALOAD_REVOKE_PASSWORD", FIXTURE_PASSWORD);
    cmd
}

#[test]
fn revoke_requires_digest_or_local_copy() {
    let mut cmd = assert_cmd::cargo_bin_cmd!("asfaload-cli");
    cmd.arg("revoke")
        .arg("-K")
        .arg(test_helpers::fixtures_sec_key(0))
        .arg(FILE_PATH);
    cmd.assert()
        .code(2)
        .stderr(predicate::str::contains(
            "required arguments were not provided",
        ))
        .stderr(predicate::str::contains("--digest"))
        .stderr(predicate::str::contains("--local-copy"));
}

#[test]
fn revoke_with_matching_digest_submits_revocation() {
    let mut server = mockito::Server::new();
    let (_file, revoke) = mock_revoke(&mut server, 1);

    let output = revoke_cmd(&server)
        .arg("--digest")
        .arg(sha512_digest_str(CONTENT))
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    revoke.assert();
}

#[test]
fn revoke_digest_not_matching_file_is_rejected() {
    let mut server = mockito::Server::new();
    let (_file, revoke) = mock_revoke(&mut server, 0);

    revoke_cmd(&server)
        .arg("--digest")
        .arg(DIGEST_NON_MATCHING)
        .assert()
        .failure()
        .stderr(predicate::str::contains(format!(
            "Computed digest ({}) does not match the expected digest ({})",
            sha512_digest_str(CONTENT),
            DIGEST_NON_MATCHING
        )));
    revoke.assert();
}

#[test]
fn revoke_local_copy_not_matching_file_is_rejected() {
    let local_content = b"other content in the local copy";
    let local_copy = tempfile::NamedTempFile::new().unwrap();
    std::fs::write(local_copy.path(), local_content).unwrap();

    let mut server = mockito::Server::new();
    let (_file, revoke) = mock_revoke(&mut server, 0);

    revoke_cmd(&server)
        .arg("--local-copy")
        .arg(local_copy.path())
        .assert()
        .failure()
        .stderr(predicate::str::contains(format!(
            "Computed digest ({}) does not match the expected digest ({})",
            sha512_digest_str(CONTENT),
            sha512_digest_str(local_content)
        )));
    revoke.assert();
}
