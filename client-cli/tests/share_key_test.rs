use features_lib::{AsfaloadKeyPairTrait, AsfaloadKeyPairs};
use predicates::prelude::*;
use std::fs;
use tempfile::TempDir;

const TEST_PASSWORD: &str = "test_password_123";

// A throwaway ssh-ed25519 keypair generated with `ssh-keygen -t ed25519`.
// asfaload can read OpenSSH ed25519 keys but never writes them, so we embed a
// fixture rather than generate one at test time (no dependency on `ssh-keygen`).
const SSH_PUBLIC_KEY: &str = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIM520sFlxFm2ZlGKI2OKYOBZ4t4aQlJ0PappXAEj3TnH test@asfaload";

// The canonical asfaload representation of SSH_PUBLIC_KEY: the same 32 ed25519
// key bytes, re-encoded with the `asfaload-pub:` prefix. share-key normalises
// every accepted public key to this form, so this is what the message must show.
const SSH_PUBLIC_KEY_AS_ASFALOAD: &str = "asfaload-pub:znbSwWXEWbZmUYojY4pg4Fni3hpCUnQ9qmlcASPdOcc";

const SSH_PRIVATE_KEY: &str = "-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
QyNTUxOQAAACDOdtLBZcRZtmZRiiNjimDgWeLeGkJSdD2qaVwBI905xwAAAJAxp53YMaed
2AAAAAtzc2gtZWQyNTUxOQAAACDOdtLBZcRZtmZRiiNjimDgWeLeGkJSdD2qaVwBI905xw
AAAECBXH02sboBOruCqVLZIQ1LG/XKbCl8pJ2ZuJGMgv+yFc520sFlxFm2ZlGKI2OKYOBZ
4t4aQlJ0PappXAEj3TnHAAAADXRlc3RAYXNmYWxvYWQ=
-----END OPENSSH PRIVATE KEY-----
";

/// Generate an asfaload keypair in a temp dir and return (temp_dir, secret_key_path).
/// The public key lives at `<secret_key_path>.pub`.
fn generate_asfaload_keypair() -> (TempDir, std::path::PathBuf) {
    let temp_dir = TempDir::new().unwrap();
    let key_path = temp_dir.path().join("test_key");
    let kp = AsfaloadKeyPairs::new(TEST_PASSWORD).unwrap();
    kp.save(&key_path).unwrap();
    (temp_dir, key_path)
}

// -------------------------------------------------------------------
// Accepting public keys
// -------------------------------------------------------------------

#[test]
fn test_share_key_asfaload_public_key() {
    let (_dir, key_path) = generate_asfaload_keypair();
    let pub_key_path = format!("{}.pub", key_path.to_string_lossy());

    // Read the public key so we can assert the message embeds it verbatim.
    let pub_key = fs::read_to_string(&pub_key_path).unwrap();
    let pub_key = pub_key.trim();
    assert!(pub_key.starts_with("asfaload-pub:"));

    let mut cmd = assert_cmd::cargo_bin_cmd!("asfaload-cli");
    cmd.arg("share-key").arg("-k").arg(&pub_key_path);

    cmd.assert()
        .success()
        .stdout(predicate::str::contains("The public key is safe to share"))
        .stdout(predicate::str::contains(pub_key.to_string()));
}

#[test]
fn test_share_key_ssh_public_key() {
    let temp_dir = TempDir::new().unwrap();
    let pub_key_path = temp_dir.path().join("ssh_key.pub");
    fs::write(&pub_key_path, SSH_PUBLIC_KEY).unwrap();

    let mut cmd = assert_cmd::cargo_bin_cmd!("asfaload-cli");
    cmd.arg("share-key").arg("-k").arg(&pub_key_path);

    // The SSH key is accepted and normalised to its canonical asfaload form.
    cmd.assert()
        .success()
        .stdout(predicate::str::contains("The public key is safe to share"))
        .stdout(predicate::str::contains(SSH_PUBLIC_KEY_AS_ASFALOAD));
}

// -------------------------------------------------------------------
// Private keys: `.pub` sibling auto-discovery
// -------------------------------------------------------------------

#[test]
fn test_share_key_finds_pub_sibling_when_given_private_key() {
    // Fixture key_0 has a key_0.pub sibling alongside it.
    let priv_key = test_helpers::fixtures_keys_dir().join("key_0");
    let pub_key = fs::read_to_string(test_helpers::fixtures_pub_key(0))
        .unwrap()
        .trim()
        .to_owned();

    // Pass the private key file — the command should find the `.pub` sibling.
    let mut cmd = assert_cmd::cargo_bin_cmd!("asfaload-cli");
    cmd.arg("share-key").arg("-k").arg(&priv_key);

    cmd.assert()
        .success()
        .stdout(predicate::str::contains("The public key is safe to share"))
        .stdout(predicate::str::contains(pub_key));
}

// Validates that the `-k <path>` handler *appends* `.pub` to the supplied
// path rather than replacing its existing extension. The private key is staged
// at `mykey.bla` and the public key at `mykey.bla.pub`; if `share-key` used
// `Path::with_extension("pub")` instead of appending, it would look for
// `mykey.pub` (replacing `.bla`), fail to find it, and the command would error.
// By staging the public key only under the appended name, this test fails under
// replace-extension semantics and passes under append semantics.
#[test]
fn test_share_key_appends_pub_extension_preserving_existing_extension() {
    let temp_dir = TempDir::new().unwrap();
    // Private key with an arbitrary extension. Its content isn't parsed as a
    // public key, so `from_file` returns ParseError and triggers the `.pub`
    // fallback. We reuse the committed key_0 fixture for stable content.
    let priv_key = temp_dir.path().join("mykey.bla");
    fs::copy(test_helpers::fixtures_keys_dir().join("key_0"), &priv_key).unwrap();

    // The public key lives only at the *appended* path. A `with_extension`
    // implementation would produce `mykey.pub`, which is never created here.
    let pub_key_path = temp_dir.path().join("mykey.bla.pub");
    fs::copy(test_helpers::fixtures_pub_key(0), &pub_key_path).unwrap();

    let pub_key = fs::read_to_string(&pub_key_path).unwrap().trim().to_owned();
    assert!(pub_key.starts_with("asfaload-pub:"));

    let mut cmd = assert_cmd::cargo_bin_cmd!("asfaload-cli");
    cmd.arg("share-key").arg("-k").arg(&priv_key);

    cmd.assert()
        .success()
        .stdout(predicate::str::contains("The public key is safe to share"))
        .stdout(predicate::str::contains(pub_key));
}

#[test]
fn test_share_key_rejects_private_key_without_pub_sibling() {
    let temp_dir = TempDir::new().unwrap();
    let priv_key = temp_dir.path().join("key");
    // Copy only the private key fixture — no .pub sidecar.
    fs::copy(test_helpers::fixtures_keys_dir().join("key_0"), &priv_key).unwrap();

    let mut cmd = assert_cmd::cargo_bin_cmd!("asfaload-cli");
    cmd.arg("share-key").arg("-k").arg(&priv_key);

    cmd.assert()
        .failure()
        .stderr(predicate::str::contains("Error loading public key"));
}

#[test]
fn test_share_key_rejects_ssh_private_key() {
    let temp_dir = TempDir::new().unwrap();
    let key_path = temp_dir.path().join("ssh_key");
    fs::write(&key_path, SSH_PRIVATE_KEY).unwrap();

    let mut cmd = assert_cmd::cargo_bin_cmd!("asfaload-cli");
    cmd.arg("share-key").arg("-k").arg(&key_path);

    cmd.assert()
        .failure()
        .stderr(predicate::str::contains("Error loading public key"));
}

// -------------------------------------------------------------------
// --raw flag
// -------------------------------------------------------------------

// The canonical asfaload form of the git signing SSH fixture key
// (core/test_helpers/fixtures/git_signing_key.pub), as produced by
// AsfaloadPublicKeys::from_file(...).to_base64(). Normalisation happens
// before the raw match arm, so this is what --raw must print.
const GIT_SIGNING_KEY_AS_ASFALOAD: &str =
    "asfaload-pub:druiW7o+/nOfS5YZN8WlmCwxv03YHfV6lQUA0J1LdVI";

/// The asfaload-pub string stored verbatim in `fixtures/keys/key_0.pub`.
/// Read from disk rather than hardcoded so the test tracks the fixture
/// instead of duplicating its content.
fn fixture_pub_key_0() -> String {
    fs::read_to_string(test_helpers::fixtures_pub_key(0))
        .unwrap()
        .trim()
        .to_owned()
}

#[test]
fn test_share_key_raw_asfaload_key() {
    let mut cmd = assert_cmd::cargo_bin_cmd!("asfaload-cli");
    cmd.arg("share-key")
        .arg("-k")
        .arg(test_helpers::fixtures_pub_key(0))
        .arg("--raw");

    cmd.assert()
        .success()
        .stdout(predicate::eq(format!("{}\n", fixture_pub_key_0())));
}

#[test]
fn test_share_key_raw_short_flag() {
    let mut cmd = assert_cmd::cargo_bin_cmd!("asfaload-cli");
    cmd.arg("share-key")
        .arg("-k")
        .arg(test_helpers::fixtures_pub_key(0))
        .arg("-r");

    cmd.assert()
        .success()
        .stdout(predicate::eq(format!("{}\n", fixture_pub_key_0())));
}

#[test]
fn test_share_key_raw_ssh_key_normalised() {
    let mut cmd = assert_cmd::cargo_bin_cmd!("asfaload-cli");
    cmd.arg("share-key")
        .arg("-k")
        .arg(test_helpers::git_signing_pub_key_path())
        .arg("--raw");

    cmd.assert()
        .success()
        .stdout(predicate::eq(format!("{}\n", GIT_SIGNING_KEY_AS_ASFALOAD)));
}

#[test]
fn test_share_key_raw_excludes_human_message() {
    let mut cmd = assert_cmd::cargo_bin_cmd!("asfaload-cli");
    cmd.arg("share-key")
        .arg("-k")
        .arg(test_helpers::fixtures_pub_key(0))
        .arg("--raw");

    cmd.assert()
        .success()
        .stdout(predicate::str::contains("The public key is safe to share").not())
        .stdout(predicate::str::contains("\u{1b}").not());
}

#[test]
fn test_share_key_raw_and_json_conflict() {
    let mut cmd = assert_cmd::cargo_bin_cmd!("asfaload-cli");
    cmd.arg("share-key")
        .arg("-k")
        .arg(test_helpers::fixtures_pub_key(0))
        .arg("--raw")
        .arg("--json");

    // clap's conflicts_with emits an error mentioning the conflicting flags.
    cmd.assert()
        .failure()
        .stderr(predicate::str::contains("--raw"))
        .stderr(predicate::str::contains("--json"));
}

#[test]
fn test_share_key_raw_default_unchanged() {
    let mut cmd = assert_cmd::cargo_bin_cmd!("asfaload-cli");
    cmd.arg("share-key")
        .arg("-k")
        .arg(test_helpers::fixtures_pub_key(0));

    cmd.assert()
        .success()
        .stdout(predicate::str::contains("The public key is safe to share"))
        .stdout(predicate::str::contains(fixture_pub_key_0()));
}

// -------------------------------------------------------------------
// Alias suggestion
// -------------------------------------------------------------------

#[test]
fn test_share_key_message_suggests_alias() {
    let mut cmd = assert_cmd::cargo_bin_cmd!("asfaload-cli");
    cmd.arg("share-key")
        .arg("-k")
        .arg(test_helpers::fixtures_pub_key(0));

    cmd.assert()
        .success()
        .stdout(predicate::str::contains(format!(
            "asfaload-cli alias --key {} <name>",
            fixture_pub_key_0()
        )));
}

#[test]
fn test_share_key_json_message_suggests_alias() {
    let mut cmd = assert_cmd::cargo_bin_cmd!("asfaload-cli");
    cmd.arg("share-key")
        .arg("-k")
        .arg(test_helpers::fixtures_pub_key(0))
        .arg("--json");

    let output = cmd.assert().success().get_output().stdout.clone();
    let json: serde_json::Value =
        serde_json::from_slice(&output).expect("stdout should be valid JSON");
    let message = json["message"]
        .as_str()
        .expect("message should be a string");
    assert!(message.contains(&format!(
        "asfaload-cli alias --key {} <name>",
        fixture_pub_key_0()
    )));
}
