use features_lib::{AsfaloadKeyPairTrait, AsfaloadKeyPairs};
use predicates::prelude::*;
use serde_json::Value;
use sha2::{Digest, Sha512};
use std::fs;
use tempfile::TempDir;
use test_helpers::fixtures_pub_key;

const TEST_PASSWORD: &str = "test_password_123";

/// Helper: generate a keypair in a temp dir and return (temp_dir, key_path)
fn generate_test_keypair() -> (TempDir, std::path::PathBuf) {
    let temp_dir = TempDir::new().unwrap();
    let key_path = temp_dir.path().join("test_key");
    let kp = AsfaloadKeyPairs::new(TEST_PASSWORD).unwrap();
    kp.save(&key_path).unwrap();
    (temp_dir, key_path)
}

// -------------------------------------------------------------------
// new-keys
// -------------------------------------------------------------------

#[test]
fn test_new_keys_json_output() {
    let temp_dir = TempDir::new().unwrap();

    let mut cmd = assert_cmd::cargo_bin_cmd!("asfaload-cli");
    cmd.arg("new-keys")
        .arg("--json")
        .arg("-n")
        .arg("mykey")
        .arg("-d")
        .arg(temp_dir.path())
        .arg("-p")
        .arg(TEST_PASSWORD)
        .arg("--accept-weak-password");

    let output = cmd.output().unwrap();
    assert!(output.status.success());

    let stdout = String::from_utf8(output.stdout).unwrap();
    let json: Value = serde_json::from_str(&stdout).expect("stdout should be valid JSON");

    assert!(json["public_key_path"].as_str().unwrap().ends_with(".pub"));
    assert!(json["secret_key_path"].as_str().unwrap().contains("mykey"));
}

#[test]
fn test_new_keys_human_output_unchanged() {
    let temp_dir = TempDir::new().unwrap();

    let mut cmd = assert_cmd::cargo_bin_cmd!("asfaload-cli");
    cmd.arg("new-keys")
        .arg("-n")
        .arg("mykey")
        .arg("-d")
        .arg(temp_dir.path())
        .arg("-p")
        .arg(TEST_PASSWORD)
        .arg("--accept-weak-password");

    cmd.assert().success().stdout(
        predicate::str::contains("The public key is safe to share")
            .and(predicate::str::contains("asfaload-pub:")),
    );
}

// -------------------------------------------------------------------
// new-signers-file
// -------------------------------------------------------------------

#[test]
fn test_new_signers_file_json_output() {
    let (_key_dir, key_path) = generate_test_keypair();
    let temp_dir = TempDir::new().unwrap();
    let output_file = temp_dir.path().join("signers.json");

    let pub_key_path = format!("{}.pub", key_path.to_string_lossy());

    let mut cmd = assert_cmd::cargo_bin_cmd!("asfaload-cli");
    cmd.arg("new-signers-file")
        .arg("--json")
        .arg("--artifact-signers-file")
        .arg(&pub_key_path)
        .arg("-A")
        .arg("1")
        .arg("-o")
        .arg(&output_file);

    let output = cmd.output().unwrap();
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8(output.stdout).unwrap();
    let json: Value = serde_json::from_str(&stdout).expect("stdout should be valid JSON");

    assert_eq!(json["artifact_signers_count"], 1);
    assert_eq!(json["artifact_threshold"], 1);
    assert_eq!(json["admin_keys_count"], 0);
    assert!(json["admin_threshold"].is_null());
    assert_eq!(json["master_keys_count"], 0);
    assert!(json["master_threshold"].is_null());
    assert!(!json["output_file"].as_str().unwrap().is_empty());
}

#[test]
fn test_new_signers_file_json_digest_present_and_correct() {
    let pub_key = fixtures_pub_key(0);
    let temp_dir = TempDir::new().unwrap();
    let output_file = temp_dir.path().join("signers.json");

    let mut cmd = assert_cmd::cargo_bin_cmd!("asfaload-cli");
    cmd.arg("new-signers-file")
        .arg("--json")
        .arg("--artifact-signers-file")
        .arg(&pub_key)
        .arg("-A")
        .arg("1")
        .arg("-o")
        .arg(&output_file);

    let output = cmd.output().unwrap();
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8(output.stdout).unwrap();
    let json: Value = serde_json::from_str(&stdout).expect("stdout should be valid JSON");

    let digest_str = json["digest"]
        .as_str()
        .expect("digest field should be a string");
    assert!(!digest_str.is_empty(), "digest should not be empty");
    assert!(
        digest_str.starts_with("sha512:"),
        "digest should start with 'sha512:', got: {}",
        digest_str
    );

    let file_bytes = fs::read(&output_file).unwrap();
    let hash = Sha512::digest(&file_bytes);
    let expected = format!("sha512:{}", hex::encode(hash));
    assert_eq!(
        digest_str, expected,
        "json digest does not match the file's actual sha512"
    );
}

#[test]
fn test_new_signers_file_human_output_includes_revocation_keys() {
    let (_key_dir, key_path) = generate_test_keypair();
    let temp_dir = TempDir::new().unwrap();
    let output_file = temp_dir.path().join("signers.json");

    let pub_key_path = format!("{}.pub", key_path.to_string_lossy());

    let mut cmd = assert_cmd::cargo_bin_cmd!("asfaload-cli");
    cmd.arg("new-signers-file")
        .arg("--artifact-signers-file")
        .arg(&pub_key_path)
        .arg("-A")
        .arg("1")
        .arg("--revocation-keys-file")
        .arg(&pub_key_path)
        .arg("-R")
        .arg("1")
        .arg("-o")
        .arg(&output_file);

    cmd.assert()
        .success()
        .stdout(predicate::str::contains(
            "Artifact signers: 1 (threshold: 1)",
        ))
        .stdout(predicate::str::contains(
            "Revocation keys: 1 (threshold: 1)",
        ));
}

#[test]
fn test_new_signers_file_with_multi_key_files_all_groups() {
    // Use distinct fixture keypairs to avoid master-vs-others conflict
    // Artifact: key_0 + key_1,  Admin: key_2 + key_3
    // Master:   key_4 + key_5,  Revocation: key_6 + key_7
    let temp_dir = TempDir::new().unwrap();
    let output_file = temp_dir.path().join("signers.json");

    let artifact_file = temp_dir.path().join("artifact.pub");
    fs::write(
        &artifact_file,
        format!(
            "{}\n{}",
            fs::read_to_string(fixtures_pub_key(0)).unwrap(),
            fs::read_to_string(fixtures_pub_key(1)).unwrap()
        ),
    )
    .unwrap();

    let admin_file = temp_dir.path().join("admin.pub");
    fs::write(
        &admin_file,
        format!(
            "{}\n{}",
            fs::read_to_string(fixtures_pub_key(2)).unwrap(),
            fs::read_to_string(fixtures_pub_key(3)).unwrap()
        ),
    )
    .unwrap();

    let master_file = temp_dir.path().join("master.pub");
    fs::write(
        &master_file,
        format!(
            "{}\n{}",
            fs::read_to_string(fixtures_pub_key(4)).unwrap(),
            fs::read_to_string(fixtures_pub_key(5)).unwrap()
        ),
    )
    .unwrap();

    let revocation_file = temp_dir.path().join("revocation.pub");
    fs::write(
        &revocation_file,
        format!(
            "{}\n{}",
            fs::read_to_string(fixtures_pub_key(6)).unwrap(),
            fs::read_to_string(fixtures_pub_key(7)).unwrap()
        ),
    )
    .unwrap();

    let mut cmd = assert_cmd::cargo_bin_cmd!("asfaload-cli");
    cmd.arg("new-signers-file")
        .arg("--json")
        .arg("--artifact-signers-file")
        .arg(&artifact_file)
        .arg("-A")
        .arg("2")
        .arg("--admin-keys-file")
        .arg(&admin_file)
        .arg("-D")
        .arg("1")
        .arg("--master-keys-file")
        .arg(&master_file)
        .arg("-M")
        .arg("1")
        .arg("--revocation-keys-file")
        .arg(&revocation_file)
        .arg("-R")
        .arg("1")
        .arg("-o")
        .arg(&output_file);

    let output = cmd.output().unwrap();
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8(output.stdout).unwrap();
    let json: Value = serde_json::from_str(&stdout).expect("stdout should be valid JSON");

    assert_eq!(json["artifact_signers_count"], 2);
    assert_eq!(json["artifact_threshold"], 2);
    assert_eq!(json["admin_keys_count"], 2);
    assert_eq!(json["admin_threshold"], 1);
    assert_eq!(json["master_keys_count"], 2);
    assert_eq!(json["master_threshold"], 1);
    assert_eq!(json["revocation_keys_count"], 2);
    assert_eq!(json["revocation_threshold"], 1);
    assert!(!json["output_file"].as_str().unwrap().is_empty());

    // Output file should exist and contain valid signers config
    assert!(output_file.exists());
    let _config =
        signers_file_types::parse_signers_config(&fs::read_to_string(&output_file).unwrap())
            .expect("output file should be a valid signers config");
}

// -------------------------------------------------------------------
// Error as JSON
// -------------------------------------------------------------------

#[test]
fn test_error_output_as_json() {
    let mut cmd = assert_cmd::cargo_bin_cmd!("asfaload-cli");
    cmd.arg("new-keys")
        .arg("--json")
        .arg("-n")
        .arg("test")
        .arg("-d")
        .arg("/nonexistent/dir")
        .arg("-p")
        .arg("test_password")
        .arg("--accept-weak-password");

    let output = cmd.output().unwrap();
    assert!(!output.status.success());

    let stderr = String::from_utf8(output.stderr).unwrap();
    let json: Value = serde_json::from_str(&stderr)
        .unwrap_or_else(|_| panic!("stderr should be valid JSON but is {}", stderr));

    assert!(json["error"].as_str().is_some());
    assert!(!json["error"].as_str().unwrap().is_empty());
}

#[test]
fn test_error_without_json_is_plain_text() {
    let mut cmd = assert_cmd::cargo_bin_cmd!("asfaload-cli");
    cmd.arg("new-keys")
        .arg("-n")
        .arg("test")
        .arg("-d")
        .arg("/nonexistent/dir")
        .arg("-p")
        .arg("test_password")
        .arg("--accept-weak-password");

    let output = cmd.output().unwrap();
    assert!(!output.status.success());

    let stderr = String::from_utf8(output.stderr).unwrap();
    // Without --json, stderr should NOT be JSON
    assert!(serde_json::from_str::<Value>(&stderr).is_err());
}
