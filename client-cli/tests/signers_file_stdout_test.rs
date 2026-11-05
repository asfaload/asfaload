use sha2::{Digest, Sha512};
use std::fs;
use tempfile::TempDir;
use test_helpers::fixtures_pub_key;

// -------------------------------------------------------------------
// new-signers-file stdout mode (-o omitted)
// -------------------------------------------------------------------

/// The headline parity test: running `new-signers-file` with `-o file`
/// must produce a structurally identical SignersConfig as capturing
/// stdout when `-o` is omitted (and redirecting it to a file). Timestamps
/// differ per-invocation, so this compares parsed configs field-by-field
/// rather than raw bytes.
#[test]
fn stdout_matches_minus_o_structurally() {
    let pub_key = fixtures_pub_key(0);
    let temp_dir = TempDir::new().unwrap();
    let file_a = temp_dir.path().join("via_minus_o.json");

    // Run 1: -o file_a
    let mut cmd_a = assert_cmd::cargo_bin_cmd!("asfaload-cli");
    cmd_a
        .arg("new-signers-file")
        .arg("--artifact-signers-file")
        .arg(&pub_key)
        .arg("-A")
        .arg("1")
        .arg("-o")
        .arg(&file_a);
    let output_a = cmd_a.output().unwrap();
    assert!(
        output_a.status.success(),
        "run 1 (-o) failed: stderr = {}",
        String::from_utf8_lossy(&output_a.stderr)
    );

    // Run 2: no -o, capture stdout
    let mut cmd_b = assert_cmd::cargo_bin_cmd!("asfaload-cli");
    cmd_b
        .arg("new-signers-file")
        .arg("--artifact-signers-file")
        .arg(&pub_key)
        .arg("-A")
        .arg("1");
    let output_b = cmd_b.output().unwrap();
    assert!(
        output_b.status.success(),
        "run 2 (stdout) failed: stderr = {}",
        String::from_utf8_lossy(&output_b.stderr)
    );

    let json_a = fs::read_to_string(&file_a).unwrap();
    let json_b = String::from_utf8(output_b.stdout).unwrap();
    let stderr_b = String::from_utf8_lossy(&output_b.stderr);

    let config_a = signers_file_types::parse_signers_config(&json_a)
        .expect("run 1 (-o) output must parse as SignersConfig");
    let config_b = signers_file_types::parse_signers_config(&json_b)
        .expect("run 2 (stdout) output must parse as SignersConfig");

    // Nothing is printed on stderr
    assert!(
        stderr_b.is_empty(),
        "stderr should be empty in stdout mode, got: {}",
        stderr_b
    );
    // Structural comparison: all fields except the per-invocation timestamp
    // must be identical.
    assert_eq!(config_a.version(), config_b.version(), "version mismatch");
    assert_eq!(
        config_a.artifact_signers(),
        config_b.artifact_signers(),
        "artifact_signers mismatch"
    );
    assert_eq!(
        config_a.admin_keys(),
        config_b.admin_keys(),
        "admin_keys mismatch"
    );
    assert_eq!(
        config_a.master_keys(),
        config_b.master_keys(),
        "master_keys mismatch"
    );
    assert_eq!(
        config_a.revocation_keys(),
        config_b.revocation_keys(),
        "revocation_keys mismatch"
    );

    // Sanity: both must have the same length (timestamp is fixed-width)
    let bytes_a = fs::read(&file_a).unwrap();
    assert_eq!(
        bytes_a.len(),
        json_b.len(),
        "byte-lengths differ: -o = {}, stdout = {}",
        bytes_a.len(),
        json_b.len()
    );
}

/// Stdout must end with exactly one trailing newline, matching the
/// canonical POSIX JSON contract enforced by `to_posix_json`
/// (core/common/src/lib.rs:96-101) and the
/// `to_posix_json_compact_with_single_trailing_newline` unit test.
#[test]
fn stdout_has_single_trailing_newline() {
    let pub_key = fixtures_pub_key(0);

    let mut cmd = assert_cmd::cargo_bin_cmd!("asfaload-cli");
    cmd.arg("new-signers-file")
        .arg("--artifact-signers-file")
        .arg(&pub_key)
        .arg("-A")
        .arg("1");
    let output = cmd.output().unwrap();
    assert!(output.status.success());

    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(
        stdout.ends_with("}\n"),
        "stdout should end with '}}\\n', got trailing bytes: {:?}",
        &stdout[stdout.len().saturating_sub(4)..]
    );
    assert!(
        !stdout.ends_with("}\n\n"),
        "stdout has a double trailing newline — `print!` was reverted to `println!` at signers_file.rs:148. Got trailing bytes: {:?}",
        &stdout[stdout.len().saturating_sub(4)..]
    );
}

/// `--json` without `-o` must not write a file, but print the JSON
/// overview. In this overview, `output_file` is null and `digest` is the
/// sha512 of the `signers_config` content.
#[test]
fn json_without_output_file_prints_signers_config() {
    let pub_key = fixtures_pub_key(0);
    let temp_dir = TempDir::new().unwrap();

    let mut cmd = assert_cmd::cargo_bin_cmd!("asfaload-cli");
    cmd.current_dir(temp_dir.path())
        .arg("new-signers-file")
        .arg("--artifact-signers-file")
        .arg(&pub_key)
        .arg("-A")
        .arg("1")
        .arg("--json");
    let output = cmd.output().unwrap();
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8(output.stdout).unwrap();
    let json: serde_json::Value =
        serde_json::from_str(&stdout).expect("stdout should be valid JSON");

    assert!(
        json["output_file"].is_null(),
        "output_file should be null without -o, got: {}",
        json["output_file"]
    );

    let signers_config = json["signers_config"]
        .as_str()
        .expect("signers_config field should be a string");
    let parsed: serde_json::Value =
        serde_json::from_str(signers_config).expect("signers_config should hold valid JSON");
    assert!(
        parsed.is_object(),
        "signers_config should hold a JSON object, got: {}",
        parsed
    );

    let expected_digest = format!(
        "sha512:{}",
        hex::encode(Sha512::digest(signers_config.as_bytes()))
    );
    assert_eq!(
        json["digest"].as_str(),
        Some(expected_digest.as_str()),
        "digest should be the sha512 of signers_config"
    );

    let written_files: Vec<_> = fs::read_dir(temp_dir.path()).unwrap().collect();
    assert!(
        written_files.is_empty(),
        "no file should be written without -o, found: {:?}",
        written_files
    );
}

/// With `-o` and no `--json`, the human output must show the sha512 of the
/// written file under the "Digest" heading, and use it in the suggested
/// register-repo command, together with the required secret key flag.
#[test]
fn digest_printed_and_correct_in_human_output() {
    let pub_key = fixtures_pub_key(0);
    let temp_dir = TempDir::new().unwrap();
    let output_file = temp_dir.path().join("signers.json");

    let mut cmd = assert_cmd::cargo_bin_cmd!("asfaload-cli");
    cmd.arg("new-signers-file")
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

    let file_bytes = fs::read(&output_file).unwrap();
    let hash = Sha512::digest(&file_bytes);
    let expected = format!("sha512:{}", hex::encode(hash));
    assert!(
        stdout.contains(&format!("Digest\n  {expected}\n")),
        "stdout should contain the sha512 digest '{}' under the Digest heading, got: {}",
        expected,
        stdout
    );
    // Long flags only, and the parts to fill in at the end.
    let expected_hint = format!(
        " register-repo \\\n       --digest {expected} \\\n       --secret-key <secret-key> <url>\n"
    );
    assert!(
        stdout.contains(&expected_hint),
        "stdout should contain the register-repo hint '{}', got: {}",
        expected_hint,
        stdout
    );
}

/// `-o` pointing at an existing file must fail with a clear message.
/// Guards the early `exists()` check at signers_file.rs and the
/// `create_new` TOCTOU hardening introduced in commit 547c80bd.
#[test]
fn output_file_refuses_overwrite() {
    let pub_key = fixtures_pub_key(0);
    let temp_dir = TempDir::new().unwrap();
    let output_file = temp_dir.path().join("existing.json");

    // Pre-create the file so -o must refuse
    fs::write(&output_file, "pre-existing content").unwrap();

    let mut cmd = assert_cmd::cargo_bin_cmd!("asfaload-cli");
    cmd.arg("new-signers-file")
        .arg("--artifact-signers-file")
        .arg(&pub_key)
        .arg("-A")
        .arg("1")
        .arg("-o")
        .arg(&output_file);
    let output = cmd.output().unwrap();

    assert!(
        !output.status.success(),
        "command should have refused to overwrite, but succeeded"
    );

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("already exists, refusing to overwrite"),
        "stderr should mention 'already exists, refusing to overwrite', got: {}",
        stderr
    );

    // The pre-existing file must be untouched
    let content = fs::read_to_string(&output_file).unwrap();
    assert_eq!(
        content, "pre-existing content",
        "existing file was modified despite the refusal"
    );
}
