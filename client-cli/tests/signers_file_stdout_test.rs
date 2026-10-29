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

/// `--json` without `-o` must be rejected at parse time by clap's
/// `required_if_eq("json", "true")` guard on `output_file`
/// (client-cli/src/cli.rs:165). Exit code 2 is clap's parse-failure
/// code. This confirms the `(None, true)` handler arm in
/// signers_file.rs
#[test]
fn json_without_output_file_rejected_by_clap() {
    let pub_key = fixtures_pub_key(0);

    let mut cmd = assert_cmd::cargo_bin_cmd!("asfaload-cli");
    cmd.arg("new-signers-file")
        .arg("--artifact-signers-file")
        .arg(&pub_key)
        .arg("-A")
        .arg("1")
        .arg("--json");
    let output = cmd.output().unwrap();

    // clap parse failure exits with code 2
    assert!(
        !output.status.success(),
        "command should have failed, but succeeded. stdout: {}, stderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let code = output.status.code().unwrap();
    assert_eq!(
        code, 2,
        "expected clap parse-failure exit code 2, got {}",
        code
    );

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("--output-file"),
        "clap error should mention --output-file, got stderr: {}",
        stderr
    );

    // stdout must be empty (nothing printed before the parse error)
    assert!(
        output.stdout.is_empty(),
        "stdout should be empty on parse failure, got: {}",
        String::from_utf8_lossy(&output.stdout)
    );
}

/// With `-o` and no `--json`, the human output must include a "Generated
/// file's digest:" line whose value is the sha512 of the written file.
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

    assert!(
        stdout.contains("Generated file's digest:"),
        "stdout should contain 'Generated file's digest:', got: {}",
        stdout
    );

    let file_bytes = fs::read(&output_file).unwrap();
    let hash = Sha512::digest(&file_bytes);
    let expected = format!("sha512:{}", hex::encode(hash));
    assert!(
        stdout.contains(&expected),
        "stdout should contain the sha512 digest '{}', got: {}",
        expected,
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
