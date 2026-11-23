// Binary-level tests of the manual pages. stdout is a pipe here, so the output is plain text.

use predicates::str::contains;

fn cli() -> assert_cmd::Command {
    assert_cmd::cargo_bin_cmd!("asfaload-cli")
}

fn stdout_of(args: &[&str]) -> String {
    let output = cli().args(args).output().unwrap();
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).unwrap()
}

#[test]
fn manual_flag_shows_the_page_of_the_subcommand() {
    let text = stdout_of(&["download", "--manual"]);
    assert!(text.contains("asfaload-cli download"), "{text}");
    assert!(
        text.contains("Download a file and verify its signatures"),
        "{text}"
    );
    assert!(!text.contains("]("), "raw link in: {text}");
    assert!(!text.contains('\x1b'), "escape code in: {text}");
}

#[test]
fn manual_flag_without_subcommand_shows_the_index() {
    let text = stdout_of(&["--manual"]);
    assert!(text.contains("Reference for all"), "{text}");
}

#[test]
fn manual_flag_ignores_values_from_environment_variables() {
    let output = cli()
        .env("ASFALOAD_BACKEND_URL", "http://127.0.0.1:9")
        .args(["download", "--manual"])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn manual_flag_with_unknown_subcommand_reports_the_error() {
    cli()
        .args(["downlaod", "--manual"])
        .assert()
        .code(2)
        .stderr(contains("unrecognized subcommand"));
}

#[test]
fn help_lists_the_manual_flag() {
    let text = stdout_of(&["download", "--help"]);
    assert!(text.contains("--manual"), "{text}");
}

#[test]
fn manual_subcommand_shows_the_same_page_as_the_flag() {
    assert_eq!(
        stdout_of(&["manual", "download"]),
        stdout_of(&["download", "--manual"])
    );
}

#[test]
fn manual_subcommand_without_command_shows_the_index() {
    assert_eq!(stdout_of(&["manual"]), stdout_of(&["--manual"]));
}

#[test]
fn manual_subcommand_with_unknown_command_fails() {
    cli()
        .args(["manual", "downlaod"])
        .assert()
        .code(2)
        .stderr(contains("invalid value"));
}
