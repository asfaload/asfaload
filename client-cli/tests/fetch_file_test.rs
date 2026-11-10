use base64::{Engine, engine::general_purpose::STANDARD_NO_PAD};
use tempfile::TempDir;

const FILE_PATH: &str = "github.com/owner/repo/v1.0.0/asfaload.index.json";
const TEXT_CONTENT: &[u8] = b"{\"files\":[]}\n";
// Not valid UTF-8, to make sure binary content is handled.
const BINARY_CONTENT: &[u8] = &[0x00, 0xff, 0xfe, 0x41, 0x0a];

fn mock_file(server: &mut mockito::Server, content: &[u8]) -> mockito::Mock {
    server
        .mock("GET", format!("/v1/files/{}", FILE_PATH).as_str())
        .with_status(200)
        .with_body(content)
        .create()
}

fn fetch_file_cmd(server: &mockito::Server) -> assert_cmd::Command {
    let mut cmd = assert_cmd::cargo_bin_cmd!("asfaload-cli");
    cmd.arg("fetch-file")
        .arg(FILE_PATH)
        .arg("--backend-url")
        .arg(server.url());
    cmd
}

#[test]
fn fetch_file_prints_exact_content_to_stdout() {
    let mut server = mockito::Server::new();
    let _m = mock_file(&mut server, TEXT_CONTENT);

    let output = fetch_file_cmd(&server).output().unwrap();

    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(output.stdout, TEXT_CONTENT);
}

#[test]
fn fetch_file_with_output_writes_binary_file_and_nothing_to_stdout() {
    let mut server = mockito::Server::new();
    let _m = mock_file(&mut server, BINARY_CONTENT);
    let temp_dir = TempDir::new().unwrap();
    let output_path = temp_dir.path().join("fetched.bin");

    let output = fetch_file_cmd(&server)
        .arg("-o")
        .arg(&output_path)
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(output.stdout.is_empty());
    assert_eq!(std::fs::read(&output_path).unwrap(), BINARY_CONTENT);
}

#[test]
fn fetch_file_json_contains_base64_content() {
    let mut server = mockito::Server::new();
    let _m = mock_file(&mut server, BINARY_CONTENT);

    let output = fetch_file_cmd(&server).arg("--json").output().unwrap();

    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let json: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("stdout should be valid JSON");
    let decoded = STANDARD_NO_PAD
        .decode(json["base64_content"].as_str().unwrap())
        .unwrap();
    assert_eq!(decoded, BINARY_CONTENT);
}

#[test]
fn fetch_file_does_not_overwrite_existing_file() {
    let mut server = mockito::Server::new();
    let _m = mock_file(&mut server, BINARY_CONTENT);
    let temp_dir = TempDir::new().unwrap();
    let output_path = temp_dir.path().join("existing.bin");
    std::fs::write(&output_path, b"keep me").unwrap();

    fetch_file_cmd(&server)
        .arg("-o")
        .arg(&output_path)
        .assert()
        .failure();

    assert_eq!(std::fs::read(&output_path).unwrap(), b"keep me");
}
