use predicates::prelude::*;
use serde_json::Value;

const SHA256_HASH: &str = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
const SHA256_OTHER: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const INDEX_PATH: &str = "project/releases/v0.5/asfaload.index.json";

fn index_json(source_url: &str, hash: &str) -> String {
    format!(
        concat!(
            r#"{{"mirroredOn":"2026-09-12T12:00:00Z","publishedOn":"2026-09-12T12:00:00Z","#,
            r#""version":1,"publishedFiles":[{{"fileName":"file-a.tar.gz","#,
            r#""algo":"Sha256","source":"{}","hash":"{}"}}]}}"#
        ),
        source_url, hash
    )
}

#[test]
fn check_index_help_lists_flags() {
    let mut cmd = assert_cmd::cargo_bin_cmd!("asfaload-cli");
    cmd.arg("check-index").arg("--help");
    cmd.assert()
        .success()
        .stdout(predicate::str::contains("--backend-url"))
        .stdout(predicate::str::contains("--json"));
}
