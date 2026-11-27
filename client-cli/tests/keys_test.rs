use std::path::Path;

use serde_json::{Value, json};
use tempfile::TempDir;

fn fixture_pub_key(n: usize) -> String {
    std::fs::read_to_string(test_helpers::fixtures_pub_key(n))
        .unwrap()
        .trim()
        .to_owned()
}

// Keys dir with the key pair key_0, the secret key key_1 without .pub file, the public key
// key_3.pub without secret key, and an unrelated file. The config gives an alias to the public
// key of key_0 and to another key.
fn setup() -> (TempDir, std::path::PathBuf, std::path::PathBuf) {
    let temp_dir = TempDir::new().unwrap();
    let keys_dir = temp_dir.path().join("keys");
    std::fs::create_dir(&keys_dir).unwrap();
    for file in ["key_0", "key_0.pub", "key_1", "key_3.pub"] {
        std::fs::copy(
            test_helpers::fixtures_keys_dir().join(file),
            keys_dir.join(file),
        )
        .unwrap();
    }
    std::fs::write(keys_dir.join("notes.txt"), "not a key").unwrap();
    let config_path = temp_dir.path().join("config.toml");
    std::fs::write(
        &config_path,
        format!(
            "[aliases]\nme = \"{}\"\nalice = \"{}\"\n",
            fixture_pub_key(0),
            fixture_pub_key(2)
        ),
    )
    .unwrap();
    (temp_dir, keys_dir, config_path)
}

fn keys_cmd(keys_dir: &Path, config_path: &Path) -> assert_cmd::Command {
    let mut cmd = assert_cmd::cargo_bin_cmd!("asfaload-cli");
    cmd.arg("keys")
        .arg("--keys-dir")
        .arg(keys_dir)
        .arg("--config-file")
        .arg(config_path);
    cmd
}

#[test]
fn keys_lists_secret_keys_and_aliases() -> anyhow::Result<()> {
    let (_temp_dir, keys_dir, config_path) = setup();

    let output = keys_cmd(&keys_dir, &config_path)
        .assert()
        .success()
        .get_output()
        .clone();

    let expected = format!(
        "Local keys\nKeys in your keys dir and config file. To use a key file in a different location, give its path to the command.\n\nKeys dir: {}\nConfig file: {}\n\nMy secret keys:\n  key_0\n  key_1\n\nMy public keys:\n  key_0.pub  ({})\n  key_3.pub  ({})\n\nPublic key aliases:\n  alice  {}\n  me     {}\n",
        keys_dir.display(),
        config_path.display(),
        fixture_pub_key(0),
        fixture_pub_key(3),
        fixture_pub_key(2),
        fixture_pub_key(0)
    );
    assert_eq!(String::from_utf8(output.stdout)?, expected);
    Ok(())
}

#[test]
fn keys_json_output() -> anyhow::Result<()> {
    let (_temp_dir, keys_dir, config_path) = setup();

    let output = keys_cmd(&keys_dir, &config_path)
        .arg("--json")
        .assert()
        .success()
        .get_output()
        .clone();

    let listed: Value = serde_json::from_slice(&output.stdout)?;
    let expected = json!({
        "keys_dir": keys_dir,
        "config_file": config_path,
        "secret_keys": ["key_0", "key_1"],
        "public_key_aliases": [
            {"alias": "alice", "public_key": fixture_pub_key(2)},
            {"alias": "me", "public_key": fixture_pub_key(0)},
        ],
        "my_public_keys": [
            {"file_name": "key_0.pub", "public_key": fixture_pub_key(0)},
            {"file_name": "key_3.pub", "public_key": fixture_pub_key(3)},
        ],
    });
    assert_eq!(listed, expected);
    Ok(())
}
