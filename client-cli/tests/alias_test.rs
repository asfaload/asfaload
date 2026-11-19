use std::{
    collections::{BTreeMap, HashMap},
    path::Path,
};

use client_lib::config::{CliConfig, load_config, save_config};
use features_lib::{AsfaloadPublicKeyTrait, AsfaloadPublicKeys};
use predicates::str::contains;
use tempfile::TempDir;
use test_helpers::TestKeys;

fn alias_cmd(config_path: &Path) -> assert_cmd::Command {
    let mut cmd = assert_cmd::cargo_bin_cmd!("asfaload-cli");
    cmd.arg("alias").arg("--config-file").arg(config_path);
    cmd
}

fn write_config(config_path: &Path, aliases: &[(&str, &AsfaloadPublicKeys)]) -> anyhow::Result<()> {
    let mut config = CliConfig::default();
    for (name, key) in aliases {
        config.add_alias(key, name, false)?;
    }
    save_config(&config, Some(config_path))?;
    Ok(())
}

fn aliases_in(config_path: &Path) -> anyhow::Result<BTreeMap<String, AsfaloadPublicKeys>> {
    Ok(load_config(Some(config_path))?.aliases().clone())
}

#[test]
fn alias_without_args_lists_all_aliases() -> anyhow::Result<()> {
    let temp_dir = TempDir::new()?;
    let config_path = temp_dir.path().join("config.toml");
    let keys = TestKeys::new(2);
    let (key_0, key_1) = (keys.pub_key(0).unwrap(), keys.pub_key(1).unwrap());
    write_config(&config_path, &[("alice", key_0), ("bob", key_1)])?;

    let output = alias_cmd(&config_path)
        .assert()
        .success()
        .get_output()
        .clone();

    let expected = format!(
        "alice = \"{}\"\nbob = \"{}\"\n",
        key_0.to_base64(),
        key_1.to_base64()
    );
    assert_eq!(String::from_utf8(output.stdout)?, expected);
    Ok(())
}

#[test]
fn alias_lookups_without_config_do_not_create_it() -> anyhow::Result<()> {
    let temp_dir = TempDir::new()?;
    let config_path = temp_dir.path().join("config.toml");

    let keys = TestKeys::new(1);
    let key_0 = keys.pub_key(0).unwrap();

    let output = alias_cmd(&config_path)
        .assert()
        .success()
        .get_output()
        .clone();
    assert_eq!(String::from_utf8(output.stdout)?.trim(), "");
    alias_cmd(&config_path).arg("alice").assert().failure();
    alias_cmd(&config_path)
        .arg("--key")
        .arg(key_0.to_base64())
        .assert()
        .failure();

    assert!(!config_path.exists());
    Ok(())
}

#[test]
fn alias_lookup_by_name_or_key() -> anyhow::Result<()> {
    let keys = TestKeys::new(2);
    let (key_0, key_1) = (keys.pub_key(0).unwrap(), keys.pub_key(1).unwrap());
    let found = format!("alice = \"{}\"", key_0.to_base64());
    // (description, arguments, expected stdout on success or stderr part on failure)
    let cases: Vec<(&str, Vec<String>, Result<String, String>)> = vec![
        (
            "existing name",
            vec!["alice".to_string()],
            Ok(found.clone()),
        ),
        (
            "unknown name",
            vec!["carol".to_string()],
            Err("Alias carol does not exist in config".to_string()),
        ),
        (
            "key with alias",
            vec!["--key".to_string(), key_0.to_base64()],
            Ok(found),
        ),
        (
            "key without alias",
            vec!["--key".to_string(), key_1.to_base64()],
            Err(format!(
                "No alias exists in config for key {}",
                key_1.to_base64()
            )),
        ),
    ];
    for (description, args, expected) in cases {
        let temp_dir = TempDir::new()?;
        let config_path = temp_dir.path().join("config.toml");
        write_config(&config_path, &[("alice", key_0)])?;

        let assert = alias_cmd(&config_path).args(&args).assert();

        match expected {
            Ok(stdout) => {
                let output = assert.success().get_output().clone();
                assert_eq!(
                    String::from_utf8(output.stdout)?.trim_end(),
                    stdout,
                    "case {description}"
                );
            }
            Err(stderr) => {
                assert.failure().stderr(contains(stderr));
            }
        }
        let unchanged = BTreeMap::from([("alice".to_string(), key_0.clone())]);
        assert_eq!(aliases_in(&config_path)?, unchanged, "case {description}");
    }
    Ok(())
}

#[test]
fn alias_with_name_and_key_adds_alias() -> anyhow::Result<()> {
    let temp_dir = TempDir::new()?;
    let config_path = temp_dir.path().join("config.toml");
    let keys = TestKeys::new(2);
    let (key_0, key_1) = (keys.pub_key(0).unwrap(), keys.pub_key(1).unwrap());
    write_config(&config_path, &[("alice", key_0)])?;

    alias_cmd(&config_path)
        .arg("bob")
        .arg("--key")
        .arg(key_1.to_base64())
        .assert()
        .success()
        .stdout(contains(format!(
            "Alias bob added for {}",
            key_1.to_base64()
        )));

    let expected = BTreeMap::from([
        ("alice".to_string(), key_0.clone()),
        ("bob".to_string(), key_1.clone()),
    ]);
    assert_eq!(aliases_in(&config_path)?, expected);
    Ok(())
}

#[test]
fn alias_rename_of_key_requires_force() -> anyhow::Result<()> {
    let temp_dir = TempDir::new()?;
    let config_path = temp_dir.path().join("config.toml");
    let keys = TestKeys::new(1);
    let key_0 = keys.pub_key(0).unwrap();
    write_config(&config_path, &[("alice", key_0)])?;

    alias_cmd(&config_path)
        .arg("alicia")
        .arg("--key")
        .arg(key_0.to_base64())
        .assert()
        .failure()
        .stderr(contains("Refusing to overwrite existing alias"));
    let unchanged = BTreeMap::from([("alice".to_string(), key_0.clone())]);
    assert_eq!(aliases_in(&config_path)?, unchanged);

    alias_cmd(&config_path)
        .arg("alicia")
        .arg("--key")
        .arg(key_0.to_base64())
        .arg("--force")
        .assert()
        .success();
    let renamed = BTreeMap::from([("alicia".to_string(), key_0.clone())]);
    assert_eq!(aliases_in(&config_path)?, renamed);
    Ok(())
}

#[test]
fn alias_with_invalid_key_fails() -> anyhow::Result<()> {
    let keys = TestKeys::new(1);
    let key_0 = keys.pub_key(0).unwrap();
    // (description, arguments)
    let cases = vec![
        ("lookup", vec!["--key", "not-a-key"]),
        ("add", vec!["bob", "--key", "not-a-key"]),
    ];
    for (description, args) in cases {
        let temp_dir = TempDir::new()?;
        let config_path = temp_dir.path().join("config.toml");
        write_config(&config_path, &[("alice", key_0)])?;

        alias_cmd(&config_path).args(&args).assert().failure();

        let unchanged = BTreeMap::from([("alice".to_string(), key_0.clone())]);
        assert_eq!(aliases_in(&config_path)?, unchanged, "case {description}");
    }
    Ok(())
}

#[test]
fn alias_json_output() -> anyhow::Result<()> {
    let keys = TestKeys::new(3);
    let (key_0, key_1, key_2) = (
        keys.pub_key(0).unwrap(),
        keys.pub_key(1).unwrap(),
        keys.pub_key(2).unwrap(),
    );
    let existing = vec![("alice", key_0), ("bob", key_1)];
    // (description, aliases in config, arguments, expected aliases in the output)
    type Aliases<'a> = Vec<(&'a str, &'a AsfaloadPublicKeys)>;
    let cases: Vec<(&str, Aliases, Vec<String>, Aliases)> = vec![
        ("list all", existing.clone(), vec![], existing.clone()),
        ("list without config", vec![], vec![], vec![]),
        (
            "lookup by name",
            existing.clone(),
            vec!["bob".to_string()],
            vec![("bob", key_1)],
        ),
        (
            "lookup by key",
            existing.clone(),
            vec!["--key".to_string(), key_0.to_base64()],
            vec![("alice", key_0)],
        ),
        (
            "add",
            existing.clone(),
            vec!["carol".to_string(), "--key".to_string(), key_2.to_base64()],
            vec![("carol", key_2)],
        ),
    ];
    for (description, config_aliases, args, expected) in cases {
        let temp_dir = TempDir::new()?;
        let config_path = temp_dir.path().join("config.toml");
        if !config_aliases.is_empty() {
            write_config(&config_path, &config_aliases)?;
        }

        let output = alias_cmd(&config_path)
            .args(&args)
            .arg("--json")
            .assert()
            .success()
            .get_output()
            .clone();

        let listed: HashMap<String, String> = serde_json::from_slice(&output.stdout)?;
        let expected: HashMap<String, String> = expected
            .into_iter()
            .map(|(name, key)| (name.to_string(), key.to_base64()))
            .collect();
        assert_eq!(listed, expected, "case {description}");
    }
    Ok(())
}

#[test]
fn alias_json_errors() -> anyhow::Result<()> {
    let keys = TestKeys::new(2);
    let (key_0, key_1) = (keys.pub_key(0).unwrap(), keys.pub_key(1).unwrap());
    // (description, arguments, expected part of the error message)
    let cases: Vec<(&str, Vec<String>, String)> = vec![
        (
            "unknown name",
            vec!["carol".to_string()],
            "Alias carol does not exist in config".to_string(),
        ),
        (
            "key without alias",
            vec!["--key".to_string(), key_1.to_base64()],
            format!("No alias exists in config for key {}", key_1.to_base64()),
        ),
        (
            "rename without force",
            vec!["alicia".to_string(), "--key".to_string(), key_0.to_base64()],
            "Refusing to overwrite existing alias".to_string(),
        ),
        (
            "invalid key",
            vec!["--key".to_string(), "not-a-key".to_string()],
            "Key parse error".to_string(),
        ),
    ];
    for (description, args, expected) in cases {
        let temp_dir = TempDir::new()?;
        let config_path = temp_dir.path().join("config.toml");
        write_config(&config_path, &[("alice", key_0)])?;

        let output = alias_cmd(&config_path)
            .args(&args)
            .arg("--json")
            .assert()
            .failure()
            .get_output()
            .clone();

        let error: serde_json::Value = serde_json::from_slice(&output.stderr)?;
        let message = error["error"].as_str().unwrap_or_default();
        assert!(
            message.contains(&expected),
            "case {description}: unexpected error {message:?}"
        );
    }
    Ok(())
}

#[test]
fn alias_delete_by_name_key_or_pair() -> anyhow::Result<()> {
    let keys = TestKeys::new(2);
    let (key_0, key_1) = (keys.pub_key(0).unwrap(), keys.pub_key(1).unwrap());
    // (description, arguments)
    let cases: Vec<(&str, Vec<String>)> = vec![
        ("by name", vec!["alice".to_string()]),
        ("by key", vec!["--key".to_string(), key_0.to_base64()]),
        (
            "by pair",
            vec!["alice".to_string(), "--key".to_string(), key_0.to_base64()],
        ),
    ];
    for (description, args) in cases {
        let temp_dir = TempDir::new()?;
        let config_path = temp_dir.path().join("config.toml");
        write_config(&config_path, &[("alice", key_0), ("bob", key_1)])?;

        alias_cmd(&config_path)
            .args(&args)
            .arg("--delete")
            .assert()
            .success()
            .stdout(contains(format!(
                "Alias alice deleted for {}",
                key_0.to_base64()
            )));

        let remaining = BTreeMap::from([("bob".to_string(), key_1.clone())]);
        assert_eq!(aliases_in(&config_path)?, remaining, "case {description}");
    }
    Ok(())
}

#[test]
fn alias_delete_rejects_invalid_arguments() -> anyhow::Result<()> {
    let keys = TestKeys::new(2);
    let (key_0, key_1) = (keys.pub_key(0).unwrap(), keys.pub_key(1).unwrap());
    // (description, arguments, expected part of the error message)
    let cases: Vec<(&str, Vec<String>, String)> = vec![
        (
            "without name or key",
            vec!["--delete".to_string()],
            "required arguments were not provided".to_string(),
        ),
        (
            "with force",
            vec![
                "alice".to_string(),
                "--delete".to_string(),
                "--force".to_string(),
            ],
            "cannot be used with".to_string(),
        ),
        (
            "pair with other key",
            vec![
                "alice".to_string(),
                "--key".to_string(),
                key_1.to_base64(),
                "--delete".to_string(),
            ],
            format!("Alias alice is not an alias for key {}", key_1.to_base64()),
        ),
    ];
    for (description, args, expected) in cases {
        let temp_dir = TempDir::new()?;
        let config_path = temp_dir.path().join("config.toml");
        write_config(&config_path, &[("alice", key_0)])?;

        alias_cmd(&config_path)
            .args(&args)
            .assert()
            .failure()
            .stderr(contains(expected));

        let unchanged = BTreeMap::from([("alice".to_string(), key_0.clone())]);
        assert_eq!(aliases_in(&config_path)?, unchanged, "case {description}");
    }
    Ok(())
}
