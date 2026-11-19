use std::collections::HashMap;
use std::path::PathBuf;

use client_lib::config::{CliConfig, load_config_or_default, save_config};
use features_lib::{AsfaloadPublicKeyTrait, AsfaloadPublicKeys};

use crate::error::ClientCliError;

// Output of a single alias, as used for lookups, additions and deletions.
fn format_alias(
    alias: &str,
    key: &AsfaloadPublicKeys,
    json: bool,
) -> Result<String, ClientCliError> {
    let key = key.to_base64();
    if json {
        Ok(serde_json::to_string(&HashMap::from([(alias, key)]))?)
    } else {
        Ok(format!("{} = {}", alias, key))
    }
}

pub fn list_aliases(
    config_file: &Option<PathBuf>,
    name: &Option<String>,
    json: bool,
) -> Result<String, ClientCliError> {
    let config = load_config_or_default(config_file.as_deref())?;
    let aliases = config.aliases();

    let output = match name {
        Some(alias) => match config.get_key(alias) {
            Some(k) => format_alias(alias, k, json)?,
            None => return Err(ClientCliError::AliasNotFound(alias.clone())),
        },
        None if json => serde_json::to_string(aliases)?,
        None => toml::to_string(aliases).map_err(|e| {
            ClientCliError::ConfigError(format!(
                "Got a problem serialising the aliases for output: {e}"
            ))
        })?,
    };

    Ok(output.clone())
}

pub fn display_key(
    config_file: &Option<PathBuf>,
    key: &AsfaloadPublicKeys,
    json: bool,
) -> Result<String, ClientCliError> {
    let config = load_config_or_default(config_file.as_deref())?;
    let output = match config.get_alias(key) {
        Some(alias) => format_alias(alias, key, json)?,
        None => return Err(ClientCliError::NoAliasForKey(key.to_base64())),
    };

    Ok(output.clone())
}

pub fn add_alias(
    config_file: &Option<PathBuf>,
    key: &AsfaloadPublicKeys,
    name: &str,
    force: bool,
    json: bool,
) -> Result<String, ClientCliError> {
    let mut config = load_config_or_default(config_file.as_deref())?;
    config.add_alias(key, name, force)?;
    save_config(&config, config_file.as_deref())?;
    if json {
        format_alias(name, key, json)
    } else {
        Ok(format!("Alias {} added for {}", name, key.to_base64()))
    }
}

fn remove_and_save(
    mut config: CliConfig,
    config_file: &Option<PathBuf>,
    name: &str,
    json: bool,
) -> Result<String, ClientCliError> {
    let key = config
        .remove_alias(name)
        .ok_or_else(|| ClientCliError::AliasNotFound(name.to_string()))?;
    save_config(&config, config_file.as_deref())?;
    if json {
        format_alias(name, &key, json)
    } else {
        Ok(format!("Alias {} deleted for {}", name, key.to_base64()))
    }
}

pub fn delete_alias(
    config_file: &Option<PathBuf>,
    name: &str,
    json: bool,
) -> Result<String, ClientCliError> {
    let config = load_config_or_default(config_file.as_deref())?;
    remove_and_save(config, config_file, name, json)
}

pub fn delete_alias_of_key(
    config_file: &Option<PathBuf>,
    key: &AsfaloadPublicKeys,
    json: bool,
) -> Result<String, ClientCliError> {
    let config = load_config_or_default(config_file.as_deref())?;
    let name = config
        .get_alias(key)
        .ok_or_else(|| ClientCliError::NoAliasForKey(key.to_base64()))?
        .to_string();
    remove_and_save(config, config_file, &name, json)
}

pub fn delete_alias_pair(
    config_file: &Option<PathBuf>,
    key: &AsfaloadPublicKeys,
    name: &str,
    json: bool,
) -> Result<String, ClientCliError> {
    let config = load_config_or_default(config_file.as_deref())?;
    match config.get_key(name) {
        None => return Err(ClientCliError::AliasNotFound(name.to_string())),
        Some(k) if k != key => {
            return Err(ClientCliError::AliasNotForKey(
                name.to_string(),
                key.to_base64(),
            ));
        }
        Some(_) => {}
    }
    remove_and_save(config, config_file, name, json)
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use client_lib::config::{CliConfig, load_config};
    use tempfile::TempDir;
    use test_helpers::TestKeys;

    use super::*;

    fn write_config(
        config_path: &Path,
        aliases: &[(&str, &AsfaloadPublicKeys)],
    ) -> anyhow::Result<()> {
        let mut config = CliConfig::default();
        for (name, key) in aliases {
            config.add_alias(key, name, false)?;
        }
        save_config(&config, Some(config_path))?;
        Ok(())
    }

    #[test]
    fn list_aliases_without_name_lists_all() -> anyhow::Result<()> {
        let temp_dir = TempDir::new()?;
        let config_path = Some(temp_dir.path().join("config.toml"));
        let keys = TestKeys::new(2);
        let (key_0, key_1) = (keys.pub_key(0).unwrap(), keys.pub_key(1).unwrap());
        write_config(
            config_path.as_deref().unwrap(),
            &[("alice", key_0), ("bob", key_1)],
        )?;

        let output = list_aliases(&config_path, &None, false)?;

        let expected = format!(
            "alice = \"{}\"\nbob = \"{}\"\n",
            key_0.to_base64(),
            key_1.to_base64()
        );
        assert_eq!(output, expected);
        Ok(())
    }

    #[test]
    fn list_aliases_with_name() -> anyhow::Result<()> {
        let temp_dir = TempDir::new()?;
        let config_path = Some(temp_dir.path().join("config.toml"));
        let keys = TestKeys::new(1);
        let key_0 = keys.pub_key(0).unwrap();
        write_config(config_path.as_deref().unwrap(), &[("alice", key_0)])?;

        let output = list_aliases(&config_path, &Some("alice".to_string()), false)?;
        assert_eq!(output, format!("alice = {}", key_0.to_base64()));

        match list_aliases(&config_path, &Some("carol".to_string()), false) {
            Err(ClientCliError::AliasNotFound(name)) => assert_eq!(name, "carol"),
            result => panic!("expected AliasNotFound, got {result:?}"),
        }
        Ok(())
    }

    #[test]
    fn display_key_shows_alias_of_key() -> anyhow::Result<()> {
        let temp_dir = TempDir::new()?;
        let config_path = Some(temp_dir.path().join("config.toml"));
        let keys = TestKeys::new(2);
        let (key_0, key_1) = (keys.pub_key(0).unwrap(), keys.pub_key(1).unwrap());
        write_config(config_path.as_deref().unwrap(), &[("alice", key_0)])?;

        let output = display_key(&config_path, key_0, false)?;
        assert_eq!(output, format!("alice = {}", key_0.to_base64()));

        match display_key(&config_path, key_1, false) {
            Err(ClientCliError::NoAliasForKey(key)) => assert_eq!(key, key_1.to_base64()),
            result => panic!("expected NoAliasForKey, got {result:?}"),
        }
        Ok(())
    }

    #[test]
    fn lookups_do_not_create_missing_config() -> anyhow::Result<()> {
        let temp_dir = TempDir::new()?;
        let path = temp_dir.path().join("config.toml");
        let config_path = Some(path.clone());
        let keys = TestKeys::new(1);
        let key_0 = keys.pub_key(0).unwrap();

        assert_eq!(list_aliases(&config_path, &None, false)?.trim(), "");
        assert!(list_aliases(&config_path, &Some("alice".to_string()), false).is_err());
        assert!(display_key(&config_path, key_0, false).is_err());

        assert!(!path.exists());
        Ok(())
    }

    #[test]
    fn add_alias_saves_alias() -> anyhow::Result<()> {
        let temp_dir = TempDir::new()?;
        let config_path = Some(temp_dir.path().join("config.toml"));
        let keys = TestKeys::new(1);
        let key_0 = keys.pub_key(0).unwrap();

        let output = add_alias(&config_path, key_0, "alice", false, false)?;

        assert_eq!(
            output,
            format!("Alias alice added for {}", key_0.to_base64())
        );
        let loaded = load_config(config_path.as_deref())?;
        assert_eq!(loaded.get_key("alice"), Some(key_0));
        Ok(())
    }

    type AliasCall<'a> = Box<dyn Fn(&Option<PathBuf>) -> Result<String, ClientCliError> + 'a>;

    #[test]
    fn delete_removes_only_the_requested_alias() -> anyhow::Result<()> {
        let keys = TestKeys::new(2);
        let (key_0, key_1) = (keys.pub_key(0).unwrap(), keys.pub_key(1).unwrap());
        // (description, call)
        let cases: Vec<(&str, AliasCall<'_>)> = vec![
            (
                "by name",
                Box::new(|path| delete_alias(path, "alice", false)),
            ),
            (
                "by key",
                Box::new(|path| delete_alias_of_key(path, key_0, false)),
            ),
            (
                "by pair",
                Box::new(|path| delete_alias_pair(path, key_0, "alice", false)),
            ),
        ];
        for (description, call) in cases {
            let temp_dir = TempDir::new()?;
            let config_path = Some(temp_dir.path().join("config.toml"));
            write_config(
                config_path.as_deref().unwrap(),
                &[("alice", key_0), ("bob", key_1)],
            )?;

            let output = call(&config_path)?;

            assert_eq!(
                output,
                format!("Alias alice deleted for {}", key_0.to_base64()),
                "case {description}"
            );
            let loaded = load_config(config_path.as_deref())?;
            assert_eq!(loaded.get_key("alice"), None, "case {description}");
            assert_eq!(loaded.get_key("bob"), Some(key_1), "case {description}");
        }
        Ok(())
    }

    #[test]
    fn delete_errors_leave_config_unchanged() -> anyhow::Result<()> {
        let keys = TestKeys::new(2);
        let (key_0, key_1) = (keys.pub_key(0).unwrap(), keys.pub_key(1).unwrap());
        // (description, call, expected error)
        let cases: Vec<(&str, AliasCall<'_>, ClientCliError)> = vec![
            (
                "unknown name",
                Box::new(|path| delete_alias(path, "carol", false)),
                ClientCliError::AliasNotFound("carol".to_string()),
            ),
            (
                "key without alias",
                Box::new(|path| delete_alias_of_key(path, key_1, false)),
                ClientCliError::NoAliasForKey(key_1.to_base64()),
            ),
            (
                "pair with unknown name",
                Box::new(|path| delete_alias_pair(path, key_0, "carol", false)),
                ClientCliError::AliasNotFound("carol".to_string()),
            ),
            (
                "pair with other key",
                Box::new(|path| delete_alias_pair(path, key_1, "alice", false)),
                ClientCliError::AliasNotForKey("alice".to_string(), key_1.to_base64()),
            ),
        ];
        for (description, call, expected) in cases {
            let temp_dir = TempDir::new()?;
            let path = temp_dir.path().join("config.toml");
            let config_path = Some(path.clone());
            write_config(&path, &[("alice", key_0)])?;
            let before = std::fs::read_to_string(&path)?;

            match call(&config_path) {
                Err(e) => assert_eq!(e.to_string(), expected.to_string(), "case {description}"),
                Ok(output) => panic!("case {description}: expected an error, got {output:?}"),
            }
            assert_eq!(
                std::fs::read_to_string(&path)?,
                before,
                "case {description}"
            );
        }
        Ok(())
    }

    #[test]
    fn delete_does_not_create_missing_config() -> anyhow::Result<()> {
        let temp_dir = TempDir::new()?;
        let path = temp_dir.path().join("config.toml");
        let config_path = Some(path.clone());
        let keys = TestKeys::new(1);
        let key_0 = keys.pub_key(0).unwrap();

        assert!(delete_alias(&config_path, "alice", false).is_err());
        assert!(delete_alias_of_key(&config_path, key_0, false).is_err());
        assert!(delete_alias_pair(&config_path, key_0, "alice", false).is_err());

        assert!(!path.exists());
        Ok(())
    }

    #[test]
    fn json_output_maps_aliases_to_keys() -> anyhow::Result<()> {
        let keys = TestKeys::new(3);
        let (key_0, key_1, key_2) = (
            keys.pub_key(0).unwrap(),
            keys.pub_key(1).unwrap(),
            keys.pub_key(2).unwrap(),
        );
        type Expected<'a> = Vec<(&'a str, &'a AsfaloadPublicKeys)>;
        // (description, call, expected aliases in the output)
        let cases: Vec<(&str, AliasCall<'_>, Expected<'_>)> = vec![
            (
                "list all",
                Box::new(|path| list_aliases(path, &None, true)),
                vec![("alice", key_0), ("bob", key_1)],
            ),
            (
                "lookup by name",
                Box::new(|path| list_aliases(path, &Some("bob".to_string()), true)),
                vec![("bob", key_1)],
            ),
            (
                "lookup by key",
                Box::new(|path| display_key(path, key_0, true)),
                vec![("alice", key_0)],
            ),
            (
                "add",
                Box::new(|path| add_alias(path, key_2, "carol", false, true)),
                vec![("carol", key_2)],
            ),
            (
                "delete",
                Box::new(|path| delete_alias(path, "bob", true)),
                vec![("bob", key_1)],
            ),
        ];
        for (description, call, expected) in cases {
            let temp_dir = TempDir::new()?;
            let config_path = Some(temp_dir.path().join("config.toml"));
            write_config(
                config_path.as_deref().unwrap(),
                &[("alice", key_0), ("bob", key_1)],
            )?;

            let output = call(&config_path)?;

            let listed: HashMap<String, String> = serde_json::from_str(&output)?;
            let expected: HashMap<String, String> = expected
                .into_iter()
                .map(|(name, key)| (name.to_string(), key.to_base64()))
                .collect();
            assert_eq!(listed, expected, "case {description}");
        }
        Ok(())
    }
}
