use std::collections::HashMap;

use client_lib::config::ConfigAccessor;
use features_lib::{AsfaloadPublicKeyTrait, AsfaloadPublicKeys};

use crate::error::ClientCliError;

// TOML lines, so the output can be copied to the aliases table of the config file.
fn to_toml_lines(aliases: &impl serde::Serialize) -> Result<String, ClientCliError> {
    let lines = toml::to_string(aliases).map_err(|e| {
        ClientCliError::ConfigError(format!(
            "Got a problem serialising the aliases for output: {e}"
        ))
    })?;
    Ok(lines.trim_end().to_string())
}

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
        to_toml_lines(&HashMap::from([(alias, key)]))
    }
}

pub fn list_aliases(
    config_accessor: &ConfigAccessor,
    name: &Option<String>,
    json: bool,
) -> Result<String, ClientCliError> {
    let config = config_accessor.get()?;
    let aliases = config.aliases();

    let output = match name {
        Some(alias) => match config.get_key(alias) {
            Some(k) => format_alias(alias, k, json)?,
            None => return Err(ClientCliError::AliasNotFound(alias.clone())),
        },
        None if json => serde_json::to_string(aliases)?,
        None => to_toml_lines(aliases)?,
    };

    Ok(output.clone())
}

pub fn display_key(
    config_accessor: &ConfigAccessor,
    key: &AsfaloadPublicKeys,
    json: bool,
) -> Result<String, ClientCliError> {
    let config = config_accessor.get()?;
    let output = match config.get_alias(key) {
        Some(alias) => format_alias(alias, key, json)?,
        None => return Err(ClientCliError::NoAliasForKey(key.to_base64())),
    };

    Ok(output.clone())
}

pub fn add_alias(
    config_accessor: &mut ConfigAccessor,
    key: &AsfaloadPublicKeys,
    name: &str,
    force: bool,
    json: bool,
) -> Result<String, ClientCliError> {
    let mut config = config_accessor.get()?.clone();
    config.add_alias(key, name, force)?;
    config_accessor.save(config)?;
    if json {
        format_alias(name, key, json)
    } else {
        Ok(format!("Alias {} added for {}", name, key.to_base64()))
    }
}

pub fn remove_alias_and_save_config(
    config_accessor: &mut ConfigAccessor,
    name: &str,
    json: bool,
) -> Result<String, ClientCliError> {
    let mut config = config_accessor.get()?.clone();
    let key = config
        .remove_alias(name)
        .ok_or_else(|| ClientCliError::AliasNotFound(name.to_string()))?;
    config_accessor.save(config)?;
    if json {
        format_alias(name, &key, json)
    } else {
        Ok(format!("Alias {} deleted for {}", name, key.to_base64()))
    }
}

pub fn delete_alias(
    config_accessor: &mut ConfigAccessor,
    name: &str,
    json: bool,
) -> Result<String, ClientCliError> {
    remove_alias_and_save_config(config_accessor, name, json)
}

pub fn delete_alias_of_key(
    config_accessor: &mut ConfigAccessor,
    key: &AsfaloadPublicKeys,
    json: bool,
) -> Result<String, ClientCliError> {
    let name = check_exists(config_accessor, None, &Some(key.clone()))?;
    remove_alias_and_save_config(config_accessor, &name, json)
}

pub fn delete_alias_pair(
    config_accessor: &mut ConfigAccessor,
    key: &AsfaloadPublicKeys,
    name: &str,
    json: bool,
) -> Result<String, ClientCliError> {
    check_exists(config_accessor, Some(name), &Some(key.clone()))?;
    remove_alias_and_save_config(config_accessor, name, json)
}

pub fn check_exists(
    config_accessor: &ConfigAccessor,
    name: Option<&str>,
    key: &Option<AsfaloadPublicKeys>,
) -> Result<String, ClientCliError> {
    let config = config_accessor.get()?;
    match (name, key) {
        (Some(n), Some(k)) => {
            let aliased_key = config
                .get_key(n)
                .ok_or_else(|| ClientCliError::AliasNotFound(n.to_string()))?;
            if aliased_key == k {
                Ok(n.to_string())
            } else {
                Err(ClientCliError::AliasNotForKey(n.to_string(), k.to_base64()))
            }
        }
        (None, Some(k)) => config
            .get_alias(k)
            .ok_or_else(|| ClientCliError::NoAliasForKey(k.to_base64()))
            .map(|n| n.to_string()),
        (Some(n), None) => config
            .get_key(n)
            .ok_or_else(|| ClientCliError::AliasNotFound(n.to_string()))
            .map(|_| n.to_string()),
        (None, None) => Err(ClientCliError::InvalidInput(
            "No name nor key received for alias lookup".to_string(),
        )),
    }
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use client_lib::config::{CliConfig, load_config, save_config};
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
        let accessor = ConfigAccessor::new(&config_path);

        let output = list_aliases(&accessor, &None, false)?;

        let expected = format!(
            "alice = \"{}\"\nbob = \"{}\"",
            key_0.to_base64(),
            key_1.to_base64()
        );
        assert_eq!(output, expected);
        Ok(())
    }

    #[test]
    fn text_output_can_be_copied_to_config_file() -> anyhow::Result<()> {
        let temp_dir = TempDir::new()?;
        let config_path = Some(temp_dir.path().join("config.toml"));
        let keys = TestKeys::new(2);
        let (key_0, key_1) = (keys.pub_key(0).unwrap(), keys.pub_key(1).unwrap());
        write_config(
            config_path.as_deref().unwrap(),
            &[("alice", key_0), ("release.v1", key_1)],
        )?;
        let expected = load_config(config_path.as_deref())?;
        let accessor = ConfigAccessor::new(&config_path);

        // A '.' in an unquoted TOML key creates a nested table, so the name must be quoted.
        let single = list_aliases(&accessor, &Some("release.v1".to_string()), false)?;
        assert_eq!(
            single,
            format!("\"release.v1\" = \"{}\"", key_1.to_base64())
        );

        let copied_path = temp_dir.path().join("copied.toml");
        let listed = list_aliases(&accessor, &None, false)?;
        std::fs::write(&copied_path, format!("[aliases]\n{listed}\n"))?;
        let copied = load_config(Some(&copied_path))?;
        assert_eq!(copied.aliases(), expected.aliases());
        Ok(())
    }

    #[test]
    fn list_aliases_with_name() -> anyhow::Result<()> {
        let temp_dir = TempDir::new()?;
        let config_path = Some(temp_dir.path().join("config.toml"));
        let keys = TestKeys::new(1);
        let key_0 = keys.pub_key(0).unwrap();
        write_config(config_path.as_deref().unwrap(), &[("alice", key_0)])?;
        let accessor = ConfigAccessor::new(&config_path);

        let output = list_aliases(&accessor, &Some("alice".to_string()), false)?;
        assert_eq!(output, format!("alice = \"{}\"", key_0.to_base64()));

        match list_aliases(&accessor, &Some("carol".to_string()), false) {
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
        let accessor = ConfigAccessor::new(&config_path);

        let output = display_key(&accessor, key_0, false)?;
        assert_eq!(output, format!("alice = \"{}\"", key_0.to_base64()));

        match display_key(&accessor, key_1, false) {
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
        let accessor = ConfigAccessor::new(&config_path);

        assert_eq!(list_aliases(&accessor, &None, false)?.trim(), "");
        assert!(list_aliases(&accessor, &Some("alice".to_string()), false).is_err());
        assert!(display_key(&accessor, key_0, false).is_err());

        assert!(!path.exists());
        Ok(())
    }

    #[test]
    fn add_alias_saves_alias() -> anyhow::Result<()> {
        let temp_dir = TempDir::new()?;
        let config_path = Some(temp_dir.path().join("config.toml"));
        let keys = TestKeys::new(1);
        let key_0 = keys.pub_key(0).unwrap();
        let mut accessor = ConfigAccessor::new(&config_path);

        let output = add_alias(&mut accessor, key_0, "alice", false, false)?;

        assert_eq!(
            output,
            format!("Alias alice added for {}", key_0.to_base64())
        );
        let loaded = load_config(config_path.as_deref())?;
        assert_eq!(loaded.get_key("alice"), Some(key_0));
        Ok(())
    }

    type AliasCall<'a> = Box<dyn Fn(&mut ConfigAccessor) -> Result<String, ClientCliError> + 'a>;

    #[test]
    fn delete_removes_only_the_requested_alias() -> anyhow::Result<()> {
        let keys = TestKeys::new(2);
        let (key_0, key_1) = (keys.pub_key(0).unwrap(), keys.pub_key(1).unwrap());
        // (description, call)
        let cases: Vec<(&str, AliasCall<'_>)> = vec![
            (
                "by name",
                Box::new(|accessor| delete_alias(accessor, "alice", false)),
            ),
            (
                "by key",
                Box::new(|accessor| delete_alias_of_key(accessor, key_0, false)),
            ),
            (
                "by pair",
                Box::new(|accessor| delete_alias_pair(accessor, key_0, "alice", false)),
            ),
        ];
        for (description, call) in cases {
            let temp_dir = TempDir::new()?;
            let config_path = Some(temp_dir.path().join("config.toml"));
            write_config(
                config_path.as_deref().unwrap(),
                &[("alice", key_0), ("bob", key_1)],
            )?;

            let output = call(&mut ConfigAccessor::new(&config_path))?;

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
                Box::new(|accessor| delete_alias(accessor, "carol", false)),
                ClientCliError::AliasNotFound("carol".to_string()),
            ),
            (
                "key without alias",
                Box::new(|accessor| delete_alias_of_key(accessor, key_1, false)),
                ClientCliError::NoAliasForKey(key_1.to_base64()),
            ),
            (
                "pair with unknown name",
                Box::new(|accessor| delete_alias_pair(accessor, key_0, "carol", false)),
                ClientCliError::AliasNotFound("carol".to_string()),
            ),
            (
                "pair with other key",
                Box::new(|accessor| delete_alias_pair(accessor, key_1, "alice", false)),
                ClientCliError::AliasNotForKey("alice".to_string(), key_1.to_base64()),
            ),
        ];
        for (description, call, expected) in cases {
            let temp_dir = TempDir::new()?;
            let path = temp_dir.path().join("config.toml");
            let config_path = Some(path.clone());
            write_config(&path, &[("alice", key_0)])?;
            let before = std::fs::read_to_string(&path)?;

            match call(&mut ConfigAccessor::new(&config_path)) {
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
        let mut accessor = ConfigAccessor::new(&config_path);

        assert!(delete_alias(&mut accessor, "alice", false).is_err());
        assert!(delete_alias_of_key(&mut accessor, key_0, false).is_err());
        assert!(delete_alias_pair(&mut accessor, key_0, "alice", false).is_err());

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
                Box::new(|accessor| list_aliases(accessor, &None, true)),
                vec![("alice", key_0), ("bob", key_1)],
            ),
            (
                "lookup by name",
                Box::new(|accessor| list_aliases(accessor, &Some("bob".to_string()), true)),
                vec![("bob", key_1)],
            ),
            (
                "lookup by key",
                Box::new(|accessor| display_key(accessor, key_0, true)),
                vec![("alice", key_0)],
            ),
            (
                "add",
                Box::new(|accessor| add_alias(accessor, key_2, "carol", false, true)),
                vec![("carol", key_2)],
            ),
            (
                "delete",
                Box::new(|accessor| delete_alias(accessor, "bob", true)),
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

            let output = call(&mut ConfigAccessor::new(&config_path))?;

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
