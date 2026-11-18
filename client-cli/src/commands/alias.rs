use std::path::PathBuf;

use client_lib::config::{load_config_or_default, save_config};
use features_lib::{AsfaloadPublicKeyTrait, AsfaloadPublicKeys};

use crate::error::ClientCliError;

pub fn list_aliases(
    config_file: &Option<PathBuf>,
    name: &Option<String>,
) -> Result<String, ClientCliError> {
    let config = load_config_or_default(config_file.as_deref())?;
    let aliases = config.aliases();

    let output = match name {
        Some(alias) => match config.get_key(alias) {
            Some(k) => format!("{} = {}", alias, k.to_base64()),
            None => return Err(ClientCliError::AliasNotFound(alias.clone())),
        },
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
) -> Result<String, ClientCliError> {
    let config = load_config_or_default(config_file.as_deref())?;
    let output = match config.get_alias(key) {
        Some(alias) => format!("{} = {}", alias, key.to_base64()),
        None => return Err(ClientCliError::NoAliasForKey(key.to_base64())),
    };

    Ok(output.clone())
}

pub fn add_alias(
    config_file: &Option<PathBuf>,
    key: &AsfaloadPublicKeys,
    name: &str,
    force: bool,
) -> Result<String, ClientCliError> {
    let mut config = load_config_or_default(config_file.as_deref())?;
    config.add_alias(key, name, force)?;
    save_config(&config, config_file.as_deref())?;
    Ok(format!("Alias {} added for {}", name, key.to_base64()))
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
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

        let output = list_aliases(&config_path, &None)?;

        // The order of the aliases in the output is not fixed.
        let listed: HashMap<String, String> = toml::from_str(&output)?;
        let expected = HashMap::from([
            ("alice".to_string(), key_0.to_base64()),
            ("bob".to_string(), key_1.to_base64()),
        ]);
        assert_eq!(listed, expected);
        Ok(())
    }

    #[test]
    fn list_aliases_with_name() -> anyhow::Result<()> {
        let temp_dir = TempDir::new()?;
        let config_path = Some(temp_dir.path().join("config.toml"));
        let keys = TestKeys::new(1);
        let key_0 = keys.pub_key(0).unwrap();
        write_config(config_path.as_deref().unwrap(), &[("alice", key_0)])?;

        let output = list_aliases(&config_path, &Some("alice".to_string()))?;
        assert_eq!(output, format!("alice = {}", key_0.to_base64()));

        match list_aliases(&config_path, &Some("carol".to_string())) {
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

        let output = display_key(&config_path, key_0)?;
        assert_eq!(output, format!("alice = {}", key_0.to_base64()));

        match display_key(&config_path, key_1) {
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

        assert_eq!(list_aliases(&config_path, &None)?.trim(), "");
        assert!(list_aliases(&config_path, &Some("alice".to_string())).is_err());
        assert!(display_key(&config_path, key_0).is_err());

        assert!(!path.exists());
        Ok(())
    }

    #[test]
    fn add_alias_saves_alias() -> anyhow::Result<()> {
        let temp_dir = TempDir::new()?;
        let config_path = Some(temp_dir.path().join("config.toml"));
        let keys = TestKeys::new(1);
        let key_0 = keys.pub_key(0).unwrap();

        let output = add_alias(&config_path, key_0, "alice", false)?;

        assert_eq!(
            output,
            format!("Alias alice added for {}", key_0.to_base64())
        );
        let loaded = load_config(config_path.as_deref())?;
        assert_eq!(loaded.get_key("alice"), Some(key_0));
        Ok(())
    }
}
