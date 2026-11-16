use etcetera::{BaseStrategy, choose_base_strategy};
use features_lib::AsfaloadPublicKeys;
use serde::{Deserialize, Serialize};
use std::{
    collections::HashMap,
    fs::OpenOptions,
    io::Write,
    path::PathBuf,
};

use crate::ClientLibError;

#[derive(Debug, Default, Deserialize, Serialize)]
/// Configuration of the client CLI
pub struct CliConfig {
    // Alias for pub keys. Key is alias, value if pubkey. Makes config file more readable.
    aliases: HashMap<String, AsfaloadPublicKeys>,
}

fn build_config_path(path_in: Option<PathBuf>) -> Result<PathBuf, ClientLibError> {
    match path_in {
        Some(p) => Ok(p),
        None => {
            let strategy = choose_base_strategy().map_err(|e| {
                ClientLibError::ConfigError(format!(
                    "Problem determining configuration location: {e}"
                ))
            })?;
            Ok(strategy
                .config_dir()
                .join("asfaload-cli")
                .join("config.toml"))
        }
    }
}

pub fn load_config(path_in: Option<PathBuf>) -> Result<CliConfig, ClientLibError> {
    let config_path = build_config_path(path_in)?;
    let content = std::fs::read_to_string(config_path)?;
    let config: CliConfig = toml::from_str(&content)
        .map_err(|e| ClientLibError::ConfigError(format!("Could not parse config file: {e}")))?;
    Ok(config)
}

pub fn init(path_in: Option<PathBuf>) -> Result<CliConfig, ClientLibError> {
    let config_path = build_config_path(path_in)?;
    let default_config = CliConfig::default();
    let config_content = toml::to_string(&default_config).map_err(|e| {
        ClientLibError::ConfigError(format!("Could not serialise default config: {e}"))
    })?;
    if let Some(parent) = config_path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let mut f = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&config_path)?;
    f.write_all(config_content.as_bytes())?;
    Ok(default_config)
}

pub fn load_or_init_config(path_in: Option<PathBuf>) -> Result<CliConfig, ClientLibError> {
    let config_path = build_config_path(path_in)?;
    match load_config(Some(config_path.clone())) {
        Err(ClientLibError::Io(e)) if e.kind() == std::io::ErrorKind::NotFound => {
            init(Some(config_path))
        }
        result => result,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::write;
    use tempfile::TempDir;
    use test_helpers::TestKeys;

    #[test]
    fn build_config_path_returns_given_path() -> anyhow::Result<()> {
        let path = PathBuf::from("/some/dir/my-config.toml");
        assert_eq!(build_config_path(Some(path.clone()))?, path);
        Ok(())
    }

    #[test]
    fn build_config_path_defaults_to_asfaload_cli_config_dir() -> anyhow::Result<()> {
        let path = build_config_path(None)?;
        assert!(
            path.ends_with(PathBuf::from("asfaload-cli").join("config.toml")),
            "unexpected default path {path:?}"
        );
        Ok(())
    }

    #[test]
    fn load_config_reads_aliases_written_to_file() -> anyhow::Result<()> {
        let temp_dir = TempDir::new()?;
        let config_path = temp_dir.path().join("config.toml");
        let keys = TestKeys::new(2);
        let aliases = HashMap::from([
            ("alice".to_string(), keys.pub_key(0).unwrap().clone()),
            ("bob".to_string(), keys.pub_key(1).unwrap().clone()),
        ]);
        let config = CliConfig {
            aliases: aliases.clone(),
        };
        write(&config_path, toml::to_string(&config)?)?;

        let loaded = load_config(Some(config_path))?;
        assert_eq!(loaded.aliases, aliases);
        Ok(())
    }

    #[test]
    fn load_config_fails_when_file_is_missing() -> anyhow::Result<()> {
        let temp_dir = TempDir::new()?;
        let config_path = temp_dir.path().join("config.toml");
        match load_config(Some(config_path)).unwrap_err() {
            ClientLibError::Io(e) => assert_eq!(e.kind(), std::io::ErrorKind::NotFound),
            e => panic!("expected Io error, got {e}"),
        }
        Ok(())
    }

    #[test]
    fn load_config_fails_on_invalid_content() -> anyhow::Result<()> {
        let cases = vec![
            ("not toml", "this is = = not toml"),
            ("aliases not a table", "aliases = 3"),
            ("invalid key", "[aliases]\nalice = \"not-a-key\""),
        ];
        for (name, content) in cases {
            let temp_dir = TempDir::new()?;
            let config_path = temp_dir.path().join("config.toml");
            write(&config_path, content)?;
            match load_config(Some(config_path)).unwrap_err() {
                ClientLibError::ConfigError(msg) => assert!(
                    msg.starts_with("Could not parse config file"),
                    "case {name}: unexpected message {msg}"
                ),
                e => panic!("case {name}: expected ConfigError, got {e}"),
            }
        }
        Ok(())
    }

    #[test]
    fn init_creates_parent_dirs_and_loadable_config() -> anyhow::Result<()> {
        let temp_dir = TempDir::new()?;
        let config_path = temp_dir.path().join("a").join("b").join("config.toml");

        let config = init(Some(config_path.clone()))?;
        assert!(config.aliases.is_empty());
        assert!(config_path.is_file());

        let loaded = load_config(Some(config_path))?;
        assert!(loaded.aliases.is_empty());
        Ok(())
    }

    #[test]
    fn init_does_not_overwrite_existing_file() -> anyhow::Result<()> {
        let temp_dir = TempDir::new()?;
        let config_path = temp_dir.path().join("config.toml");
        let existing = "# existing config\n";
        write(&config_path, existing)?;

        match init(Some(config_path.clone())).unwrap_err() {
            ClientLibError::Io(e) => assert_eq!(e.kind(), std::io::ErrorKind::AlreadyExists),
            e => panic!("expected Io error, got {e}"),
        }
        assert_eq!(std::fs::read_to_string(&config_path)?, existing);
        Ok(())
    }
}
