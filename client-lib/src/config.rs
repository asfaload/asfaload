use etcetera::{BaseStrategy, choose_base_strategy};
use features_lib::{AsfaloadPublicKeyTrait, AsfaloadPublicKeys};
use serde::{Deserialize, Serialize};
use std::{
    collections::{HashMap, HashSet},
    fs::OpenOptions,
    io::Write,
    path::{Path, PathBuf},
};

use crate::ClientLibError;

#[derive(Debug, Default, Deserialize, Serialize)]
/// Configuration of the client CLI
pub struct CliConfig {
    // Alias for pub keys. Key is alias, value if pubkey. Makes config file more readable.
    aliases: HashMap<String, AsfaloadPublicKeys>,
}

impl CliConfig {
    pub fn add_alias(
        &mut self,
        k: &AsfaloadPublicKeys,
        name: &str,
        overwrite: bool,
    ) -> Result<(), ClientLibError> {
        check_alias_name(name).map_err(ClientLibError::GenericError)?;
        // An alias never moves to another key, even with overwrite.
        if let Some(existing) = self.aliases.get(name) {
            if existing == k {
                return Ok(());
            }
            return Err(ClientLibError::GenericError(format!(
                "Alias {name} already exists for key {}",
                existing.to_base64()
            )));
        }
        if let Some(old_alias) = self.get_alias(k).map(str::to_string) {
            if !overwrite {
                return Err(ClientLibError::GenericError(format!(
                    "Refusing to overwrite existing alias for {}",
                    k.to_base64()
                )));
            }
            self.aliases.remove(&old_alias);
        }
        self.aliases.insert(name.to_string(), k.clone());
        Ok(())
    }

    pub fn get_key(&self, alias: &str) -> Option<&AsfaloadPublicKeys> {
        self.aliases.get(alias)
    }

    pub fn get_alias(&self, key: &AsfaloadPublicKeys) -> Option<&str> {
        self.aliases
            .iter()
            .find(|(_, k)| *k == key)
            .map(|(name, _)| name.as_str())
    }

    // A config file edited by hand can break the rules that add_alias enforces.
    fn validate(&self) -> Result<(), String> {
        let mut seen_keys = HashSet::new();
        for (name, key) in &self.aliases {
            check_alias_name(name)?;
            if !seen_keys.insert(key) {
                return Err(format!("Key {} has more than one alias", key.to_base64()));
            }
        }
        Ok(())
    }
}

// Restricted to characters that are safe in a shell and cannot form a public key ("asfaload-pub:...").
fn check_alias_name(name: &str) -> Result<(), String> {
    if name.is_empty() {
        return Err("Alias must not be empty".to_string());
    }
    if let Some(c) = name
        .chars()
        .find(|c| !(c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.')))
    {
        return Err(format!(
            "Alias {name:?} contains invalid character {c:?}: only ASCII letters, digits, '-', '_' and '.' are allowed"
        ));
    }
    Ok(())
}

fn build_config_path(path_in: Option<&Path>) -> Result<PathBuf, ClientLibError> {
    match path_in {
        Some(p) => Ok(p.to_path_buf()),
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

pub fn load_config(path_in: Option<&Path>) -> Result<CliConfig, ClientLibError> {
    let config_path = build_config_path(path_in)?;
    let content = std::fs::read_to_string(config_path)?;
    let config: CliConfig = toml::from_str(&content)
        .map_err(|e| ClientLibError::ConfigError(format!("Could not parse config file: {e}")))?;
    config
        .validate()
        .map_err(|e| ClientLibError::ConfigError(format!("Invalid config file: {e}")))?;
    Ok(config)
}

pub fn init(path_in: Option<&Path>) -> Result<CliConfig, ClientLibError> {
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

pub fn load_or_init_config(path_in: Option<&Path>) -> Result<CliConfig, ClientLibError> {
    let config_path = build_config_path(path_in)?;
    match load_config(Some(&config_path)) {
        Err(ClientLibError::Io(e)) if e.kind() == std::io::ErrorKind::NotFound => {
            init(Some(&config_path))
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
        assert_eq!(build_config_path(Some(&path))?, path);
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

        let loaded = load_config(Some(&config_path))?;
        assert_eq!(loaded.aliases, aliases);
        Ok(())
    }

    #[test]
    fn load_config_fails_when_file_is_missing() -> anyhow::Result<()> {
        let temp_dir = TempDir::new()?;
        let config_path = temp_dir.path().join("config.toml");
        match load_config(Some(&config_path)).unwrap_err() {
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
            match load_config(Some(&config_path)).unwrap_err() {
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

        let config = init(Some(&config_path))?;
        assert!(config.aliases.is_empty());
        assert!(config_path.is_file());

        let loaded = load_config(Some(&config_path))?;
        assert!(loaded.aliases.is_empty());
        Ok(())
    }

    #[test]
    fn init_does_not_overwrite_existing_file() -> anyhow::Result<()> {
        let temp_dir = TempDir::new()?;
        let config_path = temp_dir.path().join("config.toml");
        let existing = "# existing config\n";
        write(&config_path, existing)?;

        match init(Some(&config_path)).unwrap_err() {
            ClientLibError::Io(e) => assert_eq!(e.kind(), std::io::ErrorKind::AlreadyExists),
            e => panic!("expected Io error, got {e}"),
        }
        assert_eq!(std::fs::read_to_string(&config_path)?, existing);
        Ok(())
    }

    #[test]
    fn load_or_init_config_creates_missing_file() -> anyhow::Result<()> {
        let temp_dir = TempDir::new()?;
        let config_path = temp_dir.path().join("a").join("config.toml");

        let config = load_or_init_config(Some(&config_path))?;
        assert!(config.aliases.is_empty());
        assert!(config_path.is_file());
        Ok(())
    }

    #[test]
    fn load_or_init_config_loads_existing_file_unchanged() -> anyhow::Result<()> {
        let temp_dir = TempDir::new()?;
        let config_path = temp_dir.path().join("config.toml");
        let keys = TestKeys::new(1);
        let config = CliConfig {
            aliases: HashMap::from([("alice".to_string(), keys.pub_key(0).unwrap().clone())]),
        };
        let content = toml::to_string(&config)?;
        write(&config_path, &content)?;

        let loaded = load_or_init_config(Some(&config_path))?;
        assert_eq!(loaded.aliases, config.aliases);
        assert_eq!(std::fs::read_to_string(&config_path)?, content);
        Ok(())
    }

    #[test]
    fn load_or_init_config_does_not_replace_invalid_file() -> anyhow::Result<()> {
        let temp_dir = TempDir::new()?;
        let config_path = temp_dir.path().join("config.toml");
        let invalid = "this is = = not toml";
        write(&config_path, invalid)?;

        match load_or_init_config(Some(&config_path)).unwrap_err() {
            ClientLibError::ConfigError(_) => {}
            e => panic!("expected ConfigError, got {e}"),
        }
        assert_eq!(std::fs::read_to_string(&config_path)?, invalid);
        Ok(())
    }

    #[test]
    fn check_alias_name_accepts_and_rejects() {
        let cases = vec![
            ("alice", true),
            ("Bob-2", true),
            ("release_team.v1", true),
            ("", false),
            (" ", false),
            ("alice smith", false),
            ("alice\n", false),
            ("asfaload-pub:abc", false),
            ("a/b", false),
            ("élise", false),
        ];
        for (name, valid) in cases {
            assert_eq!(
                check_alias_name(name).is_ok(),
                valid,
                "unexpected result for {name:?}"
            );
        }
    }

    #[test]
    fn add_alias_inserts_new_aliases() -> anyhow::Result<()> {
        let keys = TestKeys::new(2);
        let (key_0, key_1) = (keys.pub_key(0).unwrap(), keys.pub_key(1).unwrap());
        let mut config = CliConfig::default();

        config.add_alias(key_0, "alice", false)?;
        config.add_alias(key_1, "bob", false)?;

        let expected = HashMap::from([
            ("alice".to_string(), key_0.clone()),
            ("bob".to_string(), key_1.clone()),
        ]);
        assert_eq!(config.aliases, expected);
        Ok(())
    }

    #[test]
    fn add_alias_with_existing_alias() -> anyhow::Result<()> {
        let keys = TestKeys::new(2);
        let key = |n: usize| keys.pub_key(n).unwrap().clone();
        // The config always starts with alice -> key 0.
        // (description, key index, alias, overwrite, expected aliases or None for an error)
        let cases: Vec<(&str, usize, &str, bool, Option<Vec<(&str, usize)>>)> = vec![
            (
                "same pair again",
                0,
                "alice",
                false,
                Some(vec![("alice", 0)]),
            ),
            ("alias of other key", 1, "alice", false, None),
            ("alias of other key, overwrite", 1, "alice", true, None),
            ("rename key", 0, "bob", false, None),
            (
                "rename key, overwrite",
                0,
                "bob",
                true,
                Some(vec![("bob", 0)]),
            ),
            (
                "new pair",
                1,
                "bob",
                false,
                Some(vec![("alice", 0), ("bob", 1)]),
            ),
            ("empty alias", 1, "", true, None),
            ("invalid alias", 1, "bob smith", true, None),
        ];
        for (description, key_index, alias, overwrite, expected) in cases {
            let mut config = CliConfig::default();
            config.add_alias(&key(0), "alice", false)?;

            let result = config.add_alias(&key(key_index), alias, overwrite);

            match (result, expected) {
                (Ok(()), Some(expected)) => {
                    let expected: HashMap<String, AsfaloadPublicKeys> = expected
                        .into_iter()
                        .map(|(name, n)| (name.to_string(), key(n)))
                        .collect();
                    assert_eq!(config.aliases, expected, "case {description}");
                }
                (Err(ClientLibError::GenericError(_)), None) => {
                    let unchanged = HashMap::from([("alice".to_string(), key(0))]);
                    assert_eq!(config.aliases, unchanged, "case {description}");
                }
                (result, expected) => {
                    panic!("case {description}: got {result:?}, expected {expected:?}")
                }
            }
        }
        Ok(())
    }

    #[test]
    fn get_key_and_get_alias() -> anyhow::Result<()> {
        let keys = TestKeys::new(3);
        let (key_0, key_1, key_2) = (
            keys.pub_key(0).unwrap(),
            keys.pub_key(1).unwrap(),
            keys.pub_key(2).unwrap(),
        );
        let mut config = CliConfig::default();
        config.add_alias(key_0, "alice", false)?;
        config.add_alias(key_1, "bob", false)?;

        assert_eq!(config.get_key("alice"), Some(key_0));
        assert_eq!(config.get_key("bob"), Some(key_1));
        assert_eq!(config.get_key("carol"), None);
        assert_eq!(config.get_alias(key_0), Some("alice"));
        assert_eq!(config.get_alias(key_1), Some("bob"));
        assert_eq!(config.get_alias(key_2), None);
        Ok(())
    }

    #[test]
    fn get_key_and_get_alias_after_rename() -> anyhow::Result<()> {
        let keys = TestKeys::new(1);
        let key = keys.pub_key(0).unwrap();
        let mut config = CliConfig::default();
        config.add_alias(key, "alice", false)?;
        config.add_alias(key, "alicia", true)?;

        assert_eq!(config.get_alias(key), Some("alicia"));
        assert_eq!(config.get_key("alicia"), Some(key));
        assert_eq!(config.get_key("alice"), None);
        Ok(())
    }

    #[test]
    fn load_config_rejects_invalid_aliases() -> anyhow::Result<()> {
        let keys = TestKeys::new(1);
        let key = keys.pub_key(0).unwrap().to_base64();
        let cases = vec![
            (
                "key with two aliases",
                format!("[aliases]\nalice = \"{key}\"\nbob = \"{key}\""),
            ),
            (
                "invalid alias",
                format!("[aliases]\n\"bob smith\" = \"{key}\""),
            ),
            ("empty alias", format!("[aliases]\n\"\" = \"{key}\"")),
        ];
        for (description, content) in cases {
            let temp_dir = TempDir::new()?;
            let config_path = temp_dir.path().join("config.toml");
            write(&config_path, content)?;
            match load_config(Some(&config_path)).unwrap_err() {
                ClientLibError::ConfigError(msg) => assert!(
                    msg.starts_with("Invalid config file"),
                    "case {description}: unexpected message {msg}"
                ),
                e => panic!("case {description}: expected ConfigError, got {e}"),
            }
        }
        Ok(())
    }
}
