use etcetera::{BaseStrategy, choose_base_strategy};
use features_lib::{AsfaloadPublicKeyTrait, AsfaloadPublicKeys};
use serde::{Deserialize, Serialize};
use std::{
    cell::OnceCell,
    collections::{BTreeMap, HashSet},
    io::Write,
    path::{Path, PathBuf},
};

use crate::ClientLibError;

type Aliases = BTreeMap<String, AsfaloadPublicKeys>;
#[derive(Debug, Default, Deserialize, Serialize, Clone)]
#[serde(deny_unknown_fields)]
/// Configuration of the client CLI
pub struct CliConfig {
    // Alias for pub keys. Key is alias, value if pubkey. Makes config file more readable.
    #[serde(default)]
    aliases: Aliases,
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

    pub fn aliases(&self) -> &Aliases {
        &self.aliases
    }

    /// Removes the alias and returns the key it was for, or `None` if the alias does not exist.
    pub fn remove_alias(&mut self, name: &str) -> Option<AsfaloadPublicKeys> {
        self.aliases.remove(name)
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

/// The ConfigAccessor loads the config lazily, preventing config failures for commands that don't
/// use the config.
pub struct ConfigAccessor {
    path: PathBuf,
    config: OnceCell<CliConfig>,
}

impl ConfigAccessor {
    pub fn new(path_in: &Option<PathBuf>) -> Result<Self, ClientLibError> {
        let config_path = build_config_path(path_in.as_deref())?;
        Ok(ConfigAccessor {
            path: config_path,
            config: OnceCell::new(),
        })
    }

    pub fn get(&self) -> Result<&CliConfig, ClientLibError> {
        if let Some(config) = self.config.get() {
            return Ok(config);
        }
        let config = load_config_or_default(Some(&self.path))?;
        Ok(self.config.get_or_init(|| config))
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
    // A leading '-' reads as a command line flag, and "." or ".." as a path.
    if !name.starts_with(|c: char| c.is_ascii_alphanumeric()) {
        return Err(format!(
            "Alias {name:?} must start with an ASCII letter or digit"
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

pub fn load_config_or_default(path_in: Option<&Path>) -> Result<CliConfig, ClientLibError> {
    match load_config(path_in) {
        Err(ClientLibError::Io(e)) if e.kind() == std::io::ErrorKind::NotFound => {
            Ok(CliConfig::default())
        }
        result => result,
    }
}

pub fn save_config(config: &CliConfig, path_in: Option<&Path>) -> Result<(), ClientLibError> {
    let config_path = build_config_path(path_in)?;
    // Write to the target of a symlink, so the symlink stays in place.
    let config_path = match std::fs::canonicalize(&config_path) {
        Ok(target) => target,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => config_path,
        Err(e) => return Err(e.into()),
    };
    let config_content = toml::to_string(config)
        .map_err(|e| ClientLibError::ConfigError(format!("Could not serialise config: {e}")))?;
    let config_dir = match config_path.parent() {
        Some(parent) if !parent.as_os_str().is_empty() => parent,
        _ => Path::new("."),
    };
    std::fs::create_dir_all(config_dir)?;
    // Write a temporary file and rename it, so a failed write keeps the existing config.
    let mut temp_file = tempfile::NamedTempFile::new_in(config_dir)?;
    temp_file.write_all(config_content.as_bytes())?;
    temp_file.persist(&config_path).map_err(|e| {
        ClientLibError::PersistError(format!(
            "Failed to move temp file to {:?}: {}",
            config_path, e
        ))
    })?;
    Ok(())
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
        let aliases = BTreeMap::from([
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
            ("misspelled aliases section", "[alias]\n"),
            ("unknown section next to aliases", "[aliases]\n\n[other]\n"),
            ("unknown top-level key", "version = 1"),
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
    fn load_config_accepts_file_without_aliases() -> anyhow::Result<()> {
        let cases = vec![
            ("empty", ""),
            ("blank lines", "\n  \n"),
            ("comment only", "# no aliases yet\n"),
        ];
        for (name, content) in cases {
            let temp_dir = TempDir::new()?;
            let config_path = temp_dir.path().join("config.toml");
            write(&config_path, content)?;
            let loaded = load_config(Some(&config_path))
                .unwrap_or_else(|e| panic!("case {name}: unexpected error {e}"));
            assert!(loaded.aliases.is_empty(), "case {name}: aliases not empty");
        }
        Ok(())
    }

    #[test]
    fn load_config_or_default_does_not_create_missing_file() -> anyhow::Result<()> {
        let temp_dir = TempDir::new()?;
        let config_path = temp_dir.path().join("a").join("config.toml");

        let config = load_config_or_default(Some(&config_path))?;
        assert!(config.aliases.is_empty());
        assert!(!temp_dir.path().join("a").exists());
        Ok(())
    }

    #[test]
    fn load_config_or_default_loads_existing_file() -> anyhow::Result<()> {
        let temp_dir = TempDir::new()?;
        let config_path = temp_dir.path().join("config.toml");
        let keys = TestKeys::new(1);
        let config = CliConfig {
            aliases: BTreeMap::from([("alice".to_string(), keys.pub_key(0).unwrap().clone())]),
        };
        write(&config_path, toml::to_string(&config)?)?;

        let loaded = load_config_or_default(Some(&config_path))?;
        assert_eq!(loaded.aliases, config.aliases);
        Ok(())
    }

    #[test]
    fn load_config_or_default_fails_on_invalid_file() -> anyhow::Result<()> {
        let temp_dir = TempDir::new()?;
        let config_path = temp_dir.path().join("config.toml");
        write(&config_path, "this is = = not toml")?;

        match load_config_or_default(Some(&config_path)).unwrap_err() {
            ClientLibError::ConfigError(_) => {}
            e => panic!("expected ConfigError, got {e}"),
        }
        Ok(())
    }

    #[test]
    fn check_alias_name_accepts_and_rejects() {
        let cases = vec![
            ("alice", true),
            ("Bob-2", true),
            ("release_team.v1", true),
            ("2fa-key", true),
            ("", false),
            ("-k", false),
            ("--force", false),
            (".", false),
            ("..", false),
            (".hidden", false),
            ("_team", false),
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

        let expected = BTreeMap::from([
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
                    let expected: BTreeMap<String, AsfaloadPublicKeys> = expected
                        .into_iter()
                        .map(|(name, n)| (name.to_string(), key(n)))
                        .collect();
                    assert_eq!(config.aliases, expected, "case {description}");
                }
                (Err(ClientLibError::GenericError(_)), None) => {
                    let unchanged = BTreeMap::from([("alice".to_string(), key(0))]);
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
    fn aliases_returns_all_aliases() -> anyhow::Result<()> {
        let keys = TestKeys::new(2);
        let (key_0, key_1) = (keys.pub_key(0).unwrap(), keys.pub_key(1).unwrap());
        let mut config = CliConfig::default();
        assert!(config.aliases().is_empty());

        config.add_alias(key_0, "alice", false)?;
        config.add_alias(key_1, "bob", false)?;

        let expected = BTreeMap::from([
            ("alice".to_string(), key_0.clone()),
            ("bob".to_string(), key_1.clone()),
        ]);
        assert_eq!(config.aliases(), &expected);
        Ok(())
    }

    #[test]
    fn remove_alias_returns_removed_key() -> anyhow::Result<()> {
        let keys = TestKeys::new(2);
        let (key_0, key_1) = (keys.pub_key(0).unwrap(), keys.pub_key(1).unwrap());
        let mut config = CliConfig::default();
        config.add_alias(key_0, "alice", false)?;
        config.add_alias(key_1, "bob", false)?;

        assert_eq!(config.remove_alias("alice"), Some(key_0.clone()));
        assert_eq!(config.remove_alias("alice"), None);
        assert_eq!(config.remove_alias("carol"), None);

        let expected = BTreeMap::from([("bob".to_string(), key_1.clone())]);
        assert_eq!(config.aliases(), &expected);
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

    #[test]
    fn save_config_writes_loadable_config_to_new_path() -> anyhow::Result<()> {
        let temp_dir = TempDir::new()?;
        let config_path = temp_dir.path().join("a").join("config.toml");
        let keys = TestKeys::new(2);
        let mut config = CliConfig::default();
        config.add_alias(keys.pub_key(0).unwrap(), "alice", false)?;
        config.add_alias(keys.pub_key(1).unwrap(), "bob", false)?;

        save_config(&config, Some(&config_path))?;

        let loaded = load_config(Some(&config_path))?;
        assert_eq!(loaded.aliases, config.aliases);
        Ok(())
    }

    #[test]
    fn save_config_replaces_existing_config() -> anyhow::Result<()> {
        let temp_dir = TempDir::new()?;
        let config_path = temp_dir.path().join("config.toml");
        let keys = TestKeys::new(1);
        write(&config_path, "[aliases]\n")?;
        let mut config = load_config(Some(&config_path))?;
        config.add_alias(keys.pub_key(0).unwrap(), "alice", false)?;

        save_config(&config, Some(&config_path))?;

        let loaded = load_config(Some(&config_path))?;
        assert_eq!(loaded.aliases, config.aliases);
        Ok(())
    }

    #[test]
    fn save_config_leaves_no_content_of_a_longer_previous_file() -> anyhow::Result<()> {
        let temp_dir = TempDir::new()?;
        let config_path = temp_dir.path().join("config.toml");
        let keys = TestKeys::new(2);
        let mut config = CliConfig::default();
        config.add_alias(keys.pub_key(0).unwrap(), "alice", false)?;
        config.add_alias(keys.pub_key(1).unwrap(), "bob", false)?;
        save_config(&config, Some(&config_path))?;

        let mut smaller = CliConfig::default();
        smaller.add_alias(keys.pub_key(0).unwrap(), "al", false)?;
        save_config(&smaller, Some(&config_path))?;

        let loaded = load_config(Some(&config_path))?;
        assert_eq!(loaded.aliases, smaller.aliases);
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn save_config_writes_through_symlink() -> anyhow::Result<()> {
        let temp_dir = TempDir::new()?;
        let target_dir = temp_dir.path().join("dotfiles");
        std::fs::create_dir(&target_dir)?;
        let target_path = target_dir.join("config.toml");
        write(&target_path, "[aliases]\n")?;
        let link_path = temp_dir.path().join("config.toml");
        std::os::unix::fs::symlink(&target_path, &link_path)?;
        let keys = TestKeys::new(1);
        let mut config = CliConfig::default();
        config.add_alias(keys.pub_key(0).unwrap(), "alice", false)?;

        save_config(&config, Some(&link_path))?;

        assert!(std::fs::symlink_metadata(&link_path)?.is_symlink());
        assert_eq!(std::fs::read_link(&link_path)?, target_path);
        let loaded = load_config(Some(&target_path))?;
        assert_eq!(loaded.aliases, config.aliases);
        Ok(())
    }
}
