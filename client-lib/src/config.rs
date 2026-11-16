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

#[derive(Default, Deserialize, Serialize)]
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
