use etcetera::{BaseStrategy, choose_base_strategy};
use features_lib::AsfaloadPublicKeys;
use std::{collections::HashMap, path::PathBuf};

use crate::ClientLibError;

#[derive(serde::Deserialize)]
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
