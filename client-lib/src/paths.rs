use std::path::{Path, PathBuf};

use etcetera::{BaseStrategy, choose_base_strategy};

use crate::ClientLibError;

pub fn build_config_path(path_in: Option<&Path>) -> Result<PathBuf, ClientLibError> {
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

pub fn get_keys_dir(user_choice: Option<PathBuf>) -> Result<PathBuf, ClientLibError> {
    match user_choice {
        Some(p) => Ok(p),
        None => {
            let strategy = choose_base_strategy().map_err(|e| {
                ClientLibError::ConfigError(format!("Problem determining data location: {e}"))
            })?;
            Ok(strategy.data_dir().join("asfaload-cli"))
        }
    }
}
