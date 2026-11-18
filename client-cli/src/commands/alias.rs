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
