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

pub fn get_keys_dir(user_choice: &Option<PathBuf>) -> Result<PathBuf, ClientLibError> {
    match user_choice {
        Some(p) => Ok(p.clone()),
        None => {
            let strategy = choose_base_strategy().map_err(|e| {
                ClientLibError::ConfigError(format!("Problem determining data location: {e}"))
            })?;
            Ok(strategy.data_dir().join("asfaload-cli"))
        }
    }
}

pub fn key_path_from_name(
    keys_dir_in: &Option<PathBuf>,
    name: &str,
) -> Result<PathBuf, ClientLibError> {
    let keys_dir = get_keys_dir(keys_dir_in)?;
    Ok(keys_dir.join(name))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_keys_dir_returns_given_path() -> anyhow::Result<()> {
        let path = PathBuf::from("/some/dir/my-keys");
        assert_eq!(get_keys_dir(&Some(path.clone()))?, path);
        Ok(())
    }

    #[test]
    fn default_keys_dir_defaults_to_asfaload_cli_data_dir() -> anyhow::Result<()> {
        let path = get_keys_dir(&None)?;
        let data_dir = choose_base_strategy()?.data_dir();
        assert_eq!(path, data_dir.join("asfaload-cli"));
        Ok(())
    }

    #[test]
    fn key_path_from_name_joins_name_to_keys_dir() -> anyhow::Result<()> {
        let default_dir = choose_base_strategy()?.data_dir().join("asfaload-cli");
        let cases = vec![
            (
                Some(PathBuf::from("/some/keys")),
                "mykey",
                PathBuf::from("/some/keys/mykey"),
            ),
            (None, "mykey", default_dir.join("mykey")),
            (
                Some(PathBuf::from("/some/keys")),
                "team/mykey",
                PathBuf::from("/some/keys/team/mykey"),
            ),
            // An absolute name replaces the keys dir, as Path::join does.
            (
                Some(PathBuf::from("/some/keys")),
                "/other/mykey",
                PathBuf::from("/other/mykey"),
            ),
        ];
        for (keys_dir, name, expected) in cases {
            assert_eq!(
                key_path_from_name(&keys_dir, name)?,
                expected,
                "unexpected path for keys dir {keys_dir:?} and name {name:?}"
            );
        }
        Ok(())
    }
}
