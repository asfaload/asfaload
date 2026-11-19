use features_lib::{AsfaloadPublicKeyTrait, AsfaloadPublicKeys};

use crate::{ClientLibError, config::CliConfig};

/// Convert an input string to a key possibly using aliases.
pub fn input_to_key(config: &CliConfig, input: &str) -> Result<AsfaloadPublicKeys, ClientLibError> {
    match AsfaloadPublicKeys::from_base64(input) {
        Ok(k) => Ok(k),
        Err(parse_error) => config.get_key(input).cloned().ok_or_else(|| {
            ClientLibError::AliasNotFound(format!(
                "'{input}' is not a known alias and not a valid public key: {parse_error}"
            ))
        }),
    }
}
        }
    }
}
