use features_lib::{AsfaloadPublicKeyTrait, AsfaloadPublicKeys};

use crate::{ClientLibError, config::ConfigAccessor};

/// Convert an input string to a key possibly using aliases.
pub fn input_to_key(
    config_accessor: &ConfigAccessor,
    input: &str,
) -> Result<AsfaloadPublicKeys, ClientLibError> {
    match AsfaloadPublicKeys::from_base64(input) {
        Ok(k) => Ok(k),
        Err(parse_error) => config_accessor
            .get()?
            .get_key(input)
            .cloned()
            .ok_or_else(|| {
                ClientLibError::AliasNotFound(format!(
                    "'{input}' is not a known alias and not a valid public key: {parse_error}"
                ))
            }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use features_lib::{ASFALOAD_PUB_PREFIX, AsfaloadSecretKeys, KeyFormat};
    use test_helpers::{TestKeys, fixtures_dir};

    fn config_with_alice(keys: &TestKeys) -> anyhow::Result<CliConfig> {
        let mut config = CliConfig::default();
        config.add_alias(keys.pub_key(0).unwrap(), "alice", false)?;
        Ok(config)
    }

    // The line of an OpenSSH public key file: "ssh-ed25519 <base64> <comment>".
    fn ssh_public_key_line() -> anyhow::Result<String> {
        let content = std::fs::read_to_string(fixtures_dir().join("git_signing_key.pub"))?;
        Ok(content.trim().to_string())
    }

    fn ssh_key_type() -> anyhow::Result<String> {
        let line = ssh_public_key_line()?;
        let key_type = line.split_whitespace().next().unwrap_or_default();
        Ok(key_type.to_string())
    }

    #[test]
    fn input_to_key_parses_ssh_public_key() -> anyhow::Result<()> {
        // Derive the expected key from the private key, so the check does not
        // depend on the public key parser under test.
        let secret_key = AsfaloadSecretKeys::from_file_for_format(
            fixtures_dir().join("git_signing_key"),
            "",
            &KeyFormat::OpenSsh,
        )?;
        let expected = AsfaloadPublicKeys::from_secret_key(&secret_key)?;
        let line = ssh_public_key_line()?;
        let without_comment = line
            .split_whitespace()
            .take(2)
            .collect::<Vec<_>>()
            .join(" ");
        let cases = vec![
            ("with comment", line.clone()),
            ("without comment", without_comment),
        ];
        for (description, input) in cases {
            let result = input_to_key(&config_with_alice(&TestKeys::new(1))?, &input)
                .unwrap_or_else(|e| panic!("case {description}: unexpected error {e}"));
            assert_eq!(result, expected, "case {description}");
        }
        Ok(())
    }

    #[test]
    fn input_to_key_resolves_alias_named_like_ssh_key_type() -> anyhow::Result<()> {
        // "ssh-ed25519" is a valid alias name: without a key body it must not be read as a key.
        let keys = TestKeys::new(2);
        let alias = ssh_key_type()?;
        let mut config = config_with_alice(&keys)?;
        config.add_alias(keys.pub_key(1).unwrap(), &alias, false)?;

        let result = input_to_key(&config, &alias)?;
        assert_eq!(&result, keys.pub_key(1).unwrap());
        Ok(())
    }

    #[test]
    fn input_to_key_parses_public_key() -> anyhow::Result<()> {
        let keys = TestKeys::new(2);
        // The key of an alias and a key without alias must both parse the same way.
        for n in 0..2 {
            let key = keys.pub_key(n).unwrap();
            let result = input_to_key(&config_with_alice(&keys)?, &key.to_base64())?;
            assert_eq!(&result, key, "key {n}");
        }
        Ok(())
    }

    #[test]
    fn input_to_key_resolves_alias() -> anyhow::Result<()> {
        let keys = TestKeys::new(1);
        let result = input_to_key(&config_with_alice(&keys)?, "alice")?;
        assert_eq!(&result, keys.pub_key(0).unwrap());
        Ok(())
    }

    #[test]
    fn input_to_key_fails_for_unknown_alias() -> anyhow::Result<()> {
        let keys = TestKeys::new(1);
        // Alias lookup is exact: no case folding and no trimming.
        let cases = vec!["bob", "", "Alice", " alice", "alice "];
        for input in cases {
            match input_to_key(&config_with_alice(&keys)?, input) {
                Err(ClientLibError::AliasNotFound(msg)) => {
                    assert!(msg.contains(&format!("'{input}'")), "case {input:?}: {msg}")
                }
                Err(e) => panic!("case {input:?}: expected AliasNotFound, got {e}"),
                Ok(k) => panic!("case {input:?}: expected an error, got key {k:?}"),
            }
        }
        Ok(())
    }

    #[test]
    fn input_to_key_fails_for_invalid_public_key() -> anyhow::Result<()> {
        let keys = TestKeys::new(1);
        let ssh_key_type = ssh_key_type()?;
        let cases = vec![
            ("empty body", ASFALOAD_PUB_PREFIX.to_string()),
            ("invalid base64", format!("{ASFALOAD_PUB_PREFIX}!!!")),
            ("wrong length", format!("{ASFALOAD_PUB_PREFIX}AAAA")),
            ("ssh empty body", format!("{ssh_key_type} ")),
            ("ssh invalid base64", format!("{ssh_key_type} !!!")),
            ("ssh wrong length", format!("{ssh_key_type} AAAA")),
        ];
        for (description, input) in cases {
            // The user must see why the key was rejected, not only that no alias matched.
            let parse_error = AsfaloadPublicKeys::from_base64(&input).unwrap_err();
            match input_to_key(&config_with_alice(&keys)?, &input) {
                Err(ClientLibError::AliasNotFound(msg)) => assert!(
                    msg.starts_with(&format!("'{input}'"))
                        && msg.ends_with(&parse_error.to_string()),
                    "case {description}: {msg}"
                ),
                Err(e) => panic!("case {description}: expected AliasNotFound, got {e}"),
                Ok(k) => panic!("case {description}: expected an error, got key {k:?}"),
            }
        }
        Ok(())
    }
}
