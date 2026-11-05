use std::fs::{self, File};
use std::io::{self, BufRead, BufReader, Write};
use std::path::PathBuf;
use std::str::FromStr;

use crate::error::{ClientCliError, Result};
use crate::utils::{ensure_dir_exists, validate_threshold};
use clap::CommandFactory;
use features_lib::{
    ASFALOAD_PRIV_PREFIX, AsfaloadPublicKeyTrait, AsfaloadPublicKeys, SignersConfig,
    sha512_for_file,
};

fn get_group_info<P: AsfaloadPublicKeyTrait>(
    keys: Vec<P>,
    threshold: Option<u32>,
) -> std::result::Result<Option<(Vec<P>, u32)>, ClientCliError> {
    if keys.is_empty() {
        Ok(None)
    } else if let Some(threshold) = threshold {
        validate_threshold(threshold, keys.len())?;
        Ok(Some((keys, threshold)))
    } else {
        Err(crate::error::ClientCliError::InvalidInput(
            "Grouo threshold is required when keys are provided for a group".to_string(),
        ))
    }
}
/// Handles the `signers_file` command.
///
/// # Arguments
/// * `artifact_signer` - List of artifact signer public keys (base64 strings)
/// * `artifact_signer_file` - List of artifact signer public key files (.pub files)
/// * `artifact_threshold` - Threshold for artifact signers
/// * `admin_key` - List of admin public keys (base64 strings)
/// * `admin_key_file` - List of admin public key files (.pub files)
/// * `admin_threshold` - Threshold for admin keys (optional)
/// * `master_key` - List of master public keys (base64 strings)
/// * `master_key_file` - List of master public key files (.pub files)
/// * `master_threshold` - Threshold for master keys (optional)
/// * `output_file` - Path to the output signers file; when None, written to stdout
///
/// # Returns
/// * `Result<()>` - Ok if the command was handled successfully, Err otherwise
#[allow(clippy::too_many_arguments)]
pub fn handle_new_signers_file_command(
    artifact_signer: &[String],
    artifact_signer_file: &[PathBuf],
    artifact_threshold: u32,
    admin_key: &[String],
    admin_key_file: &[PathBuf],
    admin_threshold: Option<u32>,
    master_key: &[String],
    master_key_file: &[PathBuf],
    master_threshold: Option<u32>,
    revocation_key: &[String],
    revocation_key_file: &[PathBuf],
    revocation_threshold: Option<u32>,
    output_file: &Option<PathBuf>,
    json: bool,
) -> Result<()> {
    // Do output file validations early
    if let Some(output_file) = output_file {
        // We do not geve a default name to the file, so we cannot work
        // with the path to a dir.
        if output_file.is_dir() {
            return Err(crate::error::ClientCliError::InvalidInput(format!(
                "Output file {:?} is a directory but it must be the path to a new file.",
                output_file
            )));
        }
        // Check if the output file already exists
        if output_file.exists() {
            return Err(crate::error::ClientCliError::InvalidInput(format!(
                "Output file {:?} already exists, refusing to overwrite",
                output_file
            )));
        }

        // Get parent directory and create it if it doesn't exist
        if let Some(parent_dir) = output_file.parent() {
            ensure_dir_exists(parent_dir)?;
        }
    };

    // Combine string and file-based artifact signers
    let all_artifact_signers: Vec<AsfaloadPublicKeys> =
        combine_key_sources(artifact_signer, artifact_signer_file)?;
    let all_artifact_signers_count = all_artifact_signers.len();

    if all_artifact_signers_count == 0 {
        return Err(crate::error::ClientCliError::InvalidInput(
            "At least one artifact signer must be provided.".to_string(),
        ));
    }
    // Validate artifact threshold
    validate_threshold(artifact_threshold, all_artifact_signers.len())?;

    // Combine string and file-based admin keys
    let all_admin_keys: Vec<AsfaloadPublicKeys> = combine_key_sources(admin_key, admin_key_file)?;
    let all_admin_keys_count = all_admin_keys.len();
    let admin_group_info = get_group_info(all_admin_keys, admin_threshold)?;

    // Combine string and file-based master keys
    let all_master_keys: Vec<AsfaloadPublicKeys> =
        combine_key_sources(master_key, master_key_file)?;
    let all_master_keys_count = all_master_keys.len();
    let master_group_info = get_group_info(all_master_keys, master_threshold)?;
    // Revocation keys
    let all_revocation_keys: Vec<AsfaloadPublicKeys> =
        combine_key_sources(revocation_key, revocation_key_file)?;
    let all_revocation_keys_count = all_revocation_keys.len();
    let revocation_group_info = get_group_info(all_revocation_keys, revocation_threshold)?;
    // Create signers config using the with_keys method
    let signers_config = SignersConfig::with_keys(
        1, // version
        (all_artifact_signers, artifact_threshold),
        admin_group_info,
        master_group_info,
        revocation_group_info,
    )
    .map_err(|e| {
        crate::error::ClientCliError::SignersFile(format!("Failed to create signers config: {}", e))
    })?;

    // Serialize to JSON
    let signers_file_content = signers_config.to_json().map_err(|e| {
        crate::error::ClientCliError::SignersFile(format!(
            "Failed to serialize signers config: {}",
            e
        ))
    })?;

    // Define lambdas to make match (-o flag, --json flag) below readable.
    // -------------------------------------------------------------------
    // Write signers file to disk
    let write_signers_file =
        |p: &PathBuf| -> std::result::Result<(), crate::error::ClientCliError> {
            let mut file = fs::File::create_new(p).map_err(|e| {
                crate::error::ClientCliError::SignersFile(format!(
                    "Failed to create signers file at {}: {}",
                    p.display(),
                    e
                ))
            })?;
            file.write_all(signers_file_content.as_bytes())
                .map_err(|e| {
                    let _ = fs::remove_file(p);
                    crate::error::ClientCliError::SignersFile(format!(
                        "Failed to write signers file at {}: {}",
                        p.display(),
                        e
                    ))
                })?;
            Ok(())
        };
    // Print signers file to stdout
    let print_signers_file_content = || {
        // We have posix json content, with trailing \n, so no println!
        print!("{}", signers_file_content);
    };
    // Print the --json flag output
    let print_json_output =
        |signers_file_destination| -> std::result::Result<(), crate::error::ClientCliError> {
            let digest = sha512_for_file(&signers_file_destination)?;
            let output = crate::output::NewSignersFileOutput {
                output_file: signers_file_destination,
                artifact_signers_count: all_artifact_signers_count,
                artifact_threshold,
                admin_keys_count: all_admin_keys_count,
                admin_threshold,
                master_keys_count: all_master_keys_count,
                master_threshold,
                revocation_keys_count: all_revocation_keys_count,
                revocation_threshold,
                digest: digest.into(),
            };
            println!("{}", serde_json::to_string(&output)?);
            Ok(())
        };

    // Print a human overview of the file written to disk
    let print_human_overview =
        |p: &PathBuf| -> std::result::Result<(), crate::error::ClientCliError> {
            let digest = sha512_for_file(p)?;
            println!("Signers file created successfully at: {}", p.display());
            println!(
                "Artifact signers: {} (threshold: {})",
                all_artifact_signers_count, artifact_threshold
            );
            println!(
                "Admin keys: {} (threshold: {})",
                all_admin_keys_count,
                admin_threshold.map_or("none".to_string(), |t| t.to_string())
            );
            println!(
                "Master keys: {} (threshold: {})",
                all_master_keys_count,
                master_threshold.map_or("none".to_string(), |t| t.to_string())
            );
            println!(
                "Revocation keys: {} (threshold: {})",
                all_revocation_keys_count,
                revocation_threshold.map_or("none".to_string(), |t| t.to_string())
            );
            println!("Generated file's digest: {}", digest);
            println!(
                "You can now place this file in your git repository.\nAfter that, you can register your repository with the following command, where you subsitute <url> by the url where you published the signers file:\n"
            );
            let executable = std::env::args_os()
                .next()
                .map(|a| a.to_string_lossy().into_owned())
                .unwrap_or_else(|| crate::cli::Cli::command().get_name().to_string());
            println!("{} register-repo --digest {} <url>\n", executable, digest);
            Ok(())
        };

    match (output_file, json) {
        // -o and --json
        (Some(p), true) => {
            write_signers_file(p)?;
            print_json_output(p.to_string_lossy().to_string())?;
        }
        // -o, no --json
        (Some(p), false) => {
            write_signers_file(p)?;
            print_human_overview(p)?;
        }
        // no -o, --json
        (None, true) => {
            return Err(crate::error::ClientCliError::InvalidInput(
                "Cannot output to stdout with --json flag".to_string(),
            ));
        }
        // no -o, no --json
        (None, false) => print_signers_file_content(),
    }

    Ok(())
}

/// Combine string-based keys and file-based keys into a single Vec of strings
fn combine_key_sources<P: AsfaloadPublicKeyTrait>(
    string_keys: &[String],
    file_keys: &[PathBuf],
) -> Result<Vec<P>> {
    // Collect public keys from base64 strings we got
    let mut combined: Vec<Result<P>> = string_keys
        .iter()
        .map(|key_str| {
            P::from_base64(key_str).map_err(|e| {
                let path_buf = PathBuf::from_str(key_str).unwrap_or(PathBuf::new());
                if path_buf.as_path().exists() {
                    crate::error::ClientCliError::SignersFile(format!(
                       "You passed a string as a public key, but it seems to be a path to a file: {}.\nUse the flag with -file suffix to pass a key stored on disk.\n{}",
                        key_str, e
                    ))
                } else {
                    crate::error::ClientCliError::SignersFile(format!(
                        "Failed to parse public key from string \"{}\": {}",
                        key_str, e
                    ))
                }
            })
        })
        .collect();

    // Add file keys by reading the public key from each file we got
    for file_path in file_keys {
        let f = File::open(file_path).map_err(|e| {
            crate::error::ClientCliError::SignersFile(format!(
                "Failed to read public key from file {:?}: problem opening file: {}",
                file_path, e
            ))
        })?;
        let reader = BufReader::new(f);

        let lines: io::Result<Vec<String>> = reader.lines().collect();
        let lines = lines.map_err(|e| {
            crate::error::ClientCliError::SignersFile(format!(
                "Failed to read public key from file {:?}: problem reading lines: {}",
                file_path, e
            ))
        })?;
        lines
            .into_iter()
            .map(|line| line.trim().to_string())
            .filter(|line| !line.is_empty())
            .for_each(|line| {
                let r = if line.starts_with(ASFALOAD_PRIV_PREFIX) {
                    Err(crate::error::ClientCliError::SignersFile(format!(
                        "Found a secret key, you need to pass public keys to build the signers file.\nIn file \"{}\" for line {}",
                        file_path.display(),
                        line.chars().take(20).collect::<String>()),
                    ))
                } else {
                    P::from_base64(&line).map_err(|e| {
                        crate::error::ClientCliError::SignersFile(format!(
                            "Failed to read public key from file \"{}\": {} for line {}",
                            file_path.display(),
                            e,
                            line
                        ))
                    })
                };
                combined.push(r)
            });
    }

    combined.into_iter().collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;
    use test_helpers::{fixtures_pub_key, fixtures_sec_key};

    // A valid public key base64 string (from fixtures key_0)
    const VALID_PUBKEY_B64: &str = "asfaload-pub:b5S+CxuqICIUn/DGBdMKeTMZCgQcg78ohiWQ1sC00c8";

    #[test]
    fn combine_key_sources_empty_inputs() {
        let result = combine_key_sources::<AsfaloadPublicKeys>(&[], &[]);
        assert!(result.is_ok());
        assert!(result.unwrap().is_empty());
    }

    #[test]
    fn combine_key_sources_valid_base64_string() {
        let keys = vec![VALID_PUBKEY_B64.to_string()];
        let result = combine_key_sources::<AsfaloadPublicKeys>(&keys, &[]);
        assert!(result.is_ok());
        let parsed = result.unwrap();
        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed[0].to_base64(), VALID_PUBKEY_B64);
    }

    #[test]
    fn combine_key_sources_multiple_valid_base64_strings() {
        let keys = vec![
            "asfaload-pub:p8p1Hb8ux9xf9mo8BGedkpv4RUFZgwXuYGu5x0grsdU".to_string(),
            "asfaload-pub:YCuPAtMNZQaYPDjWmp8voWh6bVg0bRyLu2zEkH6zYZI".to_string(),
        ];
        let result = combine_key_sources::<AsfaloadPublicKeys>(&keys, &[]);
        assert!(result.is_ok());
        assert_eq!(result.unwrap().len(), 2);
    }

    #[test]
    fn combine_key_sources_invalid_base64_string_returns_error() {
        let keys = vec!["not-a-valid-key".to_string()];
        let result = combine_key_sources::<AsfaloadPublicKeys>(&keys, &[]);
        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.contains("Failed to parse public key from string"),
            "Expected parse error message, got: {}",
            err_msg
        );
        assert!(
            err_msg.contains("not-a-valid-key"),
            "Error should contain the invalid input, got: {}",
            err_msg
        );
    }

    #[test]
    fn combine_key_sources_string_that_is_a_path_returns_path_hint() {
        // Use a fixture key file — its path exists on disk, and passing the path
        // string as a base64 key will fail, triggering the path-detection hint.
        let file_path = fixtures_pub_key(0);

        let keys = vec![file_path.to_string_lossy().to_string()];
        let result = combine_key_sources::<AsfaloadPublicKeys>(&keys, &[]);
        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.contains("seems to be a path to a file"),
            "Expected path hint in error message, got: {}",
            err_msg
        );
        assert!(
            err_msg.contains("-file suffix"),
            "Expected flag hint in error message, got: {}",
            err_msg
        );
    }

    #[test]
    fn combine_key_sources_nonexistent_path_string_gives_parse_error_not_path_hint() {
        // A path-like string that does NOT exist on disk should not trigger the path hint
        let keys = vec!["/tmp/nonexistent_key_file_12345.pub".to_string()];
        let result = combine_key_sources::<AsfaloadPublicKeys>(&keys, &[]);
        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.contains("Failed to parse public key from string"),
            "Non-existent path should get generic parse error, got: {}",
            err_msg
        );
        assert!(
            !err_msg.contains("seems to be a path to a file"),
            "Non-existent path should NOT get path hint, got: {}",
            err_msg
        );
    }

    #[test]
    fn combine_key_sources_valid_file_key() {
        let key_file = fixtures_pub_key(0);

        let result = combine_key_sources::<AsfaloadPublicKeys>(&[], &[key_file]);
        match result {
            Ok(_) => {}
            Err(e) => panic!("Got unexpected error: {e}"),
        }
        let parsed = result.unwrap();
        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed[0].to_base64(), VALID_PUBKEY_B64);
    }

    #[test]
    fn combine_key_sources_nonexistent_file_returns_error() {
        let bad_path = PathBuf::from("/tmp/does_not_exist_key_12345.pub");
        let result = combine_key_sources::<AsfaloadPublicKeys>(&[], &[bad_path]);
        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.contains("Failed to read public key from file"),
            "Expected file read error, got: {}",
            err_msg
        );
    }

    #[test]
    fn combine_key_sources_invalid_file_content_returns_error() {
        let temp_dir = TempDir::new().unwrap();
        let key_file = temp_dir.path().join("bad.pub");
        std::fs::write(&key_file, "this is not a valid key file").unwrap();

        let result = combine_key_sources::<AsfaloadPublicKeys>(&[], &[key_file]);
        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.contains("Failed to read public key from file"),
            "Expected file parse error, got: {}",
            err_msg
        );
    }

    #[test]
    fn combine_key_sources_mix_of_string_and_file_keys() {
        let key_file = fixtures_pub_key(1);

        let string_keys = vec![VALID_PUBKEY_B64.to_string()];
        let file_keys = vec![key_file.clone()];

        let result = combine_key_sources::<AsfaloadPublicKeys>(&string_keys, &file_keys);
        match result {
            Ok(parsed) => {
                assert_eq!(parsed.len(), 2);
                assert_eq!(parsed[0].to_base64(), VALID_PUBKEY_B64);
                let key_from_file = AsfaloadPublicKeys::from_file(&key_file)
                    .expect("Failed to load key from file for assertion");
                assert_eq!(parsed[1].to_base64(), key_from_file.to_base64());
            }
            Err(e) => panic!("Expected Ok, but got error: {}", e),
        }
    }

    #[test]
    fn combine_key_sources_first_invalid_string_fails_entire_call() {
        // One valid + one invalid string key: should fail
        let keys = vec![VALID_PUBKEY_B64.to_string(), "garbage".to_string()];
        let result = combine_key_sources::<AsfaloadPublicKeys>(&keys, &[]);
        assert!(result.is_err());
    }

    #[test]
    fn combine_key_sources_file_with_multiple_valid_keys() {
        let key0_b64 = fs::read_to_string(fixtures_pub_key(0)).unwrap();
        let key1_b64 = fs::read_to_string(fixtures_pub_key(1)).unwrap();
        let key2_b64 = fs::read_to_string(fixtures_pub_key(2)).unwrap();

        let temp_dir = TempDir::new().unwrap();
        let multi_key_file = temp_dir.path().join("multi.pub");
        std::fs::write(
            &multi_key_file,
            format!(
                "{}\n{}\n{}",
                key0_b64.trim(),
                key1_b64.trim(),
                key2_b64.trim()
            ),
        )
        .unwrap();

        let result = combine_key_sources::<AsfaloadPublicKeys>(&[], &[multi_key_file]);
        assert!(result.is_ok(), "Expected Ok, got: {:?}", result.err());
        let parsed = result.unwrap();
        assert_eq!(parsed.len(), 3);
        assert_eq!(parsed[0].to_base64(), key0_b64.trim());
        assert_eq!(parsed[1].to_base64(), key1_b64.trim());
        assert_eq!(parsed[2].to_base64(), key2_b64.trim());
    }

    #[test]
    fn combine_key_sources_file_with_mixed_key_formats() {
        // Asfaload-format key from fixture
        let asfaload_line = fs::read_to_string(fixtures_pub_key(0)).unwrap();

        // SSH-format key from fixture
        let ssh_line =
            fs::read_to_string(test_helpers::fixtures_dir().join("git_signing_key.pub")).unwrap();

        let temp_dir = TempDir::new().unwrap();
        let mixed_file = temp_dir.path().join("mixed.pub");
        std::fs::write(
            &mixed_file,
            format!("{}\n{}", asfaload_line.trim(), ssh_line.trim()),
        )
        .unwrap();

        let result = combine_key_sources::<AsfaloadPublicKeys>(&[], &[mixed_file]);
        assert!(result.is_ok(), "Expected Ok, got: {:?}", result.err());
        let parsed = result.unwrap();
        assert_eq!(parsed.len(), 2);
        // to_base64() always returns asfaload-pub format regardless of input format
        assert_eq!(parsed[0].to_base64(), asfaload_line.trim());
        // The SSH-format key serialises back to asfaload-pub format
        let resolved =
            fs::read_to_string(test_helpers::fixtures_dir().join("git_signing_key.pub")).unwrap();
        let pk = AsfaloadPublicKeys::from_base64(resolved.trim()).unwrap();
        assert_eq!(parsed[1].to_base64(), pk.to_base64());
    }

    #[test]
    fn combine_key_sources_file_with_invalid_key_in_middle() {
        let key0_b64 = fs::read_to_string(fixtures_pub_key(0)).unwrap();
        let key1_b64 = fs::read_to_string(fixtures_pub_key(1)).unwrap();

        let temp_dir = TempDir::new().unwrap();
        let file_path = temp_dir.path().join("bad_middle.pub");
        std::fs::write(
            &file_path,
            format!("{}\nthis is garbage\n{}", key0_b64.trim(), key1_b64.trim()),
        )
        .unwrap();

        let result = combine_key_sources::<AsfaloadPublicKeys>(&[], &[file_path]);
        assert!(result.is_err(), "Expected error for invalid key in middle");
        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.contains("this is garbage"),
            "Error should mention the invalid line, got: {}",
            err_msg
        );
    }

    #[test]
    fn combine_key_sources_file_with_secret_key_names_file_and_offending_line() {
        // Fixture private key: passing it where public
        // keys are expected must fail, and the error must name the file and
        // the offending line.
        let secret_key_line = fs::read_to_string(fixtures_sec_key(0))
            .unwrap()
            .trim()
            .to_string();
        assert!(
            secret_key_line.starts_with(ASFALOAD_PRIV_PREFIX),
            "Fixture should hold a secret key, got: {}",
            secret_key_line
        );

        let key0_b64 = fs::read_to_string(fixtures_pub_key(0)).unwrap();

        let temp_dir = TempDir::new().unwrap();
        let file_path = temp_dir.path().join("with_secret_key.pub");
        std::fs::write(
            &file_path,
            format!("{}\n{}\n", key0_b64.trim(), secret_key_line),
        )
        .unwrap();

        let result =
            combine_key_sources::<AsfaloadPublicKeys>(&[], std::slice::from_ref(&file_path));
        let err_msg = match result {
            Err(e) => e.to_string(),
            Ok(keys) => panic!("Passing a secret key must fail, got ok value {:?}", keys),
        };
        assert!(
            err_msg.contains("Found a secret key"),
            "Expected secret key error message, got: {}",
            err_msg
        );
        assert!(
            err_msg.contains(file_path.display().to_string().as_str()),
            "Error should contain the file holding the secret key, got: {}",
            err_msg
        );
        assert!(
            err_msg.contains(&secret_key_line.chars().take(20).collect::<String>()),
            "Error should contain the start of the offending line, got: {}",
            err_msg
        );
        assert!(
            !err_msg.contains(secret_key_line.as_str()),
            "Error should not contain the whole line, to not leak secret keys. Got: {}",
            err_msg
        );
        assert!(
            !err_msg.contains(key0_b64.trim()),
            "Error should not point at the valid public key, got: {}",
            err_msg
        );
    }

    #[test]
    fn combine_key_sources_file_with_short_secret_key_line_does_not_panic() {
        // The error message shows the start of the offending line; a line
        // shorter than the truncation length must yield an error, not a panic.
        let temp_dir = TempDir::new().unwrap();
        let file_path = temp_dir.path().join("with_short_secret_key.pub");
        std::fs::write(&file_path, "asfaload-priv:abc\n").unwrap();

        let result =
            combine_key_sources::<AsfaloadPublicKeys>(&[], std::slice::from_ref(&file_path));
        let err_msg = match result {
            Err(e) => e.to_string(),
            Ok(keys) => panic!("Passing a secret key must fail, got ok value {:?}", keys),
        };
        assert!(
            err_msg.contains("Found a secret key"),
            "Expected secret key error message, got: {}",
            err_msg
        );
        assert!(
            err_msg.contains("asfaload-priv:abc"),
            "A short line is shown in full as it cannot be truncated further, got: {}",
            err_msg
        );
    }

    #[test]
    fn combine_key_sources_file_with_empty_lines() {
        let key0_b64 = fs::read_to_string(fixtures_pub_key(0)).unwrap();
        let key1_b64 = fs::read_to_string(fixtures_pub_key(1)).unwrap();

        let temp_dir = TempDir::new().unwrap();
        let file_path = temp_dir.path().join("with_blanks.pub");
        std::fs::write(
            &file_path,
            format!("{}\n\n{}\n\n", key0_b64.trim(), key1_b64.trim()),
        )
        .unwrap();

        let result = combine_key_sources::<AsfaloadPublicKeys>(&[], &[file_path]);
        assert!(
            result.is_ok(),
            "Expected Ok despite empty lines, got: {:?}",
            result.err()
        );
        let parsed = result.unwrap();
        assert_eq!(parsed.len(), 2);
        assert_eq!(parsed[0].to_base64(), key0_b64.trim());
        assert_eq!(parsed[1].to_base64(), key1_b64.trim());
    }

    #[test]
    fn combine_key_sources_file_with_duplicate_keys_is_accepted() {
        let key0_b64 = fs::read_to_string(fixtures_pub_key(0)).unwrap();

        let temp_dir = TempDir::new().unwrap();
        let file_path = temp_dir.path().join("dupes.pub");
        std::fs::write(
            &file_path,
            format!("{}\n{}", key0_b64.trim(), key0_b64.trim()),
        )
        .unwrap();

        let result = combine_key_sources::<AsfaloadPublicKeys>(&[], &[file_path]);
        assert!(
            result.is_ok(),
            "Duplicate keys are currently accepted, got: {:?}",
            result.err()
        );
        let parsed = result.unwrap();
        assert_eq!(parsed.len(), 2);
        assert_eq!(parsed[0].to_base64(), key0_b64.trim());
        assert_eq!(parsed[1].to_base64(), key0_b64.trim());
    }
}
