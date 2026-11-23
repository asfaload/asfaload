use std::io::IsTerminal;

use crate::{
    cli::{Cli, Commands, DEFAULT_BACKEND},
    commands::{
        alias::{
            add_alias, check_exists, delete_alias, delete_alias_of_key, delete_alias_pair,
            display_key, list_aliases, remove_alias_and_save_config,
        },
        complete::handle_complete,
        fetch_file::handle_fetch_file,
        shell::handle_shell_command,
    },
    error::ClientCliError,
    utils::{
        PasswordConfirmation::{RequireConfirmation, WithoutConfirmation},
        expected_digest, get_password, load_secret_key,
    },
};

pub mod alias;
pub mod keys;
pub mod list_pending;
pub mod share_key;
pub mod sign_pending;
pub mod signature_status;
pub mod signers_file;
use anyhow::Result;
use clap::ValueEnum;
use client_lib::{config::ConfigAccessor, paths::get_keys_dir};
use features_lib::{AsfaloadPublicKeyTrait, AsfaloadPublicKeys, AsfaloadSecretKeys};
use inquire::prompt_confirmation;
use rest_api_types::models::ClientPendingFile;

pub mod check_index;
pub mod check_pending_signers;
pub mod complete;
pub mod download;
pub mod fetch_file;
pub mod get_digest;
pub mod ping;
pub mod register_assets;
pub mod register_repo;
pub mod release_download_output;
pub mod release_registration_output;
pub mod revocation_output;
pub mod revoke;
pub mod shell;
pub mod signers_config_output;
pub mod signers_submission_output;
pub mod update_signers;

/// used by both `register-repo` and `update-signers`.
pub(crate) struct PreparedSignersSubmission {
    pub client: admin_lib::v1::Client,
    pub public_key: features_lib::AsfaloadPublicKeys,
    pub secret_key: features_lib::AsfaloadSecretKeys,
}

/// Create an API client.
/// The caller then decides which API endpoint to call with the result.
pub(crate) async fn prepare_signed_submission(
    backend_url: &str,
    secret_key: &AsfaloadSecretKeys,
) -> crate::error::Result<PreparedSignersSubmission> {
    let public_key = features_lib::AsfaloadPublicKeys::from_secret_key(secret_key)?;
    let client = admin_lib::v1::Client::new(backend_url);

    Ok(PreparedSignersSubmission {
        client,
        public_key,
        // FIXME: we might be able to work without this field, to be validated.
        secret_key: secret_key.clone(),
    })
}

pub(crate) mod keys_helpers {

    use anstyle::Style;
    const BOLD: Style = Style::new().bold();
    const UNDERLINE: Style = Style::new().underline();
    use std::fmt::Write;
    pub fn share_pub_key_message(public_key: &str, with_ansi: bool) -> anyhow::Result<String> {
        // Define conditional bolds un case we want non-ansi output, like in json
        let bold = if with_ansi { BOLD } else { Style::new() };
        let underline = if with_ansi { UNDERLINE } else { Style::new() };

        let mut buf = String::new();
        writeln!(
            buf,
            "{bold}The public key is safe to share{bold:#} -- that's how others verify your signatures."
        )?;
        writeln!(buf,)?;
        writeln!(
            buf,
            "{underline}You can share your public key, for example with an admin, with this message:{underline:#}"
        )?;
        writeln!(buf,)?;
        writeln!(
            buf,
            "    I have a key-pair to use with Asfaload. You can use my public"
        )?;
        writeln!(buf, "    key in signers files. Here it is:")?;
        writeln!(buf, "    {public_key}")?;
        writeln!(buf,)?;
        writeln!(
            buf,
            "    To refer to my key by a name, create an alias for it:"
        )?;
        // The name is last, so the recipient can copy the command and append it.
        writeln!(buf, "    asfaload-cli alias --key {public_key} <name>")?;
        Ok(buf)
    }
}

/// Dispatches the command to the appropriate handler
pub fn handle_command(cli: &Cli) -> Result<()> {
    match &cli.command {
        Commands::NewKeys {
            name,
            output_dir,
            password_args,
            accept_weak_password,
            json_args,
        } => {
            let password = get_password(
                password_args.password.clone(),
                password_args.password_file.as_deref(),
                password_args.password_command.clone(),
                &cli.command.password_env_var(),
                &cli.command.password_file_env_var(),
                "Enter password: ",
                RequireConfirmation,
                *accept_weak_password,
            )?;
            let keys_dir = get_keys_dir(output_dir)?;
            keys::handle_new_keys_command(name, keys_dir.as_ref(), password, json_args.json)?;
        }
        Commands::ShareKey {
            public_key,
            raw,
            json_args,
        } => {
            share_key::handle_share_key_command(public_key, *raw, json_args.json)?;
        }
        Commands::NewSignersFile {
            artifact_signer,
            artifact_signers_file,
            artifact_threshold,
            admin_key,
            admin_keys_file,
            admin_threshold,
            master_key,
            master_keys_file,
            master_threshold,
            revocation_key,
            revocation_keys_file,
            revocation_threshold,
            output_file,
            json_args,
            config_args,
        } => {
            let config_accessor = ConfigAccessor::new(&config_args.config_file);
            signers_file::handle_new_signers_file_command(
                artifact_signer,
                artifact_signers_file,
                *artifact_threshold,
                admin_key,
                admin_keys_file,
                admin_threshold.as_ref().copied(),
                master_key,
                master_keys_file,
                master_threshold.as_ref().copied(),
                revocation_key,
                revocation_keys_file,
                revocation_threshold.as_ref().copied(),
                output_file,
                json_args.json,
                &config_accessor,
            )?;
        }
        Commands::ListPending {
            secret_key_args,
            password_args,
            backend_url_args,
            json_args,
            digest_filter,
        } => {
            let password = get_password(
                password_args.password.clone(),
                password_args.password_file.as_deref(),
                password_args.password_command.clone(),
                &cli.command.password_env_var(),
                &cli.command.password_file_env_var(),
                "Enter password: ",
                WithoutConfirmation,
                true,
            )?;
            let url = backend_url_args
                .backend_url
                .clone()
                .unwrap_or_else(|| DEFAULT_BACKEND.to_string());
            let secret_key = load_secret_key(
                &secret_key_args.keys_dir,
                &secret_key_args.secret_key,
                &password,
            )?;
            let runtime = tokio::runtime::Runtime::new()?;
            runtime.block_on(list_pending::handle_list_pending_command(
                &url,
                &secret_key,
                digest_filter.digest_filter.clone(),
                json_args.json,
            ))?;
        }
        Commands::SignPending {
            file_path: file_path_in,
            secret_key_args,
            password_args,
            backend_url_args,
            digest_args,
            json_args,
        } => {
            let password = get_password(
                password_args.password.clone(),
                password_args.password_file.as_deref(),
                password_args.password_command.clone(),
                &cli.command.password_env_var(),
                &cli.command.password_file_env_var(),
                "Enter password: ",
                WithoutConfirmation,
                true,
            )?;
            let secret_key = load_secret_key(
                &secret_key_args.keys_dir,
                &secret_key_args.secret_key,
                &password,
            )?;
            let url = backend_url_args
                .backend_url
                .clone()
                .unwrap_or_else(|| DEFAULT_BACKEND.to_string());
            let digest_to_sign =
                expected_digest(digest_args.digest.clone(), digest_args.local_copy.clone())?;

            let runtime = tokio::runtime::Runtime::new()?;
            let pending_file = match file_path_in {
                Some(p) => ClientPendingFile::new(p.clone(), digest_to_sign),
                None => {
                    // need to select interactively as no path passed on command line.
                    // This path is currently not tested, but it uses tested components.
                    // Leaving as it for now as testing it would introduce some complexity that might
                    // not be worth it.
                    let client = admin_lib::v1::Client::new(url.clone());
                    let server_response =
                        runtime.block_on(client.get_pending_signatures(&secret_key))?;
                    let response = server_response.filter(&digest_to_sign);
                    // Inquired formats proposals according to the Display implementation for PendingFile,
                    let proposals = response.pending_files;

                    if proposals.is_empty() {
                        let error = if server_response.pending_files.is_empty() {
                            ClientCliError::NoPendingSignature
                        } else {
                            ClientCliError::NoPendingFileWithDigest(digest_to_sign)
                        };
                        return Err(anyhow::Error::new(error));
                    } else if std::io::stdin().is_terminal() {
                        match inquire::Select::new("File to sign", proposals).prompt() {
                            Ok(choice) => choice.unseal(),
                            Err(_) => {
                                return Err(anyhow::Error::new(ClientCliError::InvalidInput(
                                    "Selection cancelled or failed: no path to sign was provided"
                                        .into(),
                                )));
                            }
                        }
                    } else {
                        return Err(anyhow::Error::msg(
                            "Not a tty and no path to sign was passed.",
                        ));
                    }
                }
            };
            runtime.block_on(sign_pending::handle_sign_pending_sec_key(
                pending_file,
                &url,
                &secret_key,
                json_args.json,
            ))?;
        }
        Commands::SignatureStatus {
            file_path,
            secret_key_args,
            password_args,
            backend_url_args,
            json_args,
            config_args,
        } => {
            let password = get_password(
                password_args.password.clone(),
                password_args.password_file.as_deref(),
                password_args.password_command.clone(),
                &cli.command.password_env_var(),
                &cli.command.password_file_env_var(),
                "Enter password: ",
                WithoutConfirmation,
                true,
            )?;
            let url = backend_url_args
                .backend_url
                .clone()
                .unwrap_or_else(|| DEFAULT_BACKEND.to_string());

            let secret_key = load_secret_key(
                &secret_key_args.keys_dir,
                &secret_key_args.secret_key,
                &password,
            )?;
            let runtime = tokio::runtime::Runtime::new()?;
            runtime.block_on(signature_status::handle_signature_status_command(
                file_path,
                &url,
                &secret_key,
                json_args.json,
                &ConfigAccessor::new(&config_args.config_file),
            ))?;
        }
        Commands::RegisterRepo {
            signers_file_url,
            digest,
            local_copy,
            secret_key_args,
            password_args,
            backend_url_args,
            json_args,
            config_args,
        } => {
            // First check valid digest was provided
            let expected_digest = expected_digest(digest.clone(), local_copy.clone())?;
            let password = get_password(
                password_args.password.clone(),
                password_args.password_file.as_deref(),
                password_args.password_command.clone(),
                &cli.command.password_env_var(),
                &cli.command.password_file_env_var(),
                "Enter password: ",
                WithoutConfirmation,
                true,
            )?;
            let url = backend_url_args
                .backend_url
                .clone()
                .unwrap_or_else(|| DEFAULT_BACKEND.to_string());
            let secret_key = load_secret_key(
                &secret_key_args.keys_dir,
                &secret_key_args.secret_key,
                &password,
            )?;

            let runtime = tokio::runtime::Runtime::new()?;
            runtime.block_on(register_repo::handle_register_repo_command(
                &url,
                signers_file_url,
                &expected_digest,
                &secret_key,
                json_args.json,
                &ConfigAccessor::new(&config_args.config_file),
            ))?;
        }
        Commands::RegisterAssets {
            github_release_url,
            csum_file,
            secret_key_args,
            password_args,
            backend_url_args,
            json_args,
            config_args,
        } => {
            let password = get_password(
                password_args.password.clone(),
                password_args.password_file.as_deref(),
                password_args.password_command.clone(),
                &cli.command.password_env_var(),
                &cli.command.password_file_env_var(),
                "Enter password: ",
                WithoutConfirmation,
                true,
            )?;
            let backend = backend_url_args
                .backend_url
                .clone()
                .unwrap_or_else(|| DEFAULT_BACKEND.to_string());

            let mode = register_assets::determine_registration_mode(github_release_url, csum_file)?;
            let secret_key = load_secret_key(
                &secret_key_args.keys_dir,
                &secret_key_args.secret_key,
                &password,
            )?;

            let runtime = tokio::runtime::Runtime::new()?;
            runtime.block_on(register_assets::handle_register_assets_command(
                &backend,
                mode,
                &secret_key,
                json_args.json,
                &ConfigAccessor::new(&config_args.config_file),
            ))?;
        }
        Commands::UpdateSigners {
            signers_file_url,
            digest,
            local_copy,
            secret_key_args,
            password_args,
            backend_url_args,
            json_args,
            config_args,
        } => {
            // First check valid digest was provided
            let expected_digest = expected_digest(digest.clone(), local_copy.clone())?;
            let password = get_password(
                password_args.password.clone(),
                password_args.password_file.as_deref(),
                password_args.password_command.clone(),
                &cli.command.password_env_var(),
                &cli.command.password_file_env_var(),
                "Enter password: ",
                WithoutConfirmation,
                true,
            )?;
            let url = backend_url_args
                .backend_url
                .clone()
                .unwrap_or_else(|| DEFAULT_BACKEND.to_string());
            let secret_key = load_secret_key(
                &secret_key_args.keys_dir,
                &secret_key_args.secret_key,
                &password,
            )?;

            let runtime = tokio::runtime::Runtime::new()?;
            runtime.block_on(update_signers::handle_update_signers_command(
                &url,
                signers_file_url,
                &expected_digest,
                &secret_key,
                json_args.json,
                &ConfigAccessor::new(&config_args.config_file),
            ))?;
        }
        Commands::Revoke {
            file_path,
            secret_key_args,
            password_args,
            backend_url_args,
            digest_args,
            json_args,
            config_args,
        } => {
            let password = get_password(
                password_args.password.clone(),
                password_args.password_file.as_deref(),
                password_args.password_command.clone(),
                &cli.command.password_env_var(),
                &cli.command.password_file_env_var(),
                "Enter password: ",
                WithoutConfirmation,
                true,
            )?;
            let url = backend_url_args
                .backend_url
                .clone()
                .unwrap_or_else(|| DEFAULT_BACKEND.to_string());
            let expected_digest =
                expected_digest(digest_args.digest.clone(), digest_args.local_copy.clone())?;
            let secret_key = load_secret_key(
                &secret_key_args.keys_dir,
                &secret_key_args.secret_key,
                &password,
            )?;

            let runtime = tokio::runtime::Runtime::new()?;
            runtime.block_on(revoke::handle_revoke_command(
                &url,
                file_path,
                &secret_key,
                &expected_digest,
                json_args.json,
                &ConfigAccessor::new(&config_args.config_file),
            ))?;
        }
        Commands::Ping {
            secret_key,
            keys_dir,
            password_args,
            backend_url_args,
            json_args,
        } => {
            // The password is only needed when a secret key is used
            let secret_key = match secret_key {
                Some(name) => {
                    let password = get_password(
                        password_args.password.clone(),
                        password_args.password_file.as_deref(),
                        password_args.password_command.clone(),
                        &cli.command.password_env_var(),
                        &cli.command.password_file_env_var(),
                        "Enter password: ",
                        WithoutConfirmation,
                        true,
                    )?;
                    Some(load_secret_key(keys_dir, name, &password)?)
                }
                None => None,
            };
            let url = backend_url_args
                .backend_url
                .clone()
                .unwrap_or_else(|| DEFAULT_BACKEND.to_string());
            let runtime = tokio::runtime::Runtime::new()?;
            runtime.block_on(ping::handle_ping_command(
                &url,
                secret_key.as_ref(),
                json_args.json,
            ))?;
        }
        Commands::Download {
            file_url,
            output,
            backend_url_args,
            forge_type_args,
        } => {
            let url = backend_url_args
                .backend_url
                .clone()
                .unwrap_or_else(|| DEFAULT_BACKEND.to_string());
            let forge_type_str = forge_type_args.forge_type.as_ref().map(|ft| ft.as_str());
            let runtime = tokio::runtime::Runtime::new()?;
            runtime.block_on(download::handle_download_command(
                file_url,
                output.as_ref(),
                &url,
                forge_type_str,
            ))?;
        }
        Commands::GetDigest { file, json_args } => {
            let runtime = tokio::runtime::Runtime::new()?;
            runtime.block_on(get_digest::handle_get_digest_command(file, json_args.json))?;
        }
        Commands::CheckIndex {
            index_path,
            backend_url_args,
            json_args,
        } => {
            let url = backend_url_args
                .backend_url
                .clone()
                .unwrap_or_else(|| DEFAULT_BACKEND.to_string());
            let runtime = tokio::runtime::Runtime::new()?;
            runtime.block_on(check_index::handle_check_index_command(
                index_path,
                &url,
                json_args.json,
            ))?;
        }
        Commands::CheckPendingSigners {
            signers_path,
            backend_url_args,
            json_args,
            config_args,
        } => {
            let url = backend_url_args
                .backend_url
                .clone()
                .unwrap_or_else(|| DEFAULT_BACKEND.to_string());
            let runtime = tokio::runtime::Runtime::new()?;
            runtime.block_on(check_pending_signers::handle_check_pending_signers_command(
                signers_path,
                &url,
                json_args.json,
                &ConfigAccessor::new(&config_args.config_file),
            ))?;
        }
        Commands::FetchFile {
            path,
            output,
            backend_url_args,
            json_args,
        } => {
            let backend_url = backend_url_args
                .backend_url
                .clone()
                .unwrap_or_else(|| DEFAULT_BACKEND.to_string());
            let runtime = tokio::runtime::Runtime::new()?;
            runtime.block_on(handle_fetch_file(
                path,
                output,
                &backend_url,
                json_args.json,
            ))?;
        }
        Commands::Complete { shell, output } => {
            let shell_value = clap_complete_command::Shell::from_str(shell, true)
                .map_err(|e| ClientCliError::InvalidInput(format!("shell not known:{e}")))?;
            let mut writer: Box<dyn std::io::Write> = match output {
                Some(path) => Box::new(std::fs::File::create(path)?),
                None => Box::new(std::io::stdout()),
            };
            handle_complete(shell_value, &mut writer)?;
        }
        Commands::Shell { shell } => {
            let exit_code = handle_shell_command(*shell)?;
            // process::exit does not run destructors. This is safe here because
            // handle_shell_command already removed its temporary directory.
            if exit_code != 0 {
                std::process::exit(exit_code);
            }
        }
        Commands::Alias {
            name,
            key,
            config_args,
            force,
            delete,
            json_args,
        } => {
            let json = json_args.json;
            let pub_key = key
                .as_deref()
                .map(AsfaloadPublicKeys::from_base64)
                .transpose()?;
            let confirm_deletion = |name: &str| -> Result<bool> {
                // Without this check, inquire reads the answer from /dev/tty, not from stdin.
                if !std::io::stdin().is_terminal() {
                    return Err(anyhow::Error::new(ClientCliError::InvalidInput(
                        "Stdin is not a terminal: use --force to delete without confirmation"
                            .into(),
                    )));
                }
                Ok(prompt_confirmation(format!(
                    "Are you sure you want to delete alias {name}?"
                ))?)
            };
            let canceled_string = |b: bool| {
                if b {
                    "{\"canceled\": true}".to_string()
                } else {
                    "Canceled".to_string()
                }
            };
            let mut config_accessor = ConfigAccessor::new(&config_args.config_file);
            let output = match (name, &pub_key, delete, force) {
                (None, None, _, _) => list_aliases(&config_accessor, &None, json)?,
                (Some(_), None, false, _) => list_aliases(&config_accessor, name, json)?,
                (Some(n), None, true, true) => delete_alias(&mut config_accessor, n, json)?,
                (Some(n), None, true, false) => {
                    let name = check_exists(&config_accessor, name.as_deref(), &pub_key)?;
                    if confirm_deletion(n)? {
                        remove_alias_and_save_config(&mut config_accessor, &name, json)?
                    } else {
                        canceled_string(json_args.json)
                    }
                }
                (None, Some(k), false, _) => display_key(&config_accessor, k, json)?,
                (None, Some(k), true, true) => delete_alias_of_key(&mut config_accessor, k, json)?,
                (None, Some(_), true, false) => {
                    let name = check_exists(&config_accessor, name.as_deref(), &pub_key)?;
                    if confirm_deletion(&name)? {
                        remove_alias_and_save_config(&mut config_accessor, &name, json)?
                    } else {
                        canceled_string(json_args.json)
                    }
                }
                (Some(n), Some(k), false, _) => {
                    add_alias(&mut config_accessor, k, n, *force, json)?
                }
                (Some(n), Some(k), true, true) => {
                    delete_alias_pair(&mut config_accessor, k, n, json)?
                }
                (Some(n), Some(_k), true, false) => {
                    check_exists(&config_accessor, name.as_deref(), &pub_key)?;
                    if confirm_deletion(n)? {
                        remove_alias_and_save_config(&mut config_accessor, n, json)?
                    } else {
                        canceled_string(json_args.json)
                    }
                }
            };
            println!("{}", output);
        }
        Commands::Manual { command } => {
            crate::manual::show(command.as_deref().unwrap_or(crate::manual::INDEX_PAGE))?;
        }
    }
    Ok(())
}
