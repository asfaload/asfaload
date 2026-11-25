use std::path::Path;

use crate::commands::keys_helpers::share_pub_key_message;
use crate::output::NewKeysOutput;
use crate::utils::ensure_private_dir_exists;
use anstream::println;
use anstyle::{AnsiColor, Color, Style};
use anyhow::Result;
use features_lib::{AsfaloadKeyPairTrait, AsfaloadKeyPairs, AsfaloadPublicKeyTrait};

const BOLD: Style = Style::new().bold();
const DIM: Style = Style::new().dimmed();
const WARN: Style = Style::new()
    .bold()
    .fg_color(Some(Color::Ansi(AnsiColor::Red)));

/// Fails if a key file for `name` exists in `keys_dir`, so that the user does not type a password
/// for nothing. `save` checks again when it writes the files.
pub fn ensure_new_key_absent(keys_dir: &Path, name: &str) -> Result<()> {
    let secret_key_path = keys_dir.join(name);
    let public_key_path = keys_dir.join(format!("{name}.pub"));
    for path in [secret_key_path, public_key_path] {
        if path.exists() {
            anyhow::bail!(
                "Refusing to write key to existing file {}",
                path.to_string_lossy()
            );
        }
    }
    Ok(())
}

/// Handles the `keys` command.
///
/// # Arguments
/// * `name` - The name of the key
/// * `output_dir` - The directory to store the key
/// * `password` - Password to protect the secret key
/// * `json` - Whether to output results as JSON
///
/// # Returns
/// * `Result<()>` - Ok if the command was handled successfully, Err otherwise
pub fn handle_new_keys_command(
    name: &str,
    output_dir: &Path,
    password: String,
    json: bool,
) -> Result<()> {
    ensure_private_dir_exists(output_dir)?;

    let kp = AsfaloadKeyPairs::new(password.as_str())?;
    let location = output_dir.join(name);
    kp.save(&location)?;

    let public_key = kp.public_key().to_base64();

    if json {
        let output = NewKeysOutput {
            public_key_path: format!("{}.pub", location.to_string_lossy()),
            secret_key_path: location.to_string_lossy().to_string(),
            public_key,
        };
        println!("{}", serde_json::to_string(&output)?);
    } else {
        let message = share_pub_key_message(&public_key, true)?;
        let sec_path = location.to_string_lossy();
        let pub_path = format!("{sec_path}.pub");

        println!("{BOLD}Generated keypair '{name}'{BOLD:#}");
        println!();
        println!("  {BOLD}Public key string:{BOLD:#}  {BOLD}{public_key}{BOLD:#}");
        println!("  {BOLD}Public key file:{BOLD:#} {DIM}{pub_path}{DIM:#}");
        println!("  {BOLD}Secret key file:{BOLD:#} {DIM}{sec_path}{DIM:#}");
        println!();
        println!(
            "{WARN}WARNING:{WARN:#} Keep the secret key private. Treat it like a password -- never share, copy, or commit it."
        );
        println!("{}", message);
    }
    Ok(())
}
