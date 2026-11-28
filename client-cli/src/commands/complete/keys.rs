//! Completion of key names and aliases, added to the scripts that clap generates.
//!
//! The completion is in shell code only: lister.sh prints the candidates, and each shell
//! script embeds it and runs it with `sh`. Thus completion never calls asfaload-cli.

use clap::{Arg, Args, Command};
use features_lib::{
    ASFALOAD_PRIV_PREFIX, ASFALOAD_PUB_PREFIX, OPENSSH_PRIVATE_KEY_PEM_HEADER, SSH_ED25519_PREFIX,
};

use crate::{
    cli::{ConfigFile, KeysDirArgs},
    commands::list_keys::HEAD_SIZE,
    error::{ClientCliError, Result},
};

const LISTER: &str = include_str!("lister.sh");
const BASH_TEMPLATE: &str = include_str!("keys.bash");
const ZSH_TEMPLATE: &str = include_str!("keys.zsh");
const FISH_TEMPLATE: &str = include_str!("keys.fish");

const SECRET_KEY_ID: &str = "secret_key";
// The options that accept an alias have this value name.
const ALIAS_VALUE_NAME: &str = "PUB_KEY";
const KEYS_DIR_ID: &str = "keys_dir";
const CONFIG_FILE_ID: &str = "config_file";
// (subcommand, positional arg id, mode)
const KEY_POSITIONALS: [(&str, &str, Mode); 2] = [
    ("share-key", "public_key", Mode::Pairs),
    ("keys", "name", Mode::Names),
];

/// The candidates that lister.sh prints.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Mode {
    /// Secret key files.
    Secret,
    /// Names X of the secret key files X that have a public key file X.pub.
    Pairs,
    /// Key files and alias names.
    Names,
    /// Alias names.
    Aliases,
}

impl Mode {
    fn as_str(self) -> &'static str {
        match self {
            Mode::Secret => "secret",
            Mode::Pairs => "pairs",
            Mode::Names => "names",
            Mode::Aliases => "aliases",
        }
    }
}

/// An option of a subcommand whose value is a key name or an alias.
#[derive(Debug, PartialEq)]
struct KeyOption {
    subcommand: String,
    flags: Vec<String>,
    mode: Mode,
}

/// The first positional of a subcommand, when its value is a key name.
#[derive(Debug, PartialEq)]
struct KeyPositional {
    subcommand: String,
    id: String,
    mode: Mode,
    /// Flags of the options of the subcommand that take a value.
    value_options: Vec<String>,
}

/// An option that gives a location, e.g. --keys-dir.
#[derive(Debug, PartialEq)]
struct LocationOption {
    short: String,
    long: String,
    env: String,
}

#[derive(Debug, PartialEq)]
struct KeyArgs {
    options: Vec<KeyOption>,
    positionals: Vec<KeyPositional>,
    keys_dir: LocationOption,
    config_file: LocationOption,
}

fn script_error(message: impl Into<String>) -> ClientCliError {
    ClientCliError::CompletionScript(message.into())
}

// The flags of an option, e.g. ["-K", "--secret-key"].
fn flags(arg: &Arg) -> Vec<String> {
    arg.get_short()
        .map(|c| format!("-{c}"))
        .into_iter()
        .chain(arg.get_long().map(|l| format!("--{l}")))
        .collect()
}

fn takes_value_option(arg: &Arg) -> bool {
    !arg.is_positional() && arg.get_action().takes_values()
}

fn key_option_mode(arg: &Arg) -> Option<Mode> {
    if arg.is_positional() {
        None
    } else if arg.get_id() == SECRET_KEY_ID {
        Some(Mode::Secret)
    } else if arg
        .get_value_names()
        .is_some_and(|names| names.iter().any(|n| n == ALIAS_VALUE_NAME))
    {
        Some(Mode::Aliases)
    } else {
        None
    }
}

fn location_option(cmd: Command, id: &str) -> Result<LocationOption> {
    let arg = cmd
        .get_arguments()
        .find(|a| a.get_id() == id)
        .ok_or_else(|| script_error(format!("no argument {id}")))?;
    let long = arg
        .get_long()
        .map(|l| format!("--{l}"))
        .ok_or_else(|| script_error(format!("argument {id} has no long flag")))?;
    // Without a short flag, the long flag takes its place in the shell functions.
    let short = arg
        .get_short()
        .map(|c| format!("-{c}"))
        .unwrap_or_else(|| long.clone());
    let env = arg
        .get_env()
        .and_then(|e| e.to_str())
        .ok_or_else(|| script_error(format!("argument {id} has no environment variable")))?
        .to_string();
    Ok(LocationOption { short, long, env })
}

fn key_args(cmd: &Command) -> Result<KeyArgs> {
    let mut options = Vec::new();
    for subcommand in cmd.get_subcommands() {
        for arg in subcommand.get_arguments() {
            if let Some(mode) = key_option_mode(arg) {
                options.push(KeyOption {
                    subcommand: subcommand.get_name().to_string(),
                    flags: flags(arg),
                    mode,
                });
            }
        }
    }
    let positionals = KEY_POSITIONALS
        .iter()
        .map(|(name, id, mode)| {
            let subcommand = cmd
                .find_subcommand(name)
                .ok_or_else(|| script_error(format!("no subcommand {name}")))?;
            let first_positional = subcommand.get_positionals().next();
            if first_positional.is_none_or(|a| a.get_id() != *id) {
                return Err(script_error(format!(
                    "{id} is not the first positional of {name}"
                )));
            }
            Ok(KeyPositional {
                subcommand: name.to_string(),
                id: id.to_string(),
                mode: *mode,
                value_options: subcommand
                    .get_arguments()
                    .filter(|a| takes_value_option(a))
                    .flat_map(flags)
                    .collect(),
            })
        })
        .collect::<Result<Vec<_>>>()?;
    Ok(KeyArgs {
        options,
        positionals,
        keys_dir: location_option(KeysDirArgs::augment_args(Command::new("k")), KEYS_DIR_ID)?,
        config_file: location_option(ConfigFile::augment_args(Command::new("c")), CONFIG_FILE_ID)?,
    })
}

fn lister(key_args: &KeyArgs) -> String {
    LISTER
        .replace("@KEYS_DIR_ENV@", &key_args.keys_dir.env)
        .replace("@CONFIG_FILE_ENV@", &key_args.config_file.env)
        .replace("@HEAD_SIZE@", &HEAD_SIZE.to_string())
        .replace("@PRIV_PREFIX@", ASFALOAD_PRIV_PREFIX)
        .replace("@OPENSSH_HEADER@", OPENSSH_PRIVATE_KEY_PEM_HEADER)
        .replace("@PUB_PREFIX@", ASFALOAD_PUB_PREFIX)
        .replace("@SSH_PREFIX@", SSH_ED25519_PREFIX)
}

// Content for a single-quoted string in bash or zsh.
fn posix_single_quoted(s: &str) -> String {
    s.replace('\'', r"'\''")
}

// Content for a single-quoted string in fish.
fn fish_single_quoted(s: &str) -> String {
    s.replace('\\', r"\\").replace('\'', r"\'")
}

fn with_locations(template: &str, key_args: &KeyArgs) -> String {
    template
        .replace("@KEYS_DIR_SHORT@", &key_args.keys_dir.short)
        .replace("@KEYS_DIR_LONG@", &key_args.keys_dir.long)
        .replace("@CONFIG_FILE_SHORT@", &key_args.config_file.short)
        .replace("@CONFIG_FILE_LONG@", &key_args.config_file.long)
}

/// Adds key completion to the bash script of clap. `bin_name` is the name of the binary.
fn bash_with_keys(script: &str, bin_name: &str, key_args: &KeyArgs) -> Result<String> {
    let clap_function = format!("_{}", bin_name.replace('-', "__"));
    if !script.contains(&format!("{clap_function}() {{")) {
        return Err(script_error(format!(
            "bash script has no function {clap_function}"
        )));
    }
    let option_cases: String = key_args
        .options
        .iter()
        .map(|o| {
            let patterns: Vec<String> = o
                .flags
                .iter()
                .map(|f| format!("\"{} {f}\"", o.subcommand))
                .collect();
            format!(
                "        {}) echo {} ;;\n",
                patterns.join(" | "),
                o.mode.as_str()
            )
        })
        .collect();
    let positional_cases: String = key_args
        .positionals
        .iter()
        .map(|p| {
            format!(
                "        {}) mode={}; value_options=\" {} \" ;;\n",
                p.subcommand,
                p.mode.as_str(),
                p.value_options.join(" ")
            )
        })
        .collect();
    let keys = with_locations(BASH_TEMPLATE, key_args)
        .replace("@OPTION_CASES@\n", &option_cases)
        .replace("@POSITIONAL_CASES@\n", &positional_cases)
        .replace("@WRAPPER@", &format!("{clap_function}_keys"))
        .replace("@CLAP_FUNCTION@", &clap_function)
        .replace("@BIN@", bin_name)
        .replace("@LISTER@", &posix_single_quoted(&lister(key_args)));
    Ok(format!("{script}{keys}"))
}

// The lines of the case block of a subcommand in the zsh script: from the line `(name)` to the
// next line `;;`. The first block is the one of the subcommand, the next ones are in `help`.
fn zsh_block(lines: &[String], subcommand: &str) -> Result<std::ops::Range<usize>> {
    let label = format!("({subcommand})");
    let start = lines
        .iter()
        .position(|l| l.trim() == label)
        .ok_or_else(|| script_error(format!("zsh script has no block {label}")))?;
    let end = lines[start..]
        .iter()
        .position(|l| l.trim() == ";;")
        .map(|i| start + i)
        .ok_or_else(|| script_error(format!("zsh block {label} has no end")))?;
    Ok(start..end)
}

// True when the zsh spec `line` is for one of `flags`, e.g. '*-a+[help]:PUB_KEY:_default' \
fn is_zsh_option_spec(line: &str, flags: &[String]) -> bool {
    let spec = line.trim_start_matches('\'');
    // Remove the exclusion list, e.g. (--json), and the repetition mark.
    let spec = match spec.strip_prefix('(') {
        Some(rest) => rest.split_once(')').map_or(rest, |(_, s)| s),
        None => spec,
    };
    let spec = spec.trim_start_matches('*');
    flags
        .iter()
        .any(|f| spec.starts_with(&format!("{f}+[")) || spec.starts_with(&format!("{f}=[")))
}

fn is_zsh_positional_spec(line: &str, id: &str) -> bool {
    line.starts_with(&format!("':{id} -- ")) || line.starts_with(&format!("'::{id} -- "))
}

// Replaces the default action of the matching specs of the block of `subcommand`.
fn patch_zsh_block(
    lines: &mut [String],
    subcommand: &str,
    mode: Mode,
    is_target: impl Fn(&str) -> bool,
) -> Result<()> {
    const DEFAULT_ACTION: &str = ":_default' \\";
    let range = zsh_block(lines, subcommand)?;
    let mut patched = 0;
    for line in &mut lines[range] {
        if is_target(line) && line.ends_with(DEFAULT_ACTION) {
            let spec = &line[..line.len() - DEFAULT_ACTION.len()];
            *line = format!("{spec}:__asfaload_cli_keys {}' \\", mode.as_str());
            patched += 1;
        }
    }
    if patched == 0 {
        return Err(script_error(format!(
            "zsh block ({subcommand}) has no spec to patch for {}",
            mode.as_str()
        )));
    }
    Ok(())
}

/// Adds key completion to the zsh script of clap. `bin_name` is the name of the binary.
fn zsh_with_keys(script: &str, bin_name: &str, key_args: &KeyArgs) -> Result<String> {
    let mut lines: Vec<String> = script.lines().map(str::to_string).collect();
    for option in &key_args.options {
        patch_zsh_block(&mut lines, &option.subcommand, option.mode, |l| {
            is_zsh_option_spec(l, &option.flags)
        })?;
    }
    for positional in &key_args.positionals {
        patch_zsh_block(&mut lines, &positional.subcommand, positional.mode, |l| {
            is_zsh_positional_spec(l, &positional.id)
        })?;
    }
    // With autoload, the file runs at each completion: our function must exist before the
    // call at the end of the file.
    let call = format!("if [ \"$funcstack[1]\" = \"_{bin_name}\" ]; then");
    let call_index = lines
        .iter()
        .position(|l| *l == call)
        .ok_or_else(|| script_error("zsh script has no final call"))?;
    let keys = with_locations(ZSH_TEMPLATE, key_args)
        .replace("@LISTER@", &posix_single_quoted(&lister(key_args)));
    lines.insert(call_index, keys);
    Ok(lines.join("\n") + "\n")
}

/// Adds key completion to the fish script of clap. `bin_name` is the name of the binary.
fn fish_with_keys(script: &str, bin_name: &str, key_args: &KeyArgs) -> Result<String> {
    let using_subcommand = format!("__fish_{}_using_subcommand", bin_name.replace('-', "_"));
    if !script.contains(&format!("function {using_subcommand}")) {
        return Err(script_error(format!(
            "fish script has no function {using_subcommand}"
        )));
    }
    let option_lines = key_args.options.iter().map(|o| {
        let flags: Vec<String> = o
            .flags
            .iter()
            .map(|f| match f.strip_prefix("--") {
                Some(long) => format!("-l {long}"),
                None => format!("-s {}", f.trim_start_matches('-')),
            })
            .collect();
        // An alias is not a path.
        let files = if o.mode == Mode::Aliases { "-x" } else { "-r" };
        format!(
            "complete -c {bin_name} -n \"{using_subcommand} {}\" {} {files} -a \"(__asfaload_cli_keys {})\"",
            o.subcommand,
            flags.join(" "),
            o.mode.as_str()
        )
    });
    let positional_lines = key_args.positionals.iter().map(|p| {
        format!(
            "complete -c {bin_name} -n \"{using_subcommand} {}; and __asfaload_cli_first_positional {}\" -a \"(__asfaload_cli_keys {})\"",
            p.subcommand,
            p.value_options.join(" "),
            p.mode.as_str()
        )
    });
    let complete_lines: Vec<String> = option_lines.chain(positional_lines).collect();
    let keys = with_locations(FISH_TEMPLATE, key_args)
        .replace("@COMPLETE_LINES@", &complete_lines.join("\n"))
        .replace("@LISTER@", &fish_single_quoted(&lister(key_args)));
    Ok(format!("{script}{keys}"))
}

/// Adds the completion of key names and aliases to `script`, the script that clap generated
/// for `shell` from `cmd`.
pub(super) fn with_key_completion(
    shell: clap_complete_command::Shell,
    script: &str,
    cmd: &Command,
) -> Result<String> {
    let key_args = key_args(cmd)?;
    let bin_name = cmd.get_name();
    match shell {
        clap_complete_command::Shell::Bash => bash_with_keys(script, bin_name, &key_args),
        clap_complete_command::Shell::Zsh => zsh_with_keys(script, bin_name, &key_args),
        clap_complete_command::Shell::Fish => fish_with_keys(script, bin_name, &key_args),
        _ => Ok(script.to_string()),
    }
}

#[cfg(test)]
mod tests {
    use clap::CommandFactory;

    use super::*;
    use crate::{cli::Cli, commands::complete::handle_complete};

    fn cli_key_args() -> KeyArgs {
        key_args(&Cli::command()).unwrap()
    }

    #[test]
    fn key_args_finds_the_key_arguments_of_the_cli() {
        let key_args = cli_key_args();
        let option = |subcommand: &str, flag: &str| {
            key_args
                .options
                .iter()
                .find(|o| o.subcommand == subcommand && o.flags.iter().any(|f| f == flag))
                .map(|o| o.mode)
        };
        let cases = vec![
            ("sign-pending", "-K", Some(Mode::Secret)),
            ("sign-pending", "--secret-key", Some(Mode::Secret)),
            ("ping", "--secret-key", Some(Mode::Secret)),
            ("new-signers-file", "-a", Some(Mode::Aliases)),
            ("new-signers-file", "--admin-key", Some(Mode::Aliases)),
            ("new-signers-file", "-m", Some(Mode::Aliases)),
            ("new-signers-file", "--revocation-key", Some(Mode::Aliases)),
            ("new-signers-file", "--artifact-signers-file", None),
            ("alias", "--key", None),
            ("share-key", "--keys-dir", None),
        ];
        for (subcommand, flag, expected) in cases {
            assert_eq!(option(subcommand, flag), expected, "{subcommand} {flag}");
        }
        assert_eq!(
            key_args.positionals,
            vec![
                KeyPositional {
                    subcommand: "share-key".to_string(),
                    id: "public_key".to_string(),
                    mode: Mode::Pairs,
                    value_options: vec!["--keys-dir".to_string()],
                },
                KeyPositional {
                    subcommand: "keys".to_string(),
                    id: "name".to_string(),
                    mode: Mode::Names,
                    value_options: ["--keys-dir", "-c", "--config-file"]
                        .map(String::from)
                        .to_vec(),
                },
            ]
        );
        assert_eq!(
            key_args.keys_dir,
            LocationOption {
                short: "--keys-dir".to_string(),
                long: "--keys-dir".to_string(),
                env: crate::cli::KEYS_DIR_ENV_VAR.to_string(),
            }
        );
        assert_eq!(key_args.config_file.long, "--config-file");
    }

    #[test]
    fn key_args_fails_without_a_key_positional() {
        let cmd = Command::new("asfaload-cli").subcommand(Command::new("keys"));
        assert!(matches!(
            key_args(&cmd),
            Err(ClientCliError::CompletionScript(_))
        ));
    }

    #[test]
    fn quoting_for_single_quoted_strings() {
        let cases = vec![
            ("plain", "plain", "plain"),
            ("it's", r"it'\''s", r"it\'s"),
            (r"tr -d '\000'", r"tr -d '\''\000'\''", r"tr -d \'\\000\'"),
        ];
        for (input, posix, fish) in cases {
            assert_eq!(posix_single_quoted(input), posix, "{input}");
            assert_eq!(fish_single_quoted(input), fish, "{input}");
        }
    }

    #[test]
    fn is_zsh_option_spec_matches_the_flags_only() {
        let flags = ["-K".to_string(), "--secret-key".to_string()];
        let cases = vec![
            ("'-K+[help]:SECRET_KEY:_default' \\", true),
            ("'--secret-key=[help]:SECRET_KEY:_default' \\", true),
            ("'*-K+[help]:SECRET_KEY:_default' \\", true),
            ("'(--json)-K+[help]:SECRET_KEY:_default' \\", true),
            ("'-Kx+[help]:X:_default' \\", false),
            ("'--secret-key-file=[help]:X:_default' \\", false),
            ("'-d+[help]:KEYS_DIR:_files' \\", false),
            ("':public_key -- help:_default' \\", false),
        ];
        for (line, expected) in cases {
            assert_eq!(is_zsh_option_spec(line, &flags), expected, "{line}");
        }
    }

    #[test]
    fn missing_patch_points_are_errors() {
        let key_args = cli_key_args();
        let results = vec![
            (
                "bash",
                bash_with_keys("other() {\n}\n", "asfaload-cli", &key_args),
            ),
            (
                "zsh",
                zsh_with_keys("(keys)\n;;\n", "asfaload-cli", &key_args),
            ),
            (
                "fish",
                fish_with_keys("complete -c x\n", "asfaload-cli", &key_args),
            ),
        ];
        for (shell, result) in results {
            assert!(
                matches!(result, Err(ClientCliError::CompletionScript(_))),
                "{shell}: {result:?}"
            );
        }
    }

    fn script(shell: clap_complete_command::Shell) -> String {
        let mut output = Vec::new();
        handle_complete(shell, &mut output).unwrap();
        String::from_utf8(output).unwrap()
    }

    #[test]
    fn zsh_script_calls_the_key_function_from_the_key_specs() {
        let script = script(clap_complete_command::Shell::Zsh);
        assert!(!script.contains(":SECRET_KEY:_default'"));
        assert!(!script.contains(":PUB_KEY:_default'"));
        assert!(script.contains(":SECRET_KEY:__asfaload_cli_keys secret' \\\n"));
        assert!(script.contains(":PUB_KEY:__asfaload_cli_keys aliases' \\\n"));
        assert!(script.contains("(see --keys-dir):__asfaload_cli_keys pairs' \\\n"));
        assert!(
            script
                .contains("'::name -- Name of the key to display:__asfaload_cli_keys names' \\\n")
        );
        // The alias name of the alias subcommand is not a key name.
        assert!(script.contains("'::name -- Alias name:_default' \\\n"));
        let function = script.find("__asfaload_cli_keys() {").unwrap();
        let call = script.find("if [ \"$funcstack[1]\"").unwrap();
        assert!(function < call, "the function must exist before the call");
    }

    // A placeholder of the templates is an upper case word between two '@'.
    fn placeholders(script: &str) -> Vec<&str> {
        let segments: Vec<&str> = script.split('@').collect();
        segments[1..segments.len() - 1]
            .iter()
            .copied()
            .filter(|w| !w.is_empty() && w.chars().all(|c| c.is_ascii_uppercase() || c == '_'))
            .collect()
    }

    #[test]
    fn scripts_have_no_placeholder_left() {
        for shell in [
            clap_complete_command::Shell::Bash,
            clap_complete_command::Shell::Zsh,
            clap_complete_command::Shell::Fish,
        ] {
            let script = script(shell);
            assert!(script.contains("list_key_files()"), "{shell:?}");
            for template in [LISTER, BASH_TEMPLATE, ZSH_TEMPLATE, FISH_TEMPLATE] {
                for placeholder in placeholders(template) {
                    let marker = format!("@{placeholder}@");
                    assert!(!script.contains(&marker), "{shell:?} has {marker}");
                }
            }
        }
    }
}
