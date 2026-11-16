//! Start an interactive shell in which completion for asfaload-cli is active.

use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::process::Command;

use clap::{CommandFactory, ValueEnum};
use tempfile::TempDir;

use crate::{
    cli::Cli,
    commands::complete::handle_complete,
    error::{ClientCliError, Result},
};

/// Set to "1" in the started shell, so that the user can show it in a prompt.
const SUBSHELL_ENV_VAR: &str = "ASFALOAD_SUBSHELL";
/// zsh must see our temporary directory as ZDOTDIR to read our startup files.
/// This variable carries the user value of ZDOTDIR through these files.
const USER_ZDOTDIR_ENV_VAR: &str = "ASFALOAD_USER_ZDOTDIR";
const ZDOTDIR_ENV_VAR: &str = "ZDOTDIR";
const COMPLETION_FILE_NAME: &str = "completion";
const BASH_RC_FILE_NAME: &str = "bashrc";
const ZSH_ENV_FILE_NAME: &str = ".zshenv";
const ZSH_RC_FILE_NAME: &str = ".zshrc";

/// Shells that the `shell` command can start.
#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
pub enum ShellKind {
    Bash,
    Zsh,
    Fish,
}

impl ShellKind {
    fn program(self) -> &'static str {
        match self {
            ShellKind::Bash => "bash",
            ShellKind::Zsh => "zsh",
            ShellKind::Fish => "fish",
        }
    }

    fn completion_shell(self) -> clap_complete_command::Shell {
        match self {
            ShellKind::Bash => clap_complete_command::Shell::Bash,
            ShellKind::Zsh => clap_complete_command::Shell::Zsh,
            ShellKind::Fish => clap_complete_command::Shell::Fish,
        }
    }
}

/// Program, arguments and environment used to start the shell.
#[derive(Debug, PartialEq, Eq)]
struct LaunchSpec {
    program: &'static str,
    args: Vec<OsString>,
    env: Vec<(&'static str, OsString)>,
}

fn quote_path(path: &Path) -> Result<String> {
    let path_str = path.to_str().ok_or_else(|| {
        ClientCliError::InvalidInput(format!(
            "path is not valid UTF-8: {}",
            path.to_string_lossy()
        ))
    })?;
    Ok(shell_words::quote(path_str).into_owned())
}

// zsh reads its startup files from ZDOTDIR, or from HOME when ZDOTDIR is not set.
// We put back the user value before we source a user file, so that the user file
// behaves as in a normal zsh start.
fn restore_user_zdotdir_line() -> String {
    format!(
        "if [[ -n \"${{{var}-}}\" ]]; then {zdotdir}=\"${var}\"; else unset {zdotdir}; fi\n",
        var = USER_ZDOTDIR_ENV_VAR,
        zdotdir = ZDOTDIR_ENV_VAR,
    )
}

fn startup_files(
    kind: ShellKind,
    tmp_dir: &Path,
    bin_dir: &Path,
) -> Result<Vec<(&'static str, String)>> {
    let completion = quote_path(&tmp_dir.join(COMPLETION_FILE_NAME))?;
    let bin = quote_path(bin_dir)?;
    // Completion triggers only if asfaload-cli is found on PATH. We add its
    // directory after the user configuration, so that the user configuration
    // cannot remove it.
    let add_completion = format!("source {completion}\nexport PATH={bin}:\"$PATH\"\n");
    let files = match kind {
        ShellKind::Bash => vec![(
            BASH_RC_FILE_NAME,
            format!("[ -f ~/.bashrc ] && . ~/.bashrc\n{add_completion}"),
        )],
        ShellKind::Zsh => {
            let restore = restore_user_zdotdir_line();
            // A user .zshenv can change ZDOTDIR. We keep its value for .zshrc and
            // set ZDOTDIR back to our directory, so that zsh reads our .zshrc.
            let zsh_env = format!(
                "{restore}\
                 [[ -f \"${{{zdotdir}:-$HOME}}/{env_file}\" ]] && source \"${{{zdotdir}:-$HOME}}/{env_file}\"\n\
                 {var}=\"${{{zdotdir}-}}\"\n\
                 {zdotdir}={tmp}\n",
                zdotdir = ZDOTDIR_ENV_VAR,
                env_file = ZSH_ENV_FILE_NAME,
                var = USER_ZDOTDIR_ENV_VAR,
                tmp = quote_path(tmp_dir)?,
            );
            // Without -i, compinit asks a question when fpath has insecure directories,
            // and aborts when it cannot ask. Our completion does not come from fpath.
            let zsh_rc = format!(
                "{restore}\
                 unset {var}\n\
                 [[ -f \"${{{zdotdir}:-$HOME}}/{rc_file}\" ]] && source \"${{{zdotdir}:-$HOME}}/{rc_file}\"\n\
                 (( $+functions[compdef] )) || {{ autoload -Uz compinit && compinit -i; }}\n\
                 {add_completion}",
                var = USER_ZDOTDIR_ENV_VAR,
                zdotdir = ZDOTDIR_ENV_VAR,
                rc_file = ZSH_RC_FILE_NAME,
            );
            vec![(ZSH_ENV_FILE_NAME, zsh_env), (ZSH_RC_FILE_NAME, zsh_rc)]
        }
        // fish loads the user configuration by itself, and the -C argument adds
        // the completion after it.
        ShellKind::Fish => vec![],
    };
    Ok(files)
}

fn launch_spec(
    kind: ShellKind,
    tmp_dir: &Path,
    bin_dir: &Path,
    user_zdotdir: Option<OsString>,
) -> Result<LaunchSpec> {
    let subshell = (SUBSHELL_ENV_VAR, OsString::from("1"));
    let (args, env) = match kind {
        ShellKind::Bash => (
            vec![
                OsString::from("--rcfile"),
                tmp_dir.join(BASH_RC_FILE_NAME).into_os_string(),
                OsString::from("-i"),
            ],
            vec![subshell],
        ),
        ShellKind::Zsh => {
            let user_zdotdir_env = (USER_ZDOTDIR_ENV_VAR, user_zdotdir.unwrap_or_default());
            let env = [
                subshell,
                (ZDOTDIR_ENV_VAR, tmp_dir.as_os_str().to_os_string()),
            ]
            .into_iter()
            .chain([user_zdotdir_env])
            .collect();
            (vec![OsString::from("-i")], env)
        }
        ShellKind::Fish => {
            let completion = quote_path(&tmp_dir.join(COMPLETION_FILE_NAME))?;
            let bin = quote_path(bin_dir)?;
            (
                vec![
                    OsString::from("-C"),
                    OsString::from(format!("source {completion}; set -gx PATH {bin} $PATH")),
                ],
                vec![subshell],
            )
        }
    };
    Ok(LaunchSpec {
        program: kind.program(),
        args,
        env,
    })
}

pub fn handle_shell_command(kind: ShellKind) -> Result<i32> {
    let tmp_dir = TempDir::new()?;
    let bin_dir = current_bin_dir()?;
    write_completion_file(kind, tmp_dir.path())?;
    startup_files(kind, tmp_dir.path(), &bin_dir)?
        .into_iter()
        .try_for_each(|(name, content)| std::fs::write(tmp_dir.path().join(name), content))?;
    let spec = launch_spec(
        kind,
        tmp_dir.path(),
        &bin_dir,
        std::env::var_os(ZDOTDIR_ENV_VAR),
    )?;
    let program = spec.program;
    eprintln!(
        "Starting {program} with {} completion. Type 'exit' to return.",
        Cli::command().get_name()
    );
    // A child process, and not a replacement of this process, so that we can
    // remove the temporary directory when the shell exits.
    let status = Command::new(program)
        .args(&spec.args)
        .envs(spec.env)
        .status()
        .map_err(|e| spawn_error(program, e))?;
    // The drop of TempDir hides a removal failure, close() reports it.
    tmp_dir.close()?;
    Ok(status.code().unwrap_or(1))
}

fn write_completion_file(kind: ShellKind, tmp_dir: &Path) -> Result<()> {
    let mut script = Vec::new();
    handle_complete(kind.completion_shell(), &mut script)?;
    std::fs::write(tmp_dir.join(COMPLETION_FILE_NAME), script)?;
    Ok(())
}

fn current_bin_dir() -> Result<PathBuf> {
    let exe = std::env::current_exe()?;
    exe.parent().map(Path::to_path_buf).ok_or_else(|| {
        ClientCliError::InvalidInput(format!(
            "executable has no parent directory: {}",
            exe.display()
        ))
    })
}

fn spawn_error(program: &str, error: std::io::Error) -> ClientCliError {
    if error.kind() == std::io::ErrorKind::NotFound {
        ClientCliError::ShellNotFound(program.to_string())
    } else {
        ClientCliError::Io(error)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // The space forces quoting, so the tests also check the quoting.
    const TMP_DIR: &str = "/tmp/asfaload shell";
    const BIN_DIR: &str = "/opt/asfaload/bin";

    #[test]
    fn quote_path_quotes_only_when_needed() -> anyhow::Result<()> {
        let cases = vec![
            ("/plain/path", "/plain/path"),
            ("/with space", "'/with space'"),
            ("/it's", r"'/it'\''s'"),
        ];
        for (input, expected) in cases {
            assert_eq!(quote_path(Path::new(input))?, expected, "input {input}");
        }
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn quote_path_rejects_non_utf8_path() {
        use std::ffi::OsStr;
        use std::os::unix::ffi::OsStrExt;

        let path = Path::new(OsStr::from_bytes(b"/tmp/\xff"));
        match quote_path(path) {
            Err(ClientCliError::InvalidInput(msg)) => assert!(msg.contains("UTF-8"), "{msg}"),
            Err(e) => panic!("Expected ClientCliError::InvalidInput but got {e}"),
            Ok(quoted) => panic!("Expected InvalidInput error, got ok value {quoted}"),
        }
    }

    #[test]
    fn bash_startup_file_loads_user_rc_then_completion_then_path() -> anyhow::Result<()> {
        let files = startup_files(ShellKind::Bash, Path::new(TMP_DIR), Path::new(BIN_DIR))?;
        let expected = r#"[ -f ~/.bashrc ] && . ~/.bashrc
source '/tmp/asfaload shell/completion'
export PATH=/opt/asfaload/bin:"$PATH"
"#;
        assert_eq!(files, vec![(BASH_RC_FILE_NAME, expected.to_string())]);
        Ok(())
    }

    #[test]
    fn zsh_startup_files_restore_user_zdotdir_and_add_completion() -> anyhow::Result<()> {
        let files = startup_files(ShellKind::Zsh, Path::new(TMP_DIR), Path::new(BIN_DIR))?;
        let expected_env = r#"if [[ -n "${ASFALOAD_USER_ZDOTDIR-}" ]]; then ZDOTDIR="$ASFALOAD_USER_ZDOTDIR"; else unset ZDOTDIR; fi
[[ -f "${ZDOTDIR:-$HOME}/.zshenv" ]] && source "${ZDOTDIR:-$HOME}/.zshenv"
ASFALOAD_USER_ZDOTDIR="${ZDOTDIR-}"
ZDOTDIR='/tmp/asfaload shell'
"#;
        let expected_rc = r#"if [[ -n "${ASFALOAD_USER_ZDOTDIR-}" ]]; then ZDOTDIR="$ASFALOAD_USER_ZDOTDIR"; else unset ZDOTDIR; fi
unset ASFALOAD_USER_ZDOTDIR
[[ -f "${ZDOTDIR:-$HOME}/.zshrc" ]] && source "${ZDOTDIR:-$HOME}/.zshrc"
(( $+functions[compdef] )) || { autoload -Uz compinit && compinit -i; }
source '/tmp/asfaload shell/completion'
export PATH=/opt/asfaload/bin:"$PATH"
"#;
        assert_eq!(
            files,
            vec![
                (ZSH_ENV_FILE_NAME, expected_env.to_string()),
                (ZSH_RC_FILE_NAME, expected_rc.to_string()),
            ]
        );
        Ok(())
    }

    #[test]
    fn fish_needs_no_startup_file() -> anyhow::Result<()> {
        let files = startup_files(ShellKind::Fish, Path::new(TMP_DIR), Path::new(BIN_DIR))?;
        assert!(files.is_empty());
        Ok(())
    }

    #[test]
    fn launch_spec_for_each_shell() -> anyhow::Result<()> {
        let subshell = (SUBSHELL_ENV_VAR, OsString::from("1"));
        let tmp_dir_env = (ZDOTDIR_ENV_VAR, OsString::from(TMP_DIR));
        let cases = vec![
            (
                ShellKind::Bash,
                None,
                LaunchSpec {
                    program: "bash",
                    args: vec![
                        "--rcfile".into(),
                        "/tmp/asfaload shell/bashrc".into(),
                        "-i".into(),
                    ],
                    env: vec![subshell.clone()],
                },
            ),
            (
                ShellKind::Zsh,
                None,
                LaunchSpec {
                    program: "zsh",
                    args: vec!["-i".into()],
                    env: vec![
                        subshell.clone(),
                        tmp_dir_env.clone(),
                        (USER_ZDOTDIR_ENV_VAR, "".into()),
                    ],
                },
            ),
            (
                ShellKind::Zsh,
                Some(OsString::new()),
                LaunchSpec {
                    program: "zsh",
                    args: vec!["-i".into()],
                    env: vec![
                        subshell.clone(),
                        tmp_dir_env.clone(),
                        (USER_ZDOTDIR_ENV_VAR, "".into()),
                    ],
                },
            ),
            (
                ShellKind::Zsh,
                Some(OsString::from("/home/user/.config/zsh")),
                LaunchSpec {
                    program: "zsh",
                    args: vec!["-i".into()],
                    env: vec![
                        subshell.clone(),
                        tmp_dir_env.clone(),
                        (USER_ZDOTDIR_ENV_VAR, "/home/user/.config/zsh".into()),
                    ],
                },
            ),
            (
                ShellKind::Fish,
                None,
                LaunchSpec {
                    program: "fish",
                    args: vec![
                        "-C".into(),
                        "source '/tmp/asfaload shell/completion'; set -gx PATH /opt/asfaload/bin $PATH"
                            .into(),
                    ],
                    env: vec![subshell.clone()],
                },
            ),
        ];
        for (kind, user_zdotdir, expected) in cases {
            let spec = launch_spec(
                kind,
                Path::new(TMP_DIR),
                Path::new(BIN_DIR),
                user_zdotdir.clone(),
            )?;
            assert_eq!(
                spec, expected,
                "kind {kind:?}, user zdotdir {user_zdotdir:?}"
            );
        }
        Ok(())
    }
}
