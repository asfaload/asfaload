# `asfaload-cli shell`

- **Usage**: `asfaload-cli shell [OPTIONS]`
- **Source**: [`src/commands/shell.rs`](../../src/commands/shell.rs)

Start an interactive shell in which completion for `asfaload-cli` is active. You do not need to install a completion script.

The shell loads your own configuration first (`~/.bashrc`, your zsh startup files, or your fish configuration), so you keep your prompt and aliases. Then it adds the completion. It also puts the directory of the running `asfaload-cli` at the start of `PATH`, because completion works only when `asfaload-cli` is found on `PATH`.

In the started shell, the environment variable `ASFALOAD_SUBSHELL` is set to `1`. You can use it in your prompt.

Type `exit` to return. The temporary files are then removed.

To enable completion in your current shell without a new shell, use the `complete` command:

    # bash
    source <(asfaload-cli complete --shell bash)

    # zsh (compinit must already be loaded)
    source <(asfaload-cli complete --shell zsh)

    # fish
    asfaload-cli complete --shell fish | source

## Limitations

With `--shell zsh`, the system file `/etc/zshenv` (or `/etc/zsh/zshenv`) can set `ZDOTDIR` without a condition. Then zsh does not read the startup files of `asfaload-cli`, and the started zsh has no completion. In this case, use the `complete` command: `source <(asfaload-cli complete --shell zsh)`.

## Options

### `--shell <SHELL>`

The shell to start: `bash`, `zsh` or `fish`. Default: `bash`. The shell must be installed and found on `PATH`.

## Examples

    # start bash with completion
    asfaload-cli shell

    # start zsh with completion
    asfaload-cli shell --shell zsh

## Exit codes

- The exit code of the started shell.
- `1` — a signal ended the started shell.
- non-zero — error (shell not found on `PATH`, temporary files cannot be written).
