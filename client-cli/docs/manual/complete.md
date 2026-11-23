# `asfaload-cli complete`

- **Usage**: `asfaload-cli complete [OPTIONS] --shell <SHELL>`

Generate a completion script for a shell. When the script is loaded, the shell completes the commands and options of `asfaload-cli`. To get completion without a script, use [`shell`](shell.md).

## Options

### `-s --shell <SHELL>`

The shell for which to generate the script: `bash`, `zsh`, `fish`, `elvish`, `powershell` or `nushell`. Upper case and lower case letters are accepted.

### `-o --output <OUTPUT>`

Write the script to this file. If the file exists, it is replaced. Without this option, the script is printed to stdout.

## Examples

    # enable completion in the current bash
    source <(asfaload-cli complete --shell bash)

    # enable completion in the current zsh (compinit must already be loaded)
    source <(asfaload-cli complete --shell zsh)

    # enable completion in the current fish
    asfaload-cli complete --shell fish | source

    # save the bash script to a file
    asfaload-cli complete --shell bash -o ~/.local/share/bash-completion/completions/asfaload-cli

## Exit codes

- `0` — the script was generated.
- non-zero — the shell is not known, or the output file cannot be written.
