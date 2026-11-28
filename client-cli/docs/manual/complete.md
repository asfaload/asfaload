# `asfaload-cli complete`

- **Usage**: `asfaload-cli complete [OPTIONS] --shell <SHELL>`

Generate a completion script for a shell. When the script is loaded, the shell completes the commands and options of `asfaload-cli`. To get completion without a script, use [`shell`](shell.md).

With `bash`, `zsh` and `fish`, the script also completes the names of your keys and aliases:

- `--secret-key` (`-K`): the secret key files in your keys dir.
- The public key of `share-key`: the names of the key pairs in your keys dir. A key pair is a secret key file `NAME` with its public key file `NAME.pub`.
- The name of `keys`: the key files in your keys dir, and the aliases of your config file.
- The public keys of `new-signers-file` (`-a`, `-d`, `-m`, `-r`): the aliases of your config file, and the names of the key pairs in your keys dir.

The script finds the keys dir and the config file when you press TAB: it uses `--keys-dir` and `--config-file` if they are in the command line, then the environment variables, then the default locations. It also completes the paths of files in the current directory.

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
