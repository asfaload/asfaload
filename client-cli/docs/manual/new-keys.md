# `asfaload-cli new-keys`

- **Usage**: `asfaload-cli new-keys [OPTIONS] -n <NAME>`
- **Source**: [`src/commands/keys.rs`](../../src/commands/keys.rs)

Generate a new signing key pair. The command creates both a secret key and a public key in the specified directory.

## Options

### `-n --name <NAME>`

Base name for the key files. Produces `<NAME>` (secret key) and `<NAME>.pub` (public key) in the output directory.

### `-d --output-dir <DIR>`

Directory to write the key files into. Defaults to the current directory; `~/.asfaload` is a common place to keep keys. Created automatically if it doesn't exist.

### `-p --password <PASSWORD>`

Password to protect the secret key. Conflicts with `--password-file` and `--password-command`. Prompted interactively if none of these is set.

### `-P --password-file <PATH>`

File containing the password. Conflicts with `--password` and `--password-command`.

### `-C --password-command <COMMAND>`

Shell command to run; its standard output is read as the password. Useful for password managers (`pass`, `op`, `bw`, etc.). Conflicts with `--password` and `--password-file`. The command string is parsed with shell-style quoting (no shell is spawned, so pipes and redirections don't apply); trailing newlines are stripped from the output.

### `--accept-weak-password`

Bypass password strength validation. **Insecure** — only use for testing.

### `--json`

Emit output as JSON instead of human-readable text.

## Environment

These variables provide fallbacks for the matching options. Password sources are tried in the order described in the [manual index](index.md#passwords): flags first (in the order `--password`, `--password-command`, `--password-file`), then environment variables, then an interactive prompt.

- `ASFALOAD_PASSWORD_FILE` — alternative to `--password-file`.
- `ASFALOAD_PASSWORD_COMMAND` — alternative to `--password-command`.
- `ASFALOAD_NEW_KEYS_PASSWORD` — alternative to `--password` (still supported, lower precedence).
- `ASFALOAD_NEW_KEYS_PASSWORD_FILE` — alternative to `--password-file` (still supported, lower precedence).

## Output

Human-readable (default):

    Generated keypair 'mykey'

      Public key string:  asfaload-pub:b5S+CxuqICIUn/DGBdMKeTMZCgQcg78ohiWQ1sC00c8
      Public key file: /home/user/.asfaload/mykey.pub
      Secret key file: /home/user/.asfaload/mykey

    WARNING: Keep the secret key private. Treat it like a password -- never share, copy, or commit it.
    The public key is safe to share -- that's how others verify your signatures.

    You can share your public key, for example with an admin, with this message:

        I have a key-pair to use with Asfaload. You can use my public
        key in signers files. Here it is:
        asfaload-pub:b5S+CxuqICIUn/DGBdMKeTMZCgQcg78ohiWQ1sC00c8

        To refer to my key by a name, create an alias for it:
        asfaload-cli alias --key asfaload-pub:b5S+CxuqICIUn/DGBdMKeTMZCgQcg78ohiWQ1sC00c8 <name>

The trailing message is the same text printed by [`share-key`](share-key.md); it can be copy-pasted directly when sharing the key.

JSON (with `--json`):

    {"public_key_path":"/home/user/.asfaload/mykey.pub","public_key":"asfaload-pub:b5S+CxuqICIUn/DGBdMKeTMZCgQcg78ohiWQ1sC00c8","secret_key_path":"/home/user/.asfaload/mykey"}

## Examples

    # generate a key pair in the current directory
    asfaload-cli new-keys -n mykey

    # store keys in the usual location
    asfaload-cli new-keys -n mykey -d ~/.asfaload

    # non-interactive usage in CI
    asfaload-cli new-keys -n ci-key -d ./keys -p "$KEY_PASSWORD"

## Exit codes

- `0` — key pair created successfully.
- non-zero — error (invalid directory, password mismatch, etc.).
