# Generate a key pair

Every signer needs their own key pair. This guide walks you through creating one.

## Prerequisites

- The `asfaload-cli` binary is installed and in your `PATH`.

## Steps

### 1. Generate the key pair

```sh
asfaload-cli new-keys --name mykey
```

You'll be prompted for a password to protect the secret key. Pick a strong one — this password is required every time you sign.

By default, the command creates the keys in your keys directory. This is the directory `asfaload-cli` in your user data directory:

- Linux and macOS: `$XDG_DATA_HOME/asfaload-cli`, usually `~/.local/share/asfaload-cli`.
- Windows: `%APPDATA%\asfaload-cli`, usually `C:\Users\<user>\AppData\Roaming\asfaload-cli`.

If the directory does not exist, the command creates it. You do not have to give a directory.

If you must keep your keys in another location, give that directory with `--keys-dir` or with the `ASFALOAD_KEYS_DIR` environment variable.

This creates two files:

| File | Purpose |
|------|---------|
| `~/.local/share/asfaload-cli/mykey` | Secret key (keep this safe) |
| `~/.local/share/asfaload-cli/mykey.pub` | Public key (share with your team) |

On Linux and macOS, only you can read the secret key file.

![Demo: generate a key pair](demos/generate-keys.gif)

### 2. Verify the output

```sh
ls ~/.local/share/asfaload-cli/mykey*
```

You should see both `mykey` and `mykey.pub`.

### 3. Use the key by its name

The commands that sign find a key by its name in the keys directory. You do not need to type the full path:

```sh
asfaload-cli list-pending --secret-key mykey
```

If a file with this name exists in the current directory, the command uses that file. To keep your keys in another directory, give it with `--keys-dir` or the `ASFALOAD_KEYS_DIR` environment variable.

## Non-interactive usage

For CI or scripting, pass the password directly:

```sh
asfaload-cli new-keys --name ci-key --password "$KEY_PASSWORD"
```

Or read the password from a file with `--password-file` (`-P`):

```sh
asfaload-cli new-keys --name ci-key --password-file /run/secrets/key-password
```

The file should contain the password on a single line. Trailing newlines are stripped.

Or fetch the password from a password manager (or any external command) with `--password-command` (`-C`). The command's standard output is used as the password:

```sh
asfaload-cli new-keys --name ci-key \
    --password-command "pass show asfaload/ci-key"
```

The command string is parsed with shell-style quoting, but no shell is spawned — pipes and redirections don't apply. Trailing newlines are stripped from the command's output.

The password file and password command can also come from environment variables — `ASFALOAD_PASSWORD_FILE` and `ASFALOAD_PASSWORD_COMMAND`:

```sh
export ASFALOAD_PASSWORD_FILE="/run/secrets/key-password"
asfaload-cli new-keys --name ci-key
```

The command-specific `ASFALOAD_NEW_KEYS_PASSWORD` and `ASFALOAD_NEW_KEYS_PASSWORD_FILE` are also still honoured (at lower precedence):

```sh
export ASFALOAD_NEW_KEYS_PASSWORD="$KEY_PASSWORD"
asfaload-cli new-keys --name ci-key
```

## Next step

Share your public key with whoever maintains the signers file. Use the `share-key` command to format it — see [Share a public key](share-public-key.md). They'll include it when [creating the signers file](create-signers-file.md).

## Reference

- [`asfaload-cli new-keys`](../manual/new-keys.md)
