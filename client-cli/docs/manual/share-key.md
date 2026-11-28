# `asfaload-cli share-key`

- **Usage**: `asfaload-cli share-key [OPTIONS] -k <PUBLIC_KEY>`

Print your public key in the base64 form used in signers files, along with a ready-to-send message for sharing it. The public key is safe to share — it is how others verify your signatures.

This command is offline: it only reads a local public key file and never contacts the backend.

By default, the command looks for the key name in the keys directory, the directory `asfaload-cli` in your user data directory:

- Linux and macOS: `$XDG_DATA_HOME/asfaload-cli`, usually `~/.local/share/asfaload-cli`.
- Windows: `%APPDATA%\asfaload-cli`, usually `C:\Users\<user>\AppData\Roaming\asfaload-cli`.

This is the directory where [`new-keys`](new-keys.md) creates keys by default. If you keep your keys in another location, use `--keys-dir`.

## Options

### `-k --public-key <PATH|NAME>`

Path to the public key file to share (asfaload or OpenSSH ed25519), or the name of a key file in the keys directory (see `--keys-dir`). If a file exists at the given path, the command uses it. If not, the command reads the file with this name in the keys directory. Required. If the file does not contain a parseable public key, the command retries with `.pub` appended to the path — so passing the secret key path or name also works, as long as its `.pub` sibling exists.

### `-d --keys-dir <DIR>`

Directory where the command looks for the public key when the value of `--public-key` is not an existing file. The command then reads `<DIR>/<value of --public-key>`. Defaults to `$XDG_DATA_HOME/asfaload-cli` (usually `~/.local/share/asfaload-cli`), the directory where [`new-keys`](new-keys.md) writes keys by default.

### `-r --raw`

Print only the public key in its canonical base64 form (`asfaload-pub:...`), without the human-readable message. Conflicts with `--json`.

### `--json`

Emit output as JSON instead of human-readable text. Conflicts with `--raw`.

## Environment

- `ASFALOAD_KEYS_DIR` — alternative to `--keys-dir`.

## Output

Human-readable (default):

    The public key is safe to share -- that's how others verify your signatures.

    You can share your public key, for example with an admin, with this message:

        I have a key-pair to use with Asfaload. You can use my public
        key in signers files. Here it is:
        asfaload-pub:b5S+CxuqICIUn/DGBdMKeTMZCgQcg78ohiWQ1sC00c8

        To refer to my key by a name, create an alias for it:
        asfaload-cli alias --key asfaload-pub:b5S+CxuqICIUn/DGBdMKeTMZCgQcg78ohiWQ1sC00c8 <name>

Note:
Do not create aliases for your own keys, they are usable by name without an alias!

Raw (with `--raw`):

    asfaload-pub:b5S+CxuqICIUn/DGBdMKeTMZCgQcg78ohiWQ1sC00c8

JSON (with `--json`):

    {"public_key":"asfaload-pub:b5S+CxuqICIUn/DGBdMKeTMZCgQcg78ohiWQ1sC00c8","message":"The public key is safe to share -- ..."}

## Examples

    # print your public key and a sharing message
    asfaload-cli share-key -k mykey

    # print only the key
    asfaload-cli share-key -k mykey --raw

    # machine-readable output
    asfaload-cli share-key --json -k mykey

## Exit codes

- `0` — public key loaded and printed.
- non-zero — error (public key file missing or unreadable, invalid key).
