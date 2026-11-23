# `asfaload-cli share-key`

- **Usage**: `asfaload-cli share-key [OPTIONS] -k <PUBLIC_KEY>`

Print your public key in the base64 form used in signers files, along with a ready-to-send message for sharing it. The public key is safe to share — it is how others verify your signatures.

This command is offline: it only reads a local public key file and never contacts the backend.

## Options

### `-k --public-key <PATH>`

Path to the public key file to share (asfaload or OpenSSH ed25519). Required. If the path does not contain a parseable public key, the command retries with `.pub` appended to the path — so passing the secret key path also works, as long as its `.pub` sibling exists.

### `-r --raw`

Print only the public key in its canonical base64 form (`asfaload-pub:...`), without the human-readable message. Conflicts with `--json`.

### `--json`

Emit output as JSON instead of human-readable text. Conflicts with `--raw`.

## Output

Human-readable (default):

    The public key is safe to share -- that's how others verify your signatures.

    You can share your public key, for example with an admin, with this message:

        I have a key-pair to use with Asfaload. You can use my public
        key in signers files. Here it is:
        asfaload-pub:b5S+CxuqICIUn/DGBdMKeTMZCgQcg78ohiWQ1sC00c8

        To refer to my key by a name, create an alias for it:
        asfaload-cli alias --key asfaload-pub:b5S+CxuqICIUn/DGBdMKeTMZCgQcg78ohiWQ1sC00c8 <name>

Raw (with `--raw`):

    asfaload-pub:b5S+CxuqICIUn/DGBdMKeTMZCgQcg78ohiWQ1sC00c8

JSON (with `--json`):

    {"public_key":"asfaload-pub:b5S+CxuqICIUn/DGBdMKeTMZCgQcg78ohiWQ1sC00c8","message":"The public key is safe to share -- ..."}

## Examples

    # print your public key and a sharing message
    asfaload-cli share-key -k ~/.asfaload/mykey.pub

    # print only the key
    asfaload-cli share-key -k ~/.asfaload/mykey.pub --raw

    # machine-readable output
    asfaload-cli share-key --json -k ~/.asfaload/mykey.pub

## Exit codes

- `0` — public key loaded and printed.
- non-zero — error (public key file missing or unreadable, invalid key).
