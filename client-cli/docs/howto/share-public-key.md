# Share a public key

Once you have a key pair, you need to share the public key with whoever maintains the signers file. The `share-key` command formats it for you.

## Prerequisites

- A public key file (`.pub`) from [Generate a key pair](generate-keys.md).

## Steps

### 1. Print a human-readable sharing message (default)

```sh
asfaload-cli share-key mykey
```

The command finds the key `mykey` in your keys directory, where `new-keys` created it, and reads the public key from `mykey.pub`. By default, your keys directory is the directory `asfaload-cli` in your user data directory:

- Linux and macOS: `$XDG_DATA_HOME/asfaload-cli`, usually `~/.local/share/asfaload-cli`.
- Windows: `%APPDATA%\asfaload-cli`, usually `C:\Users\<user>\AppData\Roaming\asfaload-cli`.

If you keep your keys in another location, give that directory with `--keys-dir` or with the `ASFALOAD_KEYS_DIR` environment variable. You can also give the path to the public key file.

This prints your public key together with a ready-to-send message you can forward to a team admin:

```
The public key is safe to share -- that's how others verify your signatures.

You can share your public key, for example with an admin, with this message:

    I have a key-pair to use with Asfaload. You can use my public
    key in signers files. Here it is:
    asfaload-pub:b5S+CxuqICIUn/DGBdMKeTMZCgQcg78ohiWQ1sC00c8

    To refer to my key by a name, create an alias for it:
    asfaload-cli alias --key asfaload-pub:b5S+CxuqICIUn/DGBdMKeTMZCgQcg78ohiWQ1sC00c8 <name>

Note:
Do not create aliases for your own keys, they are usable by name without an alias!
```

### 2. Print only the key with `--raw`

When you only need the base64 string — for example, to paste it into a signers file — use `--raw` (`-r`):

```sh
asfaload-cli share-key mykey --raw
```

Output:

```
asfaload-pub:b5S+CxuqICIUn/DGBdMKeTMZCgQcg78ohiWQ1sC00c8
```

This is the canonical base64 form used in signers files and templates.

`--raw` also works with OpenSSH ed25519 public keys — the key is normalised to its asfaload canonical form:

```sh
asfaload-cli share-key ~/.ssh/id_ed25519.pub --raw
```

`--raw` and `--json` are mutually exclusive; you cannot use both at the same time.

### 3. Machine-readable JSON output

For scripting, use `--json`:

```sh
asfaload-cli share-key mykey --json
```

Output:

```json
{"public_key":"asfaload-pub:b5S+CxuqICIUn/DGBdMKeTMZCgQcg78ohiWQ1sC00c8","message":"The public key is safe to share -- ..."}
```

## Next step

The admin will include your public key when [creating the signers file](create-signers-file.md).

## Reference

- [`asfaload-cli share-key`](../manual/share-key.md)
