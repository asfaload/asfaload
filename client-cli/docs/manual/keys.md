# `asfaload-cli keys`

- **Usage**: `asfaload-cli keys [OPTIONS]`

Show the secret and public key files in your keys directory, and the aliases of public keys in your configuration file. The command reads only local files. It does not contact the backend.

## My secret keys

A secret key is a file in the keys directory that starts with `asfaload-priv:` or with `-----BEGIN OPENSSH PRIVATE KEY-----`. The command shows the file name. You give this name to `--secret-key` in the commands that sign. The command does not examine subdirectories, and it does not ask for a password.

## My public keys

A public key file is a file in the keys directory that starts with `asfaload-pub:` or with `ssh-ed25519 `. The command shows the file name and the public key. The public key displayed is in the `asfaload-pub:` format, also for an SSH key file.

## Public key aliases

The aliases of the configuration file, with their public keys. See [`alias`](alias.md).

## Options

### `-d --keys-dir <DIR>`

The directory of the key files, in place of the default keys directory.

### `-c --config-file <CONFIG_FILE>`

The configuration file to use instead of the default file.

### `--json`

Emit output as JSON instead of human-readable text.

## Environment

- `ASFALOAD_KEYS_DIR` — alternative to `--keys-dir`.
- `ASFALOAD_CONFIG_FILE` — alternative to `--config-file`.

## Output

Human-readable (default). The output starts with a title and a short note. Then two lines show the keys directory and the configuration file that the command uses. If one of them does not exist, its line ends with `(does not exist)`. An empty section shows `none`:

    Local keys
    Keys in your keys dir and config file. To use a key file in a different location, give its path to the command.

    Keys dir: /home/alice/.local/share/asfaload-cli
    Config file: /home/alice/.config/asfaload-cli/config.toml

    My secret keys:
      mykey
      release

    My public keys:
      mykey.pub    (asfaload-pub:b5S+CxuqICIUn/DGBdMKeTMZCgQcg78ohiWQ1sC00c8)
      release.pub  (asfaload-pub:YCuPAtMNZQaYPDjWmp8voWh6bVg0bRyLu2zEkH6zYZI)

    Public key aliases:
      bob  asfaload-pub:p8p1Hb8ux9xf9mo8BGedkpv4RUFZgwXuYGu5x0grsdU
      me   asfaload-pub:b5S+CxuqICIUn/DGBdMKeTMZCgQcg78ohiWQ1sC00c8

JSON (with `--json`):

    {"keys_dir":"/home/alice/.local/share/asfaload-cli","config_file":"/home/alice/.config/asfaload-cli/config.toml","secret_keys":["mykey","release"],"my_public_keys":[{"file_name":"mykey.pub","public_key":"asfaload-pub:b5S+CxuqICIUn/DGBdMKeTMZCgQcg78ohiWQ1sC00c8"},{"file_name":"release.pub","public_key":"asfaload-pub:YCuPAtMNZQaYPDjWmp8voWh6bVg0bRyLu2zEkH6zYZI"}],"public_key_aliases":[{"alias":"bob","public_key":"asfaload-pub:p8p1Hb8ux9xf9mo8BGedkpv4RUFZgwXuYGu5x0grsdU"},{"alias":"me","public_key":"asfaload-pub:b5S+CxuqICIUn/DGBdMKeTMZCgQcg78ohiWQ1sC00c8"}]}

## Examples

    # show your keys
    asfaload-cli keys

    # show the keys of a different keys directory
    asfaload-cli keys --keys-dir ~/project-keys

    # names of the secret keys, for use in a script
    asfaload-cli keys --json | jq -r '.secret_keys[]'

## Exit codes

- `0` — the keys are shown. This is also the case when there is no key, or when the keys directory or the configuration file does not exist.
- non-zero — error. For example, the keys directory cannot be read, or the configuration file is not valid.
