# `asfaload-cli new-signers-file`

- **Usage**: `asfaload-cli new-signers-file [OPTIONS] --artifact-threshold <ARTIFACT_THRESHOLD>`

Create a new signers file that defines who can sign artifacts, administer, and manage the project. At minimum, one artifact signer and its threshold are required.

## Public keys

The options `--artifact-signer`, `--admin-key`, `--master-key` and `--revocation-key` accept a public key in one of these forms:

- The public key as a base64 string (`asfaload-pub:...`).
- An [alias](alias.md) of the configuration file.
- A key file: the path to a file, or the name of a file in the keys directory (see `--keys-dir`). If a file exists at the given path, the command uses it. If not, the command reads the file with this name in the keys directory. If the file is not a public key, the command reads the file with `.pub` appended, so the name of your key pair also works. Use this form for your own keys: do not create aliases for them.

When a name is an alias and a key file of different keys, the command fails. Then give the base64 string or the path to the file.

## Options

### Artifact signers

Every signers file needs at least one artifact signer.

#### `-a --artifact-signer <PUB_KEY>`

Public key (see [Public keys](#public-keys)). Repeatable.

#### `--artifact-signers-file <FILE_PATH>` (`--af`)

Path to a file holding public keys, **one per line**. Repeatable. Combines with `--artifact-signer`.

#### `-A --artifact-threshold <N>`

Number of artifact signers required to complete a signature. Must be between 1 and the total number of artifact signers.

### Admin keys (optional)

When admin keys are not specified, there is a fallback to artifact signers keys.

#### `-d --admin-key <PUB_KEY>`

Admin public key (see [Public keys](#public-keys)). Repeatable.

#### `--admin-keys-file <FILE_PATH>` (`--df`)

Path to a file holding admin public keys, **one per line**. Repeatable. Combines with `--admin-key`.

#### `-D --admin-threshold <N>`

Required when admin keys are provided. Number of admins required to approve changes.

### Master keys (optional)

Master keys can approve a signers file update in place of the admin keys. Keep them offline. When master keys are not specified, only the admin keys can approve an update.

#### `-m --master-key <PUB_KEY>`

Master public key (see [Public keys](#public-keys)). Repeatable.

#### `--master-keys-file <FILE_PATH>` (`--mf`)

Path to a file holding master public keys, **one per line**. Repeatable. Combines with `--master-key`.

#### `-M --master-threshold <N>`

Required when master keys are provided.

### Revocation keys (optional)

When revocation keys are not specified, there is a fallback to the admin keys.

#### `-r --revocation-key <PUB_KEY>`

Revocation public key (see [Public keys](#public-keys)). Repeatable.

#### `--revocation-keys-file <FILE_PATH>` (`--rf`)

Path to a file holding revocation public keys, **one per line**. Repeatable. Combines with `--revocation-key`.

#### `-R --revocation-threshold <N>`

Required when revocation keys are provided.

### General

#### `-o --output-file <OUTPUT_FILE>`

Path for the new signers file. The file must not already exist — the command refuses to overwrite. Parent directories are created automatically. Required when `--json` is used; otherwise the signers file is printed to stdout if omitted.

#### `--json`

Emit output as JSON instead of human-readable text.

#### `--keys-dir <DIR>`

Directory where the command looks for a key file when the public key is not an existing file. Defaults to `$XDG_DATA_HOME/asfaload-cli` (usually `~/.local/share/asfaload-cli`), the directory where [`new-keys`](new-keys.md) writes keys by default.

#### `-c --config-file <CONFIG_FILE>`

The configuration file to read aliases from, instead of the default file. Refer to [alias](alias.md#configuration-file).

## Environment

- `ASFALOAD_CONFIG_FILE` — alternative to `--config-file`.
- `ASFALOAD_KEYS_DIR` — alternative to `--keys-dir`.

## Output

Human-readable (default):

    Signers file created: signers.json

    Signer groups
      Artifact signers   2 of 3 keys must sign
        asfaload-pub:b5S+CxuqICIUn/DGBdMKeTMZCgQcg78ohiWQ1sC00c8 (alice)
        asfaload-pub:p8p1Hb8ux9xf9mo8BGedkpv4RUFZgwXuYGu5x0grsdU (bob)
        asfaload-pub:YCuPAtMNZQaYPDjWmp8voWh6bVg0bRyLu2zEkH6zYZI
      Admin keys         none (fallback to artifact signers)
      Master keys        none
      Revocation keys    none (fallback to admin keys)

    Digest
      sha512:2e2fde4e...

    Next steps
      1. Commit this file to your git repository and publish it.
      2. Register your repository. Replace <url> with the URL of the
         published file and <secret-key> with your secret key file:

         asfaload-cli register-repo \
           --digest sha512:2e2fde4e... \
           --secret-key <secret-key> <url>

A key that has an [alias](alias.md) shows as `<base64 public key> (<alias>)`. If the configuration file cannot be read or is not valid, the command writes a warning to the standard error and shows the keys without aliases. The JSON output never shows aliases.

The digest identifies the created file; see [`get-digest`](get-digest.md) for how to recompute and compare it later.

JSON (with `--json`):

    {"output_file":"signers.json","artifact_signers_count":3,"artifact_threshold":2,"admin_keys_count":1,"admin_threshold":1,"master_keys_count":0,"master_threshold":null,"revocation_keys_count":0,"revocation_threshold":null,"digest":"sha512:2e2fde4e..."}

## Examples

    # minimal: two artifact signers, threshold of 2
    asfaload-cli new-signers-file \
        --artifact-signers-file alice.pub \
        --artifact-signers-file bob.pub \
        -A 2 \
        -o signers.json

    # with admin and revocation groups
    asfaload-cli new-signers-file \
        --artifact-signers-file alice.pub \
        --artifact-signers-file bob.pub \
        -A 2 \
        --admin-keys-file admin.pub \
        -D 1 \
        --revocation-keys-file revoke.pub \
        -R 1 \
        -o signers.json

    # your key pair "my_key" from the keys dir, and the alias "bob"
    asfaload-cli new-signers-file -a my_key -a bob -A 2 -o signers.json

    # mix base64 strings and files
    asfaload-cli new-signers-file \
        -a "asfaload-pub:b5S+CxuqICIUn/DGBdMKeTMZCgQcg78ohiWQ1sC00c8" \
        --artifact-signers-file bob.pub \
        -A 1 \
        -o signers.json

    # one key per line in a single file (--af is an alias for --artifact-signers-file)
    asfaload-cli new-signers-file \
        --af signers.txt \
        -A 2 \
        -o signers.json

## Exit codes

- `0` — signers file created.
- non-zero — error (output file exists, invalid threshold, missing keys, etc.).
