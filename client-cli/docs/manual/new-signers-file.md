# `asfaload-cli new-signers-file`

- **Usage**: `asfaload-cli new-signers-file [OPTIONS] --artifact-threshold <ARTIFACT_THRESHOLD>`

Create a new signers file that defines who can sign artifacts, administer, and manage the project. At minimum, one artifact signer and its threshold are required.

## Options

### Artifact signers

Every signers file needs at least one artifact signer.

#### `-a --artifact-signer <PUB_KEY>`

Public key as a base64 string. Repeatable.

#### `--artifact-signers-file <FILE_PATH>` (`--af`)

Path to a file holding public keys, **one per line**. Repeatable. Combines with `--artifact-signer`.

#### `-A --artifact-threshold <N>`

Number of artifact signers required to complete a signature. Must be between 1 and the total number of artifact signers.

### Admin keys (optional)

#### `-d --admin-key <PUB_KEY>`

Admin public key as a base64 string. Repeatable.

#### `--admin-keys-file <FILE_PATH>` (`--df`)

Path to a file holding admin public keys, **one per line**. Repeatable. Combines with `--admin-key`.

#### `-D --admin-threshold <N>`

Required when admin keys are provided. Number of admins required to approve changes.

### Master keys (optional)

#### `-m --master-key <PUB_KEY>`

Master public key as a base64 string. Repeatable.

#### `--master-keys-file <FILE_PATH>` (`--mf`)

Path to a file holding master public keys, **one per line**. Repeatable. Combines with `--master-key`.

#### `-M --master-threshold <N>`

Required when master keys are provided.

### Revocation keys (optional)

#### `-r --revocation-key <PUB_KEY>`

Revocation public key as a base64 string. Repeatable.

#### `--revocation-keys-file <FILE_PATH>` (`--rf`)

Path to a file holding revocation public keys, **one per line**. Repeatable. Combines with `--revocation-key`.

#### `-R --revocation-threshold <N>`

Required when revocation keys are provided.

### General

#### `-o --output-file <OUTPUT_FILE>`

Path for the new signers file. The file must not already exist — the command refuses to overwrite. Parent directories are created automatically. Required when `--json` is used; otherwise the signers file is printed to stdout if omitted.

#### `--json`

Emit output as JSON instead of human-readable text.

#### `-c --config-file <CONFIG_FILE>`

The configuration file to read aliases from, instead of the default file. Refer to [alias](alias.md#configuration-file).

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
