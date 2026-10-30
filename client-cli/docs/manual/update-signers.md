# `asfaload-cli update-signers`

- **Usage**: `asfaload-cli update-signers [OPTIONS] -K <SECRET_KEY> (--digest <VALUE> | --local-copy <PATH>) <SIGNERS_FILE_URL>`
- **Source**: [`src/commands/update_signers.rs`](../../src/commands/update_signers.rs)

Propose an update to an existing project's signers file. The CLI signs the new signers file and the metadata with your secret key, and the backend records both signatures.

Update-signers computes the digest of the file served at `<SIGNERS_FILE_URL>` and aborts with an error before contacting the backend if it does not match the expected digest.

If your signature completes the required signers, the update is active at once. Otherwise the backend starts a signature collection round — signers from the **current** configuration must approve the change before it takes effect.

## Arguments

### `<SIGNERS_FILE_URL>`

Public URL to the **new** signers file on the forge. For example:

    https://raw.githubusercontent.com/owner/repo/main/asfaload.signers/index.json

## Options

Exactly one of `--digest` or `--local-copy` is required.

### `--digest <VALUE>`

Digest of the new signers file that must be found at the remote URL before update-signers contacts the backend. Format `sha512:<hex>`, exactly as printed by `get-digest`.

### `--local-copy <PATH>`

Path to a local copy of the new signers file. Its digest is computed with sha512 and used as the expected value.

### `-K --secret-key <PATH>`

Path to your secret key file. Required.

### `-p --password <PASSWORD>`

Password for the secret key. Conflicts with `--password-file` and `--password-command`. Prompted interactively if none of these is set.

### `-P --password-file <PATH>`

File containing the password. Conflicts with `--password` and `--password-command`.

### `-c --password-command <COMMAND>`

Shell command to run; its standard output is read as the password. Useful for password managers (`pass`, `op`, `bw`, etc.). Conflicts with `--password` and `--password-file`. The command string is parsed with shell-style quoting (no shell is spawned, so pipes and redirections don't apply); trailing newlines are stripped from the output.

### `-u --backend-url <URL>`

Backend API URL. Defaults to `https://backend.asfaload.com`.

### `--json`

Emit output as JSON instead of human-readable text.

## Environment

These variables provide fallbacks for the matching options. Password sources are tried in the order described in the [manual index](index.md#passwords): flags first (in the order `--password`, `--password-command`, `--password-file`), then environment variables, then an interactive prompt.

- `ASFALOAD_SECRET_KEY` — alternative to `--secret-key`.
- `ASFALOAD_BACKEND_URL` — alternative to `--backend-url`.
- `ASFALOAD_PASSWORD_FILE` — alternative to `--password-file`.
- `ASFALOAD_PASSWORD_COMMAND` — alternative to `--password-command`.
- `ASFALOAD_UPDATE_SIGNERS_PASSWORD` — alternative to `--password` (still supported, lower precedence).
- `ASFALOAD_UPDATE_SIGNERS_PASSWORD_FILE` — alternative to `--password-file` (still supported, lower precedence).

## Output

Human-readable (default), when more signatures are necessary:

    Signers update proposed successfully!
    Project ID: abc123
    Required signers (2): alice, bob
    Success: Signers update proposed successfully. Collect signatures to activate.

When your signature completes the required signers, `Required signers` is empty and the last line reports the activation.

JSON (with `--json`):

    {"success":true,"project_id":"abc123","message":"Signers update proposed successfully. Collect signatures to activate.","required_signers":["alice","bob"],"signature_submission_url":"/v1/signatures"}

## Examples

    # propose a signers update; get the digest with get-digest
    asfaload-cli update-signers -K ~/.asfaload/key \
        --digest sha512:2e2fde4e... \
        https://raw.githubusercontent.com/acme/tool/main/asfaload.signers/index.json

    # with a local copy of the new signers file
    asfaload-cli update-signers -K ~/.asfaload/key \
        --local-copy ~/Downloads/index_v2.json \
        https://raw.githubusercontent.com/acme/tool/main/asfaload.signers/index.json

## Exit codes

- `0` — update proposed.
- non-zero — error (authentication failure, digest mismatch, invalid signers file, network error).
