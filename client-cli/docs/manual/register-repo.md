# `asfaload-cli register-repo`

- **Usage**: `asfaload-cli register-repo [OPTIONS] -K <SECRET_KEY> (--digest <VALUE> | --local-copy <PATH>) <SIGNERS_FILE_URL>`
- **Source**: [`src/commands/register_repo.rs`](../../src/commands/register_repo.rs)

Register a new repository with the backend. Points the backend at your signers file so it knows which keys are authorized to sign artifacts for this project.

The CLI signs the signers file and the metadata with your secret key, and sends both signatures. If your signature completes the required signers, the project is active at once. Otherwise the remaining signers must submit their signatures to activate the project.

## Arguments

### `<SIGNERS_FILE_URL>`

Public URL to the signers file on the forge. For example:

    https://raw.githubusercontent.com/owner/repo/main/asfaload.signers/index.json

## Options

Exactly one of `--digest` or `--local-copy` is required.

Register-repo computes the digest of the file served at `<SIGNERS_FILE_URL>` and aborts with an error before contacting the backend if it does not match the expected digest.

### `--digest <VALUE>`

Digest of the signers file that must be found at the remote URL before register-repo contacts the backend. Format `sha512:<hex>`, exactly as printed by `get-digest`.

### `--local-copy <PATH>`

Path to a local copy of the signers file. Its digest is computed with sha512 and used as the expected value.

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
- `ASFALOAD_REGISTER_REPO_PASSWORD` — alternative to `--password` (still supported, lower precedence).
- `ASFALOAD_REGISTER_REPO_PASSWORD_FILE` — alternative to `--password-file` (still supported, lower precedence).

## Output

Human-readable (default), when more signatures are necessary:

    Repository registered: https/github.com/443/acme/tool

    Keys that can still sign
      asfaload-pub:alice-key
      asfaload-pub:bob-key

    Next step
      Send this command to the signers. Each signer replaces <secret-key>
      with their secret key file:

         asfaload-cli sign-pending \
           --digest sha512:2e2fde4e... \
           https/github.com/443/acme/tool/asfaload.signers.pending/index.json \
           --secret-key <secret-key>

Send the `sign-pending` command to the signers. Each signer replaces `<secret-key>` with their secret key file. When you use a backend other than the default, the command contains `--backend-url`. If the backend returns an unexpected project ID or signers file path, a warning replaces the command.

When your signature completes the required signers, the output says that the signers file is active:

    Repository registered: https/github.com/443/acme/tool

    The signers file is active. No more signatures are necessary.

JSON (with `--json`):

    {"success":true,"project_id":"https/github.com/443/acme/tool","message":"Project registered successfully. Collect signatures to activate.","required_signers":["asfaload-pub:alice-key","asfaload-pub:bob-key"],"signature_submission_url":"/v1/signatures","signers_file_path":"https/github.com/443/acme/tool/asfaload.signers.pending/index.json"}

## Examples

    # register a GitHub-hosted signers file; get the digest with get-digest
    asfaload-cli register-repo -K ~/.asfaload/key \
        --digest sha512:2e2fde4e... \
        https://raw.githubusercontent.com/acme/tool/main/asfaload.signers/index.json

    # with a local copy of the signers file, and an explicit backend
    asfaload-cli register-repo -K ~/.asfaload/key \
        --local-copy ~/Downloads/index.json \
        -u https://asfaload.example.com \
        https://raw.githubusercontent.com/acme/tool/main/asfaload.signers/index.json

## Exit codes

- `0` — repository registered.
- non-zero — error (authentication failure, digest mismatch, invalid signers file URL, network error, backend reports a failure).
