# `asfaload-cli signature-status`

- **Usage**: `asfaload-cli signature-status [OPTIONS] <FILE_PATH>`
- **Source**: [`src/commands/signature_status.rs`](../../src/commands/signature_status.rs)
- **Related endpoint**: [`GET /v1/signatures/{file_path}`](../../../rest-api/docs/manual/signature-status.md)

Query the backend for the signature collection status of a file. The caller must be an authorized signer in the file's current signers file; see the linked endpoint for the exact authorization rule.

## Arguments

### `<FILE_PATH>`

Mirror-relative path to the file to query, for example `https/github.com/443/acme/repo/releases/tag/v1.0/asfaload.index.json`.

You can also give the path of a pending signers file or a pending revocation file after its signature is complete and the backend moved the file. The output then shows the path of the moved file as complete.

## Options

### `-K --secret-key <PATH>`

Path to the caller's secret key file. Required.

### `-p --password <PASSWORD>`

Password for the secret key. Conflicts with `--password-file` and `--password-command`. Prompted interactively if none of these is set.

### `-P --password-file <PATH>`

File containing the password. Conflicts with `--password` and `--password-command`.

### `-c --password-command <COMMAND>`

Shell command to run; its standard output is read as the password. Useful for password managers (`pass`, `op`, `bw`, etc.). Conflicts with `--password` and `--password-file`. The command string is parsed with shell-style quoting (no shell is spawned, so pipes and redirections don't apply); trailing newlines are stripped from the output.

### `-u --backend-url <URL>`

Backend API URL. Defaults to `https://backend.asfaload.com`.

### `--json`

Emit the backend response as JSON instead of human-readable text.

## Environment

These variables provide fallbacks for the matching options. Password sources are tried in the order described in the [manual index](index.md#passwords): flags first (in the order `--password`, `--password-command`, `--password-file`), then environment variables, then an interactive prompt.

- `ASFALOAD_SECRET_KEY` — alternative to `--secret-key`.
- `ASFALOAD_BACKEND_URL` — alternative to `--backend-url`.
- `ASFALOAD_PASSWORD_FILE` — alternative to `--password-file`.
- `ASFALOAD_PASSWORD_COMMAND` — alternative to `--password-command`.
- `ASFALOAD_SIGNATURE_STATUS_PASSWORD` — alternative to `--password` (still supported, lower precedence).
- `ASFALOAD_SIGNATURE_STATUS_PASSWORD_FILE` — alternative to `--password-file` (still supported, lower precedence).

## Output

Human-readable (default):

    <file_path>: pending

    Keys that can still sign
      <base64 public key>
      <base64 public key>

A key is in the list when it has no valid signature yet. The list does not tell how many signatures are still necessary.

or

    <file_path>: complete

JSON (with `--json`):

    {"file_path":"<file_path>","is_complete":false,"required_signers":["<base64 public key>","<base64 public key>"]}

## Examples

    # check a pending release index
    asfaload-cli signature-status -K ~/.asfaload/key \
        https/github.com/443/acme/repo/releases/tag/v1.0/asfaload.index.json

    # use a non-default backend
    asfaload-cli signature-status -K ~/.asfaload/key -u https://asfaload.example.com \
        https/github.com/443/acme/repo/releases/tag/v1.0/asfaload.index.json

    # machine-readable output
    asfaload-cli signature-status --json -K ~/.asfaload/key \
        https/github.com/443/acme/repo/releases/tag/v1.0/asfaload.index.json

## Exit codes

- `0` — query succeeded.
- non-zero — error (authentication failure, not authorized, file not found, revoked file, network error).
