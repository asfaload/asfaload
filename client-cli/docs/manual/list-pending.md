# `asfaload-cli list-pending`

- **Usage**: `asfaload-cli list-pending [OPTIONS] -K <SECRET_KEY>`
- **Source**: [`src/commands/list_pending.rs`](../../src/commands/list_pending.rs)

List all files on the backend that still need your signature. The command authenticates with your secret key and returns only the files where your public key is among the expected signers.

## Options

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

### `--digest-filter <DIGEST>` (`--df`)

Only list pending files whose digest matches the given value. The value must be a full `sha512:<128 hexadecimal characters>` digest (e.g. as printed by [`get-digest`](get-digest.md) or in the list output itself); anything else is rejected. Filtered results are subject to the same output rules as unfiltered ones (an empty result prints `No pending signatures found.`).

### `--json`

Emit the backend response as JSON instead of human-readable text.

## Environment

These variables provide fallbacks for the matching options. Password sources are tried in the order described in the [manual index](index.md#passwords): flags first (in the order `--password`, `--password-command`, `--password-file`), then environment variables, then an interactive prompt.

- `ASFALOAD_SECRET_KEY` — alternative to `--secret-key`.
- `ASFALOAD_BACKEND_URL` — alternative to `--backend-url`.
- `ASFALOAD_PASSWORD_FILE` — alternative to `--password-file`.
- `ASFALOAD_PASSWORD_COMMAND` — alternative to `--password-command`.
- `ASFALOAD_LIST_PENDING_PASSWORD` — alternative to `--password` (still supported, lower precedence).
- `ASFALOAD_LIST_PENDING_PASSWORD_FILE` — alternative to `--password-file` (still supported, lower precedence).

## Output

Human-readable (default), when files are pending. Each entry shows the path and its digest:

    Files requiring your signature:
      - path: https/github.com/443/acme/repo/releases/tag/v1.0/asfaload.index.json
    digest: sha512:2e2fde4ead7c6846656431dd4f2d2f3013e2b35d31fc32978fc03a32f54034589d65ab6666a72aab3835bf409dc7b86fdab6b2f488486c4012c0acffc41438d7

When nothing is pending:

    No pending signatures found.

JSON (with `--json`):

    {"pending_files":[{"path":"https/github.com/443/acme/repo/releases/tag/v1.0/asfaload.index.json","digest":"sha512:2e2fde4ead7c6846656431dd4f2d2f3013e2b35d31fc32978fc03a32f54034589d65ab6666a72aab3835bf409dc7b86fdab6b2f488486c4012c0acffc41438d7"}]}

An empty result serializes as `{"pending_files":[]}`.

## Examples

    # list pending files
    asfaload-cli list-pending -K ~/.asfaload/key

    # list pending files for one specific digest
    asfaload-cli list-pending --df sha512:2e2fde4e... -K ~/.asfaload/key

    # non-interactive, piped into sign-pending
    asfaload-cli list-pending --json -K ~/.asfaload/key -p "$PASSWORD" \
        | jq -r '.pending_files[0] | "--digest \(.digest) \(.path)"' \
        | xargs asfaload-cli sign-pending -K ~/.asfaload/key -p "$PASSWORD"

## Exit codes

- `0` — query succeeded (even if no files are pending).
- non-zero — error (authentication failure, network error).
