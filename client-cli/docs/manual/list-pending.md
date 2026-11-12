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

Only list pending files whose digest matches the given value. The value must be a full `sha512:<128 hexadecimal characters>` digest (e.g. as printed by [`get-digest`](get-digest.md)); anything else is rejected. Filtered results are subject to the same output rules as unfiltered ones (an empty result prints `No pending signatures found.`).

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

Human-readable (default), when files are pending. Each entry shows the path and a short digest: the start and the end of the digest that the backend gives. The full digest is not shown, because you must not take the expected digest of [`sign-pending`](sign-pending.md) from the backend. Use the short digest to make sure that the pending file has the digest that you expect, for example when `sign-pending` reports a digest mismatch:

    Files requiring your signature:
      - path: https/github.com/443/acme/repo/releases/tag/v1.0/asfaload.index.json
    digest: sha512:2e2fde4e....c41438d7

When nothing is pending:

    No pending signatures found.

JSON (with `--json`). `short_digest` is the short digest:

    {"pending_files":[{"path":"https/github.com/443/acme/repo/releases/tag/v1.0/asfaload.index.json","short_digest":"sha512:2e2fde4e....c41438d7"}]}

An empty result serializes as `{"pending_files":[]}`.

## Examples

    # list pending files
    asfaload-cli list-pending -K ~/.asfaload/key

    # list pending files for one specific digest
    asfaload-cli list-pending --df sha512:2e2fde4e... -K ~/.asfaload/key

    # non-interactive: sign the first pending file. EXPECTED_DIGEST
    # comes from a source that you trust, not from list-pending.
    PENDING_PATH=$(asfaload-cli list-pending --json -K ~/.asfaload/key -p "$PASSWORD" \
        | jq -r '.pending_files[0].path')
    asfaload-cli sign-pending -K ~/.asfaload/key -p "$PASSWORD" \
        --digest "$EXPECTED_DIGEST" "$PENDING_PATH"

## Exit codes

- `0` — query succeeded (even if no files are pending).
- non-zero — error (authentication failure, network error).
