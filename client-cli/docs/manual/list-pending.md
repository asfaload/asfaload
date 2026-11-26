# `asfaload-cli list-pending`

- **Usage**: `asfaload-cli list-pending [OPTIONS] -K <SECRET_KEY>`

List all files on the backend that still need your signature. The command authenticates with your secret key and returns only the files where your public key is among the expected signers.

## Options

### `-K --secret-key <PATH|NAME>`

Path to your secret key file, or the name of a key file in the keys directory (see `--keys-dir`). If a file exists at the given path, the command uses it. If not, the command reads the file with this name in the keys directory. Required.

### `-d --keys-dir <DIR>`

Directory where the command looks for the secret key when the value of `--secret-key` is not an existing file. The command then reads `<DIR>/<value of --secret-key>`. Defaults to `$XDG_DATA_HOME/asfaload-cli` (usually `~/.local/share/asfaload-cli`), the directory where [`new-keys`](new-keys.md) writes keys by default.

### `-p --password <PASSWORD>`

Password for the secret key. Conflicts with `--password-file` and `--password-command`. Prompted interactively if none of these is set.

### `-P --password-file <PATH>`

File containing the password. Conflicts with `--password` and `--password-command`.

### `-C --password-command <COMMAND>`

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
- `ASFALOAD_KEYS_DIR` — alternative to `--keys-dir`.
- `ASFALOAD_BACKEND_URL` — alternative to `--backend-url`.
- `ASFALOAD_PASSWORD_FILE` — alternative to `--password-file`.
- `ASFALOAD_PASSWORD_COMMAND` — alternative to `--password-command`.
- `ASFALOAD_LIST_PENDING_PASSWORD` — alternative to `--password` (still supported, lower precedence).
- `ASFALOAD_LIST_PENDING_PASSWORD_FILE` — alternative to `--password-file` (still supported, lower precedence).

## Output

Human-readable (default), when files are pending. Each entry shows a number, the path and a short digest: the start and the end of the digest that the backend gives. The full digest is not shown, because you must not take the expected digest of [`sign-pending`](sign-pending.md) from the backend. Use the short digest to make sure that the pending file has the digest that you expect, for example when `sign-pending` reports a digest mismatch:

    Files requiring your signature
      1. path:   https/github.com/443/acme/repo/releases/tag/v1.0/asfaload.index.json
         digest: sha512:2e2fde4e....c41438d7

    Before you sign
      The digests above are shortened. Get the full digest of the file from
      the user who started the signature process. Use the full digest to
      sign. Make sure that it starts and ends like the shortened digest.

    Next step
      To sign pending file 1, run this command. Replace <full-digest> with the
      full digest:

         asfaload-cli sign-pending \
           --digest <full-digest> \
           https/github.com/443/acme/repo/releases/tag/v1.0/asfaload.index.json \
           --secret-key key

The `sign-pending` example uses the first pending file with a path that is safe in a shell command, and gives the number of this file. To sign a different file, replace the path. When no path is safe, the example shows `<file-path>`. The example uses the `--secret-key` and `--keys-dir` values that you gave to `list-pending`. The sample above is the output of `asfaload-cli list-pending -K key`. When a value contains characters that are not safe in a shell command, the example shows `--secret-key <secret-key>` instead.

When nothing is pending:

    No pending signatures found.

JSON (with `--json`). `short_digest` is the short digest:

    {"pending_files":[{"path":"https/github.com/443/acme/repo/releases/tag/v1.0/asfaload.index.json","short_digest":"sha512:2e2fde4e....c41438d7"}]}

An empty result serializes as `{"pending_files":[]}`.

## Examples

    # list pending files
    asfaload-cli list-pending -K key

    # list pending files for one specific digest
    asfaload-cli list-pending --df sha512:2e2fde4e... -K key

    # non-interactive: sign the first pending file. EXPECTED_DIGEST
    # comes from a source that you trust, not from list-pending.
    PENDING_PATH=$(asfaload-cli list-pending --json -K key -p "$PASSWORD" \
        | jq -r '.pending_files[0].path')
    asfaload-cli sign-pending -K key -p "$PASSWORD" \
        --digest "$EXPECTED_DIGEST" "$PENDING_PATH"

## Exit codes

- `0` — query succeeded (even if no files are pending).
- non-zero — error (authentication failure, network error).
