# `asfaload-cli sign-pending`

- **Usage**: `asfaload-cli sign-pending [OPTIONS] -K <SECRET_KEY> [<FILE_PATH> --digest <DIGEST>]`
- **Source**: [`src/commands/sign_pending.rs`](../../src/commands/sign_pending.rs)

Sign a pending file. The command fetches all files associated with the given path from the backend, computes a SHA-512 hash of each, signs them with your secret key, and submits the signatures in a single request.

Use [`list-pending`](list-pending.md) to discover which files need signing.

## Arguments

### `<FILE_PATH>`

Mirror-relative path to the file to sign, as returned by `list-pending`. For example `https/github.com/443/acme/repo/releases/tag/v1.0/asfaload.index.json`. Optional: if omitted, an interactive selector is shown (see below).

`<FILE_PATH>` and `--digest` are tied together: passing one requires the other.

## Options

### `--digest <DIGEST>`

The `sha512:<128 hexadecimal characters>` digest of the file to sign, as printed by [`list-pending`](list-pending.md) or [`get-digest`](get-digest.md). Required when `<FILE_PATH>` is given. Before signing, the digest of the fetched file is verified against this value and the command aborts on mismatch.

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

Only used when `<FILE_PATH>` is omitted: pre-filters the interactive selection list to pending files matching the given `sha512:<128 hexadecimal characters>` digest. Same value format as `--digest`.

### `--json`

Emit output as JSON instead of human-readable text.

## Environment

These variables provide fallbacks for the matching options. Password sources are tried in the order described in the [manual index](index.md#passwords): flags first (in the order `--password`, `--password-command`, `--password-file`), then environment variables, then an interactive prompt.

- `ASFALOAD_SECRET_KEY` — alternative to `--secret-key`.
- `ASFALOAD_BACKEND_URL` — alternative to `--backend-url`.
- `ASFALOAD_PASSWORD_FILE` — alternative to `--password-file`.
- `ASFALOAD_PASSWORD_COMMAND` — alternative to `--password-command`.
- `ASFALOAD_SIGN_PENDING_PASSWORD` — alternative to `--password` (still supported, lower precedence).
- `ASFALOAD_SIGN_PENDING_PASSWORD_FILE` — alternative to `--password-file` (still supported, lower precedence).

## Interactive selection

When `<FILE_PATH>` (and therefore `--digest`) is omitted, the command fetches your pending files and, on a terminal, shows an interactive `Select` prompt, one pending file at a time. Each proposal lists the file path, its digest, and its bishop art so you can visually confirm you are signing the intended file. Navigate with `↑`/`↓` to cycle through the pending files, or use `--digest-filter` to narrow the list beforehand.

If nothing is pending, the command fails with `No pending signature found`. If stdin is not a terminal (e.g. in CI), the command fails with `Not a tty and no path to sign was passed.` — pass `<FILE_PATH>` and `--digest` explicitly in that case.

## Output

Human-readable (default), when the aggregate signature is now complete:

    Success! Your signature has been included and the aggregate signature is now complete. No further signature will be included in this aggregate signature.

When other signers must still provide their signatures:

    Success! Your signature has been included, but the aggregate signature is not yet complete. Other signers must still provide their signatures.

JSON (with `--json`):

    {"is_complete":true}

## Examples

    # sign a pending release index
    asfaload-cli sign-pending -K ~/.asfaload/key \
        --digest sha512:2e2fde4e... \
        https/github.com/443/acme/repo/releases/tag/v1.0/asfaload.index.json

    # sign with explicit password (CI usage)
    asfaload-cli sign-pending -K ~/.asfaload/key -p "$PASSWORD" \
        --digest sha512:2e2fde4e... \
        https/github.com/443/acme/repo/releases/tag/v1.0/asfaload.index.json

    # interactive selection from the pending list
    asfaload-cli sign-pending -K ~/.asfaload/key

    # interactive selection, restricted to one digest
    asfaload-cli sign-pending -K ~/.asfaload/key --df sha512:2e2fde4e...

## Exit codes

- `0` — signature submitted successfully.
- non-zero — error (authentication failure, file not found, network error).
