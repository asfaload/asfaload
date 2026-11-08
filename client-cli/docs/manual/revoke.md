# `asfaload-cli revoke`

- **Usage**: `asfaload-cli revoke [OPTIONS] -K <SECRET_KEY> <FILE_PATH>`
- **Source**: [`src/commands/revoke.rs`](../../src/commands/revoke.rs)

Revoke a previously signed file on the mirror. The command fetches the file from the backend, builds a revocation document (timestamped, with the initiator's public key and the file's SHA-512 digest), signs it, and submits it.

The revocation becomes active when enough revocation keys have signed it. If the revocation threshold is 1, your signature completes the revocation. If the threshold is more than 1, the revocation stays pending: other revocation signers must sign it with [`sign-pending`](sign-pending.md). Until the revocation is complete, users can still [`download`](download.md) the file. When the revocation is complete, a download of the file fails.

## Arguments

### `<FILE_PATH>`

Mirror-relative path to the signed file, for example `https/github.com/443/acme/repo/releases/tag/v1.0/asfaload.index.json`.

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

### `--json`

Emit output as JSON instead of human-readable text.

## Environment

These variables provide fallbacks for the matching options. Password sources are tried in the order described in the [manual index](index.md#passwords): flags first (in the order `--password`, `--password-command`, `--password-file`), then environment variables, then an interactive prompt.

- `ASFALOAD_SECRET_KEY` — alternative to `--secret-key`.
- `ASFALOAD_BACKEND_URL` — alternative to `--backend-url`.
- `ASFALOAD_PASSWORD_FILE` — alternative to `--password-file`.
- `ASFALOAD_PASSWORD_COMMAND` — alternative to `--password-command`.
- `ASFALOAD_REVOKE_PASSWORD` — alternative to `--password` (still supported, lower precedence).
- `ASFALOAD_REVOKE_PASSWORD_FILE` — alternative to `--password-file` (still supported, lower precedence).

## Output

Human-readable (default), when more revocation signatures are necessary:

    Revocation started: https/github.com/443/acme/repo/releases/tag/v1.0/asfaload.index.json
    Your signature is included.
    Users can still download the file until the revocation is complete.

    Keys that can still sign
      asfaload-pub:b5S+CxuqICIUn/DGBdMKeTMZCgQcg78ohiWQ1sC00c8

    Next step
      Send this command to the signers. Each signer replaces <secret-key>
      with their secret key file:

         asfaload-cli sign-pending \
           --digest sha512:2e2fde4e... \
           https/github.com/443/acme/repo/releases/tag/v1.0/asfaload.index.json.revocation.json.pending \
           --secret-key <secret-key>

When you use a backend other than the default one, the command also contains `--backend-url`.

Human-readable (default), when your signature completes the revocation:

    File revoked: https/github.com/443/acme/repo/releases/tag/v1.0/asfaload.index.json
    Your signature is included.

    The revocation is complete. Downloads of this file now fail.

JSON (with `--json`). `required_signers` contains the keys that can still sign. It is empty when the revocation is complete:

    {"success":true,"message":"Revocation started, more signatures are necessary","required_signers":["asfaload-pub:b5S+CxuqICIUn/DGBdMKeTMZCgQcg78ohiWQ1sC00c8"]}

## Examples

    # revoke a release index
    asfaload-cli revoke -K ~/.asfaload/key \
        https/github.com/443/acme/repo/releases/tag/v1.0/asfaload.index.json

## Exit codes

- `0` — revocation started or completed.
- non-zero — error (authentication failure, file not found, not authorized, revocation already pending, network error, backend reports a failed revocation).
