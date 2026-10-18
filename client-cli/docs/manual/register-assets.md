# `asfaload-cli register-assets`

- **Usage**: `asfaload-cli register-assets [OPTIONS] -K <SECRET_KEY>`
- **Source**: [`src/commands/register_assets.rs`](../../src/commands/register_assets.rs)

Register assets for signing. Tell the backend about a new set of files — either a GitHub release or one or more checksum files — so that the signature collection process can begin.

After registration you still need to sign the assets yourself with [`sign-pending`](sign-pending.md).

Registration is authenticated with your secret key. In GitHub release mode, that key must also be an authorized artifact signer for the release path; otherwise the backend answers `403 Forbidden`. In checksums mode, the backend currently checks only that a signers config exists for the target directory.

## Options

### `--github-release-url <URL>`

URL of a GitHub release page. The backend fetches the release assets automatically. The host must be a known GitHub host (e.g. `github.com`); anything else is rejected. Mutually exclusive with `--csum-file`.

### `--csum-file <URL>`

URL of a checksums file. Repeatable — pass once per file. All URLs must share the same origin (scheme, host, and port) and a common parent path. Mutually exclusive with `--github-release-url`.

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
- `ASFALOAD_REGISTER_ASSETS_PASSWORD` — alternative to `--password` (still supported, lower precedence).
- `ASFALOAD_REGISTER_ASSETS_PASSWORD_FILE` — alternative to `--password-file` (still supported, lower precedence).

## Output

Human-readable (default):

    Assets registered successfully! Remember you still need to sign it yourself!
    Index file path: https/github.com/443/acme/tool/releases/tag/v1.0/asfaload.index.json

JSON (with `--json`):

    {"success":true,"message":"","index_file_path":"https/github.com/443/acme/tool/releases/tag/v1.0/asfaload.index.json"}

## Examples

    # register a GitHub release
    asfaload-cli register-assets -K ~/.asfaload/key \
        --github-release-url https://github.com/acme/tool/releases/tag/v1.0

    # register checksum files
    asfaload-cli register-assets -K ~/.asfaload/key \
        --csum-file https://example.com/releases/v1.0/SHA256SUMS \
        --csum-file https://example.com/releases/v1.0/SHA512SUMS

## Exit codes

- `0` — assets registered.
- non-zero — error (authentication failure, invalid URL, mutually exclusive flags, network error).
