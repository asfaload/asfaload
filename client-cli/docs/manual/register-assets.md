# `asfaload-cli register-assets`

- **Usage**: `asfaload-cli register-assets [OPTIONS] -K <SECRET_KEY>`
- **Source**: [`src/commands/register_assets.rs`](../../src/commands/register_assets.rs)

Register assets for signing. Tell the backend about a new set of files — either a GitHub release or one or more checksum files — so that the signature collection process can begin.

The registrant's signature is recorded at registration. The other artifact signers add their signatures with [`sign-pending`](sign-pending.md).

Registration is authenticated with your secret key. The CLI signs the release index with that key before it sends the request.

## Options

### `--github-release-url <URL>`

URL of a GitHub release page. The CLI uses it to compute the release index. The host must be a known GitHub host (e.g. `github.com`); anything else is rejected. Mutually exclusive with `--csum-file`.

### `--csum-file <URL>`

URL of a checksums file. Repeatable — pass once per file. All URLs must share the same origin (scheme, host, and port) and a common parent path. The CLI downloads these files and computes the release index from them. Mutually exclusive with `--github-release-url`.

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

Human-readable (default), when more signatures are necessary:

    Release registered: https/github.com/443/acme/tool/releases/tag/v1.0/asfaload.index.json
    Your signature is included.

    Keys that can still sign
      asfaload-pub:alice-key
      asfaload-pub:bob-key

    Next step
      Send this command to the signers. Each signer replaces <secret-key>
      with their secret key file:

         asfaload-cli sign-pending \
           --digest sha512:2e2fde4e... \
           https/github.com/443/acme/tool/releases/tag/v1.0/asfaload.index.json \
           --secret-key <secret-key>

Send the `sign-pending` command to the signers. Each signer replaces `<secret-key>` with their secret key file. The digest is the digest of the index that you signed. When you use a backend other than the default, the command contains `--backend-url`. If the backend returns an unexpected index file path, a warning replaces the command.

When your signature completes the aggregate signature, the output says that the release is fully signed:

    Release registered: https/github.com/443/acme/tool/releases/tag/v1.0/asfaload.index.json
    Your signature is included.

    The release is fully signed. No more signatures are necessary.

JSON (with `--json`):

    {"success":true,"message":"Release registered successfully","index_file_path":"https/github.com/443/acme/tool/releases/tag/v1.0/asfaload.index.json","required_signers":["asfaload-pub:alice-key","asfaload-pub:bob-key"]}

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

## Errors

You register the assets with your own signature key. If your key is not in the
project signers file, the server refuses the request. The CLI then shows
`403 Forbidden` and a message from the server. Use a key that signs the current
signers file.
