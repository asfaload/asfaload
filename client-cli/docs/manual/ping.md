# `asfaload-cli ping`

- **Usage**: `asfaload-cli ping [OPTIONS]`

Check that the backend is reachable. Without a secret key the request is unauthenticated and simply confirms connectivity. With a secret key the request is authenticated, and the backend reports whether your credentials were accepted and for which public key — useful for diagnosing key or clock problems before running a command that signs.

## Options

### `-K --secret-key <PATH>`

Path to your secret key file (asfaload or OpenSSH ed25519). Optional — when given, the ping is authenticated, and a password is required to use the key.

### `-p --password <PASSWORD>`

Password for the secret key. Only used when `--secret-key` is given. Conflicts with `--password-file` and `--password-command`. Prompted interactively if none of these is set.

### `-P --password-file <PATH>`

File containing the password. Conflicts with `--password` and `--password-command`.

### `-C --password-command <COMMAND>`

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
- `ASFALOAD_PING_PASSWORD` — alternative to `--password` (still supported, lower precedence).
- `ASFALOAD_PING_PASSWORD_FILE` — alternative to `--password-file` (still supported, lower precedence).

## Output

Human-readable (default), unauthenticated:

    pong from https://backend.asfaload.com — unauthenticated

Authenticated successfully:

    pong from https://backend.asfaload.com — authenticated as asfaload-pub:b5S+CxuqICIUn/DGBdMKeTMZCgQcg78ohiWQ1sC00c8

Authentication attempted but failed:

    pong from https://backend.asfaload.com — auth FAILED for key asfaload-pub:b5S+CxuqICIUn/DGBdMKeTMZCgQcg78ohiWQ1sC00c8: Replay attack detected: nonce already used

JSON (with `--json`):

    {"message":"pong","auth":{"status":"unauthenticated"}}
    {"message":"pong","auth":{"status":"success","public_key":"asfaload-pub:b5S+CxuqICIUn/DGBdMKeTMZCgQcg78ohiWQ1sC00c8"}}
    {"message":"pong","auth":{"status":"failed","public_key":"asfaload-pub:b5S+CxuqICIUn/DGBdMKeTMZCgQcg78ohiWQ1sC00c8","reason":"Replay attack detected: nonce already used"}}

## Examples

    # check connectivity (unauthenticated)
    asfaload-cli ping

    # verify your credentials are accepted
    asfaload-cli ping -K ~/.asfaload/mykey

    # against a non-default backend
    asfaload-cli ping -u https://my-asfaload-deployment.example.com

## Exit codes

- `0` — backend reachable; either an unauthenticated ping or authentication succeeded.
- non-zero — backend unreachable, or authentication was attempted and failed.
