# `asfaload-cli revoke`

- **Usage**: `asfaload-cli revoke [OPTIONS] -K <SECRET_KEY> <--digest <DIGEST>|--local-copy <PATH>> <FILE_PATH>`
- **Source**: [`src/commands/revoke.rs`](../../src/commands/revoke.rs)

Revoke a previously signed file on the mirror. The command fetches the file from the backend and compares its SHA-512 digest with the expected digest that you give with `--digest` or `--local-copy`. If the two digests are not the same, the command stops and sends nothing to the backend. Then the command builds a revocation document (timestamped, with the initiator's public key and the file's SHA-512 digest), signs it, and submits it.

The revocation becomes active when enough revocation keys have signed it. If the revocation threshold is 1, your signature completes the revocation. If the threshold is more than 1, the revocation stays pending: other revocation signers must sign it with [`sign-pending`](sign-pending.md). Until the revocation is complete, users can still [`download`](download.md) the file. When the revocation is complete, a download of the file fails.

## Arguments

### `<FILE_PATH>`

Mirror-relative path to the signed file, for example `https/github.com/443/acme/repo/releases/tag/v1.0/asfaload.index.json`.

You must always give the expected digest of the file to revoke, with `--digest` or `--local-copy`.

## Options

### `--digest <DIGEST>`

The expected `sha512:<128 hexadecimal characters>` digest of the file to revoke. Get it from a trusted source: for a release index, the output of [`register-assets`](register-assets.md) gives it (`index_digest` with `--json`). Or compute it with [`get-digest`](get-digest.md) on a local copy of the file. Do not take it from the backend. Before the command signs the revocation, it compares the digest of the fetched file with this value. If the two digests are not the same, the command stops. Conflicts with `--local-copy`. You must give `--digest` or `--local-copy`.

### `--local-copy <PATH>`

Path to your local copy of the file to revoke. Its SHA-512 digest is the expected digest, and the command uses it as it uses the value of `--digest`. Conflicts with `--digest`.

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

If the file path contains unexpected characters, a warning replaces the command. The other revocation signers can then find the pending revocation with [`list-pending`](list-pending.md).

Human-readable (default), when your signature completes the revocation:

    File revoked: https/github.com/443/acme/repo/releases/tag/v1.0/asfaload.index.json
    Your signature is included.

    The revocation is complete. Downloads of this file now fail.

JSON (with `--json`). `required_signers` contains the keys that can still sign. It is empty when the revocation is complete. `revocation_digest` is the digest of the revocation document that you signed. Send it to the other revocation signers: they give it as the `--digest` value of `sign-pending`:

    {"success":true,"message":"Revocation started, more signatures are necessary","required_signers":["asfaload-pub:b5S+CxuqICIUn/DGBdMKeTMZCgQcg78ohiWQ1sC00c8"],"revocation_digest":"sha512:2e2fde4e..."}

## Examples

    # revoke a release index
    asfaload-cli revoke -K ~/.asfaload/key \
        --digest sha512:7d4a1c90... \
        https/github.com/443/acme/repo/releases/tag/v1.0/asfaload.index.json

## Exit codes

- `0` — revocation started or completed.
- non-zero — error (the digest of the fetched file is not equal to the expected digest, authentication failure, file not found, not authorized, revocation already pending, network error, backend reports a failed revocation).
