# `asfaload-cli check-pending-signers`

- **Usage**: `asfaload-cli check-pending-signers [OPTIONS] <SIGNERS_PATH>`
- **Source**: [`src/commands/check_pending_signers.rs`](../../src/commands/check_pending_signers.rs)

Fetch a pending signers file (`asfaload.signers.pending/index.json`) from the mirror, together with its metadata file, and verify that the file is byte-identical to the content served at the retrieval URL recorded in the metadata. The source is fetched from the metadata's retrieval URL and both contents are compared by SHA-512. A compromised mirror could otherwise hold a signers file that differs from the one the project actually published on its forge.

This is the same verification the CLI performs before letting you sign a pending signers file with [`sign-pending`](sign-pending.md), exposed on its own so you can check a pending signers file without signing it.

## Arguments

### `<SIGNERS_PATH>`

Mirror-relative path of the pending signers file, as displayed by `list-pending`, e.g. `https/github.com/443/acme/repo/asfaload.signers.pending/index.json`. Required. Paths that are not pending signers files are rejected before any network request.

## Options

### `-u --backend-url <URL>`

Backend API URL. Defaults to `https://backend.asfaload.com`.

### `-c --config-file <CONFIG_FILE>`

The configuration file to read aliases from, instead of the default file. Refer to [alias](alias.md#configuration-file).

### `--json`

Emit a summary object instead of human-readable text.

## Environment

- `ASFALOAD_BACKEND_URL` — alternative to `--backend-url`.

The command is unauthenticated: no secret key or password is needed.

## Output

Human-readable (default):

    ✓ Pending signers file matches the content published at https://raw.githubusercontent.com/acme/repo/main/asfaload.signers/index.json
    sha512:4a0f0c…2b9e

    Signer groups
      Artifact signers   2 of 3 keys must sign
        asfaload-pub:b5S+CxuqICIUn/DGBdMKeTMZCgQcg78ohiWQ1sC00c8 (alice)
        asfaload-pub:p8p1Hb8ux9xf9mo8BGedkpv4RUFZgwXuYGu5x0grsdU (bob)
        asfaload-pub:8kQnyEL5mjvWrd8Y/sw3FmyKfN6FMh9kCMpvTRJWd2k
      Admin keys         none (fallback to artifact signers)
      Master keys        none
      Revocation keys    none (fallback to admin keys)

A key that has an [alias](alias.md) shows as `<base64 public key> (<alias>)`. If the configuration file cannot be read or is not valid, the command writes a warning to the standard error and shows the keys without aliases. The JSON output never shows aliases.

JSON (with `--json`). Success is implied by exit code `0` — on failure the command exits non-zero and reports `{"error": "…"}` on stderr instead. The `hash` is the SHA-512 of the pending signers file as held by the mirror:

    {"signers_path":"https/github.com/443/acme/repo/asfaload.signers.pending/index.json","retrieval_url":"https://raw.githubusercontent.com/acme/repo/main/asfaload.signers/index.json","hash":"sha512:4a0f0c…2b9e"}

On failure, the error identifies the problem: a fetch error (unknown path, unreachable source), an unparseable metadata file, a file that is not a valid signers file, or a hash mismatch naming the retrieval URL of the diverging source.

## Examples

    # check the pending signers file shown by list-pending before signing it
    asfaload-cli check-pending-signers https/github.com/443/acme/repo/asfaload.signers.pending/index.json

    # machine-readable result
    asfaload-cli check-pending-signers --json https/github.com/443/acme/repo/asfaload.signers.pending/index.json

## Exit codes

- `0` — the pending signers file matches the content at its retrieval URL.
- non-zero — the file differs from the published source, the source or metadata could not be fetched or parsed, the file is not a valid signers file, or the files could not be fetched from the mirror.
