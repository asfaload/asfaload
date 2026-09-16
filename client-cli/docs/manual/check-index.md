# `asfaload-cli check-index`

- **Usage**: `asfaload-cli check-index [OPTIONS] <INDEX_PATH>`
- **Source**: [`src/commands/check_index.rs`](../../src/commands/check_index.rs)

Fetch an index file (`asfaload.index.json`) from the mirror and validate every digest it records against its original digest source. The digest sources are fetched over the network from the URLs recorded in the index itself. As a result, the mirror — and anyone who can write to it — controls which URLs the CLI contacts when validating, so only trust indexes from mirrors you trust.

This validates digests only. It does not verify the signatures on the index (see [`download`](download.md) for signature verification); its typical use is inspecting a pending index shown by [`list-pending`](list-pending.md) before deciding to sign it.

## Arguments

### `<INDEX_PATH>`

Mirror-relative path of the index file, as displayed by `list-pending`, e.g. `https/github.com/443/acme/repo/releases/tag/v1.0/asfaload.index.json`. Required.

## Options

### `-u --backend-url <URL>`

Backend API URL. Defaults to `https://backend.asfaload.com`.

### `--json`

Emit a summary object instead of human-readable text.

## Environment

- `ASFALOAD_BACKEND_URL` — alternative to `--backend-url`.

The command is unauthenticated: no secret key or password is needed.

## Output

Human-readable (default):

    ✓ Index valid: 1 file(s) verified against their digest sources

JSON (with `--json`). The `index` field carries the whole validated index object (camelCase fields, as in the index file itself):

    {"index_path":"https/github.com/443/acme/repo/releases/tag/v1.0/asfaload.index.json","valid":true,"files_checked":1,"index":{"mirroredOn":"2026-01-15T09:30:00Z","publishedOn":"2026-01-14T18:02:11Z","version":1,"publishedFiles":[{"fileName":"app-v1.0.tar.gz","algo":"Sha256","source":"https://github.com/acme/repo/releases/download/v1.0/SHA256SUMS.txt","hash":"e3b0c44…b855"}]}}

On failure, the error identifies the problem: a fetch error (unknown path, unreachable digest source), an unparseable body, or a digest mismatch naming the value in the index, the value in the source, and the source URL.

## Examples

    # validate a pending index before signing it
    asfaload-cli check-index https/github.com/443/acme/repo/releases/tag/v1.0/asfaload.index.json

    # machine-readable result
    asfaload-cli check-index --json https/github.com/443/acme/repo/releases/tag/v1.0/asfaload.index.json

## Exit codes

- `0` — all digests in the index match their sources.
- non-zero — validation failed (mismatch, unreachable or unparseable source) or the index could not be fetched or parsed.
