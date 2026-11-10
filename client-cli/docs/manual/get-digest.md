# `asfaload-cli get-digest`

- **Usage**: `asfaload-cli get-digest [OPTIONS] <FILE>`
- **Source**: [`src/commands/get_digest.rs`](../../src/commands/get_digest.rs)

Compute the SHA-512 digest of a local file or a file served over HTTP(S) and display it.

The digest is the same value the backend uses to identify pending files, and the value expected by [`sign-pending`](sign-pending.md) `--digest`.

## Arguments

### `<FILE>`

Either a path to a local file, or an `http://`/`https://` URL (e.g. the URL of an artifact on a release page).

## Options

### `--json`

Emit output as JSON instead of human-readable text.

## Output

Human-readable (default):

    sha512:2e2fde4ead7c6846656431dd4f2d2f3013e2b35d31fc32978fc03a32f54034589d65ab6666a72aab3835bf409dc7b86fdab6b2f488486c4012c0acffc41438d7

JSON (with `--json`):

    {"digest":"sha512:2e2fde4ead7c6846656431dd4f2d2f3013e2b35d31fc32978fc03a32f54034589d65ab6666a72aab3835bf409dc7b86fdab6b2f488486c4012c0acffc41438d7"}

## Examples

    # digest of a local file
    asfaload-cli get-digest release.tar.gz

    # digest of a remote artifact
    asfaload-cli get-digest https://github.com/acme/repo/releases/download/v1.0.0/release.tar.gz

    # JSON output, e.g. to extract the digest in a script
    asfaload-cli get-digest --json release.tar.gz | jq -r .digest

## Exit codes

- `0` — digest computed.
- non-zero — error (file not found, invalid URL, network error).
