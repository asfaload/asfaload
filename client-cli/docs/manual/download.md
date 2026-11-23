# `asfaload-cli download`

- **Usage**: `asfaload-cli download [OPTIONS] <FILE_URL>`

Download a file and verify its signatures before saving. The command fetches the index and its signatures from the backend, validates the full signers chain history, probes for a revocation, and downloads the actual file. The download, chain validation and revocation probe run in parallel: a failed verification or a detected revocation aborts the in-flight download. Signatures are verified once the file is downloaded, then the file hash is checked before saving. Full signers chain validation is always performed; there is no option to skip it.

If the file has been revoked, a warning is printed to stderr and the download is aborted.

## Arguments

### `<FILE_URL>`

Public URL of the file to download. For example:

    https://github.com/acme/tool/releases/download/v1.0/tool-linux-amd64.tar.gz

## Options

### `-o --output <PATH>`

Output file path. Defaults to the filename extracted from the URL.

### `-u --backend-url <URL>`

Backend API URL. Defaults to `https://backend.asfaload.com`.

### `--type <FORGE_TYPE>`

Override automatic forge type detection.

| Value | Description |
|-------|-------------|
| `github` | GitHub release |
| `gitlab` | GitLab release |
| `fileserver` | Generic file server |

## Environment

- `ASFALOAD_BACKEND_URL` — alternative to `--backend-url` (an explicit `--backend-url` wins).

## Output

The command prints progress to stdout as each step completes:

    Starting download: https://github.com/acme/tool/releases/download/v1.0/tool.tar.gz
    ✓ Downloaded index file (567 bytes)
    ✓ Downloaded signatures file (890 bytes)
    Downloading tool.tar.gz
    Progress: 2.00 MB
    ✓ Signers chain history verified (3 entries)
    ✓ Signatures verified successfully (2 valid)
    ✓ Download complete (12.50 MB)
    ✓ File hash verified (SHA-256)
    ✓ File saved to: ./tool.tar.gz
    ✓ All done! Verified 2 signature(s)

Notes:

- The file download, signers chain validation, and revocation probe run in parallel, so `Progress:` and `✓ Signers chain history verified` lines may interleave in any order.
- Progress lines are emitted at milestones (roughly every megabyte), overwriting each other with `\r`; the shown `Progress: 2.00 MB` is one such milestone.
- If any signature is invalid, a `⚠ Warning: N invalid signature(s)` line precedes the `✓ Signatures verified successfully` line.
- A `✗ Signers chain verification failed: <reason>` line goes to stderr when chain validation fails.

If the file has been revoked:

    This file has been revoked.
      Revoked at: 2025-03-15T10:30:00Z
      Revoked by: asfaload-pub:b5S+CxuqICIUn/DGBdMKeTMZCgQcg78ohiWQ1sC00c8

## Examples

    # download and verify a release artifact
    asfaload-cli download \
        https://github.com/acme/tool/releases/download/v1.0/tool-linux-amd64.tar.gz

    # save to a specific path
    asfaload-cli download -o /tmp/tool.tar.gz \
        https://github.com/acme/tool/releases/download/v1.0/tool-linux-amd64.tar.gz

    # override forge detection
    asfaload-cli download --type gitlab \
        https://gitlab.com/acme/tool/-/releases/v1.0/downloads/tool.tar.gz

## Exit codes

- `0` — download and verification succeeded.
- non-zero — error (verification failure, revoked file, network error).
