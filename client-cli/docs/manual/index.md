# asfaload-cli manual

Reference for all `asfaload-cli` commands.

## Keys

- [`new-keys`](new-keys.md) — generate a new signing key pair
- [`share-key`](share-key.md) — print your public key and a message for sharing it

## Signers

- [`new-signers-file`](new-signers-file.md) — create a signers file defining authorized keys and thresholds
- [`update-signers`](update-signers.md) — propose an update to an existing signers file

## Registration

- [`register-repo`](register-repo.md) — register a repository with the backend
- [`register-assets`](register-assets.md) — register assets (GitHub release or checksum files) for signing

## Signing

- [`list-pending`](list-pending.md) — list files that still need your signature
- [`sign-pending`](sign-pending.md) — sign a pending file
- [`signature-status`](signature-status.md) — check a file's signature collection status

## Revocation

- [`revoke`](revoke.md) — revoke a previously signed file

## Verification

- [`get-digest`](get-digest.md) — compute the SHA-512 digest of a local file or URL
- [`download`](download.md) — download a file with signature verification
- [`check-index`](check-index.md) — validate an index file's digests against their sources

## Diagnostics

- [`ping`](ping.md) — check backend connectivity and, optionally, your credentials

## Common notes

### Passwords

Password sources are tried in this order: `--password`, then `--password-command`
(flag or `ASFALOAD_PASSWORD_COMMAND`), then `--password-file` (flag or
`ASFALOAD_PASSWORD_FILE`), then the command-specific variables
(`ASFALOAD_<COMMAND>_PASSWORD`, `ASFALOAD_<COMMAND>_PASSWORD_FILE`), then an
interactive prompt.

### JSON errors

When `--json` is active and a command fails, the error is printed to **stderr**
as `{"error":"<message>"}` and the process exits non-zero.
