# `GET /v1/signatures/{file_path}`

- **Auth**: required
- **Source**: [`src/handlers.rs`](../../src/handlers.rs) — `get_signature_status_handler`
- **Related command**: [`client signature-status`](../../client-cli/manual/signature-status.md)

Return the current signature collection status of a file. Authorization is checked against the current global signers file, not the copy frozen at the file's registration time; this keeps revocation semantics uniform across all authenticated endpoints.

## Path parameters

### `file_path`

Mirror-relative path to the file. Slashes are preserved (the route uses a catch-all parameter).

## Request headers

Standard Asfaload authentication headers, signed by the caller's secret key:

- `X-asfld-timestamp` — request timestamp, RFC 3339 format.
- `X-asfld-nonce` — random UUID v4, unique per request.
- `X-asfld-sig` — Ed25519 signature, computed as described in [Authentication](index.md#authentication).
- `X-asfld-pk` — caller's public key.

## Response

### `200 OK`

    {
      "file_path": "https/github.com/443/acme/repo/releases/tag/v1.0/asfaload.index.json",
      "is_complete": false,
      "required_signers": ["<base64 public key>", "..."]
    }

Fields:

- `file_path` — normalized mirror-relative path to the file.
- `is_complete` — `true` once the aggregate signature threshold has been met; `false` while signatures are still being collected.
- `required_signers` — base64 public keys that can still sign, sorted. Empty when the aggregate signature is complete. A key is in the list when it has no valid signature yet; the list does not tell how many signatures are still necessary.

## Errors

- `400 Bad Request` — path is empty.
- `400 Bad Request` — "File is revoked: <file_path>": a revocation of the file is complete.
- `401 Unauthorized` — missing or invalid authentication headers.
- `403 Forbidden` — caller's public key is not in the file's current signers file.
- `404 Not Found` — no file exists at the given path, or no signers file could be located for it.
- `500 Internal Server Error` — backend failure (read, parse, or actor error).

## Examples

### Successful query

    curl -sS 'http://127.0.0.1:3000/v1/signatures/https/github.com/443/acme/repo/releases/tag/v1.0/asfaload.index.json' \
      -H 'X-asfld-timestamp: 2024-04-11T20:00:00+00:00' \
      -H 'X-asfld-nonce: <random-uuid-v4>' \
      -H 'X-asfld-sig: <base64-signature>' \
      -H 'X-asfld-pk: <base64-public-key>'

    {"file_path":"https/github.com/443/acme/repo/releases/tag/v1.0/asfaload.index.json","is_complete":false,"required_signers":["<base64 public key>","..."]}

### Caller not an authorized signer

    curl -sS -i 'http://127.0.0.1:3000/v1/signatures/https/github.com/443/acme/repo/releases/tag/v1.0/asfaload.index.json' \
      -H 'X-asfld-timestamp: 2024-04-11T20:00:00+00:00' \
      -H 'X-asfld-nonce: <random-uuid-v4>' \
      -H 'X-asfld-sig: <base64-signature>' \
      -H 'X-asfld-pk: <base64-non-signer-public-key>'

    HTTP/1.1 403 Forbidden
