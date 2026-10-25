# `POST /v1/assets`

- **Auth**: required
- **Source**: [`src/handlers.rs`](../../src/handlers.rs) — `register_assets_handler`

Register assets for signing. Accepts either a GitHub release URL or a list of checksums file URLs — exactly one must be provided.

In both modes, the server verifies the signature of the client index. Then it re-derives the index from the source and compares the two indexes. In GitHub mode, the source is the release metadata and the assets. In checksums mode, the source is the referenced checksums files.

The client signature is the registrant's signature and the first signature of the release. The server adds the signature to the signature file and commits the index and the signature to the repository. The other artifact signers add their signatures with [Submit a signature](submit-signature.md) until the threshold is met.

## Authorization

All requests must be authenticated (see [Request headers](#request-headers)).

In GitHub release mode and in checksums mode, the caller's public key (`X-asfld-pk`) must be an authorized artifact signer for the release path. The server reads the `artifact_signers` group of the project's active signers config and refuses a key that is not a member with `403 Forbidden`.

## Request headers

Standard Asfaload authentication headers, signed by the caller's secret key:

- `X-asfld-timestamp` — request timestamp, RFC 3339 format.
- `X-asfld-nonce` — random UUID v4, unique per request.
- `X-asfld-sig` — Ed25519 signature, computed as described in [Authentication](index.md#authentication).
- `X-asfld-pk` — caller's public key.

## Request body

JSON object carrying the payload under one variant tag. The tag selects the
registration mode. In both modes, the client computes the release index and
signs it with the same secret key that signs the authentication headers. An
unknown tag, both tags at once, or a payload with missing fields are refused.

### GitHub release mode

    {
      "GithubRelease": {
        "github_release_url": "https://github.com/acme/repo/releases/tag/v1.0",
        "index": "<base64 index json>",
        "signature": "<base64 index signature>"
      }
    }

### Checksums mode

    {
      "ChecksumFiles": {
        "csum_files": [
          "https://example.com/releases/v1.0/SHA256SUMS",
          "https://example.com/releases/v1.0/SHA512SUMS"
        ],
        "index": "<base64 index json>",
        "signature": "<base64 index signature>"
      }
    }

Fields:

- `github_release_url` — full URL to a GitHub release page. Must point to a known GitHub host. Required in GitHub release mode.
- `index` — the release index JSON, base64 encoded. Required in both modes.
- `signature` — signature over the index JSON, base64 encoded. Required in both modes.
- `csum_files` — list of URLs to checksums files. All URLs must share the same origin and parent directory. Required in checksums mode.

## Response

### `200 OK`

    {
      "success": true,
      "message": "Release registered successfully",
      "index_file_path": "https/github.com/443/acme/repo/releases/tag/v1.0/asfaload.index.json"
    }

Fields:

- `success` — always `true` on success.
- `message` — human-readable status. Always "Release registered successfully".
- `index_file_path` — mirror-relative path to the generated index file.

## Errors

- `400 Bad Request` — invalid URL format, non-GitHub host for `github_release_url`, invalid checksums URLs, an index that cannot be decoded, an index signature that is invalid or does not verify, a client index that does not match the index re-derived from the source, or no active signers file for the target directory.
- `422 Unprocessable Entity` — the body does not carry a valid payload: unknown tag, both tags at once, or missing fields in a payload.
- `401 Unauthorized` — missing or invalid authentication headers.
- `403 Forbidden` — the caller's public key is not an authorized artifact signer for the release path. Applies in GitHub release mode and in checksums mode.
- `409 Conflict` — release already registered.
- `500 Internal Server Error` — release processing, checksums download, or Git commit failed.

## Examples

### Register a GitHub release

    curl -sS -X POST 'http://127.0.0.1:3000/v1/assets' \
      -H 'Content-Type: application/json' \
      -H 'X-asfld-timestamp: 2024-04-11T20:00:00+00:00' \
      -H 'X-asfld-nonce: <random-uuid-v4>' \
      -H 'X-asfld-sig: <base64-signature>' \
      -H 'X-asfld-pk: <base64-public-key>' \
      -d '{
        "GithubRelease": {
          "github_release_url": "https://github.com/acme/repo/releases/tag/v1.0",
          "index": "<base64 index json>",
          "signature": "<base64 index signature>"
        }
      }'

    {"success":true,"message":"Release registered successfully","index_file_path":"https/github.com/443/acme/repo/releases/tag/v1.0/asfaload.index.json"}

### Register checksums files

    curl -sS -X POST 'http://127.0.0.1:3000/v1/assets' \
      -H 'Content-Type: application/json' \
      -H 'X-asfld-timestamp: 2024-04-11T20:00:00+00:00' \
      -H 'X-asfld-nonce: <random-uuid-v4>' \
      -H 'X-asfld-sig: <base64-signature>' \
      -H 'X-asfld-pk: <base64-public-key>' \
      -d '{"ChecksumFiles":{"csum_files":["https://example.com/releases/v1.0/SHA256SUMS"],"index":"<base64 index json>","signature":"<base64 index signature>"}}'

    {"success":true,"message":"Release registered successfully","index_file_path":"https/example.com/443/releases/v1.0/asfaload.index.json"}

The `index` and `signature` values for both payload types are base64 encoded
strings for the index JSON, and its signature. A real client, such as
asfaload-cli with the `register-assets` command, makes these values for you.

### Unknown payload type

A body tagged with a name that is not `GithubRelease` or `ChecksumFiles` is
refused by the payload type before the endpoint runs. The answer body is a
plain text message from the JSON layer.

    HTTP/1.1 422 Unprocessable Entity
