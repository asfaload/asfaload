# `POST /v1/assets`

- **Auth**: required
- **Source**: [`src/handlers.rs`](../../src/handlers.rs) — `register_assets_handler`

Register assets for signing. Accepts either a GitHub release URL or a list of checksums file URLs — exactly one must be provided.

In GitHub mode, the server fetches the release metadata, downloads all assets, builds an index file, and commits everything to the repository. In checksums mode, it downloads the referenced checksums files, builds the index, and commits.

## Request headers

Standard Asfaload authentication headers, signed by the caller's secret key:

- `X-asfld-timestamp` — request timestamp, RFC 3339 format.
- `X-asfld-nonce` — random UUID v4, unique per request.
- `X-asfld-sig` — Ed25519 signature, computed as described in [Authentication](index.md#authentication).
- `X-asfld-pk` — caller's public key.

## Request body

JSON object carrying the payload under one variant tag. The tag selects the
registration mode. An unknown tag, both tags at once, or a payload with
missing fields is refused.

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
        ]
      }
    }

Fields:

- `github_release_url` — full URL to a GitHub release page. Must point to a known GitHub host.
- `index` — the release index JSON, base64 encoded.
- `signature` — signature over the index JSON, base64 encoded.
- `csum_files` — list of URLs to checksums files. All URLs must share the same origin and parent directory.

## Response

### `200 OK`

    {
      "success": true,
      "message": "Release registered successfully",
      "index_file_path": "https/github.com/443/acme/repo/releases/tag/v1.0/asfaload.index.json"
    }

Fields:

- `success` — always `true` on success.
- `message` — human-readable status. Either "Release registered successfully" (GitHub mode) or "Assets registered successfully" (checksums mode).
- `index_file_path` — mirror-relative path to the generated index file.

## Errors

- `400 Bad Request` — invalid URL format, non-GitHub host for `github_release_url`, or invalid checksums URLs.
- `422 Unprocessable Entity` — the body does not carry a valid payload: unknown tag, both tags at once, or missing fields in a payload.
- `401 Unauthorized` — missing or invalid authentication headers.
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
      -d '{"ChecksumFiles":{"csum_files":["https://example.com/releases/v1.0/SHA256SUMS"]}}'

    {"success":true,"message":"Assets registered successfully","index_file_path":"https/example.com/443/releases/v1.0/asfaload.index.json"}

### Unknown payload type

A body tagged with a name that is not `GithubRelease` or `ChecksumFiles` is
refused by the payload type before the endpoint runs. The answer body is a
plain text message from the JSON layer.

    HTTP/1.1 422 Unprocessable Entity
