# `POST /v1/update_signers`

- **Auth**: required
- **Source**: [`src/handlers.rs`](../../src/handlers.rs) — `update_signers_handler`

Propose an update to a project's signers file. The server fetches the new signers file from the forge, verifies the client signatures over the signers file and the metadata, stores the client-provided bytes, and commits the result. The project must already be registered and have an active signers file.

The submitter signs the new signers file and the metadata with the request. The server records these signatures. If they complete the required signers, the update is active at once and the response message says so. Otherwise the update stays pending until the remaining signers submit their signatures.

## Request headers

Standard Asfaload authentication headers, signed by the caller's secret key:

- `X-asfld-timestamp` — request timestamp, RFC 3339 format.
- `X-asfld-nonce` — random UUID v4, unique per request.
- `X-asfld-sig` — Ed25519 signature, computed as described in [Authentication](index.md#authentication).
- `X-asfld-pk` — caller's public key.

## Request body

JSON object (same shape as `register_repo`):

    {
      "signers_file_url": "https://github.com/acme/repo/blob/main/asfaload.signers.json",
      "public_key": "<base64-public-key>",
      "signature": "<base64-signature-over-signers-file>",
      "metadata": "<base64-metadata-json>",
      "metadata_signature": "<base64-signature-over-metadata>"
    }

Fields:

- `signers_file_url` — URL pointing to the updated signers file on the forge.
- `public_key` — base64-encoded Ed25519 public key of the submitter. The key must be an admin key of the active signers file.
- `signature` — base64-encoded signature of the SHA-512 digest of the new signers file content, made with the secret key of `public_key`. The signature must verify against the exact content the server fetches from `signers_file_url`.
- `metadata` — base64-encoded JSON serialisation of the metadata. The object has the fields `kind`, `url`, `verified_content`, and `retrieved_at`. The `verified_content` object has `retrieval_url` and `content_hash`. `retrieved_at` must be within 60 seconds in the past and within the accepted clock skew in the future.
- `metadata_signature` — base64-encoded signature of the SHA-512 digest of the metadata JSON bytes, made with the secret key of `public_key`. The signature must verify against the exact `metadata` bytes the client sends.

## Response

### `200 OK`

    {
      "success": true,
      "project_id": "https/github.com/443/acme/repo",
      "message": "Signers update proposed successfully. Collect signatures to activate.",
      "required_signers": ["<base64-public-key-1>", "<base64-public-key-2>"],
      "signature_submission_url": "/v1/signatures"
    }

Fields:

- `success` — always `true` on success.
- `project_id` — normalised project identifier.
- `message` — human-readable status message. When the client signatures complete the required signers, the message is `"Signers updated successfully, and signers file activated."`. Otherwise it is `"Signers update proposed successfully. Collect signatures to activate."`.
- `required_signers` — list of base64-encoded public keys that need to sign the update. Empty when the update is active.
- `signature_submission_url` — path to use for submitting signatures.

## Errors

- `400 Bad Request` — project not registered, no active signers file, invalid forge URL, invalid public key, invalid base64, malformed metadata, metadata outside the accepted time window, or metadata that does not match the server data.
- `401 Unauthorized` — missing or invalid authentication headers, or a client signature that does not verify.
- `500 Internal Server Error` — forge validation, proposal creation, or Git commit failed.

## Examples

### Successful update proposal

    curl -sS -X POST 'http://127.0.0.1:3000/v1/update_signers' \
      -H 'Content-Type: application/json' \
      -H 'X-asfld-timestamp: 2024-04-11T20:00:00+00:00' \
      -H 'X-asfld-nonce: <random-uuid-v4>' \
      -H 'X-asfld-sig: <base64-signature>' \
      -H 'X-asfld-pk: <base64-public-key>' \
      -d '{
        "signers_file_url": "https://github.com/acme/repo/blob/main/asfaload.signers.json",
        "public_key": "<base64-public-key>",
        "signature": "<base64-signature-over-signers-file>",
        "metadata": "<base64-metadata-json>",
        "metadata_signature": "<base64-signature-over-metadata>"
      }'

    {"success":true,"project_id":"https/github.com/443/acme/repo","message":"Signers update proposed successfully. Collect signatures to activate.","required_signers":["<base64-pk-1>","<base64-pk-2>"],"signature_submission_url":"/v1/signatures"}

### Project not registered

    HTTP/1.1 400 Bad Request

    {"error":"Project 'https/github.com/443/acme/repo' is not registered. Register the repo first."}
