# `POST /v1/register_repo`

- **Auth**: required
- **Source**: [`src/handlers.rs`](../../src/handlers.rs) — `register_repo_handler`

Register a new project with the Asfaload backend. The server fetches the signers file from the forge URL, verifies the client signatures over the signers file and the metadata, stores the client-provided bytes, and commits the result to the backing Git repository.

A project can only be registered once. Calling this endpoint again for an already-registered project returns an error.

The submitter signs the signers file and the metadata with the request. The server records these signatures. If they complete the required signers, the project is active at once and the response message says so. Otherwise the project stays pending until the remaining signers submit their signatures.

## Request headers

Standard Asfaload authentication headers, signed by the caller's secret key:

- `X-asfld-timestamp` — request timestamp, RFC 3339 format.
- `X-asfld-nonce` — random UUID v4, unique per request.
- `X-asfld-sig` — Ed25519 signature, computed as described in [Authentication](index.md#authentication).
- `X-asfld-pk` — caller's public key.

## Request body

JSON object:

    {
      "signers_file_url": "https://github.com/acme/repo/blob/main/asfaload.signers.json",
      "public_key": "<base64-public-key>",
      "signature": "<base64-signature-over-signers-file>",
      "metadata": "<base64-metadata-json>",
      "metadata_signature": "<base64-signature-over-metadata>"
    }

Fields:

- `signers_file_url` — URL pointing to the signers file on the forge (GitHub, GitLab, or file server).
- `public_key` — base64-encoded Ed25519 public key of the submitter. Must match one of the keys in the signers file.
- `signature` — base64-encoded signature of the SHA-512 digest of the signers file content, made with the secret key of `public_key`. The signature must verify against the exact content the server fetches from `signers_file_url`.
- `metadata` — base64-encoded JSON serialisation of the metadata. The object has the fields `kind`, `url`, `verified_content`, and `retrieved_at`. The `verified_content` object has `retrieval_url` and `content_hash`. `retrieved_at` must be within 60 seconds in the past and within the accepted clock skew in the future.
- `metadata_signature` — base64-encoded signature of the SHA-512 digest of the metadata JSON bytes, made with the secret key of `public_key`. The signature must verify against the exact `metadata` bytes the client sends.

## Response

### `200 OK`

    {
      "success": true,
      "project_id": "https/github.com/443/acme/repo",
      "message": "Project registered successfully. Collect signatures to activate.",
      "required_signers": ["<base64-public-key-1>", "<base64-public-key-2>"],
      "signature_submission_url": "/v1/signatures"
    }

Fields:

- `success` — always `true` on success.
- `project_id` — normalised identifier for the registered project.
- `message` — human-readable status message. When the client signatures complete the required signers, the message is `"Project registered successfully, and signers file activated."`. Otherwise it is `"Project registered successfully. Collect signatures to activate."`.
- `required_signers` — list of base64-encoded public keys that still need to sign. Empty when the project is active.
- `signature_submission_url` — path to use for submitting signatures.

## Errors

- `400 Bad Request` — invalid or unparseable forge URL, invalid public key, invalid base64, malformed metadata, metadata outside the accepted time window, or metadata that does not match the server data.
- `401 Unauthorized` — missing or invalid authentication headers, or a client signature that does not verify.
- `409 Conflict` — project is already registered or registration is in progress.
- `500 Internal Server Error` — forge validation, signers initialisation, or Git commit failed.

## Examples

### Successful registration

    curl -sS -X POST 'http://127.0.0.1:3000/v1/register_repo' \
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

    {"success":true,"project_id":"https/github.com/443/acme/repo","message":"Project registered successfully. Collect signatures to activate.","required_signers":["<base64-pk-1>","<base64-pk-2>"],"signature_submission_url":"/v1/signatures"}

### Project already registered

    HTTP/1.1 409 Conflict

    {"error":"Project 'https/github.com/443/acme/repo' is already registered or registration is in progress."}
