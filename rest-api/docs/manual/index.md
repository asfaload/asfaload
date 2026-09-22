# rest-api manual

Reference for the Asfaload REST API.

## Authentication

Authenticated endpoints require four HTTP headers, signing the request with the caller's Ed25519 secret key:

- `X-asfld-timestamp` — request timestamp, [RFC 3339](https://datatracker.ietf.org/doc/html/rfc3339) format (e.g. `2025-06-17T14:03:22.123456789+00:00`). It must be in canonical UTC form: offset written as `+00:00` (never `Z` or another offset), and fractional seconds with no trailing zeros (omitted entirely when zero). This is exactly what chrono's `DateTime::<Utc>::to_rfc3339()` emits. The server normalizes any valid RFC 3339 timestamp to this form before verifying the signature, so a validly-signed request with a non-canonical timestamp string is rejected.
- `X-asfld-nonce` — random UUID v4, unique per request.
- `X-asfld-sig` — base64-encoded (unpadded) Ed25519 signature, computed as described below.
- `X-asfld-pk` — caller's public key in asfaload format: the literal prefix `asfaload-pub:` followed by the base64 encoding (standard alphabet, unpadded) of the 32 raw key bytes (e.g. `asfaload-pub:b5S+CxuqICIUn/DGBdMKeTMZCgQcg78ohiWQ1sC00c8`).

### Computing the signature

1. Build the canonical request string by joining the timestamp, the nonce and the request payload with the `##` separator:

       {timestamp}##{nonce}##{payload}

   - `timestamp` — the exact string sent in `X-asfld-timestamp`, which must already be in the canonical form described above.
   - `nonce` — the exact string sent in `X-asfld-nonce`.
   - `payload` — the raw request body as a UTF-8 string. For requests without a body (e.g. `GET /v1/ping`), use the empty string.

2. Compute the SHA-512 digest of the canonical request string. The digest is used raw (64 bytes); do not hex- or base64-encode it.
3. Sign the raw digest bytes with the Ed25519 secret key: the signature covers the digest itself, not the canonical string.
4. Base64-encode (unpadded) the 64-byte signature and send it in `X-asfld-sig`.

Pseudocode:

    canonical = timestamp + "##" + nonce + "##" + payload
    digest    = SHA-512(canonical)                        // 64 raw bytes
    signature = Ed25519-sign(secret key, digest)
    sig header = base64(signature)                        // unpadded
    pk header  = "asfaload-pub:" + base64(public key)     // unpadded, 32 raw bytes

The server rebuilds the canonical request string from the received headers and body, computes its SHA-512 digest, and verifies the signature with the transmitted public key. A request is rejected when its timestamp's age — truncated to whole minutes — exceeds 5 minutes (so requests up to just under 6 minutes old are accepted), when it is more than 10 seconds in the future, when the nonce was already used, or when the signature does not verify.

## Registration

- [`POST /v1/register_repo`](register-repo.md) — register a new project with the signing server
- [`POST /v1/update_signers`](update-signers.md) — propose an update to a project's signers file

## Signatures

- [`POST /v1/signatures`](submit-signature.md) — submit signatures for a file
- [`GET /v1/signatures/{file_path}`](signature-status.md) — query signature collection status for a file
- [`GET /v1/pending_signatures`](pending-signatures.md) — list files awaiting the caller's signature

## Files

- [`GET /v1/files/{file_path}`](get-file.md) — fetch raw file content from the repository
- [`GET /v1/files-to-sign/{file_path}`](files-to-sign.md) — fetch file contents needed for signing

## Signers

- [`GET /v1/get_signers/{file_path}`](get-signers.md) — get the signers configuration for a path
- [`GET /v1/get_artifact_signers_chain/{artifact_path}`](get-artifact-signers-chain.md) — get the signers history chain for a signed artifact

## Revocation

- [`POST /v1/revoke`](revoke.md) — revoke a previously signed file

## Assets

- [`POST /v1/assets`](register-assets.md) — register assets from a GitHub release or checksums files
