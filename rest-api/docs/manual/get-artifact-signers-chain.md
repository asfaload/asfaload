# `GET /v1/get_artifact_signers_chain/{artifact_path}`

- **Auth**: none
- **Source**: [`src/handlers.rs`](../../src/handlers.rs) — `get_artifact_signers_chain_handler`

Fetch the signers history chain for a signed artifact. The server traces the artifact's local signers copy back to its source commit, reads the history file and all associated signers/metadata/signature files at that point in time, and returns the chain of signers configurations that were active up to and including the one used to sign the artifact.

This endpoint is useful for verifying the full provenance of an artifact's signing authority.

## Path parameters

### `artifact_path`

Mirror-relative path to the signed artifact. Slashes are preserved (the route uses a catch-all parameter).

## Response

### `200 OK`

    {
      "history": {
        "entries": [
          {
            "signers_config": "...",
            "signatures": "...",
            "metadata": "...",
            "metadata_signatures": "...",
            "timestamp": "2024-04-11T12:00:00Z"
          }
        ]
      }
    }

Fields:

- `history` — a `HistoryFile` object containing the chain of signers configurations. Each entry includes the signers config, its signatures, metadata, metadata signatures, and the timestamp when it became active. The chain is filtered to entries relevant to the artifact's signing time.

## Errors

- `400 Bad Request` — invalid artifact path or cannot derive signers path.
- `500 Internal Server Error` — failed to trace signers source, read files from Git history, or build the chain.

## Examples

### Fetch the signers chain

    curl -sS 'http://127.0.0.1:3000/v1/get_artifact_signers_chain/https/github.com/443/acme/repo/releases/tag/v1.0/asfaload.index.json'

    {"history":{"entries":[...]}}

### Invalid artifact path

    curl -sS -i 'http://127.0.0.1:3000/v1/get_artifact_signers_chain/invalid'

    HTTP/1.1 400 Bad Request

    {"error":"Invalid artifact path: ..."}
