# Summary

[Introduction](index.md)

# Concepts

- [Concepts](concepts/index.md)

# Client CLI

- [How-to Guides](client-cli/howto/index.md)
  - [Generate a key pair](client-cli/howto/generate-keys.md)
  - [Share a public key](client-cli/howto/share-public-key.md)
  - [Create a signers file](client-cli/howto/create-signers-file.md)
  - [Register a repository](client-cli/howto/register-repo.md)
  - [Activate a signers file](client-cli/howto/activate-signers-file.md)
  - [Register a release](client-cli/howto/register-release.md)
  - [Sign a release](client-cli/howto/sign-release.md)
  - [Update a signers file](client-cli/howto/update-signers-file.md)
  - [Revoke a signed release](client-cli/howto/revoke-release.md)
  - [Download with verification](client-cli/howto/download-with-verification.md)
- [Manual](client-cli/manual/index.md)
  - [new-keys](client-cli/manual/new-keys.md)
  - [share-key](client-cli/manual/share-key.md)
  - [new-signers-file](client-cli/manual/new-signers-file.md)
  - [update-signers](client-cli/manual/update-signers.md)
  - [register-repo](client-cli/manual/register-repo.md)
  - [register-assets](client-cli/manual/register-assets.md)
  - [list-pending](client-cli/manual/list-pending.md)
  - [sign-pending](client-cli/manual/sign-pending.md)
  - [signature-status](client-cli/manual/signature-status.md)
  - [revoke](client-cli/manual/revoke.md)
  - [get-digest](client-cli/manual/get-digest.md)
  - [download](client-cli/manual/download.md)
  - [check-index](client-cli/manual/check-index.md)
  - [check-pending-signers](client-cli/manual/check-pending-signers.md)
  - [ping](client-cli/manual/ping.md)

# REST API

- [Manual](rest-api/manual/index.md)
  - [POST /v1/register_repo](rest-api/manual/register-repo.md)
  - [POST /v1/update_signers](rest-api/manual/update-signers.md)
  - [POST /v1/signatures](rest-api/manual/submit-signature.md)
  - [GET /v1/signatures/{file_path}](rest-api/manual/signature-status.md)
  - [GET /v1/pending_signatures](rest-api/manual/pending-signatures.md)
  - [GET /v1/files/{file_path}](rest-api/manual/get-file.md)
  - [GET /v1/files-to-sign/{file_path}](rest-api/manual/files-to-sign.md)
  - [GET /v1/get_signers/{file_path}](rest-api/manual/get-signers.md)
  - [GET /v1/get_artifact_signers_chain/{artifact_path}](rest-api/manual/get-artifact-signers-chain.md)
  - [POST /v1/revoke](rest-api/manual/revoke.md)
  - [POST /v1/assets](rest-api/manual/register-assets.md)
