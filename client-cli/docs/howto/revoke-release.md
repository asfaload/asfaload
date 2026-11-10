# Revoke a signed release

If a release needs to be recalled — a vulnerability was found, or the wrong artifacts were published — you can revoke it. Revoked files can no longer be downloaded with verification.

## Prerequisites

- The release is fully signed and active on the backend.
- Your key is listed as a **revocation key** in the active signers file. Artifact signers without revocation privileges cannot revoke.
- The signers file has a revocation group with a threshold. See [Create a signers file](create-signers-file.md).

## Steps

### 1. Initiate the revocation

```sh
asfaload-cli revoke \
    --secret-key ~/.asfaload/revoke-key \
    https/github.com/443/acme/tool/releases/tag/v1.0/asfaload.index.json
```

If the revocation threshold is 1, your signature completes the revocation:

```
File revoked: https/github.com/443/acme/tool/releases/tag/v1.0/asfaload.index.json
Your signature is included.

The revocation is complete. Downloads of this file now fail.
```

If the threshold is higher, the revocation enters a **pending** state. Users can still download the file until more revocation signers co-sign. The output shows the keys that can still sign and the command to send to them:

```
Revocation started: https/github.com/443/acme/tool/releases/tag/v1.0/asfaload.index.json
Your signature is included.
Users can still download the file until the revocation is complete.

Keys that can still sign
  asfaload-pub:b5S+CxuqICIUn/DGBdMKeTMZCgQcg78ohiWQ1sC00c8

Next step
  Send this command to the signers. Each signer replaces <secret-key>
  with their secret key file:

     asfaload-cli sign-pending \
       --digest sha512:2e2fde4e... \
       https/github.com/443/acme/tool/releases/tag/v1.0/asfaload.index.json.revocation.json.pending \
       --secret-key <secret-key>
```

![Demo: initiate a revocation](demos/revoke-release-initiate.gif)

### 2. Co-sign the revocation (if threshold > 1)

When the revocation threshold requires multiple signatures, additional revocation signers use `list-pending` and `sign-pending` to add their signatures:

```sh
# Another revocation signer checks for pending work
asfaload-cli list-pending --secret-key ~/.asfaload/revoke-key-2
```

The pending revocation shows up as a path ending in `.revocation.json.pending`, together with its digest:

```
Files requiring your signature:
  - path: https/github.com/443/acme/tool/releases/tag/v1.0/asfaload.index.json.revocation.json.pending
digest: sha512:2e2fde4e...
```

Sign it (copy path and digest from the output above):

```sh
asfaload-cli sign-pending --secret-key ~/.asfaload/revoke-key-2 \
    --digest sha512:2e2fde4e... \
    https/github.com/443/acme/tool/releases/tag/v1.0/asfaload.index.json.revocation.json.pending
```

When the threshold is met, the revocation is complete:

```
Success! Your signature has been included and the aggregate signature is now complete. No further signature will be included in this aggregate signature.

The revocation is complete. Downloads of this file now fail.
```

If more signatures are still necessary, the last line is `Users can still download the file until the revocation is complete.`

![Demo: co-sign a revocation](demos/revoke-release-cosign.gif)

### 3. Verify the revocation

Attempting to download a revoked file fails:

```sh
asfaload-cli download https://github.com/acme/tool/releases/download/v1.0/artifact.bin
```

```
This file has been revoked.
  Revoked at: 2025-03-15T10:30:00Z
  Revoked by: asfaload-pub:b5S+CxuqICIUn/DGBdMKeTMZCgQcg78ohiWQ1sC00c8
```

## Important notes

- **Only revocation keys can revoke.** Artifact signers listed in the `artifact_signers` group cannot initiate or co-sign a revocation.
- **Revocation is irreversible.** Once a file is revoked, it stays revoked.
- **Other releases are unaffected.** Revoking v1.0 does not impact v2.0.
- **Re-initiating a pending revocation fails.** If a revocation is already pending, starting another one for the same file is rejected.

## Reference

- [`asfaload-cli revoke`](../manual/revoke.md)
- [`asfaload-cli list-pending`](../manual/list-pending.md)
- [`asfaload-cli sign-pending`](../manual/sign-pending.md)
