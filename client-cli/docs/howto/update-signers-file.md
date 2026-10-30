# Update a signers file

Need to add a signer, remove one, or change the threshold? This guide covers proposing and activating a signers file update.

## Prerequisites

- The repository is already registered and the current signers file is active.
- A new signers file has been created (see [Create a signers file](create-signers-file.md)), committed, and pushed to the forge.
- Your secret key file. See [Generate a key pair](generate-keys.md).

## Steps

### 1. Create and push the new signers file

Generate a new signers file with the updated set of keys and thresholds:

```sh
asfaload-cli new-signers-file \
    --artifact-signers-file alice.pub \
    --artifact-signers-file bob.pub \
    --artifact-signers-file carol.pub \
    --artifact-signers-file dave.pub \
    --artifact-threshold 3 \
    --revocation-keys-file revoke1.pub \
    --revocation-keys-file revoke2.pub \
    --revocation-keys-file revoke3.pub \
    --revocation-threshold 2 \
    --output-file signers_v2.json
```

Commit and push it to your repository so the backend can fetch it by URL.
We advise to commit the file either in your main branch, or in a dedicated branch in which you save all signers files updates.

### 2. Propose the update

Get the digest of the published file with `get-digest`, then pass it with `--digest`:

```sh
asfaload-cli get-digest --json \
    https://raw.githubusercontent.com/acme/tool/main/asfaload.signers/index_v2.json \
    | jq -r .digest

asfaload-cli update-signers \
    --secret-key ~/.asfaload/mykey \
    --digest sha512:2e2fde4e... \
    https://raw.githubusercontent.com/acme/tool/main/asfaload.signers/index_v2.json
```

Use the raw URL of the file, not the page URL you see in the browser (`https://github.com/acme/tool/blob/main/...`). The page is an HTML document. `get-digest` computes the digest of that HTML page, not of the signers file, so the digest check fails.

If you still have the new signers file locally and its bytes are identical to the published file, pass `--local-copy` instead of `--digest`:

```sh
asfaload-cli update-signers \
    --secret-key ~/.asfaload/mykey \
    --local-copy ./signers_v2.json \
    https://raw.githubusercontent.com/acme/tool/main/asfaload.signers/index_v2.json
```

One of `--digest` or `--local-copy` is required. Update-signers fetches the file at the URL you give it and stops with an error before it contacts the backend if the digest does not match.

On success:

```
Signers update proposed successfully!
Project ID: abc123
Required signers (4): alice, bob, carol, dave
Success: Signers update proposed successfully. Collect signatures to activate.
```

![Demo: propose a signers update](demos/update-signers-file.gif)

### 3. All signers must sign

Just like initial activation, **every** signer listed in the **new** signers file must sign before the update takes effect. This includes both existing and newly added signers.

Each signer runs:

```sh
asfaload-cli list-pending --secret-key ~/.asfaload/mykey
asfaload-cli sign-pending --secret-key ~/.asfaload/mykey \
    --digest sha512:2e2fde4e... \
    https/github.com/443/acme/tool/asfaload.signers.pending/index.json
```

The digest is taken from the `list-pending` output. See [Activate a signers file](activate-signers-file.md) for the full signing flow.

## What about existing releases?

Releases signed under the **previous** signers file remain valid. The backend keeps a signers chain history, so older releases can still be verified against the signers file that was active when they were signed.

## Reference

- [`asfaload-cli new-signers-file`](../manual/new-signers-file.md)
- [`asfaload-cli update-signers`](../manual/update-signers.md)
