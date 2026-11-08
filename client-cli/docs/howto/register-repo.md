# Register a repository

Registering a repository tells the backend where your signers file lives. Once registered, the backend can enforce signature requirements for your project.

## Prerequisites

- A signers file committed and pushed to your repository. See [Create a signers file](create-signers-file.md).
- Your secret key file. See [Generate a key pair](generate-keys.md).
- The backend is running and reachable.

## Steps

### 1. Get the signers file URL and its digest

You need the public URL that points to your signers file on the forge. For GitHub, use the raw URL of the file:

```
https://raw.githubusercontent.com/acme/tool/main/asfaload.signers/index.json
```

Do not use the page URL you see in the browser (`https://github.com/acme/tool/blob/main/...`). That page is an HTML document. `get-digest` computes the digest of that HTML page, not of the signers file, so the digest check fails.

`register-repo` requires the digest of the signers file. It fetches the file at the URL you give it and stops with an error before it contacts the backend if the digest does not match. Get the digest with [`get-digest`](../manual/get-digest.md):

```sh
asfaload-cli get-digest --json \
    https://raw.githubusercontent.com/acme/tool/main/asfaload.signers/index.json \
    | jq -r .digest
```

### 2. Register the repository

Pass the digest with `--digest`. One of `--digest` or `--local-copy` is required; the two flags are mutually exclusive.

```sh
asfaload-cli register-repo \
    --secret-key ~/.asfaload/mykey \
    --digest sha512:2e2fde4e... \
    https://raw.githubusercontent.com/acme/tool/main/asfaload.signers/index.json
```

If you still have the signers file locally and its bytes are identical to the published file, you can pass `--local-copy` instead. `register-repo` computes the digest of the local copy for you:

```sh
asfaload-cli register-repo \
    --secret-key ~/.asfaload/mykey \
    --local-copy ./asfaload.signers/index.json \
    https://raw.githubusercontent.com/acme/tool/main/asfaload.signers/index.json
```

On success, when the submitter's signature completes the required signers:

```
Repository registered: https/github.com/443/acme/tool

The signers file is active. No more signatures are necessary.
```

When more signatures are necessary, the output shows the keys that can still sign. It also shows the command that the signers run:

```
Repository registered: https/github.com/443/acme/tool

Keys that can still sign
  asfaload-pub:bob-key
  asfaload-pub:carol-key

Next step
  Send this command to the signers. Each signer replaces <secret-key>
  with their secret key file:

     asfaload-cli sign-pending \
       --digest sha512:2e2fde4e... \
       https/github.com/443/acme/tool/asfaload.signers.pending/index.json \
       --secret-key <secret-key>
```

The CLI signs the signers file and the metadata with your key. The backend records these signatures. If they complete the required signers, the project is active at once. Otherwise the backend creates a pending signers entry and waits for the remaining signers before the project becomes active.

![Demo: register a repository](demos/register-repo.gif)

### 3. Point to a non-default backend

If your backend is not Asfaload's:

```sh
asfaload-cli register-repo \
    --secret-key ~/.asfaload/mykey \
    --digest sha512:2e2fde4e... \
    -u https://my-asfaload-deployment.example.com \
    https://raw.githubusercontent.com/acme/tool/main/asfaload.signers/index.json
```

## What happens next

If registration did not complete the required signatures, the signers file stays in a **pending** state. Every signer listed in it must sign before the project is activated. See [Activate a signers file](activate-signers-file.md).

## Reference

- [`asfaload-cli register-repo`](../manual/register-repo.md)
