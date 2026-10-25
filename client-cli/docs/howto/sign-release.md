# Sign a release

The person who registers a release signs its index at registration. If the signers file threshold is higher, the other artifact signers use this flow to meet it. This is the same `list-pending` / `sign-pending` flow used for [activating a signers file](activate-signers-file.md), but applied to a release index.

## Prerequisites

- A release has been [registered](register-release.md).
- Your key is listed as an artifact signer in the active signers file.

## Steps

### 1. List pending files

```sh
asfaload-cli list-pending --secret-key ~/.asfaload/mykey
```

Each pending file is listed with its path, its digest, and a bishop art block derived from the digest:

```
Files requiring your signature:
  - path: https/github.com/443/acme/tool/releases/tag/v1.0/asfaload.index.json
digest: sha512:2e2fde4ead7c6846656431dd4f2d2f3013e2b35d31fc32978fc03a32f54034589d65ab6666a72aab3835bf409dc7b86fdab6b2f488486c4012c0acffc41438d7

+----[SHA-512]----+
|▍  ▏ ▏   ▎▃▎▏▍▂ ▏|
| ▎▁ ▁ E ▏▏▎▎▃▏▎▎▁|
|▁ ▏▁ ▏   ▎▁▏ ▎▁▍▏|
|▏▁  ▏  ▏ ▎▂▎▁▁▎▏▂|
| ▏▏▁  ▏ S▎▎▎▃▏▏▍▏|
|  ▏▁▁▏▁▏▎▎▁▂▏▁▏ ▏|
|   ▁▎▏▁▎▂▎▏▏▏    |
|   ▁▁▁▏▄▃▍▎▏     |
|    ▁▁▎▍▅▋▍▏     |
+---[2e2fde4e…]---+
```

### 2. Sign the release index

Copy the path **and** the digest from the output above:

```sh
asfaload-cli sign-pending --secret-key ~/.asfaload/mykey \
    --digest sha512:2e2fde4e... \
    https/github.com/443/acme/tool/releases/tag/v1.0/asfaload.index.json
```

The command fetches all files associated with the release, hashes each one, signs the hashes, and submits everything in a single request.

If more signatures are needed:

```
Success! Your signature has been included, but the aggregate signature is not yet complete. Other signers must still provide their signatures.
```

When the threshold is met:

```
Success! Your signature has been included and the aggregate signature is now complete. No further signature will be included in this aggregate signature.
```

![Demo: sign a release](demos/sign-release.gif)

### 3. Check progress

At any point, you can check whether the threshold has been reached:

```sh
asfaload-cli signature-status --secret-key ~/.asfaload/mykey \
    https/github.com/443/acme/tool/releases/tag/v1.0/asfaload.index.json
```

```
https/github.com/443/acme/tool/releases/tag/v1.0/asfaload.index.json: pending
```

or

```
https/github.com/443/acme/tool/releases/tag/v1.0/asfaload.index.json: complete
```

## Example: two-of-three threshold

With three artifact signers and a threshold of 2, only two need to sign. Alice registers the release and her signature is recorded at registration. Bob's signature meets the threshold:

```
alice: asfaload-cli register-assets ...                     → signature recorded
bob:   asfaload-cli sign-pending --secret-key bob.key ...   → "now complete"
# carol doesn't need to sign — threshold already met
```

## Next step

Once the release is fully signed, users can [download it with verification](download-with-verification.md).

## Reference

- [`asfaload-cli list-pending`](../manual/list-pending.md)
- [`asfaload-cli sign-pending`](../manual/sign-pending.md)
- [`asfaload-cli signature-status`](../manual/signature-status.md)
