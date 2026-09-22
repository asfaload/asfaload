# Activate a signers file

After a repository is registered (or a signers file is updated), the signers file sits in a **pending** state. Every signer listed in it must sign before the project becomes active. This guide covers the signing round.

## Prerequisites

- A repository has been [registered](register-repo.md) or a signers file [update proposed](update-signers-file.md).
- Each signer has their own secret key. See [Generate a key pair](generate-keys.md).

## Steps

Each signer performs steps 1–2 independently.

### 1. Check for pending work

```sh
asfaload-cli list-pending --secret-key ~/.asfaload/mykey
```

If the signers file is waiting for your signature, you'll see its path, its digest, and a bishop art block (a small picture derived from the digest, acting as a visual fingerprint):

```
Files requiring your signature:
  - path: https/github.com/443/acme/tool/asfaload.signers.pending/index.json
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

If nothing is pending for you, the output says `No pending signatures found.`

### 2. Sign the pending signers file

Copy the path **and** the digest from the output above and pass both to `sign-pending`:

```sh
asfaload-cli sign-pending --secret-key ~/.asfaload/mykey \
    --digest sha512:2e2fde4e... \
    https/github.com/443/acme/tool/asfaload.signers.pending/index.json
```

If more signatures are needed:

```
Success! Your signature has been included, but the aggregate signature is not yet complete. Other signers must still provide their signatures.
```

When your signature completes the required count (every signer must sign for an initial signers file):

```
Success! Your signature has been included and the aggregate signature is now complete. No further signature will be included in this aggregate signature.
```

![Demo: sign the pending signers file](demos/activate-signers-file.gif)

### 3. Verify activation

Once every signer has signed, the signers file moves from pending to active. There is no separate activation step — the last signature triggers it automatically.

## Coordinating signers

Signers don't need to sign in any particular order. The workflow looks like:

```
alice: asfaload-cli list-pending --secret-key alice.key    → sees pending signers
alice: asfaload-cli sign-pending --secret-key alice.key ...  → "not yet complete"

bob:   asfaload-cli list-pending --secret-key bob.key      → sees pending signers
bob:   asfaload-cli sign-pending --secret-key bob.key ...    → "not yet complete"

carol: asfaload-cli list-pending --secret-key carol.key    → sees pending signers
carol: asfaload-cli sign-pending --secret-key carol.key ...  → "now complete"
```

## Scripting the sign step

For CI, supply the password and digest non-interactively:

```sh
asfaload-cli sign-pending \
    --secret-key ~/.asfaload/mykey \
    --password-file "/path/to/password-file" \
    --digest "sha512:2e2fde4e..." \
    https/github.com/443/acme/tool/asfaload.signers.pending/index.json
```

If several files are pending, `--digest-filter` (alias `--df`) restricts both `list-pending` output and the interactive selection of `sign-pending` to a single digest:

```sh
asfaload-cli list-pending --secret-key ~/.asfaload/mykey --df sha512:2e2fde4e...
```

On an interactive terminal you can also omit the path and digest entirely: `sign-pending` then shows a selection prompt, one pending file at a time, cycling through them with `↑`/`↓`, each with its bishop art.

## Troubleshooting

**"Already completed" error when signing** — someone else already provided the final signature. The signers file is active; no action needed.

**list-pending returns empty** — either your key is not listed in the signers file, or the file has already been fully signed.

## Next step

Once the signers file is active, you can [register a release](register-release.md) for signing.

## Reference

- [`asfaload-cli list-pending`](../manual/list-pending.md)
- [`asfaload-cli sign-pending`](../manual/sign-pending.md)
