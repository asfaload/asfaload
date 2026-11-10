# Create a signers file

A signers file defines who can sign artifacts for your project, and how many signatures are needed (the threshold). You create it once, commit it to your repository, then register it with the backend.

## Prerequisites

- Public key files (`.pub`) for every signer. See [Generate a key pair](generate-keys.md).
- A target repository where the signers file will live.

## Steps

### 1. Collect the public keys

Gather `.pub` files from all signers. For this example, three artifact signers with a threshold of 2 (any two out of three must sign):

```
alice.pub
bob.pub
carol.pub
```

### 2. Create the signers file

```sh
asfaload-cli new-signers-file \
    --artifact-signers-file alice.pub \
    --artifact-signers-file bob.pub \
    --artifact-signers-file carol.pub \
    --artifact-threshold 2 \
    --output-file signers.json
```

The command prints a summary, ending with the SHA-512 digest of the created file (use it to spot-check the file later with [`get-digest`](../manual/get-digest.md)):

```
Signers file created successfully at: signers.json
Artifact signers: 3 (threshold: 2)
Admin keys: 0 (threshold: none)
Master keys: 0 (threshold: none)
Revocation keys: 0 (threshold: none)
Generated file's digest: sha512:2e2fde4e...
```

![Demo: create the signers file](demos/create-signers-file.gif)

### 3. Commit and push

Place the signers file in your repository and push it.
We advise to commit the file in your main branch (eg under a directory `.asfaload.signers`) or in a dedicated branch of the repo.
You can choose any naming convention that suits you, as long as the file stays
available at the URL, so that downloaders can confirm its validity.
You could choose to place it in your main branch:

```
https://github.com/acme/tool/blob/main/asfaload.signers/index.json
```

or in a dedicated branch (in this example `signers`):
```
https://github.com/acme/tool/blob/signers/20260413_signers.json
```
If you publish an updated signers file, you must make it available at distinct
URL. In other words, you must add a new file to your repo, and you must not
edit an existing signers file.


The backend needs to fetch it by URL during [repository registration](register-repo.md).

A common location is at the root of your repo:

```sh
cp signers.json my-project/asfaload.signers/index.json
cd my-project
git add asfaload.signers/index.json
git commit -m "Add asfaload signers file"
git push
```

## Adding optional key groups

Beyond artifact signers, you can define admin, master, and revocation key groups. Each group has its own keys and threshold.

### With revocation keys

Revocation keys can revoke signed releases. Useful to have a separate set of keys for emergency access:

```sh
asfaload-cli new-signers-file \
    --artifact-signers-file alice.pub \
    --artifact-signers-file bob.pub \
    --artifact-signers-file carol.pub \
    --artifact-threshold 2 \
    --revocation-keys-file revoke1.pub \
    --revocation-keys-file revoke2.pub \
    --revocation-keys-file revoke3.pub \
    --revocation-threshold 2 \
    --output-file signers.json
```

### With admin keys

Admin keys can propose signers file updates:

```sh
asfaload-cli new-signers-file \
    --artifact-signers-file alice.pub \
    --artifact-signers-file bob.pub \
    --artifact-threshold 2 \
    --admin-keys-file admin.pub \
    --admin-threshold 1 \
    --output-file signers.json
```

## Mixing base64 strings and files

You can pass public keys as base64 strings instead of files. This is handy when keys come from a secrets manager:

```sh
asfaload-cli new-signers-file \
    --artifact-signer "asfaload-pub:b5S+CxuqICIUn/DGBdMKeTMZCgQcg78ohiWQ1sC00c8" \
    --artifact-signers-file bob.pub \
    --artifact-threshold 1 \
    --output-file signers.json
```

To obtain the base64 string from a `.pub` file, use `share-key --raw`:

```sh
asfaload-cli share-key -k alice.pub --raw
```

See [Share a public key](share-public-key.md) for more details.

## Passing keys from a single file

For a longer signer list, repeating `--artifact-signers-file` quickly gets verbose. Each `*-keys-file` option reads **one key per line**, so you can collect several keys in a single text file and pass it once:

```sh
# signers.txt  (one base64 public key per line)
asfaload-pub:b5S+CxuqICIUn/DGBdMKeTMZCgQcg78ohiWQ1sC00c8
asfaload-pub:9wX6TbqMn2pPJ5vLV4R5gazKc2sQ7rH8oY3tV1uWfQk
asfaload-pub:7yQ4Tm1VxLpHoC2dRsKuVwMqY3nJbZ8iPtXaVeF9fBg
```

```sh
asfaload-cli new-signers-file \
    --af signers.txt \
    -A 2 \
    -o signers.json
```

The short alias `--af` (= `--artifact-signers-file`) keeps the command readable. The same `--df`, `--mf`, and `--rf` aliases exist for admin, master, and revocation key files.

## Next step

[Register the repository](register-repo.md) with the backend so it knows where to find your signers file.

## Reference

- [`asfaload-cli new-signers-file`](../manual/new-signers-file.md)
