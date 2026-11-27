# The Asfaload workflow

Asfaload makes sure that the files you download are the files that the project team signed. A group of signers signs each release. Users then download the files with signature verification.

This page gives an overview of the workflow.
For more information about each step, see [https://www.asfaload.com/docs](https://www.asfaload.com/docs), or use the flag `--manual` with each `asfaload-cli` command.

## 1. Each signer generates a key pair

Each signer creates a key pair. A password protects the secret key.

```sh
asfaload-cli new-keys --name mykey
```

See [Generate a key pair](howto/generate-keys.md).

## 2. Each signer shares the public key with the admin

The public key is safe to share. Send it to the admin of the project.

```sh
asfaload-cli share-key -k mykey
```

See [Share a public key](howto/share-public-key.md).

## 3. The admin creates and publishes the signers file

The signers file contains the public keys of the signers and the number of signatures necessary for a release (the threshold). The admin creates it, commits it to the repository and pushes it. Then the admin registers the repository with the URL of the published file.

```sh
asfaload-cli new-signers-file \
    --artifact-signers-file alice.pub \
    --artifact-signers-file bob.pub \
    --artifact-threshold 2 \
    --output-file signers.json
```

After you commit and push `signers.json`, register the repository:

```sh
asfaload-cli register-repo --secret-key mykey \
    --local-copy signers.json \
    https://raw.githubusercontent.com/acme/tool/main/signers.json
```

The output of `register-repo` shows the digest of the signers file and the `sign-pending` command. The admin sends them to all signers.

See [Create a signers file](howto/create-signers-file.md) and [Register a repository](howto/register-repo.md).

## 4. The signers sign the signers file

Each signer signs the signers file with the digest from the admin, this makes sure that the correct file is signed. When all signers have signed, the signers file is active and can be used to sign a release.

```sh
asfaload-cli sign-pending --secret-key mykey \
    --digest sha512:2e2fde4e... \
    https/github.com/443/acme/tool/asfaload.signers.pending/index.json
```

Use `asfaload-cli list-pending --secret-key mykey` to see the files that wait for your signature.

See [Activate a signers file](howto/activate-signers-file.md).

## 5. A signer registers a release

The CLI computes the release index aggregating the release artifacts' digests, and signs it. The output shows the digest of the index and command to be run by other signers. The registrant sends them to the other signers.

```sh
asfaload-cli register-assets --secret-key mykey \
    --github-release-url https://github.com/acme/tool/releases/tag/v1.0
```

Asfaload also supports other forges and HTTP file servers. For these, register the checksums files of the release with `--csum-file`.

See [Register a release](howto/register-release.md).

## 6. The signers sign the release

Each signer signs the release index with the digest from the registrant. When the number of signatures reaches the threshold, the release is signed.

```sh
asfaload-cli sign-pending --secret-key mykey \
    --digest sha512:7a1c90b3... \
    https/github.com/443/acme/tool/releases/tag/v1.0/asfaload.index.json
```

See [Sign a release](howto/sign-release.md).

## 7. Users download with verification

Users can now download the files of the release with authentication using the original URL. The CLI verifies the signatures and the file digest before it saves the file.
You can validate the download with this command

```sh
asfaload-cli download \
    https://github.com/acme/tool/releases/download/v1.0/tool.tar.gz
```

See [Download a file with signature verification](howto/download-with-verification.md).
