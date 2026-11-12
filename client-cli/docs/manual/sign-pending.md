# `asfaload-cli sign-pending`

- **Usage**: `asfaload-cli sign-pending [OPTIONS] -K <SECRET_KEY> <--digest <DIGEST>|--local-copy <PATH>> [FILE_PATH]`
- **Source**: [`src/commands/sign_pending.rs`](../../src/commands/sign_pending.rs)

Sign a pending file. The command fetches all files associated with the given path from the backend, computes a SHA-512 hash of each, signs them with your secret key, and submits the signatures in a single request.

Use [`list-pending`](list-pending.md) to discover which files need signing.

## Arguments

### `<FILE_PATH>`

Mirror-relative path to the file to sign, as returned by `list-pending`. For example `https/github.com/443/acme/repo/releases/tag/v1.0/asfaload.index.json`. Optional: if omitted, an interactive selector is shown (see below).

You must always give the expected digest of the file to sign, with `--digest` or `--local-copy`.

## Options

### `--digest <DIGEST>`

The expected `sha512:<128 hexadecimal characters>` digest of the file to sign. Get it from the person who started the signature: the outputs of `register-repo`, `update-signers`, `register-assets` and `revoke` give it. Or compute it with [`get-digest`](get-digest.md) on the original file. Do not take it from the backend: [`list-pending`](list-pending.md) shows only a short digest. Before signing, the digest of the fetched file is verified against this value and the command aborts on mismatch. When `<FILE_PATH>` is omitted, the interactive selection shows only the pending files with this digest. Conflicts with `--local-copy`. You must give `--digest` or `--local-copy`.

### `--local-copy <PATH>`

Path to your local copy of the file to sign, for example the signers file that you received from the project. Its SHA-512 digest is the expected digest, and the command uses it as it uses the value of `--digest`. Use this option when you have the file: you then do not have to get the digest from another person. Conflicts with `--digest`.

### `-K --secret-key <PATH>`

Path to your secret key file. Required.

### `-p --password <PASSWORD>`

Password for the secret key. Conflicts with `--password-file` and `--password-command`. Prompted interactively if none of these is set.

### `-P --password-file <PATH>`

File containing the password. Conflicts with `--password` and `--password-command`.

### `-c --password-command <COMMAND>`

Shell command to run; its standard output is read as the password. Useful for password managers (`pass`, `op`, `bw`, etc.). Conflicts with `--password` and `--password-file`. The command string is parsed with shell-style quoting (no shell is spawned, so pipes and redirections don't apply); trailing newlines are stripped from the output.

### `-u --backend-url <URL>`

Backend API URL. Defaults to `https://backend.asfaload.com`.

### `--json`

Emit output as JSON instead of human-readable text.

## Environment

These variables provide fallbacks for the matching options. Password sources are tried in the order described in the [manual index](index.md#passwords): flags first (in the order `--password`, `--password-command`, `--password-file`), then environment variables, then an interactive prompt.

- `ASFALOAD_SECRET_KEY` — alternative to `--secret-key`.
- `ASFALOAD_BACKEND_URL` — alternative to `--backend-url`.
- `ASFALOAD_PASSWORD_FILE` — alternative to `--password-file`.
- `ASFALOAD_PASSWORD_COMMAND` — alternative to `--password-command`.
- `ASFALOAD_SIGN_PENDING_PASSWORD` — alternative to `--password` (still supported, lower precedence).
- `ASFALOAD_SIGN_PENDING_PASSWORD_FILE` — alternative to `--password-file` (still supported, lower precedence).

## Interactive selection

When `<FILE_PATH>` is omitted, the command fetches your pending files and keeps only the files with the expected digest (from `--digest` or `--local-copy`). On a terminal, it shows an interactive `Select` prompt. Each proposal shows the file path and its digest. Use `↑`/`↓` to move through the list, or type to filter it.

If nothing is pending, the command fails with `No pending signature found`. If files are pending, but none has the expected digest, the command fails with `No pending file has the expected digest <DIGEST>`. If stdin is not a terminal (e.g. in CI), the command fails with `Not a tty and no path to sign was passed.` — pass `<FILE_PATH>` explicitly in that case.

## Output

Human-readable (default), when the aggregate signature is now complete:

    Success! Your signature has been included and the aggregate signature is now complete. No further signature will be included in this aggregate signature.

When your signature completes a pending signers file, that file is now the active signers file. The output then also shows an example command to register a release. For a project on GitHub, the owner and repository come from the signers file metadata:

    Next step
      The signers file is now active. An artifact signer can register a release.
      Example for a GitHub release. Replace <tag> and <secret-key>:

         asfaload-cli register-assets \
           --github-release-url https://github.com/acme/tool/releases/tag/<tag> \
           --secret-key <secret-key>

      Releases on other forges or file servers are registered with their
      checksums files, using --csum-file.

For a project on another forge or on a file server, the example uses checksums files:

    Next step
      The signers file is now active. An artifact signer can register a release
      with its checksums files. Replace <checksums-file-url> and <secret-key>:

         asfaload-cli register-assets \
           --csum-file <checksums-file-url> \
           --secret-key <secret-key>

      --csum-file can be repeated. For a GitHub release, use --github-release-url.

When you use a backend that is not the default one, the command also contains `--backend-url`.

When your signature completes a release index, the output also shows how users can download the artifacts of the release with verification. The example uses the first artifact listed in the index. The URL of the artifact directory comes from the index path:

    Next step
      The release is now signed. Users can download its artifacts with
      signature verification. Example:

         asfaload-cli download \
           https://github.com/acme/tool/releases/download/v1.0/tool-linux-amd64.tar.gz

      The artifacts of this release are at
      https://github.com/acme/tool/releases/download/v1.0/
      You can also download them with asfald, our dedicated download tool.

When the name of the artifact cannot be used in a command (the index has no artifact, or the name contains characters that are not safe in a shell), the command contains `<download-url>`, and the output gives the start of the artifact URLs. When the URL of the artifact directory also cannot be used, the output only tells you to replace `<download-url>` with the URL of an artifact of the release. When you use a backend that is not the default one, the command also contains `--backend-url`.

When other signers must still provide their signatures:

    Success! Your signature has been included, but the aggregate signature is not yet complete. Other signers must still provide their signatures.

    To follow the status of the signature, run this command:

         asfaload-cli signature-status \
           <file_path> \
           --secret-key <secret-key>

When you use a backend that is not the default one, the command also contains `--backend-url`. When the path contains unexpected characters, the output tells you to use the signature-status command, but does not show the command.

When you sign a pending revocation, the output also tells if downloads of the file now fail. When your signature completes the revocation:

    Success! Your signature has been included and the aggregate signature is now complete. No further signature will be included in this aggregate signature.

    The revocation is complete. Downloads of this file now fail.

When the revocation is still pending:

    Success! Your signature has been included, but the aggregate signature is not yet complete. Other signers must still provide their signatures.
    Users can still download the file until the revocation is complete.

    To follow the status of the signature, run this command:

         asfaload-cli signature-status \
           <file_path> \
           --secret-key <secret-key>

JSON (with `--json`):

    {"is_complete":true}

## Examples

    # sign a pending release index
    asfaload-cli sign-pending -K ~/.asfaload/key \
        --digest sha512:2e2fde4e... \
        https/github.com/443/acme/repo/releases/tag/v1.0/asfaload.index.json

    # sign with explicit password (CI usage)
    asfaload-cli sign-pending -K ~/.asfaload/key -p "$PASSWORD" \
        --digest sha512:2e2fde4e... \
        https/github.com/443/acme/repo/releases/tag/v1.0/asfaload.index.json

    # sign a pending signers file, with your local copy of the signers file
    asfaload-cli sign-pending -K ~/.asfaload/key \
        --local-copy ./asfaload.signers/index.json \
        https/github.com/443/acme/repo/asfaload.signers.pending/index.json

    # interactive selection of the pending files with the expected digest
    asfaload-cli sign-pending -K ~/.asfaload/key --digest sha512:2e2fde4e...

## Exit codes

- `0` — signature submitted successfully.
- non-zero — error (authentication failure, file not found, network error).
