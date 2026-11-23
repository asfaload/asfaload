# `asfaload-cli fetch-file`

- **Usage**: `asfaload-cli fetch-file [OPTIONS] <PATH>`

Fetch a file from the backend, as the backend stores it. Use this command to examine a file before you sign it, for example a file that [`list-pending`](list-pending.md) shows. The command does not verify signatures. To download a release file and verify its signatures, use [`download`](download.md).

## Arguments

### `<PATH>`

Path of the file on the backend, as `list-pending` shows it. For example:

    https/github.com/443/acme/repo/releases/tag/v1.0/asfaload.index.json

## Options

### `-o --output <OUTPUT>`

Write the file to this path. The file must not exist: the command does not overwrite a file. Without this option, the content is printed to stdout.

### `-u --backend-url <URL>`

Backend API URL. Defaults to `https://backend.asfaload.com`.

### `--json`

Print a JSON object instead of the raw content. The object contains the content encoded in base64. With `--output`, the file is also written.

## Environment

- `ASFALOAD_BACKEND_URL` — alternative to `--backend-url` (an explicit `--backend-url` wins).

## Output

Without `--output` and without `--json`, the content is printed to stdout as it is. The content must be valid UTF-8 text. For a binary file, use `--output` or `--json`.

With `--output` and without `--json`, nothing is printed.

JSON (with `--json`). `output` is the path given with `--output`, or `null`:

    {"output":null,"base64_content":"eyJmaWxlcyI6W119Cg=="}

## Examples

    # print a pending index file
    asfaload-cli fetch-file https/github.com/443/acme/repo/releases/tag/v1.0/asfaload.index.json

    # save it to a file
    asfaload-cli fetch-file -o index.json https/github.com/443/acme/repo/releases/tag/v1.0/asfaload.index.json

## Exit codes

- `0` — the file was fetched and printed or saved.
- non-zero — the backend is not available, the file does not exist, the output file already exists, or the content is not UTF-8 text and must be printed to stdout.
