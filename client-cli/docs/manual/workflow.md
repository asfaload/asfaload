# `asfaload-cli workflow`

- **Usage**: `asfaload-cli workflow`

Show an overview of the asfaload workflow from key generation to download with verification. Read it first if you are a new user.

## Output

The workflow documentation in a pager with colors when the output goes to a terminal, otherwise as plain text, 80 characters wide.

## Environment

- `NO_COLOR` — when set, the overview is shown without colors.

## Examples

    asfaload-cli workflow

## Exit codes

- `0` — the overview was shown.
- non-zero — the overview cannot be written.
