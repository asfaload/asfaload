# `asfaload-cli manual`

- **Usage**: `asfaload-cli manual [COMMAND]`

Show the manual of `asfaload-cli`. Without `COMMAND`, show the index page, which lists all commands. With `COMMAND`, show the manual page of this command.

`asfaload-cli <COMMAND> --manual` shows the same page. With `--manual`, the required arguments of `COMMAND` are not necessary. Other arguments are ignored.

## Arguments

### `[COMMAND]`

The command to show the manual page of, for example `download`.

## Output

When the output goes to a terminal, the page is shown with colors in a pager. A page that fits on the screen is printed without the pager. In the pager, type `q` to quit. When the output goes to a pipe or to a file, the page is printed as plain text with no colors, 80 characters wide.

## Environment

- `NO_COLOR` — when set, the page is shown without colors.

## Examples

    # show the index page
    asfaload-cli manual

    # show the manual page of download
    asfaload-cli manual download

    # the same page
    asfaload-cli download --manual

    # search in a page
    asfaload-cli download --manual | grep backend

## Exit codes

- `0` — the page was shown.
- non-zero — the command is not known (exit code `2`), or the page cannot be written.
