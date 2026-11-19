# `asfaload-cli alias`

- **Usage**: `asfaload-cli alias [OPTIONS] [NAME]`
- **Source**: [`src/commands/alias.rs`](../../src/commands/alias.rs)

Give a name to a public key, show the aliases, or delete an alias. An alias is easier to read than a public key.

Aliases are stored in a local configuration file. They are not sent to the backend, and they have no effect on signatures or verification.

## Operations

The arguments that you give select the operation:

| Arguments | Operation |
|---|---|
| none | Show all aliases. |
| `NAME` | Show the key of the alias `NAME`. |
| `--key KEY` | Show the alias of the key `KEY`. |
| `NAME --key KEY` | Add the alias `NAME` for the key `KEY`. |
| `NAME --delete` | Delete the alias `NAME`. |
| `--key KEY --delete` | Delete the alias of the key `KEY`. |
| `NAME --key KEY --delete` | Delete the alias `NAME`, but only if it is the alias of `KEY`. |

## Alias rules

- A key has one alias at most, and an alias identifies one key.
- An alias never moves to a different key. To give an alias to a different key, first delete the alias.
- If the key already has an alias, the add operation fails. With `--force`, the old alias of the key is replaced by `NAME`.
- If you add an alias that already exists for the same key, nothing changes.
- An alias starts with an ASCII letter or digit. It contains only ASCII letters, digits, `-`, `_` and `.`. Thus, an alias is safe to use in a shell, and it cannot be read as a public key.

## Configuration file

The default location is `asfaload-cli/config.toml` in your configuration directory:

- Linux and macOS: `$XDG_CONFIG_HOME/asfaload-cli/config.toml`, or `~/.config/asfaload-cli/config.toml` when `XDG_CONFIG_HOME` is not set.
- Windows: `%APPDATA%\asfaload-cli\config.toml`.

Use `--config-file` to use a different file.

The file is in TOML format. Each alias is an entry in the `[aliases]` table:

    [aliases]
    alice = "asfaload-pub:b5S+CxuqICIUn/DGBdMKeTMZCgQcg78ohiWQ1sC00c8"
    bob = "asfaload-pub:p8p1Hb8ux9xf9mo8BGedkpv4RUFZgwXuYGu5x0grsdU"

Notes:

- The operations that show aliases do not create the file. The first add operation creates it, together with its directories.
- You can edit the file manually. When the command reads the file, it checks the alias rules, and it rejects unknown tables and keys. Thus, a spelling mistake such as `[alias]` causes an error, and is not ignored.
- When the command saves the file, it writes the full file again. **Comments and formatting are not kept.**
- If the file is a symbolic link, the command writes to the target of the link. The link stays.

## Options

### `NAME`

The alias. Optional.

### `-k --key <KEY>`

The public key, in the format `asfaload-pub:...`. Optional.

### `-f --force`

When the key already has an alias, replace that alias with `NAME`. Used only to add an alias. Conflicts with `--delete`.

### `-d --delete`

Delete an alias. Requires `NAME`, `--key`, or both. Refer to [Operations](#operations).

### `-c --config-file <CONFIG_FILE>`

The configuration file to use instead of the default file.

### `--json`

Write the result as JSON instead of human-readable text.

## Output

Show all aliases:

    alice = "asfaload-pub:b5S+CxuqICIUn/DGBdMKeTMZCgQcg78ohiWQ1sC00c8"
    bob = "asfaload-pub:p8p1Hb8ux9xf9mo8BGedkpv4RUFZgwXuYGu5x0grsdU"

Show one alias (from `NAME` or from `--key`):

    alice = asfaload-pub:b5S+CxuqICIUn/DGBdMKeTMZCgQcg78ohiWQ1sC00c8

Add an alias:

    Alias alice added for asfaload-pub:b5S+CxuqICIUn/DGBdMKeTMZCgQcg78ohiWQ1sC00c8

Delete an alias:

    Alias bob deleted for asfaload-pub:p8p1Hb8ux9xf9mo8BGedkpv4RUFZgwXuYGu5x0grsdU

JSON (with `--json`). To show all aliases, the object contains all aliases. For all other operations, it contains the alias that was found, added or deleted:

    {"alice":"asfaload-pub:b5S+CxuqICIUn/DGBdMKeTMZCgQcg78ohiWQ1sC00c8","bob":"asfaload-pub:p8p1Hb8ux9xf9mo8BGedkpv4RUFZgwXuYGu5x0grsdU"}
    {"alice":"asfaload-pub:b5S+CxuqICIUn/DGBdMKeTMZCgQcg78ohiWQ1sC00c8"}

## Examples

    # give a name to a key
    asfaload-cli alias alice --key asfaload-pub:b5S+CxuqICIUn/DGBdMKeTMZCgQcg78ohiWQ1sC00c8

    # show all aliases
    asfaload-cli alias

    # find the key of an alias, for use in a script
    asfaload-cli alias alice --json

    # rename the alias of a key
    asfaload-cli alias alicia --key asfaload-pub:b5S+CxuqICIUn/DGBdMKeTMZCgQcg78ohiWQ1sC00c8 --force

    # delete an alias
    asfaload-cli alias alicia --delete

## Exit codes

- `0` — the operation succeeded. The operation that shows all aliases also succeeds when no alias exists.
- non-zero — error. For example, the alias or the key is not found, the alias rules prevent the change, or the configuration file is not valid.
