# Give names to public keys

A public key is long and difficult to read. Use the `alias` command to give a short name to the public key of each signer. The names are stored only on your computer. They are not sent to the backend.

## Prerequisites

- The public keys of the signers, for example from [Share a public key](share-public-key.md).

## Steps

### 1. Give a name to a key

```sh
asfaload-cli alias alice --key asfaload-pub:b5S+CxuqICIUn/DGBdMKeTMZCgQcg78ohiWQ1sC00c8
```

Output:

```
Alias alice added for asfaload-pub:b5S+CxuqICIUn/DGBdMKeTMZCgQcg78ohiWQ1sC00c8
```

A key has one alias at most. An alias starts with a letter or digit, and contains only letters, digits, `-`, `_` and `.`.

### 2. Show the aliases

Show all aliases:

```sh
asfaload-cli alias
```

Show the key of an alias, or the alias of a key:

```sh
asfaload-cli alias alice
asfaload-cli alias --key asfaload-pub:b5S+CxuqICIUn/DGBdMKeTMZCgQcg78ohiWQ1sC00c8
```

The output is in TOML format, so you can copy it into the configuration file:

```
alice = "asfaload-pub:b5S+CxuqICIUn/DGBdMKeTMZCgQcg78ohiWQ1sC00c8"
```

If the alias or the key is not found, the command fails. Thus, you can use it in a script.

### 3. Rename the alias of a key

If the key already has an alias, add `--force` to replace that alias:

```sh
asfaload-cli alias alicia --key asfaload-pub:b5S+CxuqICIUn/DGBdMKeTMZCgQcg78ohiWQ1sC00c8 --force
```

### 4. Delete an alias

```sh
asfaload-cli alias alicia --delete
```

The command asks for confirmation. Type `y` to delete the alias, or `n` to keep it. If you type `n`, the output is `Canceled`.

If the alias is not found, the command fails before it asks for confirmation.

In a script, add `--force` to delete the alias without confirmation:

```sh
asfaload-cli alias alicia --delete --force
```

Without `--force`, the command fails if its standard input is not a terminal.

![Demo: give names to public keys](demos/name-public-keys.gif)

## Reference

- [`asfaload-cli alias`](../manual/alias.md), which also gives the location and the format of the configuration file.
