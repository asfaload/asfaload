# Manual test: GitHub releases (backend only)

This environment starts a backend only. It does not start a file server.

The backend reads release data and signers files from the GitHub
repository `asfaload/repo_for_e2e_tests`. This is the same data as the
automated e2e `basic_flow` test uses.

Internet access is necessary. The backend sends requests to the GitHub
API and downloads release assets.

## State after the start

- The signers file from GitHub is active. It has the keys `key_0`,
  `key_1` and `key_2`. The threshold is 2.
- Release `v0.1` is registered. Its index is signed to completion.
- Release `v0.2` is registered. Its index has no signature yet.

## Start

1. Run this command:
   `./setup`
2. Wait for the setup to complete. A new shell opens.

The first start builds the binaries. This can take some time.

## Use the environment

The new shell has these variables:

- `ASFALOAD_BACKEND_URL`: the address of the backend
- `ASFALOAD_PASSWORD_FILE`: the file with the key password
- `KEY_0`, `KEY_1`, `KEY_2`: the paths to the test keys
- `BACKEND_REPO`: the backend git repository
- `RELEASE_URL_V01`, `RELEASE_URL_V02`: GitHub release URLs
- `RELEASE_INDEX_V01`, `RELEASE_INDEX_V02`: mirror-relative index paths
- `ARTIFACT_URL_V01`, `ARTIFACT_URL_V02`: GitHub download URLs

Example commands:

```
asfaload-cli list-pending -K $KEY_0
asfaload-cli signature-status $RELEASE_INDEX_V02
asfaload-cli download -o /tmp/artifact.bin $ARTIFACT_URL_V01
```

Expected results:

- The download of `v0.1` completes.
- The download of `v0.2` fails because the index is not signed.
- `list-pending` shows the index of `v0.2`.

To sign the index of `v0.2`:

1. Obtain the path and the digest from the `list-pending` output.
2. Run `sign-pending` with two keys.

## Stop

Type `exit` in the new shell. The setup stops the backend and removes
the temporary files.

## Notes

- The keys are test data only.
- Releases `v0.1` and `v0.2` are also data for the automated e2e test.
  Changes to these GitHub releases change this environment too.
