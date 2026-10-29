# Register a repository

Registering a repository tells the backend where your signers file lives. Once registered, the backend can enforce signature requirements for your project.

## Prerequisites

- A signers file committed and pushed to your repository. See [Create a signers file](create-signers-file.md).
- Your secret key file. See [Generate a key pair](generate-keys.md).
- The backend is running and reachable.

## Steps

### 1. Get the signers file URL

You need the public URL that points to your signers file on the forge. For GitHub, you can simply copy the URL from your browser when displaying the file of your repo.
This will give you an URL of this form:

```
https://github.com/acme/tool/blob/main/asfaload.signers/index.json
```

### 2. Register the repository

```sh
asfaload-cli register-repo \
    --secret-key ~/.asfaload/mykey \
    https://github.com/acme/tool/blob/main/asfaload.signers/index.json
```

On success, when the submitter's signature completes the required signers:

```
Repository registered successfully!
Project ID: abc123
Required signers (0):
Success! Project registered successfully, and signers file activated.
```

When more signatures are necessary:

```
Repository registered successfully!
Project ID: abc123
Required signers (2): bob, carol
Success! Project registered successfully. Collect signatures to activate.
```

The CLI signs the signers file and the metadata with your key. The backend records these signatures. If they complete the required signers, the project is active at once. Otherwise the backend creates a pending signers entry and waits for the remaining signers before the project becomes active.

![Demo: register a repository](demos/register-repo.gif)

### 3. Point to a non-default backend

If your backend is not Asfaload's:

```sh
asfaload-cli register-repo \
    --secret-key ~/.asfaload/mykey \
    -u https://my-asfaload-deployment.example.com \
    https://github.com/acme/tool/blob/main/asfaload.signers/index.json
```

## What happens next

If registration did not complete the required signatures, the signers file stays in a **pending** state. Every signer listed in it must sign before the project is activated. See [Activate a signers file](activate-signers-file.md).

## Reference

- [`asfaload-cli register-repo`](../manual/register-repo.md)
