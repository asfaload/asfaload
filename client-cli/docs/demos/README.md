# CLI how-to demos

VHS recordings of the [`asfaload-cli` how-tos](../howto/).

## Run

From the repo root:

```sh
make demos
```

This builds `asfaload-cli`, `rest-api`, and `test-file-server`, sets up an isolated fixture (a fake `$HOME`, a fake fileserver doc-root, a fresh git repo), starts a local rest-api and file-server in the background, renders each `.tape.tmpl` for the active profile, plays the rendered tape, and writes GIFs to `howto/out/` (gitignored).

Set `KEEP_FIXTURE=1` to preserve the fixture directory for debugging — the script prints its path on stderr.

## Profiles

`make demos` renders every tape under one of two profiles, selected via the `DEMO_PROFILE` env var:

| Profile | `Set TypingSpeed` | `Sleep` lines | `$END_PAUSE` |
|---------|-------------------|---------------|--------------|
| `production` (default) | `20ms` | played as written | `20s` |
| `fast` | `1ms` | stripped (rendered as comments) | `0s` |

```sh
make demos                          # production
DEMO_PROFILE=fast make demos   # fast: instant typing, no sleeps
```

`fast` exists for fast iteration on a tape — the GIFs still render but flash by quickly. Use `production` for shareable output.

The pace settings are not hard-coded into the tape sources. Each tape is a `.tape.tmpl` template that uses `$TYPING_SPEED` for the typing speed value and a `$SLEEP` line prefix for delays. The driver substitutes both based on the active profile and writes the rendered `.tape` into a temp directory before invoking `vhs`.

```
Set TypingSpeed $TYPING_SPEED   # → 20ms or 1ms
$SLEEP 4s                       # → Sleep 4s, or "# 4s" (a comment)
Sleep $END_PAUSE                # → Sleep 20s or Sleep 0s (always a real Sleep)
```

## Embedding in howtos

Each how-to embeds its matching demo at the end of the section that shows the CLI invocation. Run `make demos` to render the GIFs into `howto/out/`, then `make docs` to copy them into `../howto/demos/` (gitignored) and rebuild the mdbook site. The howto markdown references the copied path as `demos/<tape-name>.gif`.

`make demos` must run before `make docs` for the embedded GIFs to appear. If GIFs are missing, `make docs` emits a single warning and continues; the site renders broken-image placeholders for the missing entries.

## Requirements

- [`vhs`](https://github.com/charmbracelet/vhs) on `PATH`. Tested with v0.11.0.
- [`ttyd`](https://github.com/tsl0922/ttyd) on `PATH` (VHS depends on it). On Debian/Ubuntu, install with `apt-get install ttyd`, or grab a static binary from the upstream releases page.
- A working Rust toolchain — the driver builds the binaries with `cargo build`.

## What gets recorded

The recordings show only what a reader following the how-to would type. Server lifecycle, fixture setup, the equivalent of "commit and push", and signing rounds the howto delegates to other guides all happen in the driver and are not visible on screen.

Each tape stands on its own: comments don't refer to earlier demos, and only `generate-keys.tape.tmpl` actually generates a key. Every other tape works against the project's fixture keys, which the driver pre-stages into `$HOME/.asfaload/` before recording starts. That means the order tapes are recorded in does not matter for any single tape's correctness — only the backend state flows from one to the next.

### Keys used in the demos

The driver copies `core/test_helpers/fixtures/keys/key_0..key_6` (and matching `.pub` files) into `$HOME/.asfaload/` before any tape runs. Tapes reference them as `~/.asfaload/key_N`. The fixture keys are encrypted with the password `password`, so the demo's `.demo-password` file holds that exact string; the driver points `ASFALOAD_PASSWORD_FILE` at it, so every command decrypts its key without an on-screen `--password-file` flag.

| Key | Role in the demos |
|-----|------------------|
| `key_0` | Submitter (registers the repo and the release; first artifact signer) |
| `key_1` | Second artifact signer |
| `key_2` | Third artifact signer (not needed for the threshold-2 release signature, but signs the signers file at activation) |
| `key_3` | Fourth artifact signer, added in the v2 signers update |
| `key_4` | Revocation key — initiates revocation |
| `key_5` | Revocation key — co-signs revocation (threshold 2) |
| `key_6` | Third revocation key |

`generate-keys.tape.tmpl` produces a key called `mykey` purely to demonstrate the `new-keys` command; nothing else consumes it.

### Run order

The driver renders tapes in this order, mirroring the howto index:

1. `generate-keys` — runs `new-keys` (the only `new-keys` invocation across all tapes).
2. `create-signers-file` — assembles the initial signers file from `key_0/1/2.pub`.
3. `register-repo` — submits the signers file to the backend with `key_0`.
4. `activate-signers-file` — `key_0`, `key_1`, `key_2` each `sign-pending`; signers file becomes active.
5. `register-release` — registers `v1.0` against the backend via `--csum-file`.
6. `sign-release` — `key_1` signs the release index and completes the threshold of 2. `key_0` signed the index at registration.
7. `download-with-verification` — fetches the signed `v1.0` artifact with full verification.
8. `update-signers-file` — proposes a new signers file (4 artifact + 3 revocation keys).
9. `revoke-release-initiate` — `key_4` initiates the revocation of `v1.0` (leaves a pending revocation on the backend).
10. `revoke-release-cosign` — `key_5` co-signs the pending revocation; threshold 2 is met and `v1.0` becomes revoked.

`download-with-verification` is recorded before `update-signers-file`/`revoke-release` so the verification path stays the happy one. By the end of the run, `v1.0` is revoked.

## Visible deviations from the source how-tos

- **Localhost URL.** Anywhere a forge URL appears (`register-repo`, `update-signers-file`, list-pending output, etc.) the demo shows a `http://localhost:<port>/...` URL instead of a `https://github.com/...` URL because the demo runs against a local file server. The forge-url module accepts localhost in this position via the FileServer fallback.
- **`key_0` is the submitter and an artifact signer.** The how-to lists `alice`/`bob`/`carol` as the three artifact signers and then has `register-repo` use `mykey` as the secret key. That only works if the secret key is itself a signer — registration authenticates against the signers file's admin group, which falls back to artifact signers. The demos therefore use `key_0` for both roles.
- **Env-var paths in the recording.** Pending file paths and forge URLs contain a random localhost port that changes every run, so the tapes pass them through env vars (e.g. `"$ASFALOAD_DEMO_PENDING_SIGNERS_PATH"`) rather than hard-coding them. In a real session the user would copy the path from the previous command's output.

## Hidden steps

These run silently in the driver to bridge demos:

- **At fixture setup**: copy `core/test_helpers/fixtures/keys/key_0..key_6{,.pub}` into `$HOME/.asfaload/` and stage a v1.0 release artifact + `SHA256SUMS` in the file-server doc-root.
- **Before `update-signers-file.tape`**: pre-publish the v2 signers file at `$ASFALOAD_DEMO_NEW_SIGNERS_URL`. The tape re-runs `new-signers-file` for the camera, but it's the pre-published version the backend fetches. Local content matches except for an embedded timestamp.
- **After `create-signers-file.tape`**: copy `$HOME/signers.json` into the fileserver doc-root at `demo-project/asfaload.signers/index.json`. Equivalent of the how-to's "commit and push".
- **After `update-signers-file.tape`**: run `sign-pending` for `key_0` through `key_6` so the v2 signers file becomes active. The signing-round how-to (`activate-signers-file`) already showed the user-facing flow, so we don't re-record it here. This is what makes `revoke-release` work — the active signers file now has a revocation group.
- **Backend URL and password file via env vars**: the driver exports `ASFALOAD_BACKEND_URL` (the local rest-api) and `ASFALOAD_PASSWORD_FILE` (the fixture `.demo-password`) to the `vhs` process. The CLI reads both through clap's env support, so on-screen commands omit `-u` and `--password-file`. In a real session the user only passes `-u` to override the default backend (`https://backend.asfaload.com`) and supplies the password interactively or via `--password-file`.

## Env vars exposed to tapes

| Env var | Meaning |
|---------|---------|
| `ASFALOAD_DEMO_FILESERVER_URL` | Local file-server origin, e.g. `http://localhost:42977`. |
| `ASFALOAD_DEMO_SIGNERS_URL` | URL of the initial signers file. |
| `ASFALOAD_DEMO_NEW_SIGNERS_URL` | URL of the v2 signers file (pre-staged before `update-signers-file.tape`). |
| `ASFALOAD_DEMO_CSUM_URL` | URL of `SHA256SUMS` for the v1.0 release. |
| `ASFALOAD_DEMO_ARTIFACT_URL` | URL of the v1.0 artifact for `download`. |
| `ASFALOAD_DEMO_PENDING_SIGNERS_PATH` | Backend-relative path of the pending signers file (`http/localhost/<port>/...`). |
| `ASFALOAD_DEMO_PENDING_SIGNERS_DIGEST` | Digest of the pending signers file, looked up from the backend before the tape runs (`sign-pending` requires `--digest`). |
| `ASFALOAD_DEMO_RELEASE_INDEX_PATH` | Backend-relative path of the v1.0 release index. |
| `ASFALOAD_DEMO_RELEASE_INDEX_DIGEST` | Digest of the v1.0 release index, looked up from the backend before the tape runs. |
| `ASFALOAD_DEMO_PENDING_REVOCATION_PATH` | Backend-relative path of the pending revocation file for v1.0. |
| `ASFALOAD_DEMO_PENDING_REVOCATION_DIGEST` | Digest of the pending revocation file, looked up from the backend before the tape runs. |

## Adding a new demo

1. Drop `<howto-name>.tape.tmpl` into `howto/` (filename mirrors the source how-to's basename, no numeric prefix).
2. Use `Set TypingSpeed $TYPING_SPEED` and `$SLEEP Ns` for in-tape delays — never literal values, otherwise the profile won't apply.
3. End every tape with a single `Sleep $END_PAUSE` line (not `$SLEEP …`) so the last frame stays readable in both profiles.
4. Append the basename (without `.tmpl`) to the `TAPES` array in `run-demos.sh`. The driver appends `.tmpl` when reading.
5. Use one of the staged fixture keys (`~/.asfaload/key_N`) rather than calling `new-keys` for setup. Only `generate-keys.tape.tmpl` should ever invoke `new-keys`.
6. If the new demo depends on state from a previous demo, add a `case` arm in `hidden_step_after()` (or `hidden_step_before()` for prerequisites the howto assumes are already in place) to bridge it.
7. If the new demo introduces a new env var, add it to the env-var table and export it from `run-demos.sh` before the `vhs` invocation.

## Reference

Driver: [`run-demos.sh`](run-demos.sh). Mirrors the orchestration in [`tests/e2e_tests/basic_flow_local.sh`](../../../tests/e2e_tests/basic_flow_local.sh).
