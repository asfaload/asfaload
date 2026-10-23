#!/bin/bash
set -euo pipefail

# E2E test for OpenSSH ed25519 key support through the CLI.
#
# Uses real SSH ed25519 keys (generated with ssh-keygen at runtime) as
# artifact signers. This exercises the import-only OpenSsh key format
# end-to-end through the admin + client CLI.

# helpers.sh's urls.sh branch requires KEY_TYPE to be asfaload.
# This test uses neither shared fixture set — it generates its own keys —
# but we still source helpers.sh for run_step / section / color output,
# so we pin a valid value to satisfy the check.
export KEY_TYPE="${KEY_TYPE:-asfaload}"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
. "$SCRIPT_DIR/lib/helpers.sh"

# --- Cleanup trap ---

FILE_SERVER_PID=""
SERVER_PID=""
background_pids=()
to_delete_on_filesystem=()

cleanup() {
    if [[ -n "$SERVER_PID" ]] && kill -0 "$SERVER_PID" 2>/dev/null; then
        kill "$SERVER_PID" 2>/dev/null
        wait "$SERVER_PID" 2>/dev/null || true
    fi
    if [[ -n "$FILE_SERVER_PID" ]] && kill -0 "$FILE_SERVER_PID" 2>/dev/null; then
        kill "$FILE_SERVER_PID" 2>/dev/null
        wait "$FILE_SERVER_PID" 2>/dev/null || true
    fi
    for pid in "${background_pids[@]}"; do
        if kill -0 "$pid" 2>/dev/null; then
            kill "$pid" 2>/dev/null || true
        fi
    done

    for path in "${to_delete_on_filesystem[@]}"; do
        if [[ -e "$path" ]]; then
            rm -rf "$path"
        fi
    done
}
trap cleanup EXIT

base_dir="$(git rev-parse --show-toplevel)"

if ! command -v ssh-keygen &> /dev/null; then
    printf '%sssh-keygen is required but not installed.%s\n' "$RED" "$RESET"
    exit 1
fi

################################################################################
section "Generate SSH ed25519 keys"
################################################################################

SSH_KEYS_DIR=$(mktemp -d)
to_delete_on_filesystem+=("$SSH_KEYS_DIR")
SSH_KEY_1="$SSH_KEYS_DIR/id_ed25519_1"
SSH_KEY_2="$SSH_KEYS_DIR/id_ed25519_2"

run_step "Generate SSH ed25519 key 1 (passphrase-protected)" \
    ssh-keygen -t ed25519 -N "$key_password" -C "ssh-e2e-key-1" -f "$SSH_KEY_1" -q

run_step "Generate SSH ed25519 key 2 (passphrase-protected)" \
    ssh-keygen -t ed25519 -N "$key_password" -C "ssh-e2e-key-2" -f "$SSH_KEY_2" -q

run_step "SSH key 1 has secret and public files" \
    bash -c "[[ -f '$SSH_KEY_1' ]] && [[ -f '$SSH_KEY_1.pub' ]]"
run_step "SSH key 2 has secret and public files" \
    bash -c "[[ -f '$SSH_KEY_2' ]] && [[ -f '$SSH_KEY_2.pub' ]]"

################################################################################
section "Create signers file with 2 SSH artifact signers"
################################################################################

# Place the signers file directly into the file-server tree so it can be
# served unchanged by register-repo in the next section.
FILE_SERVER_DIR=$(mktemp -d)
to_delete_on_filesystem+=("$FILE_SERVER_DIR")
FS_PROJECT_NAME="e2e_project"
FS_PROJECT_DIR="$FILE_SERVER_DIR/$FS_PROJECT_NAME"
mkdir -p "$FS_PROJECT_DIR/$HIDDEN_SIGNERS_DIR"
SIGNERS_FILE_NAME="signers_file_ssh.json"
SIGNERS_FILE_ON_FS="$FS_PROJECT_DIR/$HIDDEN_SIGNERS_DIR/$SIGNERS_FILE_NAME"

run_step "Create signers file with 2 SSH ed25519 artifact signers (threshold 2)" \
    cargo run --quiet --manifest-path "$base_dir/client-cli/Cargo.toml" -- new-signers-file \
        --artifact-signers-file "$SSH_KEY_1.pub" \
        --artifact-signers-file "$SSH_KEY_2.pub" \
        -A 2 \
        -o "$SIGNERS_FILE_ON_FS"

run_step "Signers file exists" \
    bash -c "[[ -f '$SIGNERS_FILE_ON_FS' ]]"

run_step "Signers file is valid JSON" \
    jq empty "$SIGNERS_FILE_ON_FS"

run_step "Signers file records a single artifact-signer group" \
    bash -c "jq -e '.artifact_signers | length == 1' '$SIGNERS_FILE_ON_FS' > /dev/null"

run_step "Artifact-signer group has threshold of 2" \
    bash -c "jq -e '.artifact_signers[0].threshold == 2' '$SIGNERS_FILE_ON_FS' > /dev/null"

run_step "Artifact-signer group contains 2 keys" \
    bash -c "jq -e '.artifact_signers[0].signers | length == 2' '$SIGNERS_FILE_ON_FS' > /dev/null"

run_step "Artifact-signer keys are stored as ed25519 (asfaload-pub: prefix)" \
    bash -c "jq -e '[.artifact_signers[0].signers[].data.pubkey] | all(startswith(\"asfaload-pub:\"))' '$SIGNERS_FILE_ON_FS' > /dev/null"

# Read back the normalised pubkey strings the CLI wrote. The backend keys
# signatures by these strings, so we use them directly in the assertions
# below rather than deriving them from the SSH .pub files (which use the
# ssh-ed25519 wire form).
SSH_PK_1=$(jq -r '.artifact_signers[0].signers[0].data.pubkey' "$SIGNERS_FILE_ON_FS")
SSH_PK_2=$(jq -r '.artifact_signers[0].signers[1].data.pubkey' "$SIGNERS_FILE_ON_FS")

################################################################################
section "Start local file server"
################################################################################

printf '%sBuilding test-file-server...%s ' "$DIM" "$RESET"
cargo build -p test-file-server --quiet
printf '%s✓%s\n' "$GREEN" "$RESET"

FILE_SERVER_LOG="$FILE_SERVER_DIR/file_server.log"
"${base_dir}/target/debug/test-file-server" --dir "$FILE_SERVER_DIR" > "$FILE_SERVER_LOG" 2>&1 &
FILE_SERVER_PID=$!

printf '%sWaiting for file server...%s ' "$DIM" "$RESET"
FILE_SERVER_PORT=""
for i in $(seq 1 30); do
    if [[ -f "$FILE_SERVER_LOG" ]]; then
        FILE_SERVER_PORT=$(grep -oP 'LISTENING_PORT=\K[0-9]+' "$FILE_SERVER_LOG" 2>/dev/null || true)
        [[ -n "$FILE_SERVER_PORT" ]] && break
    fi
    if ! kill -0 "$FILE_SERVER_PID" 2>/dev/null; then
        printf '%s✗%s\n' "$RED" "$RESET"
        printf '%sFile server process died unexpectedly.%s\n' "$RED" "$RESET"
        exit 1
    fi
    sleep 0.2
done
if [[ -z "$FILE_SERVER_PORT" ]]; then
    printf '%s✗%s\n' "$RED" "$RESET"
    printf '%sFile server did not report a port in time.%s\n' "$RED" "$RESET"
    exit 1
fi
FILE_SERVER_URL="http://localhost:${FILE_SERVER_PORT}"
printf '%s✓ %s%s\n' "$GREEN" "$FILE_SERVER_URL" "$RESET"

if [[ -n $debug ]]; then
    tail -f "$FILE_SERVER_LOG" &
    background_pids+=($!)
fi

# backend_assertions.sh uses these to locate the project dir inside the
# backend git repo (matches forge-url's scheme/host/port path prefix).
export PROJECT_DIR_OVERRIDE="http/localhost/${FILE_SERVER_PORT}/${FS_PROJECT_NAME}"
export RELEASE_DIR_TEMPLATE="releases/v%s"

################################################################################
section "Start backend"
################################################################################

port="${ASFALOAD_SERVER_PORT:-$((3000 + RANDOM % 1000))}"
export ASFALOAD_SERVER_PORT="$port"
backend="http://localhost:$port"

E2E_GIT_REPO_PATH=$(mktemp -d)
to_delete_on_filesystem+=("$E2E_GIT_REPO_PATH")
init_backend_repo "$E2E_GIT_REPO_PATH"
export ASFALOAD_GIT_REPO_PATH="$E2E_GIT_REPO_PATH"

build_rest_api
"${base_dir}/target/debug/rest-api" > "$E2E_GIT_REPO_PATH/server.log" &
SERVER_PID=$!
if [[ -n $debug ]]; then
    tail -f "$E2E_GIT_REPO_PATH/server.log" &
    background_pids+=($!)
fi

printf '%sWaiting for backend at %s with repo %s ...%s ' "$DIM" "$backend" "$ASFALOAD_GIT_REPO_PATH" "$RESET"
for i in $(seq 1 30); do
    if curl "$backend" --silent > /dev/null 2>&1; then
        printf '%s✓%s\n\n' "$GREEN" "$RESET"
        break
    fi
    if ! kill -0 "$SERVER_PID" 2>/dev/null; then
        printf '%s✗%s\n' "$RED" "$RESET"
        printf '%sBackend process died unexpectedly.%s\n' "$RED" "$RESET"
        exit 1
    fi
    sleep 0.5
done
if ! curl "$backend" --silent > /dev/null 2>&1; then
    printf '%s✗%s\n' "$RED" "$RESET"
    printf '%sBackend at %s did not become ready in 15s.%s\n' "$RED" "$backend" "$RESET"
    exit 1
fi

################################################################################
section "Register repo with SSH key"
################################################################################

SIGNERS_FILE_URL="${FILE_SERVER_URL}/${FS_PROJECT_NAME}/${HIDDEN_SIGNERS_DIR}/${SIGNERS_FILE_NAME}"

cd "$base_dir/client-cli/"

run_step_json "Register repo with SSH key 1 (submitter)" \
    '.success == true' \
    cargo run --quiet -- register-repo \
        --secret-key "$SSH_KEY_1" -u "$backend" --password "$key_password" \
        "$SIGNERS_FILE_URL"

# Backend: verify pending signers created (no signatures yet in two-phase flow)
assert_pending_signers_exist
assert_pending_metadata_exist
assert_pending_signers_signature_count 0
assert_pending_metadata_signature_count 0
assert_last_commit_contains "$PENDING_SIGNERS_DIR/$SIGNERS_FILE"

# Pending signers file records both SSH pubkeys (in asfaload-pub: form).
PENDING_SIGNERS_PATH="$(_project_dir)/$PENDING_SIGNERS_DIR/$SIGNERS_FILE"
run_step "Pending signers contains SSH pubkey 1" \
    bash -c "jq -e '[.artifact_signers[].signers[].data.pubkey] | any(. == \"$SSH_PK_1\")' '$PENDING_SIGNERS_PATH' > /dev/null"
run_step "Pending signers contains SSH pubkey 2" \
    bash -c "jq -e '[.artifact_signers[].signers[].data.pubkey] | any(. == \"$SSH_PK_2\")' '$PENDING_SIGNERS_PATH' > /dev/null"

################################################################################
section "Activate pending signers (both SSH keys sign)"
################################################################################

SIGNERS_SIGN_ARGS=$(pending_signers_sign_args "$SSH_KEY_1" "$backend" "$key_password")

run_step_json "Sign pending signers with SSH key 1 (1st of 2)" \
    '.is_complete == false' \
    cargo run --quiet -- sign-pending \
        --secret-key "$SSH_KEY_1" -u "$backend" --password "$key_password" \
        $SIGNERS_SIGN_ARGS

assert_pending_signers_signature_count 1
assert_pending_metadata_signature_count 1

PENDING_SIG_PATH="$(_project_dir)/$PENDING_SIGNERS_DIR/$SIGNERS_FILE.$PENDING_SIGNATURES_SUFFIX"
run_step "Pending signers signed by SSH key 1" \
    bash -c "jq -e '.entries | has(\"$SSH_PK_1\")' '$PENDING_SIG_PATH' > /dev/null"

run_step_json "Sign pending signers with SSH key 2 (threshold met, activates)" \
    '.is_complete == true' \
    cargo run --quiet -- sign-pending \
        --secret-key "$SSH_KEY_2" -u "$backend" --password "$key_password" \
        $SIGNERS_SIGN_ARGS

# Backend: signers are now active.
assert_signers_active

ACTIVE_SIGNERS_PATH="$(_project_dir)/$SIGNERS_DIR/$SIGNERS_FILE"
run_step "Active signers contains SSH pubkey 1" \
    bash -c "jq -e '[.artifact_signers[].signers[].data.pubkey] | any(. == \"$SSH_PK_1\")' '$ACTIVE_SIGNERS_PATH' > /dev/null"
run_step "Active signers contains SSH pubkey 2" \
    bash -c "jq -e '[.artifact_signers[].signers[].data.pubkey] | any(. == \"$SSH_PK_2\")' '$ACTIVE_SIGNERS_PATH' > /dev/null"

ACTIVE_SIG_PATH="$(_project_dir)/$SIGNERS_DIR/$SIGNERS_FILE.$SIGNATURES_SUFFIX"
run_step "Active signers signed by SSH key 1" \
    bash -c "jq -e '.entries | has(\"$SSH_PK_1\")' '$ACTIVE_SIG_PATH' > /dev/null"
run_step "Active signers signed by SSH key 2" \
    bash -c "jq -e '.entries | has(\"$SSH_PK_2\")' '$ACTIVE_SIG_PATH' > /dev/null"

################################################################################
section "Register release artifact"
################################################################################

RELEASE_VERSION="0.1"
RELEASE_DIR_ON_FS="$FS_PROJECT_DIR/releases/v$RELEASE_VERSION"
mkdir -p "$RELEASE_DIR_ON_FS"
ARTIFACT_NAME="artifact.bin"

# Deterministic content so the hash is stable across test runs.
printf 'asfaload ssh e2e artifact v%s' "$RELEASE_VERSION" > "$RELEASE_DIR_ON_FS/$ARTIFACT_NAME"
(cd "$RELEASE_DIR_ON_FS" && sha256sum "$ARTIFACT_NAME" > SHA256SUMS)

CSUM_URL="${FILE_SERVER_URL}/${FS_PROJECT_NAME}/releases/v${RELEASE_VERSION}/SHA256SUMS"
ARTIFACT_URL="${FILE_SERVER_URL}/${FS_PROJECT_NAME}/releases/v${RELEASE_VERSION}/${ARTIFACT_NAME}"
run_step_json "Register release via SHA256SUMS (SSH key 1 as submitter)" \
    '.success == true' \
    cargo run --quiet -- register-assets \
        --secret-key "$SSH_KEY_1" -u "$backend" --password "$key_password" \
        --csum-file "$CSUM_URL"

assert_release_index_exists "$RELEASE_VERSION"
assert_release_index_pending "$RELEASE_VERSION"
assert_last_commit_contains "$INDEX_FILE"

# Registration records the submitter's signature, so SSH key 1 has already
# signed the index: only SSH key 2 still has to sign, and its signature
# meets the threshold.
RELEASE_SIGN_ARGS=$(pending_sign_args "$INDEX_FILE" "$SSH_KEY_2" "$backend" "$key_password")

################################################################################
section "Sign release index with both SSH keys"
################################################################################

run_step_json "Sign release index with SSH key 2 (threshold met, activates)" \
    '.is_complete == true' \
    cargo run --quiet -- sign-pending \
        --secret-key "$SSH_KEY_2" -u "$backend" --password "$key_password" \
        $RELEASE_SIGN_ARGS

assert_release_index_active "$RELEASE_VERSION"

RELEASE_SIG_PATH="$(_release_dir "$RELEASE_VERSION")/$INDEX_FILE.$SIGNATURES_SUFFIX"
run_step "Release index signed by SSH key 1" \
    bash -c "jq -e '.entries | has(\"$SSH_PK_1\")' '$RELEASE_SIG_PATH' > /dev/null"
run_step "Release index signed by SSH key 2" \
    bash -c "jq -e '.entries | has(\"$SSH_PK_2\")' '$RELEASE_SIG_PATH' > /dev/null"

################################################################################
section "Verified download of signed artifact"
################################################################################

DOWNLOAD_PATH="$(mktemp)"
to_delete_on_filesystem+=("$DOWNLOAD_PATH")

run_step "Download artifact with verification" \
    cargo run --quiet -- download \
        -o "$DOWNLOAD_PATH" -u "$backend" --type fileserver \
        "$ARTIFACT_URL"

assert_artifact_hash_matches "$RELEASE_VERSION" "$ARTIFACT_NAME" "$DOWNLOAD_PATH"

run_step "Downloaded content matches source artifact" \
    cmp "$DOWNLOAD_PATH" "$RELEASE_DIR_ON_FS/$ARTIFACT_NAME"

################################################################################
print_summary
