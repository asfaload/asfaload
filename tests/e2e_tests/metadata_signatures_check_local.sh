#!/bin/bash
set -euo pipefail

# E2E test: verify that rejects artifacts when the trust anchor's
# metadata signatures have been tampered with.
#
# Uses a local file server (same pattern as basic_flow_local.sh).
# The chain for v0.2 has 2 entries after a signers update:
#   entry[0] = original signers_file_1 (trust anchor, in history)
#   entry[1] = updated signers_file_2 (active)
#
# We tamper entry[0]'s metadata_signatures via git replace and verify
# that download fails.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
. "$SCRIPT_DIR/lib/helpers.sh"
# Override URL functions with local file server variants
. "$SCRIPT_DIR/lib/urls_local.sh"

# --- Cleanup trap ---

SERVER_PID=""
FILE_SERVER_PID=""
FILE_SERVER_DIR=""
E2E_GIT_REPO_PATH=""

cleanup() {
    if [[ -n "$SERVER_PID" ]] && kill -0 "$SERVER_PID" 2>/dev/null; then
        kill "$SERVER_PID" 2>/dev/null
        wait "$SERVER_PID" 2>/dev/null || true
    fi
    if [[ -n "$FILE_SERVER_PID" ]] && kill -0 "$FILE_SERVER_PID" 2>/dev/null; then
        kill "$FILE_SERVER_PID" 2>/dev/null
        wait "$FILE_SERVER_PID" 2>/dev/null || true
    fi
    if [[ -n "$E2E_GIT_REPO_PATH" ]] && [[ -d "$E2E_GIT_REPO_PATH" ]]; then
        rm -rf "$E2E_GIT_REPO_PATH"
    fi
    if [[ -n "$FILE_SERVER_DIR" ]] && [[ -d "$FILE_SERVER_DIR" ]]; then
        rm -rf "$FILE_SERVER_DIR"
    fi
    rm -f "${DOWNLOAD_V02:-}" "${DOWNLOAD_V02_FULL_CHECK:-}"
}
trap cleanup EXIT

# --- Setup ---

base_dir="$(git rev-parse --show-toplevel)"

# --- Generate fixture files for the local file server ---

FILE_SERVER_DIR=$(mktemp -d)
FS_PROJECT_DIR="$FILE_SERVER_DIR/e2e_project"
mkdir -p "$FS_PROJECT_DIR/$HIDDEN_SIGNERS_DIR"
mkdir -p "$FS_PROJECT_DIR/releases/v0.1"
mkdir -p "$FS_PROJECT_DIR/releases/v0.2"

printf '%sGenerating fixture files...%s ' "$DIM" "$RESET"

# Generate signers file 1 (3 artifact signers, threshold 2)
cargo run --quiet --manifest-path "$base_dir/client-cli/Cargo.toml" -- new-signers-file \
    --artifact-signers-file "$KEY_0.pub" \
    --artifact-signers-file "$KEY_1.pub" \
    --artifact-signers-file "$KEY_2.pub" \
    -A 2 \
    -o "$FS_PROJECT_DIR/$HIDDEN_SIGNERS_DIR/signers_file_1${_SIGNERS_SUFFIX}.json"

# Generate signers file 2 (4 artifact signers threshold 3, 3 revocation keys threshold 2)
cargo run --quiet --manifest-path "$base_dir/client-cli/Cargo.toml" -- new-signers-file \
    --artifact-signers-file "$KEY_0.pub" \
    --artifact-signers-file "$KEY_1.pub" \
    --artifact-signers-file "$KEY_2.pub" \
    --artifact-signers-file "$KEY_3.pub" \
    -A 3 \
    --revocation-keys-file "$KEY_4.pub" \
    --revocation-keys-file "$KEY_5.pub" \
    --revocation-keys-file "$KEY_6.pub" \
    -R 2 \
    -o "$FS_PROJECT_DIR/$HIDDEN_SIGNERS_DIR/signers_file_2${_SIGNERS_SUFFIX}.json"

# Generate artifact binaries
dd if=/dev/urandom of="$FS_PROJECT_DIR/releases/v0.1/artifact.bin" bs=1024 count=4 2>/dev/null
dd if=/dev/urandom of="$FS_PROJECT_DIR/releases/v0.2/artifact.bin" bs=1024 count=4 2>/dev/null

# Generate SHA256SUMS files
(cd "$FS_PROJECT_DIR/releases/v0.1" && sha256sum artifact.bin > SHA256SUMS)
(cd "$FS_PROJECT_DIR/releases/v0.2" && sha256sum artifact.bin > SHA256SUMS)

printf '%s✓%s\n' "$GREEN" "$RESET"

# --- Build and start file server ---

printf '%sBuilding test-file-server...%s ' "$DIM" "$RESET"
cargo build -p test-file-server --quiet
printf '%s✓%s\n' "$GREEN" "$RESET"

FILE_SERVER_LOG="$FILE_SERVER_DIR/file_server.log"
"${base_dir}/target/debug/test-file-server" --dir "$FILE_SERVER_DIR" > "$FILE_SERVER_LOG" 2>&1 &
FILE_SERVER_PID=$!

# Wait for file server to emit its port
printf '%sWaiting for file server...%s ' "$DIM" "$RESET"
FILE_SERVER_PORT=""
for i in $(seq 1 30); do
    if [[ -f "$FILE_SERVER_LOG" ]]; then
        FILE_SERVER_PORT=$(grep -oP 'LISTENING_PORT=\K[0-9]+' "$FILE_SERVER_LOG" 2>/dev/null || true)
        if [[ -n "$FILE_SERVER_PORT" ]]; then
            break
        fi
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
fi

# --- Set backend assertion overrides ---
export PROJECT_DIR_OVERRIDE="http/localhost/${FILE_SERVER_PORT}/e2e_project"
export RELEASE_DIR_TEMPLATE="releases/v%s"

# --- Detect or start backend ---

if [[ -n "${backend:-}" ]] && curl "$backend" --silent > /dev/null 2>&1; then
    printf '%sUsing existing backend at %s%s\n\n' "$DIM" "$backend" "$RESET"
else
    port="${ASFALOAD_SERVER_PORT:-$((3000 + RANDOM % 1000))}"
    export ASFALOAD_SERVER_PORT="$port"
    backend="http://localhost:$port"

    E2E_GIT_REPO_PATH=$(mktemp -d)
    init_backend_repo "$E2E_GIT_REPO_PATH"
    export ASFALOAD_GIT_REPO_PATH="$E2E_GIT_REPO_PATH"

    build_rest_api
    "${base_dir}/target/debug/rest-api" > $E2E_GIT_REPO_PATH/server.log &
    SERVER_PID=$!
    if [[ -n $debug ]]; then
        tail -f  $E2E_GIT_REPO_PATH/server.log &
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
fi

cd "$base_dir/client-cli/"

################################################################################
section "Initial Setup and Repo Registration"
################################################################################

run_step_json "Register repo with key0" \
    '.success == true' \
    cargo run --quiet -- register-repo --secret-key "$KEY_0" -u $backend --password $key_password $(signers_file 1)

assert_pending_signers_exist
assert_pending_metadata_exist

################################################################################
section "Signers File Activation"
################################################################################

SIGNERS_SIGN_ARGS=$(pending_signers_sign_args "$KEY_1" "$backend" $key_password)

# Key0 already signed the pending signers file and metadata at registration.

run_step_json "Sign signers file with key1" \
    '.is_complete == false' \
    cargo run --quiet -- sign-pending --secret-key "$KEY_1" -u "$backend" --password $key_password $SIGNERS_SIGN_ARGS

run_step_json "Sign signers file with key2 (completes)" \
    '.is_complete == true' \
    cargo run --quiet -- sign-pending --secret-key "$KEY_2" -u "$backend" --password $key_password $SIGNERS_SIGN_ARGS

assert_signers_active

################################################################################
section "Register and Sign Release v0.1"
################################################################################

run_step_json "Register release v0.1" \
    '.success == true' \
    cargo run --quiet -- register-assets --secret-key "$KEY_2" -u "$backend" --password $key_password --csum-file $(csum_file_url 0.1)

RELEASE_0_1_SIGN_ARGS=$(release_index_sign_args 0.1 "$KEY_0" "$backend" $key_password)
# key2 recorded its signature at registration, so key0's signature meets
# the threshold.
run_step_json "Sign release v0.1 with key0 (completes, threshold=2)" \
    '.is_complete == true' \
    cargo run --quiet -- sign-pending --secret-key "$KEY_0" -u "$backend" --password $key_password $RELEASE_0_1_SIGN_ARGS

assert_release_index_active "0.1"

################################################################################
section "Update Signers File (creates history entry)"
################################################################################

run_step_json "Update signers file with key0" \
    '.success == true' \
    cargo run -- update-signers --secret-key "$KEY_0" -u "$backend" -p $key_password $(signers_file 2)

assert_pending_signers_exist
assert_pending_metadata_exist

SIGNERS_SIGN_ARGS=$(pending_signers_sign_args "$KEY_1" "$backend" $key_password)

# Key0 already signed the pending signers file and metadata with the update.

run_step_json "Sign pending signers with key1" \
    '.is_complete == false' \
    cargo run --quiet -- sign-pending --secret-key "$KEY_1" -u "$backend" --password $key_password $SIGNERS_SIGN_ARGS

run_step_json "Sign pending signers with key3 (newly added artifact signer)" \
    '.is_complete == false' \
    cargo run --quiet -- sign-pending --secret-key "$KEY_3" -u "$backend" --password $key_password $SIGNERS_SIGN_ARGS

run_step_json "Sign pending signers with key4 (newly added revocation key)" \
    '.is_complete == false' \
    cargo run --quiet -- sign-pending --secret-key "$KEY_4" -u "$backend" --password $key_password $SIGNERS_SIGN_ARGS

run_step_json "Sign pending signers with key5 (newly added revocation key)" \
    '.is_complete == false' \
    cargo run --quiet -- sign-pending --secret-key "$KEY_5" -u "$backend" --password $key_password $SIGNERS_SIGN_ARGS

run_step_json "Sign pending signers with key6 (activates new signers file)" \
    '.is_complete == true' \
    cargo run --quiet -- sign-pending --secret-key "$KEY_6" -u "$backend" --password $key_password $SIGNERS_SIGN_ARGS

assert_signers_active

################################################################################
section "Register and Sign Release v0.2 (under updated signers)"
################################################################################

run_step_json "Register release v0.2" \
    '.success == true' \
    cargo run --quiet -- register-assets --secret-key "$KEY_2" -u "$backend" --password $key_password --csum-file $(csum_file_url 0.2)

RELEASE_0_2_SIGN_ARGS=$(release_index_sign_args 0.2 "$KEY_0" "$backend" $key_password)
# key2 recorded its signature at registration, so key1's signature meets
# the threshold of 3.
run_step_json "Sign release v0.2 with key0 (2 of 3 signatures)" \
    '.is_complete == false' \
    cargo run --quiet -- sign-pending --secret-key "$KEY_0" -u "$backend" --password $key_password $RELEASE_0_2_SIGN_ARGS

run_step_json "Sign release v0.2 with key1 (completes, threshold=3)" \
    '.is_complete == true' \
    cargo run --quiet -- sign-pending --secret-key "$KEY_1" -u "$backend" --password $key_password $RELEASE_0_2_SIGN_ARGS

assert_release_index_active "0.2"

################################################################################
section "Full Check Baseline (should succeed)"
################################################################################

DOWNLOAD_V02_FULL_CHECK="$(mktemp)"
run_step "Download v0.2 with (baseline)" \
    cargo run --quiet -- download -o "$DOWNLOAD_V02_FULL_CHECK" -u "$backend" --type fileserver $(artifact_url 0.2)
assert_artifact_hash_matches "0.2" "artifact.bin" "$DOWNLOAD_V02_FULL_CHECK"

################################################################################
section "Full Check Failure: Tampered Metadata Signatures"
################################################################################

# The chain for v0.2 has 2 entries:
#   entry[0] = original signers_file_1 (trust anchor, metadata in history)
#   entry[1] = updated signers_file_2 (active, metadata in metadata.json)
#
# validate_first_entry checks entry[0]'s metadata signatures. We remove one
# signature from entry[0].metadata_signatures to break the check_all_signers
# validation.
#
# The history is read via file_content_at_commit (pinned to a specific commit),
# so we use git replace to transparently swap the blob.

HISTORY_REL_PATH="$(_project_dir)/$SIGNERS_HISTORY_FILE"
HISTORY_REL_PATH="${HISTORY_REL_PATH#"$E2E_GIT_REPO_PATH/"}"
HISTORY_BLOB=$(git -C "$E2E_GIT_REPO_PATH" rev-parse "HEAD:$HISTORY_REL_PATH")

# Remove one signature from entry[0].metadata_signatures.entries
TAMPERED_BLOB=$(git -C "$E2E_GIT_REPO_PATH" show "$HISTORY_BLOB" | \
    jq '.entries[0].metadata_signatures.entries |= (keys[0] as $k | del(.[$k]))' | \
    git -C "$E2E_GIT_REPO_PATH" hash-object -w --stdin)
git -C "$E2E_GIT_REPO_PATH" replace "$HISTORY_BLOB" "$TAMPERED_BLOB"

expect_fail "Download with (tampered metadata signatures)" \
    cargo run --quiet -- download -o "$(mktemp)" -u "$backend" --type fileserver $(artifact_url 0.2)

git -C "$E2E_GIT_REPO_PATH" replace -d "$HISTORY_BLOB"

################################################################################
print_summary
