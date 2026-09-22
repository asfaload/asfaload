#!/bin/bash
set -euo pipefail

# E2E test: basic_flow using a local file server instead of GitHub.
# Mirrors basic_flow.sh but uses --csum-file and --type fileserver.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
. "$SCRIPT_DIR/lib/helpers.sh"
# Override URL functions with local file server variants
. "$SCRIPT_DIR/lib/urls_local.sh"

# --- Cleanup trap ---

SERVER_PID=""
FILE_SERVER_PID=""
E2E_GIT_REPO_PATH="${E2E_GIT_REPO_PATH:-}"
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

# --- Setup ---

base_dir="$(git rev-parse --show-toplevel)"

# --- Generate fixture files for the local file server ---

FILE_SERVER_DIR=$(mktemp -d)
to_delete_on_filesystem+=("$FILE_SERVER_DIR")
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

# Append a trailing newline, as a text editor commonly would on save. The exact
# bytes of the signers file are what gets signed, so chain validation must read
# them back verbatim -- regression guard against content being trimmed on
# retrieval from git.
printf '\n' >> "$FS_PROJECT_DIR/$HIDDEN_SIGNERS_DIR/signers_file_2${_SIGNERS_SUFFIX}.json"

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
    background_pids+=($!)
fi

# --- Set backend assertion overrides ---
export PROJECT_DIR_OVERRIDE="http/localhost/${FILE_SERVER_PORT}/e2e_project"
export RELEASE_DIR_TEMPLATE="releases/v%s"

# --- Detect or start backend ---

if [[ -n "${backend:-}" ]] && curl "$backend" --silent > /dev/null 2>&1; then
    printf '%sUsing existing backend at %s%s\n\n' "$DIM" "$backend" "$RESET"
else
    # No running backend — start one automatically
    port="${ASFALOAD_SERVER_PORT:-$((3000 + RANDOM % 1000))}"
    export ASFALOAD_SERVER_PORT="$port"
    backend="http://localhost:$port"

    E2E_GIT_REPO_PATH=$(mktemp -d)
    to_delete_on_filesystem+=("$E2E_GIT_REPO_PATH")
    init_backend_repo "$E2E_GIT_REPO_PATH"
    export ASFALOAD_GIT_REPO_PATH="$E2E_GIT_REPO_PATH"

    build_rest_api
    "${base_dir}/target/debug/rest-api" > $E2E_GIT_REPO_PATH/server.log &
    SERVER_PID=$!
    if [[ -n $debug ]]; then
        tail -f  $E2E_GIT_REPO_PATH/server.log &
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

    # Final check if the loop exhausted without connecting
    if ! curl "$backend" --silent > /dev/null 2>&1; then
        printf '%s✗%s\n' "$RED" "$RESET"
        printf '%sBackend at %s did not become ready in 15s.%s\n' "$RED" "$backend" "$RESET"
        exit 1
    fi
fi

cd "$base_dir/client-cli/"

################################################################################
section "Authenticated ping with secret key from ASFALOAD_SECRET_KEY env var"
################################################################################

# Regression guard for the ASFALOAD_SECRET_KEY env binding on `ping`. The key is
# supplied through the environment (no -K flag); the real backend validates the
# request signature, so an authenticated status proves the env-provided key
# produced a request the server accepts -- not merely that auth headers were sent.
run_step_json "Ping authenticates using ASFALOAD_SECRET_KEY env var (no -K)" \
    '.auth.status == "success"' \
    env ASFALOAD_SECRET_KEY="$KEY_0" cargo run --quiet -- ping -u "$backend" --password $key_password

# Counterpart: the very same call without ASFALOAD_SECRET_KEY (and no -K) must
# stay unauthenticated. `env -u` clears the variable so the result does not
# depend on whatever the developer happens to have exported.
run_step_json "Ping is unauthenticated without ASFALOAD_SECRET_KEY (no -K)" \
    '.auth.status == "unauthenticated"' \
    env -u ASFALOAD_SECRET_KEY cargo run --quiet -- ping -u "$backend"

################################################################################
section "Initial Setup and Repo Registration"
################################################################################

echo "$(signers_file 1)"
run_step_json "Register repo with key0" \
    '.success == true' \
    cargo run --quiet -- register-repo --secret-key "$KEY_0" -u $backend --password $key_password $(signers_file 1)

# --- Backend: verify pending signers created (no signatures yet in two-phase flow) ---
assert_pending_signers_exist
assert_pending_metadata_exist
assert_pending_signers_signature_count 0
assert_pending_metadata_signature_count 0
assert_pending_signers_contain_keys "$KEY_0" "$KEY_1" "$KEY_2"
assert_last_commit_contains "$PENDING_SIGNERS_DIR/$SIGNERS_FILE"

################################################################################
section "Signers File Activation"
################################################################################

run_step_json "List pending for key0 (should show pending signers)" \
    '.pending_files | length > 0' \
    cargo run --quiet -- list-pending --secret-key "$KEY_0" -u "$backend" --password $key_password

SIGNERS_SIGN_ARGS=$(pending_signers_sign_args "$KEY_0" "$backend" $key_password)

# Only run this if we started the backend ourselves, giving us direct access
# to its git repo working tree.
if [[ -n ${E2E_GIT_REPO_PATH} ]]; then
    ################################################################################
    section "Pending Signers Validation Against Forge Source"
    ################################################################################

    # Simulate a compromised backend: the pending signers file is replaced with
    # different (still valid) signers content. list-pending computes the digest
    # from the tampered file on disk, so the client's digest pre-check passes;
    # only the validation of the file against the forge source recorded in its
    # metadata catches the tampering.
    PENDING_SIGNERS_FILE="$(_project_dir)/$PENDING_SIGNERS_DIR/$SIGNERS_FILE"
    PENDING_SIGNERS_BACKUP=$(mktemp)
    to_delete_on_filesystem+=("$PENDING_SIGNERS_BACKUP")
    cp "$PENDING_SIGNERS_FILE" "$PENDING_SIGNERS_BACKUP"
    cp "$FS_PROJECT_DIR/$HIDDEN_SIGNERS_DIR/signers_file_2${_SIGNERS_SUFFIX}.json" "$PENDING_SIGNERS_FILE"

    TAMPERED_SIGNERS_SIGN_ARGS=$(pending_signers_sign_args "$KEY_0" "$backend" $key_password)
    expect_fail_json "Sign pending signers differing from forge source" \
        '.error | contains("Hash mismatch")' \
        cargo run --quiet -- sign-pending --secret-key "$KEY_0" -u "$backend" --password $key_password $TAMPERED_SIGNERS_SIGN_ARGS

    # Restore the original content so the rest of the flow proceeds unchanged.
    cp "$PENDING_SIGNERS_BACKUP" "$PENDING_SIGNERS_FILE"
fi

run_step_json "Sign signers file with key0 (submitter signs in second phase)" \
    '.is_complete == false' \
    cargo run --quiet -- sign-pending --secret-key "$KEY_0" -u "$backend" --password $key_password $SIGNERS_SIGN_ARGS

# --- Backend: verify 1st signature on pending signers and metadata ---
assert_pending_signers_signature_count 1
assert_pending_signers_signatures_contain_keys "$KEY_0"
assert_pending_metadata_signature_count 1
assert_pending_metadata_signatures_contain_keys "$KEY_0"

run_step_json "List pending for key1" \
    '.pending_files | length > 0' \
    cargo run --quiet -- list-pending --secret-key "$KEY_1" -u "$backend" --password $key_password
run_step_json "Sign signers file with key1" \
    '.is_complete == false' \
    cargo run --quiet -- sign-pending --secret-key "$KEY_1" -u "$backend" --password $key_password $SIGNERS_SIGN_ARGS

# --- Backend: verify 2nd signature on pending signers and metadata ---
assert_pending_signers_signature_count 2
assert_pending_signers_signatures_contain_keys "$KEY_0" "$KEY_1"
assert_pending_metadata_signature_count 2
assert_pending_metadata_signatures_contain_keys "$KEY_0" "$KEY_1"

run_step_json "Sign signers file with key2 (completes signature)" \
    '.is_complete == true' \
    cargo run --quiet -- sign-pending --secret-key "$KEY_2" -u "$backend" --password $key_password $SIGNERS_SIGN_ARGS

# --- Backend: verify signers activated ---
assert_signers_active
assert_signers_contain_keys "$KEY_0" "$KEY_1" "$KEY_2"

expect_fail "Sign signers file with key0 (already completed)" \
    cargo run --quiet -- sign-pending --secret-key "$KEY_0" -u "$backend" --password $key_password $SIGNERS_SIGN_ARGS

# Test interactive sign-pending when no pending signature is available:
# no file_path arg triggers the interactive path, which fetches pending
# signatures from the backend; key2 has none → NoPendingSignature error.
expect_fail_json "Interactive sign-pending with no pending signatures" \
    '.error == "No pending signature found"' \
    cargo run --quiet -- sign-pending --secret-key "$KEY_2" -u "$backend" --password "$key_password"

################################################################################
section "Release Registration and Signing"
################################################################################

run_step_json "Register release with key2 (does not sign it)" \
    '.success == true' \
    cargo run --quiet -- register-assets --secret-key "$KEY_2" -u "$backend" --password $key_password --csum-file $(csum_file_url 0.1)

# --- Backend: verify release index created ---
assert_release_index_exists "0.1"
assert_release_index_pending "0.1"
assert_last_commit_contains "$INDEX_FILE"

# A never-registered release has no index file at all.
tmp=$(mktemp); to_delete_on_filesystem+=("$tmp")
expect_fail "Download never-registered artifact (v9.9)" \
    cargo run --quiet -- download -o "$tmp" -u "$backend" --type fileserver $(artifact_url 9.9)

# v0.1 is registered but has zero signatures yet (still pending).
tmp=$(mktemp); to_delete_on_filesystem+=("$tmp")
expect_fail "Download unsigned artifact (v0.1, 0 signatures)" \
    cargo run --quiet -- download -o "$tmp" -u "$backend" --type fileserver $(artifact_url 0.1)

run_step_json "List pending for key2" \
    '.pending_files | length > 0' \
    cargo run --quiet -- list-pending --secret-key "$KEY_2" -u "$backend" --password $key_password

RELEASE_0_1_SIGN_ARGS=$(release_index_sign_args 0.1 "$KEY_0" "$backend" $key_password)

run_step_json "Sign release index with key0" \
    '.is_complete == false' \
    cargo run --quiet -- sign-pending --secret-key "$KEY_0" -u "$backend" --password $key_password $RELEASE_0_1_SIGN_ARGS

assert_release_index_signature_count "0.1" 1

# v0.1 now has 1 of 2 required signatures: still below threshold, not active.
tmp=$(mktemp); to_delete_on_filesystem+=("$tmp")
expect_fail "Download partially-signed artifact (v0.1, 1 of 2 signatures)" \
    cargo run --quiet -- download -o "$tmp" -u "$backend" --type fileserver $(artifact_url 0.1)

run_step_json "Check signature status for v0.1 index (pending)" \
    '.is_complete == false' \
    cargo run --quiet -- signature-status --secret-key "$KEY_0" -u "$backend" --password $key_password $(release_index 0.1)

expect_fail "Register release with key2 (fails as already registered)" \
    cargo run --quiet -- register-assets --secret-key "$KEY_2" -u "$backend" --password $key_password --csum-file $(csum_file_url 0.1)

# Ensure a second release registration does not override the signatures already collected
assert_release_index_signature_count "0.1" 1

run_step_json "Sign release index with key1 (completes, threshold=2)" \
    '.is_complete == true' \
    cargo run --quiet -- sign-pending --secret-key "$KEY_1" -u "$backend" --password $key_password $RELEASE_0_1_SIGN_ARGS

# --- Backend: verify release index activated ---
assert_release_index_active "0.1"
assert_release_index_signers "0.1" "$KEY_0" "$KEY_1" "$KEY_2"

run_step_json "Check signature status for v0.1 index (complete)" \
    '.is_complete == true' \
    cargo run --quiet -- signature-status --secret-key "$KEY_0" -u "$backend" --password $key_password $(release_index 0.1)

expect_fail "Sign release index with key2 (already completed)" \
    cargo run --quiet -- sign-pending --secret-key "$KEY_2" -u "$backend" --password $key_password $RELEASE_0_1_SIGN_ARGS

DOWNLOAD_V01="$(mktemp)"
to_delete_on_filesystem+=("$DOWNLOAD_V01")
run_step "Download release artifact (v0.1)" \
    cargo run --quiet -- download -o "$DOWNLOAD_V01" -u "$backend" --type fileserver $(artifact_url 0.1)

# --- Backend: verify artifact hash ---
assert_artifact_hash_matches "0.1" "artifact.bin" "$DOWNLOAD_V01"

################################################################################
section "Updating Signers File"
################################################################################

run_step_json "Update signers file with key0" \
    '.success == true' \
    cargo run --quiet -- update-signers --secret-key "$KEY_0" -u "$backend" -p $key_password $(signers_file 2)

# --- Backend: verify pending signers updated (no signatures yet) ---
assert_pending_signers_exist
assert_pending_metadata_exist
assert_pending_signers_signature_count 0
assert_pending_metadata_signature_count 0
assert_pending_signers_contain_keys "$KEY_0" "$KEY_1" "$KEY_2" "$KEY_3"

run_step_json "List pending for key0 (should show pending signers)" \
    '.pending_files | length > 0' \
    cargo run --quiet -- list-pending --secret-key "$KEY_0" -u "$backend" --password $key_password

SIGNERS_SIGN_ARGS=$(pending_signers_sign_args "$KEY_0" "$backend" $key_password)

run_step_json "Sign pending signers with key0" \
    '.is_complete == false' \
    cargo run --quiet -- sign-pending --secret-key "$KEY_0" -u "$backend" --password $key_password $SIGNERS_SIGN_ARGS

assert_pending_signers_signature_count 1
assert_pending_signers_signatures_contain_keys "$KEY_0"
assert_pending_metadata_signature_count 1
assert_pending_metadata_signatures_contain_keys "$KEY_0"

expect_fail "Attempts to re-sign pending signers with key0 (should fail)" \
    cargo run --quiet -- sign-pending --secret-key "$KEY_0" -u "$backend" --password $key_password $SIGNERS_SIGN_ARGS

run_step_json "List pending for key1 (should show pending)" \
    '.pending_files | length > 0' \
    cargo run --quiet -- list-pending --secret-key "$KEY_1" -u "$backend" --password $key_password

run_step_json "Sign pending signers with key1" \
    '.is_complete == false' \
    cargo run --quiet -- sign-pending --secret-key "$KEY_1" -u "$backend" --password $key_password $SIGNERS_SIGN_ARGS

assert_pending_signers_signature_count 2
assert_pending_signers_signatures_contain_keys "$KEY_0" "$KEY_1"
assert_pending_metadata_signature_count 2
assert_pending_metadata_signatures_contain_keys "$KEY_0" "$KEY_1"

run_step_json "Sign pending signers with key3 (newly added artifact signer)" \
    '.is_complete == false' \
    cargo run --quiet -- sign-pending --secret-key "$KEY_3" -u "$backend" --password $key_password $SIGNERS_SIGN_ARGS

assert_pending_signers_signature_count 3
assert_pending_signers_signatures_contain_keys "$KEY_0" "$KEY_1" "$KEY_3"
assert_pending_metadata_signature_count 3
assert_pending_metadata_signatures_contain_keys "$KEY_0" "$KEY_1" "$KEY_3"

run_step_json "Sign pending signers with key4 (newly added revocation key)" \
    '.is_complete == false' \
    cargo run --quiet -- sign-pending --secret-key "$KEY_4" -u "$backend" --password $key_password $SIGNERS_SIGN_ARGS

run_step_json "Sign pending signers with key5 (newly added revocation key)" \
    '.is_complete == false' \
    cargo run --quiet -- sign-pending --secret-key "$KEY_5" -u "$backend" --password $key_password $SIGNERS_SIGN_ARGS

run_step_json "Sign pending signers with key6 (activates new signers file)" \
    '.is_complete == true' \
    cargo run --quiet -- sign-pending --secret-key "$KEY_6" -u "$backend" --password $key_password $SIGNERS_SIGN_ARGS

# --- Backend: verify new signers activated ---
assert_signers_active
assert_signers_contain_keys "$KEY_0" "$KEY_1" "$KEY_2" "$KEY_3"

DOWNLOAD_V01_HISTORICAL="$(mktemp)"
to_delete_on_filesystem+=("$DOWNLOAD_V01_HISTORICAL")
run_step "Download artifact (v0.1, signed with historical signers)" \
    cargo run --quiet -- download -o "$DOWNLOAD_V01_HISTORICAL" -u "$backend" --type fileserver $(artifact_url 0.1)

assert_artifact_hash_matches "0.1" "artifact.bin" "$DOWNLOAD_V01_HISTORICAL"

################################################################################
section "Registering Release with New Signers File"
################################################################################

run_step_json "Register second release with key2" \
    '.success == true' \
    cargo run --quiet -- register-assets --secret-key "$KEY_2" -u "$backend" --password $key_password --csum-file $(csum_file_url 0.2)

# --- Backend: verify second release index created ---
assert_release_index_exists "0.2"
assert_release_index_pending "0.2"

run_step_json "List pending for key2" \
    '.pending_files | length > 0' \
    cargo run --quiet -- list-pending --secret-key "$KEY_2" -u "$backend" --password $key_password

RELEASE_0_2_SIGN_ARGS=$(release_index_sign_args 0.2 "$KEY_0" "$backend" $key_password)

run_step_json "Sign release index with key0" \
    '.is_complete == false' \
    cargo run --quiet -- sign-pending --secret-key "$KEY_0" -u "$backend" --password $key_password $RELEASE_0_2_SIGN_ARGS

assert_release_index_signature_count "0.2" 1

run_step_json "Sign release index with key1" \
    '.is_complete == false' \
    cargo run --quiet -- sign-pending --secret-key "$KEY_1" -u "$backend" --password $key_password $RELEASE_0_2_SIGN_ARGS

assert_release_index_signature_count "0.2" 2

run_step_json "Sign release index with key3 (key2 does not sign)" \
    '.is_complete == true' \
    cargo run --quiet -- sign-pending --secret-key "$KEY_3" -u "$backend" --password $key_password $RELEASE_0_2_SIGN_ARGS

# --- Backend: verify v0.2 release index activated ---
assert_release_index_active "0.2"
assert_release_index_signers "0.2" "$KEY_0" "$KEY_1" "$KEY_2" "$KEY_3"

DOWNLOAD_V02="$(mktemp)"
to_delete_on_filesystem+=("$DOWNLOAD_V02")
run_step "Download artifact (v0.2)" \
    cargo run --quiet -- download -o "$DOWNLOAD_V02" -u "$backend" --type fileserver $(artifact_url 0.2)

assert_artifact_hash_matches "0.2" "artifact.bin" "$DOWNLOAD_V02"

# --- Revoke release 0.1 ---

expect_fail "revoke index file for v0.1, not authorized" \
    cargo run -- revoke --secret-key "$KEY_3" -p $key_password -u "$backend" $(release_index 0.1)

run_step "initiate revoke index file for v0.1" \
    cargo run -- revoke --secret-key "$KEY_4" -p $key_password -u "$backend" $(release_index 0.1)

expect_fail "revoke index file for v0.1 again (already pending)" \
    cargo run -- revoke --secret-key "$KEY_5" -p $key_password -u "$backend" $(release_index 0.1)

DOWNLOAD_V01_bis="$(mktemp)"
to_delete_on_filesystem+=("$DOWNLOAD_V01_bis")
run_step "Download artifact (v0.1), not yet revoked as need 2 signatures" \
    cargo run --quiet -- download -o "$DOWNLOAD_V01_bis" -u "$backend" --type fileserver $(artifact_url 0.1)
assert_artifact_hash_matches "0.1" "artifact.bin" "$DOWNLOAD_V01_bis"

run_step_json "List pending for key0 (none expected, key0 cannot revoke)" \
    '.pending_files | length == 0' \
    cargo run --quiet -- list-pending --secret-key "$KEY_0" -u "$backend" --password $key_password

run_step_json "List pending for key5 (one expected, key5 can revoke)" \
    '.pending_files | length == 1' \
    cargo run --quiet -- list-pending --secret-key "$KEY_5" -u "$backend" --password $key_password

REVOCATION_SIGN_ARGS=$(pending_sign_args "$REVOCATION_SUFFIX" "$KEY_5" "$backend" $key_password)
run_step "sign pending revocation for v0.1 (second signer via sign-pending)" \
    cargo run -- sign-pending --secret-key "$KEY_5" -p $key_password -u "$backend" $REVOCATION_SIGN_ARGS

# --- Backend: verify v0.1 revoked ---
assert_release_index_revoked "0.1"
assert_revocation_signers "0.1" "$KEY_4" "$KEY_5" "$KEY_6"
assert_last_commit_contains "$REVOCATION_SUFFIX"

tmp=$(mktemp); to_delete_on_filesystem+=("$tmp")
expect_fail "Download artifact (v0.1, revoked)" \
    cargo run --quiet -- download -o "$tmp" -u "$backend" --type fileserver $(artifact_url 0.1)

# --- v0.2 is unaffected --
DOWNLOAD_V02_bis="$(mktemp)"
to_delete_on_filesystem+=("$DOWNLOAD_V02_bis")
run_step "Download artifact (v0.2), not revoked" \
    cargo run --quiet -- download -o "$DOWNLOAD_V02_bis" -u "$backend" --type fileserver $(artifact_url 0.2)
assert_artifact_hash_matches "0.2" "artifact.bin" "$DOWNLOAD_V02_bis"

################################################################################
section "Download with Full Signers Chain Verification"
################################################################################

# v0.2 was signed after the signers update, so the chain has 2 entries:
# entry 1 = original signers_file_1 (registered with register-repo)
# entry 2 = updated signers_file_2 (registered with update-signers)
# Both are still served by the file server, so forge content comparison will pass.

DOWNLOAD_V02_FULL_CHECK="$(mktemp)"
to_delete_on_filesystem+=("$DOWNLOAD_V02_FULL_CHECK")
run_step "Download artifact (v0.2) with (2-entry chain)" \
    cargo run --quiet -- download -o "$DOWNLOAD_V02_FULL_CHECK" -u "$backend" --type fileserver $(artifact_url 0.2)
assert_artifact_hash_matches "0.2" "artifact.bin" "$DOWNLOAD_V02_FULL_CHECK"

################################################################################
section "Full Check Failure: Tampered/Missing Initial Signers File"
################################################################################

# The first entry in the signers chain is the trust anchor. It cannot be
# validated cryptographically (no previous entry to sign it). The only way
# to validate it is to confirm the forge still serves the original content.

INITIAL_SIGNERS_FILE="$FS_PROJECT_DIR/$HIDDEN_SIGNERS_DIR/signers_file_1${_SIGNERS_SUFFIX}.json"

# --- Tamper: overwrite initial signers file with signers_file_2 content ---
# The file is still valid JSON, but the content no longer matches what was
# registered in the backend history.
cp "$FS_PROJECT_DIR/$HIDDEN_SIGNERS_DIR/signers_file_2${_SIGNERS_SUFFIX}.json" "$INITIAL_SIGNERS_FILE"

tmp=$(mktemp); to_delete_on_filesystem+=("$tmp")
expect_fail "Download with (tampered initial signers file)" \
    cargo run --quiet -- download -o "$tmp" -u "$backend" --type fileserver $(artifact_url 0.2)

# --- Delete: remove initial signers file entirely ---
rm "$INITIAL_SIGNERS_FILE"

tmp=$(mktemp); to_delete_on_filesystem+=("$tmp")
expect_fail "Download with (missing initial signers file, 404)" \
    cargo run --quiet -- download -o "$tmp" -u "$backend" --type fileserver $(artifact_url 0.2)

################################################################################
print_summary
