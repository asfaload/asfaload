#!/bin/bash
set -euo pipefail


# run with env var debug=1 to print commands and outputs.
# If you start the backend separately, send the backend env var the the backedn url,
# eg http://localhost:3000
# If you run the script with a remote backend, set the env var NO_ASSERT to a non-empty string, eg "1"
#
# Signers file generation (asfaload):
# -----------------------------------
# cargo run -- new-signers-file --artifact-signers-file $PWD/../core/test_helpers/fixtures/keys/key_0.pub --artifact-signers-file $PWD/../core/test_helpers/fixtures/keys/key_1.pub --artifact-signers-file $PWD/../core/test_helpers/fixtures/keys/key_2.pub -A 2 -o ../../repo_for_e2e_tests/basic_flow/signers_file_1_asfaload.json
# cargo run --quiet -- new-signers-file  --artifact-signers-file ../core/test_helpers/fixtures/keys/key_0.pub  --artifact-signers-file ../core/test_helpers/fixtures/keys/key_1.pub  --artifact-signers-file ../core/test_helpers/fixtures/keys/key_2.pub  --artifact-signers-file ../core/test_helpers/fixtures/keys/key_3.pub  -A 3  --revocation-keys-file ../core/test_helpers/fixtures/keys/key_4.pub  --revocation-keys-file ../core/test_helpers/fixtures/keys/key_5.pub  --revocation-keys-file ../core/test_helpers/fixtures/keys/key_6.pub  -R 2  -o ../../repo_for_e2e_tests/basic_flow/signers_file_2_asfaload.json
# Signers file generation (ed25519):
# ----------------------------------
# cargo run -- new-signers-file --artifact-signers-file $PWD/../core/test_helpers/fixtures/keys/ed25519_key_0.pub --artifact-signers-file $PWD/../core/test_helpers/fixtures/keys/ed25519_key_1.pub --artifact-signers-file $PWD/../core/test_helpers/fixtures/keys/ed25519_key_2.pub -A 2 -o ../../repo_for_e2e_tests/basic_flowsigners_file_1_ed25519.json
# cargo run --quiet -- new-signers-file  --artifact-signers-file ../core/test_helpers/fixtures/keys/ed25519_key_0.pub  --artifact-signers-file ../core/test_helpers/fixtures/keys/ed25519_key_1.pub  --artifact-signers-file ../core/test_helpers/fixtures/keys/ed25519_key_2.pub  --artifact-signers-file ../core/test_helpers/fixtures/keys/ed25519_key_3.pub  -A 3  --revocation-keys-file ../core/test_helpers/fixtures/keys/ed25519_key_4.pub  --revocation-keys-file ../core/test_helpers/fixtures/keys/ed25519_key_5.pub  --revocation-keys-file ../core/test_helpers/fixtures/keys/ed25519_key_6.pub  -R 2  -o ../../repo_for_e2e_tests/basic_flow/signers_file_2_ed25519.json
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
. "$SCRIPT_DIR/lib/helpers.sh"

# --- Cleanup trap ---

SERVER_PID=""
# It can be set by the caller, eg if they started the local backend manually.
E2E_GIT_REPO_PATH="${E2E_GIT_REPO_PATH:-""}"
background_pids=()
to_delete_on_filesystem=()

cleanup() {
    if [[ -n "$SERVER_PID" ]] && kill -0 "$SERVER_PID" 2>/dev/null; then
        kill "$SERVER_PID" 2>/dev/null
        wait "$SERVER_PID" 2>/dev/null || true
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

# --- Detect or start backend ---

base_dir="$(git rev-parse --show-toplevel)"

if [[ -n "${backend:-}" ]] && curl "$backend" --silent > /dev/null 2>&1; then
    printf '%sUsing existing backend at %s%s\n\n' "$DIM" "$backend" "$RESET"
    # git repo path is required unless we set NO_ASSERT, in which case we can use a remote backend
    if [[ -z "${E2E_GIT_REPO_PATH}" && -z "${NO_ASSERT:-""}" ]]; then
        echo "E2E_GIT_REPO_PATH unset, you need to set it before calling this script"
        exit 1
    fi
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
section "Initial Setup and Repo Registration"
################################################################################

echo "$(signers_file 1)"
run_step_json "Register repo with key1" \
    '.success == true' \
    cargo run --quiet -- register-repo --secret-key "$KEY_0" -u $backend --password $key_password $(signers_file 1)

# --- Backend: the submitter's signature is recorded at registration ---
assert_pending_signers_exist
assert_pending_metadata_exist
assert_pending_signers_signature_count 1
assert_pending_metadata_signature_count 1
assert_pending_signers_signatures_contain_keys "$KEY_0"
assert_pending_metadata_signatures_contain_keys "$KEY_0"
assert_pending_signers_contain_keys "$KEY_0" "$KEY_1" "$KEY_2"
assert_last_commit_contains "$PENDING_SIGNERS_DIR/$SIGNERS_FILE"

################################################################################
section "Signers File Activation"
################################################################################

run_step_json "List pending for key1 (should show pending signers, key0 already signed)" \
    '.pending_files | length > 0' \
    cargo run --quiet -- list-pending --secret-key "$KEY_1" -u "$backend" --password $key_password

run_step_json "Check pending signers match forge source" \
    '.hash | startswith("sha512:")' \
    cargo run --quiet -- check-pending-signers -u "$backend" $(pending_signers_file)

# Tamper the pending signers file held by the backend: the mirror content no
# longer matches the signers file published on the forge, and the divergence
# must be detected. The original content is restored so the flow can continue.
if [[ -n ${E2E_GIT_REPO_PATH} ]]; then
    PENDING_SIGNERS_FILE="$(_project_dir)/$PENDING_SIGNERS_DIR/$SIGNERS_FILE"
    PENDING_SIGNERS_BACKUP=$(mktemp)
    to_delete_on_filesystem+=("$PENDING_SIGNERS_BACKUP")
    cp "$PENDING_SIGNERS_FILE" "$PENDING_SIGNERS_BACKUP"
    printf '\n' >> "$PENDING_SIGNERS_FILE"

    expect_fail_json "Check pending signers differing from forge source" \
        '.error | contains("Hash mismatch")' \
        cargo run --quiet -- check-pending-signers -u "$backend" $(pending_signers_file)

    cp "$PENDING_SIGNERS_BACKUP" "$PENDING_SIGNERS_FILE"
fi

SIGNERS_SIGN_ARGS=$(pending_signers_sign_args "$KEY_1" "$backend" $key_password)

# Key0 already signed the pending signers file and metadata at registration.

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

################################################################################
section "Release Registration and Signing"
################################################################################

# A release may only be registered by one of the project's authorised
# artifact signers. Key3 is not in the active signers file (keys 0, 1 and 2
# are), so its registration request must be rejected before any file is
# written for the release.
expect_fail_json "Register release with key3 (not an authorised signer)" \
    '.error | contains("Not authorized")' \
    cargo run --quiet -- register-assets --secret-key "$KEY_3" -u "$backend" --password $key_password --github-release-url $(release_url 0.1)

assert_file_not_exists "release v0.1 index after rejected registration" \
    "$(_release_dir "0.1")/$INDEX_FILE"

run_step_json "Register release with key2 (which signs it)" \
    '.success == true' \
    cargo run --quiet -- register-assets --secret-key "$KEY_2" -u "$backend" --password $key_password --github-release-url $(release_url 0.1)

# --- Backend: verify release index created ---
assert_release_index_exists "0.1"
assert_release_index_pending "0.1"
assert_last_commit_contains "$INDEX_FILE"

run_step_json "Check index digests against digest sources" \
    '.files_checked > 0' \
    cargo run --quiet -- check-index -u "$backend" $(release_index 0.1)

# Pin the on-disk index content to the release data served by github, so a
# change in index generation (fields, casing, digest source, published date
# handling) fails the flow instead of silently changing what gets signed.
# Values are hard-coded to the v0.1 release assets: the release is immutable,
# so the expectation cannot drift. Digests and dates fetched from the GH api
# on 2026-10-14. mirroredOn is the registration time (non-deterministic), so
# it is only checked to be later than the release publication date.
V0_1_INDEX_CONTENT_FILTER='.version == 1 and .publishedOn == "2026-02-14T11:01:47Z" and .mirroredOn > .publishedOn and .publishedFiles == [
    {fileName: "artifact.bin",  algo: "Sha256", source: "https://api.github.com/repos/asfaload/repo_for_e2e_tests/releases/286360244", sourceFormat: "GithubRelease", hash: "e88bf264f6b3f8364154083af4e3d8e9dfea20902ed737170056effc944d7a3e"},
    {fileName: "artifact1.bin", algo: "Sha256", source: "https://api.github.com/repos/asfaload/repo_for_e2e_tests/releases/286360244", sourceFormat: "GithubRelease", hash: "ec6dcee07ba8df5bbd129a0db6c2c7d30fcb48f586883759910ce7f755ff399f"},
    {fileName: "artifact2.bin", algo: "Sha256", source: "https://api.github.com/repos/asfaload/repo_for_e2e_tests/releases/286360244", sourceFormat: "GithubRelease", hash: "59bbfc692ecd7e93fbc7d6fa8839e574f10ab83917a8512e25b7db9bf8647d60"},
    {fileName: "artifact3.bin", algo: "Sha256", source: "https://api.github.com/repos/asfaload/repo_for_e2e_tests/releases/286360244", sourceFormat: "GithubRelease", hash: "31e16442f3bdeda534e9c73122959b2caf03a3faaf8d047993282c0ab9dd50dc"},
    {fileName: "artifact4.bin", algo: "Sha256", source: "https://api.github.com/repos/asfaload/repo_for_e2e_tests/releases/286360244", sourceFormat: "GithubRelease", hash: "62b01279a210dd74324e5cef7cb1980d189ed33501c2011c01afc46ad443810d"},
    {fileName: "artifact5.bin", algo: "Sha256", source: "https://api.github.com/repos/asfaload/repo_for_e2e_tests/releases/286360244", sourceFormat: "GithubRelease", hash: "152ddb72d4e846266b830b2bc06b8c4021a121e6a2be26944617c2de81d7eeea"}
]'
assert_index_posix_json_contract "0.1"
assert_json_field "$(_release_dir "0.1")/$INDEX_FILE" \
    "$V0_1_INDEX_CONTENT_FILTER" \
    "Release v0.1 index content matches github release assets"

# Tamper the index held by the backend: one recorded digest no longer matches
# the digest computed from its source, and check-index must detect it. The
# original content is restored so the flow can continue.
if [[ -n ${E2E_GIT_REPO_PATH} ]]; then
    V01_INDEX_PATH="$(_release_dir "0.1")/$INDEX_FILE"
    V01_INDEX_BACKUP=$(mktemp)
    to_delete_on_filesystem+=("$V01_INDEX_BACKUP")
    cp "$V01_INDEX_PATH" "$V01_INDEX_BACKUP"
    jq '(.publishedFiles[0].hash) = "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"' \
        "$V01_INDEX_BACKUP" > "$V01_INDEX_PATH"

    expect_fail_json "Check index with tampered digest" \
        '.error | contains("digest mismatch")' \
        cargo run --quiet -- check-index -u "$backend" $(release_index 0.1)

    cp "$V01_INDEX_BACKUP" "$V01_INDEX_PATH"
fi

# A never-registered release has no index file at all.
tmp=$(mktemp); to_delete_on_filesystem+=("$tmp")
expect_fail "Download never-registered artifact (v9.9)" \
    cargo run --quiet -- download -o "$tmp" -u "$backend" $(artifact_url 9.9)

# v0.1 is registered but has one of two required signatures (the submitter's,
# recorded at registration): still below threshold, not active.
tmp=$(mktemp); to_delete_on_filesystem+=("$tmp")
expect_fail "Download unsigned artifact (v0.1, 1 of 2 signatures)" \
    cargo run --quiet -- download -o "$tmp" -u "$backend" $(artifact_url 0.1)

# The index is not complete yet: its status must still be pending.
run_step_json "Check signature status for v0.1 index (pending)" \
    '.is_complete == false' \
    cargo run --quiet -- signature-status --secret-key "$KEY_0" -u "$backend" --password $key_password $(release_index 0.1)

# Registration records the submitter's signature, so the registrant (key2)
# has already signed the index: only keys that still have to sign see it as
# pending.
run_step_json "List pending for key0 (should show pending release index)" \
    '.pending_files | length > 0' \
    cargo run --quiet -- list-pending --secret-key "$KEY_0" -u "$backend" --password $key_password

RELEASE_0_1_SIGN_ARGS=$(release_index_sign_args 0.1 "$KEY_0" "$backend" $key_password)
run_step_json "Sign release index with key0 (completes, threshold=2)" \
    '.is_complete == true' \
    cargo run --quiet -- sign-pending --secret-key "$KEY_0" -u "$backend" --password $key_password $RELEASE_0_1_SIGN_ARGS

assert_release_index_signature_count "0.1" 2

expect_fail "Register release with key3 (fails as already registered)" \
    cargo run --quiet -- register-assets --secret-key "$KEY_2" -u "$backend" --password $key_password --github-release-url $(release_url 0.1)

# Ensure a second release registration does not override the signatures already collected
assert_release_index_signature_count "0.1" 2

# The index was completed by key0's signature (key2 signed at registration):
# further signatures must be rejected.
expect_fail "Sign release index with key1 (already completed)" \
    cargo run --quiet -- sign-pending --secret-key "$KEY_1" -u "$backend" --password $key_password $RELEASE_0_1_SIGN_ARGS

# --- Backend: verify release index activated ---
assert_release_index_active "0.1"
assert_release_index_signers "0.1" "$KEY_0" "$KEY_1" "$KEY_2"

run_step_json "Check signature status for v0.1 index (complete)" \
    '.is_complete == true' \
    cargo run --quiet -- signature-status --secret-key "$KEY_0" -u "$backend" --password $key_password $(release_index 0.1)

expect_fail "Sign release index with key3 (already completed)" \
    cargo run --quiet -- sign-pending --secret-key "$KEY_2" -u "$backend" --password $key_password $RELEASE_0_1_SIGN_ARGS

DOWNLOAD_V01="$(mktemp)"
to_delete_on_filesystem+=("$DOWNLOAD_V01")
run_step "Download release artifact (v0.1)" \
    cargo run --quiet -- download -o "$DOWNLOAD_V01" -u "$backend" $(artifact_url 0.1)

# --- Backend: verify artifact hash ---
assert_artifact_hash_matches "0.1" "artifact.bin" "$DOWNLOAD_V01"

################################################################################
section "Updating Signers File"
################################################################################

run_step_json "Update signers file with key0" \
    '.success == true' \
    cargo run -- update-signers --secret-key "$KEY_0" -u "$backend" -p $key_password $(signers_file 2)

# --- Backend: verify pending signers updated with the submitter's signature ---
assert_pending_signers_exist
assert_pending_metadata_exist
assert_pending_signers_signature_count 1
assert_pending_metadata_signature_count 1
assert_pending_signers_signatures_contain_keys "$KEY_0"
assert_pending_metadata_signatures_contain_keys "$KEY_0"
assert_pending_signers_contain_keys "$KEY_0" "$KEY_1" "$KEY_2" "$KEY_3"

run_step_json "List pending for key1 (should show pending signers, key0 already signed)" \
    '.pending_files | length > 0' \
    cargo run --quiet -- list-pending --secret-key "$KEY_1" -u "$backend" --password $key_password

SIGNERS_SIGN_ARGS=$(pending_signers_sign_args "$KEY_1" "$backend" $key_password)

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
    cargo run --quiet -- download -o "$DOWNLOAD_V01_HISTORICAL" -u "$backend" $(artifact_url 0.1)

assert_artifact_hash_matches "0.1" "artifact.bin" "$DOWNLOAD_V01_HISTORICAL"

################################################################################
section "Registering Release with New Signers File"
################################################################################

run_step_json "Register second release with key3" \
    '.success == true' \
    cargo run --quiet -- register-assets --secret-key "$KEY_2" -u "$backend" --password $key_password --github-release-url $(release_url 0.2)

# --- Backend: verify second release index created ---
assert_release_index_exists "0.2"
assert_release_index_pending "0.2"

# Same content pinning as v0.1, with the v0.2 release assets (fetched from
# the GH api on 2026-10-14).
V0_2_INDEX_CONTENT_FILTER='.version == 1 and .publishedOn == "2026-02-14T11:07:06Z" and .mirroredOn > .publishedOn and .publishedFiles == [
    {fileName: "artifact.bin",  algo: "Sha256", source: "https://api.github.com/repos/asfaload/repo_for_e2e_tests/releases/286360893", sourceFormat: "GithubRelease", hash: "e88bf264f6b3f8364154083af4e3d8e9dfea20902ed737170056effc944d7a3e"},
    {fileName: "artifact1.bin", algo: "Sha256", source: "https://api.github.com/repos/asfaload/repo_for_e2e_tests/releases/286360893", sourceFormat: "GithubRelease", hash: "4b6c7044ba94a0e181f9af0c32700f1e8148f0eecc271b7641fa65dfeaad9d9c"},
    {fileName: "artifact2.bin", algo: "Sha256", source: "https://api.github.com/repos/asfaload/repo_for_e2e_tests/releases/286360893", sourceFormat: "GithubRelease", hash: "ccc33ee7566da198aa81772d0c9819487b28e8a9aabe7297000ad6d0c2504823"},
    {fileName: "artifact3.bin", algo: "Sha256", source: "https://api.github.com/repos/asfaload/repo_for_e2e_tests/releases/286360893", sourceFormat: "GithubRelease", hash: "0d152981fc9b4b8de5828064211b3e23d943a68c83b2ea2cbb3d861bb8d27f87"},
    {fileName: "artifact4.bin", algo: "Sha256", source: "https://api.github.com/repos/asfaload/repo_for_e2e_tests/releases/286360893", sourceFormat: "GithubRelease", hash: "19ca33cd92fa00ccf7550315577051757837d33a084ecc8b871afba135c944f0"},
    {fileName: "artifact5.bin", algo: "Sha256", source: "https://api.github.com/repos/asfaload/repo_for_e2e_tests/releases/286360893", sourceFormat: "GithubRelease", hash: "ed69fc21157da16e2504650eb75c9a41f51a769a33c3fcff0a5b02517491e44f"}
]'
assert_index_posix_json_contract "0.2"
assert_json_field "$(_release_dir "0.2")/$INDEX_FILE" \
    "$V0_2_INDEX_CONTENT_FILTER" \
    "Release v0.2 index content matches github release assets"

# As for v0.1: key2 signed the index at registration time, so it no longer
# sees it as pending.
run_step_json "List pending for key0 (should show pending release index)" \
    '.pending_files | length > 0' \
    cargo run --quiet -- list-pending --secret-key "$KEY_0" -u "$backend" --password $key_password

RELEASE_0_2_SIGN_ARGS=$(release_index_sign_args 0.2 "$KEY_0" "$backend" $key_password)
run_step_json "Sign release index with key0 (2 of 3 signatures)" \
    '.is_complete == false' \
    cargo run --quiet -- sign-pending --secret-key "$KEY_0" -u "$backend" --password $key_password $RELEASE_0_2_SIGN_ARGS

assert_release_index_signature_count "0.2" 2

run_step_json "Sign release index with key1 (completes, threshold=3)" \
    '.is_complete == true' \
    cargo run --quiet -- sign-pending --secret-key "$KEY_1" -u "$backend" --password $key_password $RELEASE_0_2_SIGN_ARGS

assert_release_index_signature_count "0.2" 3

expect_fail "Sign release index with key3 (already completed)" \
    cargo run --quiet -- sign-pending --secret-key "$KEY_3" -u "$backend" --password $key_password $RELEASE_0_2_SIGN_ARGS

# --- Backend: verify v0.2 release index activated ---
assert_release_index_active "0.2"
assert_release_index_signers "0.2" "$KEY_0" "$KEY_1" "$KEY_2" "$KEY_3"

DOWNLOAD_V02="$(mktemp)"
to_delete_on_filesystem+=("$DOWNLOAD_V02")
run_step "Download artifact (v0.2)" \
    cargo run --quiet -- download -o "$DOWNLOAD_V02" -u "$backend" $(artifact_url 0.2)

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
    cargo run --quiet -- download -o "$DOWNLOAD_V01_bis" -u "$backend" $(artifact_url 0.1)
assert_artifact_hash_matches "0.1" "artifact.bin" "$DOWNLOAD_V01_bis"

run_step_json "List pending for key1 (none expected, key1 cannot revoke)" \
    '.pending_files | length == 0' \
    cargo run --quiet -- list-pending --secret-key "$KEY_0" -u "$backend" --password $key_password

run_step_json "List pending for key5 (one expected, key1 can revoke)" \
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
    cargo run --quiet -- download -o "$tmp" -u "$backend" $(artifact_url 0.1)

# --- v0.2 is unaffected --
DOWNLOAD_V02_bis="$(mktemp)"
to_delete_on_filesystem+=("$DOWNLOAD_V02_bis")
run_step "Download artifact (v0.2), not revoked" \
    cargo run --quiet -- download -o "$DOWNLOAD_V02_bis" -u "$backend" $(artifact_url 0.2)
assert_artifact_hash_matches "0.2" "artifact.bin" "$DOWNLOAD_V02_bis"

################################################################################
section "Download with Full Signers Chain Verification"
################################################################################

# v0.2 was signed after the signers update, so the chain has 2 entries:
# entry 1 = original signers_file_1 (registered with register-repo)
# entry 2 = updated signers_file_2 (registered with update-signers)
# The forge URLs point to the GitHub test repo, so content comparison should pass.

DOWNLOAD_V02_FULL_CHECK="$(mktemp)"
to_delete_on_filesystem+=("$DOWNLOAD_V02_FULL_CHECK")
run_step "Download artifact (v0.2) with (2-entry chain)" \
    cargo run --quiet -- download -o "$DOWNLOAD_V02_FULL_CHECK" -u "$backend" $(artifact_url 0.2)
assert_artifact_hash_matches "0.2" "artifact.bin" "$DOWNLOAD_V02_FULL_CHECK"

# Only run these tests if we use a local git repo, which we can directly access.
if [[ -n ${E2E_GIT_REPO_PATH} ]]; then
    ################################################################################
    section "Full Check Failure: Tampered Metadata"
    ################################################################################

    # The first entry in the signers chain is the trust anchor. It cannot be
    # validated cryptographically (no previous entry). The only validation is
    # to fetch the signers file from the forge URL stored in metadata and compare.
    #
    # The chain for v0.2 has 2 entries:
    #   entry[0] = original signers_file_1 (trust anchor, metadata in history file)
    #   entry[1] = updated signers_file_2  (active, metadata in metadata.json)
    #
    # validate_first_entry checks entry[0], whose metadata is embedded in the
    # history file blob. The backend reads this blob via `git show COMMIT:path`,
    # so we use `git replace` to transparently swap the blob without rewriting
    # history. This simulates a compromised trust anchor.

    HISTORY_REL_PATH="$(_project_dir)/$SIGNERS_HISTORY_FILE"
    HISTORY_REL_PATH="${HISTORY_REL_PATH#"$E2E_GIT_REPO_PATH/"}"
    HISTORY_BLOB=$(git -C "$E2E_GIT_REPO_PATH" rev-parse "HEAD:$HISTORY_REL_PATH")

    # Build the raw.githubusercontent.com URL for signers_file_2 (valid but different content)
    # The metadata field in history entries is base64-encoded JSON. To tamper
    # with the retrieval URL we must: decode base64 → modify JSON → re-encode base64.
    TAMPERED_RAW_URL="https://raw.githubusercontent.com/${E2E_REPO}/master/${TEST_NAME}/signers_file_2${_SIGNERS_SUFFIX}.json"
    TAMPERED_HISTORY_BLOB=$(git -C "$E2E_GIT_REPO_PATH" show "$HISTORY_BLOB" | \
        jq --arg url "$TAMPERED_RAW_URL" '
        .entries[0].metadata |= (
            @base64d | fromjson |
            .verified_content.retrieval_url = $url |
            tojson | @base64
        )' | \
        git -C "$E2E_GIT_REPO_PATH" hash-object -w --stdin)

    # Assert the rewrite really changed the retrieval URL.
    WRITTEN_URL=$(git -C "$E2E_GIT_REPO_PATH" show "$TAMPERED_HISTORY_BLOB" | \
        jq -r '.entries[0].metadata | @base64d | fromjson | .verified_content.retrieval_url')
    if [[ $WRITTEN_URL != "$TAMPERED_RAW_URL" ]]; then
        echo "Tamper failed: metadata retrieval URL is '$WRITTEN_URL', expected '$TAMPERED_RAW_URL'"
        exit 1
    fi

    git -C "$E2E_GIT_REPO_PATH" replace "$HISTORY_BLOB" "$TAMPERED_HISTORY_BLOB"

    tmp=$(mktemp); to_delete_on_filesystem+=("$tmp")
    expect_fail "Download with (tampered metadata URL, content mismatch)" \
        cargo run --quiet -- download -o "$tmp" -u "$backend" $(artifact_url 0.2)

    git -C "$E2E_GIT_REPO_PATH" replace -d "$HISTORY_BLOB"

    # --- Tamper: point metadata URL to non-existent file (404) ---
    NONEXISTENT_RAW_URL="https://raw.githubusercontent.com/${E2E_REPO}/master/${TEST_NAME}/signers_file_nonexistent.json"
    NOTFOUND_HISTORY_BLOB=$(git -C "$E2E_GIT_REPO_PATH" show "$HISTORY_BLOB" | \
        jq --arg url "$NONEXISTENT_RAW_URL" '
        .entries[0].metadata |= (
            @base64d | fromjson |
            .verified_content.retrieval_url = $url |
            tojson | @base64
        )' | \
        git -C "$E2E_GIT_REPO_PATH" hash-object -w --stdin)

    # Assert the rewrite really changed the retrieval URL.
    WRITTEN_URL=$(git -C "$E2E_GIT_REPO_PATH" show "$NOTFOUND_HISTORY_BLOB" | \
        jq -r '.entries[0].metadata | @base64d | fromjson | .verified_content.retrieval_url')
    if [[ $WRITTEN_URL != "$NONEXISTENT_RAW_URL" ]]; then
        echo "Tamper failed: metadata retrieval URL is '$WRITTEN_URL', expected '$NONEXISTENT_RAW_URL'"
        exit 1
    fi

    git -C "$E2E_GIT_REPO_PATH" replace "$HISTORY_BLOB" "$NOTFOUND_HISTORY_BLOB"

    tmp=$(mktemp); to_delete_on_filesystem+=("$tmp")
    expect_fail "Download with (tampered metadata URL, 404)" \
        cargo run --quiet -- download -o "$tmp" -u "$backend" $(artifact_url 0.2)

    git -C "$E2E_GIT_REPO_PATH" replace -d "$HISTORY_BLOB"

fi;

################################################################################
print_summary
