#!/bin/bash
set -euo pipefail

# E2E test: register-assets requests with invalid client provided data are
# rejected.
#
# Unlike other flows, no register-repo is done and no signers file is
# installed: the client data is validated during the registration of the
# release, before any signers state is consulted, so a rejection must happen
# on a bare backend.
#
# The payloads are built by the e2e-sign-payload helper crate: it
# authenticates the request with a real key but forges the index content
# and the key that signs it, so only the validation of the client provided
# data is exercised. Each step checks the request is answered with a bad
# request whose error explains the reason of the rejection.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
. "$SCRIPT_DIR/lib/helpers.sh"

# --- Cleanup trap ---

SERVER_PID=""
# Set by the script when it starts the backend itself, giving access to its
# git repo working tree for the no-side-effect assertions.
STARTED_REPO_PATH=""
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
else
    port="${ASFALOAD_SERVER_PORT:-$((3000 + RANDOM % 1000))}"
    export ASFALOAD_SERVER_PORT="$port"
    backend="http://localhost:$port"

    STARTED_REPO_PATH=$(mktemp -d)
    to_delete_on_filesystem+=("$STARTED_REPO_PATH")
    init_backend_repo "$STARTED_REPO_PATH"
    export ASFALOAD_GIT_REPO_PATH="$STARTED_REPO_PATH"

    build_rest_api
    cargo build --quiet -p e2e-sign-payload > /dev/null 2>&1
    SIG_PAYLOAD_BIN="$base_dir/target/debug/e2e-sign-payload"
    if [[ ! -x "$SIG_PAYLOAD_BIN" ]]; then
        printf '%sCould not build e2e-sign-payload helper.%s\n' "$RED" "$RESET"
        exit 1
    fi

    "${base_dir}/target/debug/rest-api" > "$STARTED_REPO_PATH/server.log" &
    SERVER_PID=$!
    if [[ -n $debug ]]; then
        tail -f "$STARTED_REPO_PATH/server.log" &
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

# Directory the backend would write release files to for a successful
# registration. Its absence strengthens every rejection below: invalid data
# must leave no trace, not even the empty release directory.
RELEASE_DIR="$STARTED_REPO_PATH/https/github.com/443/${E2E_REPO}/releases/tag/v0.1"
RELEASE_DIR_SUBSTR="https/github.com/443/${E2E_REPO}/releases/tag/v0.1"

RELEASE_URL=$(release_url 0.1)

# Post one register-assets request built by the payload helper. Arguments
# after the description recognise the helper's --index-* arguments. Prints
# "status_code<TAB>body".
post_register_assets() {
    local helper_out index_args=("$@")
    local payload_file body_file

    helper_out=$("$SIG_PAYLOAD_BIN" \
        --secret-key "$KEY_0" \
        --password "$key_password" \
        --github-release-url "$RELEASE_URL" \
        "${index_args[@]}")

    local payload_json
    payload_json="$(printf '%s' "$helper_out" | jq -S .)"
    payload_file=$(mktemp)
    body_file=$(mktemp)
    to_delete_on_filesystem+=("$payload_file" "$body_file")
    # -j outputs the exact signed bytes without jq's trailing newline.
    printf '%s' "$payload_json" | jq -j .payload > "$payload_file"

    curl "$backend/v1/assets" \
        --request POST \
        --silent \
        --output "$body_file" \
        --write-out '%{http_code}\n' \
        --header "Content-Type: application/json" \
        --header "X-asfld-timestamp: $(printf '%s' "$payload_json" | jq -j .timestamp)" \
        --header "X-asfld-nonce: $(printf '%s' "$payload_json" | jq -j .nonce)" \
        --header "X-asfld-sig: $(printf '%s' "$payload_json" | jq -j .signature)" \
        --header "X-asfld-pk: $(printf '%s' "$payload_json" | jq -j .public_key)" \
        --data-binary "@$payload_file"

    printf '\t'
    cat "$body_file"
}

# Expect a bad request whose error matches the given jq filter. The
# remaining arguments are passed to the payload helper.
expect_fail_invalid_register_assets() {
    local desc="$1" jq_filter="$2"; shift 2
    STEP_NUM=$((STEP_NUM + 1))
    printf '%s[%2d]%s %s %s(expect fail)%s... ' \
        "$DIM" "$STEP_NUM" "$RESET" "$desc" "$YELLOW" "$RESET"

    local step_start step_end elapsed
    step_start=$(date +%s)

    local outcome status body
    outcome=$(post_register_assets "$@")
    status="${outcome%%$'\t'*}"
    body="${outcome#*$'\t'}"
    status="$(printf '%s' "$status" | tr -d '[:space:]')"

    step_end=$(date +%s)
    elapsed=$((step_end - step_start))

    if [[ "$status" == "2"* ]]; then
        printf '\n%s✗ UNEXPECTED SUCCESS%s %s(%ds)%s\n' "$RED" "$RESET" "$DIM" "$elapsed" "$RESET"
        printf '  %sRequest was expected to be rejected but succeeded:%s %s\n' "$RED" "$RESET" "$desc"
        printf '  %sBody:%s\n%s\n' "$RED" "$RESET" "$body"
        exit 1
    fi

    if [[ "$status" != "400" ]]; then
        printf '\n%s✗ WRONG STATUS%s %s(%ds)%s\n' "$RED" "$RESET" "$DIM" "$elapsed" "$RESET"
        printf '  %sExpected 400 bad request, got:%s %s\n' "$RED" "$RESET" "$status"
        printf '  %sBody:%s\n%s\n' "$RED" "$RESET" "$body"
        exit 1
    fi

    if ! printf '%s' "$body" | jq -e "$jq_filter" > /dev/null 2>&1; then
        printf '\n%s✗ ASSERTION FAILED%s %s(%ds)%s\n' "$RED" "$RESET" "$DIM" "$elapsed" "$RESET"
        printf '  %sFilter:%s  %s\n' "$RED" "$RESET" "$jq_filter"
        printf '  %sBody:%s\n%s\n' "$RED" "$RESET" "$body"
        exit 1
    fi

    printf '%s⚠ expected failure%s %s(%ds)%s\n' "$YELLOW" "$RESET" "$DIM" "$elapsed" "$RESET"
    EXPECTED_FAIL_COUNT=$((EXPECTED_FAIL_COUNT + 1))
}

assert_release_dir_absent() {
    if [[ -n "$STARTED_REPO_PATH" && -e "$RELEASE_DIR_SUBSTR" || -e "$RELEASE_DIR" ]]; then
        printf '\n%s✗ SIDE EFFECT DETECTED%s\n' "$RED" "$RESET"
        printf '  %sA rejected registration left files under:%s %s\n' "$RED" "$RESET" "$RELEASE_DIR"
        exit 1
    fi
}

# Content the client would have sent for the mocked release, with the digest
# of one file changed: a validly signed index that contradicts the release
# must be rejected.
WRONG_HASH_INDEX=$(mktemp)
to_delete_on_filesystem+=("$WRONG_HASH_INDEX")
cat > "$WRONG_HASH_INDEX" <<'EOF'
{"version": 1, "publishedOn": "2026-02-14T11:01:47Z", "mirroredOn": "2026-02-14T11:01:47Z", "publishedFiles": [
    {"fileName": "artifact.bin", "algo": "Sha256", "source": "https://api.github.com/repos/asfaload/repo_for_e2e_tests/releases/286360244", "sourceFormat": "GithubRelease", "hash": "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"},
    {"fileName": "artifact1.bin", "algo": "Sha256", "source": "https://api.github.com/repos/asfaload/repo_for_e2e_tests/releases/286360244", "sourceFormat": "GithubRelease", "hash": "ec6dcee07ba8df5bbd129a0db6c2c7d30fcb48f586883759910ce7f755ff399f"},
    {"fileName": "artifact2.bin", "algo": "Sha256", "source": "https://api.github.com/repos/asfaload/repo_for_e2e_tests/releases/286360244", "sourceFormat": "GithubRelease", "hash": "59bbfc692ecd7e93fbc7d6fa8839e574f10ab83917a8512e25b7db9bf8647d60"},
    {"fileName": "artifact3.bin", "algo": "Sha256", "source": "https://api.github.com/repos/asfaload/repo_for_e2e_tests/releases/286360244", "sourceFormat": "GithubRelease", "hash": "31e16442f3bdeda534e9c73122959b2caf03a3faaf8d047993282c0ab9dd50dc"},
    {"fileName": "artifact4.bin", "algo": "Sha256", "source": "https://api.github.com/repos/asfaload/repo_for_e2e_tests/releases/286360244", "sourceFormat": "GithubRelease", "hash": "62b01279a210dd74324e5cef7cb1980d189ed33501c2011c01afc46ad443810d"},
    {"fileName": "artifact5.bin", "algo": "Sha256", "source": "https://api.github.com/repos/asfaload/repo_for_e2e_tests/releases/286360244", "sourceFormat": "GithubRelease", "hash": "152ddb72d4e846266b830b2bc06b8c4021a121e6a2be26944617c2de81d7eeea"}
]}
EOF

GARBAGE_INDEX=$(mktemp)
to_delete_on_filesystem+=("$GARBAGE_INDEX")
printf 'not index json at all\n' > "$GARBAGE_INDEX"

assert_release_dir_absent

################################################################################
section "Register-Assets With Invalid Client Provided Data"
################################################################################

# The payload index is signed by a key other than the public key the request
# declares: its signature must not verify.
expect_fail_invalid_register_assets "Register release with an index signed by another key" \
    '.error | contains("does not verify")' \
    --index-file "$GARBAGE_INDEX" \
    --index-signature-key "$KEY_1"

# The index decodes but is not index json: invalid client data, not a
# server-side problem.
# Note: this case runs against a bare backend, with no signers file: the
# rejection must happen before any signers state is consulted.
# The release url points to a real github release, but it is never fetched:
# validation fails at parsing the sent index.
expect_fail_invalid_register_assets "Register release with an index that is not json" \
    '.error | contains("Could not parse index sent by client")' \
    --index-file "$GARBAGE_INDEX"

# An index that does not even decode from base64.
expect_fail_invalid_register_assets "Register release with an index not decodable from base64" \
    '.error | contains("Could not decode index sent by client")' \
    --index-b64 '!!! not base64 !!!'

# A validly signed index contradicting the release: the server builds its own
# index from the github api and must detect the divergence.
# This needs github to serve the release, like the other flows.
expect_fail_invalid_register_assets "Register release with an index not matching the github release" \
    '.error | contains("not identical to index generated server side")' \
    --index-file "$WRONG_HASH_INDEX"

assert_release_dir_absent

print_summary
