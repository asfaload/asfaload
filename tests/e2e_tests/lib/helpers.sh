# --- Fixture key paths ---
_HELPERS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# --- Key type selection (must be before sourcing urls.sh which uses KEY_TYPE) ---
KEY_TYPE="${KEY_TYPE:-asfaload}"
KEYS_DIR="$(cd "$_HELPERS_DIR/../../.." && pwd)/core/test_helpers/fixtures/keys"
# The key the test backend will sign commits with. ssh refuses a private key
# that is group/world readable, and the committed fixture is checked out with
# the umask's mode, so stage a 0600 copy in a temp dir rather than using the
# fixture in place.
_SIGNING_KEY_SRC="$(cd "$_HELPERS_DIR/../../.." && pwd)/core/test_helpers/fixtures/git_signing_key"
_SIGNING_KEY_DIR="$(mktemp -d)"
cp "$_SIGNING_KEY_SRC" "$_SIGNING_KEY_SRC.pub" "$_SIGNING_KEY_DIR/"
chmod 600 "$_SIGNING_KEY_DIR/git_signing_key"
export ASFALOAD_GIT_SIGNING_PUB_KEY_PATH="$_SIGNING_KEY_DIR/git_signing_key.pub"
case "$KEY_TYPE" in
    asfaload) _KEY_PREFIX="" ;;
    *)
        printf 'Unknown KEY_TYPE: %s (expected: asfaload)\n' "$KEY_TYPE" >&2
        exit 1
        ;;
esac

. "$_HELPERS_DIR/urls.sh"
. "$_HELPERS_DIR/constants.sh"
. "$_HELPERS_DIR/backend_assertions.sh"

KEY_0="$KEYS_DIR/${_KEY_PREFIX}key_0"
KEY_1="$KEYS_DIR/${_KEY_PREFIX}key_1"
KEY_2="$KEYS_DIR/${_KEY_PREFIX}key_2"
KEY_3="$KEYS_DIR/${_KEY_PREFIX}key_3"
KEY_4="$KEYS_DIR/${_KEY_PREFIX}key_4"
KEY_5="$KEYS_DIR/${_KEY_PREFIX}key_5"
KEY_6="$KEYS_DIR/${_KEY_PREFIX}key_6"
KEY_7="$KEYS_DIR/${_KEY_PREFIX}key_7"
KEY_8="$KEYS_DIR/${_KEY_PREFIX}key_8"
KEY_9="$KEYS_DIR/${_KEY_PREFIX}key_9"

# --- Git OID-aware helpers ---

# Initialize a git repo
# Usage: init_backend_repo "$path"
init_backend_repo() {
    local repo_path="$1"
    git init --object-format=sha256 "$repo_path" --quiet
}

# Build the rest-api binary.
build_rest_api() {
    cargo build -p rest-api --quiet
}

# --- Terminal color support ---
if [ -t 1 ]; then
    BOLD=$'\033[1m'
    DIM=$'\033[2m'
    RED=$'\033[31m'
    GREEN=$'\033[32m'
    YELLOW=$'\033[33m'
    BLUE=$'\033[34m'
    RESET=$'\033[0m'
else
    BOLD='' DIM='' RED='' GREEN='' YELLOW='' BLUE='' RESET=''
fi

# --- Dependency check ---
if ! command -v jq &> /dev/null; then
    printf '%sjq is required but not installed.%s\n' "$RED" "$RESET"
    exit 1
fi

# --- Global state ---
STEP_NUM=0
PASS_COUNT=0
EXPECTED_FAIL_COUNT=0
SCRIPT_START=$(date +%s)
CURRENT_SECTION="setup"
debug="${debug:-}"

# --- ERR trap for unguarded failures ---
on_error() {
    local line="$1" cmd="$2"
    printf '\n%s%s══ UNEXPECTED ERROR ══════════════════════════════════════════%s\n' \
        "$BOLD" "$RED" "$RESET"
    printf '  %sLine:%s    %d\n' "$RED" "$RESET" "$line"
    printf '  %sCommand:%s %s\n' "$RED" "$RESET" "$cmd"
    printf '  %sSection:%s %s\n' "$RED" "$RESET" "${CURRENT_SECTION}"
    exit 1
}
trap 'on_error $LINENO "$BASH_COMMAND"' ERR

# --- Helper functions ---

section() {
    local title="$1"
    CURRENT_SECTION="$title"
    printf '\n%s%s══════════════════════════════════════════════════════════════%s\n' \
        "$BOLD" "$BLUE" "$RESET"
    printf '%s%s  %s%s\n' "$BOLD" "$BLUE" "$title" "$RESET"
    printf '%s%s══════════════════════════════════════════════════════════════%s\n\n' \
        "$BOLD" "$BLUE" "$RESET"
}

run_step() {
    local desc="$1"; shift
    STEP_NUM=$((STEP_NUM + 1))
    printf '%s[%2d]%s %s... ' "$DIM" "$STEP_NUM" "$RESET" "$desc"

    if [[ -n $debug ]]; then
        echo
        echo "$@";
    fi

    local step_start output exit_code=0
    step_start=$(date +%s)

    output=$("$@" 2>&1) || exit_code=$?

    local step_end elapsed
    step_end=$(date +%s)
    elapsed=$((step_end - step_start))

    if [[ -n $debug ]]; then
        echo
        echo "$output"
    fi

    if [ "$exit_code" -eq 0 ]; then
        printf '%s✓%s %s(%ds)%s\n' "$GREEN" "$RESET" "$DIM" "$elapsed" "$RESET"
        PASS_COUNT=$((PASS_COUNT + 1))
    else
        printf '%s✗ FAILED%s %s(%ds)%s\n' "$RED" "$RESET" "$DIM" "$elapsed" "$RESET"
        printf '  %sCommand:%s %s\n' "$RED" "$RESET" "$*"
        printf '  %sExit code:%s %d\n' "$RED" "$RESET" "$exit_code"
        printf '  %sSection:%s %s\n' "$RED" "$RESET" "$CURRENT_SECTION"
        if [ -n "$output" ]; then
            printf '  %sOutput:%s\n%s\n' "$RED" "$RESET" "$output"
        fi
        exit 1
    fi
}

# On success, the JSON output of the command is in LAST_STEP_OUTPUT.
run_step_json() {
    local desc="$1"; shift
    local jq_filter="$1"; shift
    STEP_NUM=$((STEP_NUM + 1))
    printf '%s[%2d]%s %s... ' "$DIM" "$STEP_NUM" "$RESET" "$desc"

    if [[ -n $debug ]]; then
        echo
        echo "$@" --json
    fi

    local step_start output exit_code=0
    step_start=$(date +%s)

    local stderr_file=$(mktemp)
    output=$("$@" --json 2>"$stderr_file") || exit_code=$?
    local stderr_output
    stderr_output=$(<"$stderr_file")
    rm -f "$stderr_file"

    local step_end elapsed
    step_end=$(date +%s)
    elapsed=$((step_end - step_start))

    if [[ -n $debug ]]; then
        echo
        echo "stdout: $output"
        [[ -n "$stderr_output" ]] && echo "stderr: $stderr_output"
    fi

    if [ "$exit_code" -ne 0 ]; then
        printf '%s✗ FAILED%s %s(%ds)%s\n' "$RED" "$RESET" "$DIM" "$elapsed" "$RESET"
        printf '  %sCommand:%s %s --json\n' "$RED" "$RESET" "$*"
        printf '  %sExit code:%s %d\n' "$RED" "$RESET" "$exit_code"
        printf '  %sSection:%s %s\n' "$RED" "$RESET" "$CURRENT_SECTION"
        [[ -n "$output" ]] && printf '  %sStdout:%s\n%s\n' "$RED" "$RESET" "$output"
        [[ -n "$stderr_output" ]] && printf '  %sStderr:%s\n%s\n' "$RED" "$RESET" "$stderr_output"
        exit 1
    fi

    if ! echo "$output" | jq -e "$jq_filter" > /dev/null 2>&1; then
        printf '%s✗ ASSERTION FAILED%s %s(%ds)%s\n' "$RED" "$RESET" "$DIM" "$elapsed" "$RESET"
        printf '  %sCommand:%s %s --json\n' "$RED" "$RESET" "$*"
        printf '  %sFilter:%s  %s\n' "$RED" "$RESET" "$jq_filter"
        printf '  %sJSON:%s\n%s\n' "$RED" "$RESET" "$output"
        [[ -n "$stderr_output" ]] && printf '  %sStderr:%s\n%s\n' "$RED" "$RESET" "$stderr_output"
        printf '  %sSection:%s %s\n' "$RED" "$RESET" "$CURRENT_SECTION"
        exit 1
    fi

    printf '%s✓%s %s(%ds)%s\n' "$GREEN" "$RESET" "$DIM" "$elapsed" "$RESET"
    PASS_COUNT=$((PASS_COUNT + 1))
    LAST_STEP_OUTPUT="$output"
}

# Stop the test run when the client rejects its command line.
# clap exits with code 2 for a usage error (missing or conflicting flags),
# and the client exits with code 1 for an error of the command.
# An expected failure must come from the command, not from a usage error:
# a usage error only shows that the test gives incorrect arguments.
# Usage: fail_on_usage_error EXIT_CODE OUTPUT COMMAND...
fail_on_usage_error() {
    local exit_code="$1" output="$2"; shift 2
    if [ "$exit_code" -eq 2 ]; then
        printf '%s✗ USAGE ERROR%s\n' "$RED" "$RESET"
        printf '  %sThe client rejected the command line:%s %s\n' "$RED" "$RESET" "$*"
        printf '  %sSection:%s %s\n' "$RED" "$RESET" "$CURRENT_SECTION"
        [[ -n "$output" ]] && printf '  %sOutput:%s\n%s\n' "$RED" "$RESET" "$output"
        exit 1
    fi
}

expect_fail() {
    local desc="$1"; shift
    STEP_NUM=$((STEP_NUM + 1))
    printf '%s[%2d]%s %s %s(expect fail)%s... ' \
        "$DIM" "$STEP_NUM" "$RESET" "$desc" "$YELLOW" "$RESET"

    if [[ -n $debug ]]; then
        echo
        echo "$@";
    fi

    local step_start output exit_code=0
    step_start=$(date +%s)

    output=$("$@" 2>&1) || exit_code=$?

    local step_end elapsed
    step_end=$(date +%s)
    elapsed=$((step_end - step_start))

    if [[ -n $debug ]]; then
        echo
        echo "$output"
    fi

    fail_on_usage_error "$exit_code" "$output" "$@"

    if [ "$exit_code" -ne 0 ]; then
        printf '%s⚠ expected failure%s %s(%ds)%s\n' "$YELLOW" "$RESET" "$DIM" "$elapsed" "$RESET"
        EXPECTED_FAIL_COUNT=$((EXPECTED_FAIL_COUNT + 1))
    else
        printf '%s✗ UNEXPECTED SUCCESS%s %s(%ds)%s\n' "$RED" "$RESET" "$DIM" "$elapsed" "$RESET"
        printf '  %sCommand was expected to fail but succeeded:%s %s\n' "$RED" "$RESET" "$*"
        printf '  %sSection:%s %s\n' "$RED" "$RESET" "$CURRENT_SECTION"
        if [ -n "$output" ]; then
            printf '  %sOutput:%s\n%s\n' "$RED" "$RESET" "$output"
        fi
        exit 1
    fi
}

expect_fail_json() {
    local desc="$1"; shift
    local jq_filter="$1"; shift
    STEP_NUM=$((STEP_NUM + 1))
    printf '%s[%2d]%s %s %s(expect fail)%s... ' \
        "$DIM" "$STEP_NUM" "$RESET" "$desc" "$YELLOW" "$RESET"

    if [[ -n $debug ]]; then
        echo
        echo "$@" --json
    fi

    local step_start stdout_output exit_code=0
    step_start=$(date +%s)

    local stderr_file=$(mktemp)
    stdout_output=$("$@" --json 2>"$stderr_file") || exit_code=$?
    local stderr_output
    stderr_output=$(<"$stderr_file")
    rm -f "$stderr_file"

    local step_end elapsed
    step_end=$(date +%s)
    elapsed=$((step_end - step_start))

    if [[ -n $debug ]]; then
        echo
        [[ -n "$stdout_output" ]] && echo "stdout: $stdout_output"
        echo "stderr: $stderr_output"
    fi

    fail_on_usage_error "$exit_code" "$stderr_output" "$@" --json

    if [ "$exit_code" -eq 0 ]; then
        printf '%s✗ UNEXPECTED SUCCESS%s %s(%ds)%s\n' "$RED" "$RESET" "$DIM" "$elapsed" "$RESET"
        printf '  %sCommand was expected to fail but succeeded:%s %s --json\n' "$RED" "$RESET" "$*"
        printf '  %sSection:%s %s\n' "$RED" "$RESET" "$CURRENT_SECTION"
        [[ -n "$stdout_output" ]] && printf '  %sStdout:%s\n%s\n' "$RED" "$RESET" "$stdout_output"
        exit 1
    fi

    if ! echo "$stderr_output" | jq -e "$jq_filter" > /dev/null 2>&1; then
        printf '%s✗ ASSERTION FAILED%s %s(%ds)%s\n' "$RED" "$RESET" "$DIM" "$elapsed" "$RESET"
        printf '  %sCommand:%s %s --json\n' "$RED" "$RESET" "$*"
        printf '  %sFilter:%s  %s\n' "$RED" "$RESET" "$jq_filter"
        printf '  %sStderr JSON:%s\n%s\n' "$RED" "$RESET" "$stderr_output"
        printf '  %sSection:%s %s\n' "$RED" "$RESET" "$CURRENT_SECTION"
        exit 1
    fi

    printf '%s⚠ expected failure%s %s(%ds)%s\n' "$YELLOW" "$RESET" "$DIM" "$elapsed" "$RESET"
    EXPECTED_FAIL_COUNT=$((EXPECTED_FAIL_COUNT + 1))
}

# ── Pending-file sign helpers ──────────────────────────────────────────────────
#
# Query list-pending for the path and return "PATH --digest DIGEST", ready to
# append to a sign-pending invocation.  The three tokens are word-split by the
# caller; paths and SHA-512 hex digests contain no spaces, so this is safe.
#
# list-pending does not give the full digest, and the client must not trust
# a digest from the backend. The caller gives the expected DIGEST, from the
# same source as a real signer: get-digest on the signers file, the
# index_digest of register-assets, or the revocation_digest of revoke.

# Get sign-pending args for a pending file matching a substring pattern.
# Usage: args=$(pending_sign_args PATTERN KEY BACKEND PASSWORD DIGEST)
#        cargo run -- sign-pending ... $args
pending_sign_args() {
    local pattern="$1" key="$2" url="$3" pass="$4" digest="$5"
    local json path
    json=$(cargo run --quiet -- list-pending \
        --secret-key "$key" -u "$url" --password "$pass" --json 2>/dev/null)
    path=$(echo "$json" | jq -r \
        ".pending_files[] | select(.path | contains(\"$pattern\")) | .path" \
        | head -1)
    printf '%s --digest %s' "$path" "$digest"
}

# Get sign-pending args for the pending signers file.
# Usage: args=$(pending_signers_sign_args KEY BACKEND PASSWORD DIGEST)
#        cargo run -- sign-pending ... $args
pending_signers_sign_args() {
    pending_sign_args "$PENDING_SIGNERS_DIR" "$1" "$2" "$3" "$4"
}

# Get sign-pending args for a release index file.
# Usage: args=$(release_index_sign_args VERSION KEY BACKEND PASSWORD DIGEST)
#        cargo run -- sign-pending ... $args
release_index_sign_args() {
    local version="$1" key="$2" url="$3" pass="$4" digest="$5"
    local idx_path json path
    idx_path=$(release_index "$version")
    json=$(cargo run --quiet -- list-pending \
        --secret-key "$key" -u "$url" --password "$pass" --json 2>/dev/null)
    path=$(echo "$json" | jq -r ".pending_files[] | select(.path == \"$idx_path\") | .path")
    printf '%s --digest %s' "$path" "$digest"
}

print_summary() {
    local script_end total_elapsed
    script_end=$(date +%s)
    total_elapsed=$((script_end - SCRIPT_START))
    local total_steps=$((PASS_COUNT + EXPECTED_FAIL_COUNT))
    local minutes=$((total_elapsed / 60))
    local seconds=$((total_elapsed % 60))

    printf '\n'
    printf '%s%s╔══════════════════════════════════════════════════╗%s\n' "$BOLD" "$GREEN" "$RESET"
    printf '%s%s║            ALL TESTS PASSED                      ║%s\n' "$BOLD" "$GREEN" "$RESET"
    printf '%s%s╠══════════════════════════════════════════════════╣%s\n' "$BOLD" "$GREEN" "$RESET"
    printf '%s%s║%s  Steps passed:            %-23d%s%s║%s\n' \
        "$BOLD" "$GREEN" "$RESET" "$PASS_COUNT" "$BOLD" "$GREEN" "$RESET"
    printf '%s%s║%s  Expected failures:       %-23d%s%s║%s\n' \
        "$BOLD" "$GREEN" "$RESET" "$EXPECTED_FAIL_COUNT" "$BOLD" "$GREEN" "$RESET"
    printf '%s%s║%s  Total steps:             %-23d%s%s║%s\n' \
        "$BOLD" "$GREEN" "$RESET" "$total_steps" "$BOLD" "$GREEN" "$RESET"
    printf '%s%s║%s  Total time:              %-23s%s%s║%s\n' \
        "$BOLD" "$GREEN" "$RESET" "${minutes}m ${seconds}s" "$BOLD" "$GREEN" "$RESET"
    printf '%s%s╚══════════════════════════════════════════════════╝%s\n' "$BOLD" "$GREEN" "$RESET"
}
