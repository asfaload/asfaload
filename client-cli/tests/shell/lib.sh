# Helpers for the shell integration tests of asfaload-cli.
# Source this file from a test script.

set -euo pipefail

_LIB_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
_REPO_ROOT="$(cd "$_LIB_DIR/../../.." && pwd)"
# pwd -P because the CLI finds its directory from the resolved executable path.
_CLI_PATH="${ASFALOAD_CLI:-${CARGO_TARGET_DIR:-$_REPO_ROOT/target}/debug/asfaload-cli}"
if [[ ! -x "$_CLI_PATH" ]]; then
    printf 'asfaload-cli not found at %s, build it with: cargo build --package client-cli\n' \
        "$_CLI_PATH" >&2
    exit 1
fi
CLI_DIR="$(cd "$(dirname "$_CLI_PATH")" && pwd -P)"
CLI="$CLI_DIR/$(basename "$_CLI_PATH")"

_to_delete=()
_cleanup() {
    for path in "${_to_delete[@]+"${_to_delete[@]}"}"; do
        rm -rf "$path"
    done
}
trap _cleanup EXIT

# Also prints the stderr of the last command run with run_cli_shell, because
# the shell reports startup errors there.
fail() {
    printf 'FAIL: %s\n' "$*" >&2
    if [[ -n "${ERR-}" ]]; then
        printf 'stderr of the command:\n%s\n' "$ERR" >&2
    fi
    exit 1
}

# Sets VAR to a new temporary directory that is removed at exit. It sets a
# variable instead of printing, because $(...) would lose the registration.
# Usage: new_temp_dir VAR
new_temp_dir() {
    local dir
    dir="$(mktemp -d)"
    _to_delete+=("$dir")
    printf -v "$1" '%s' "$dir"
}

skip_unless_installed() {
    if ! command -v "$1" >/dev/null 2>&1; then
        printf 'SKIP: %s is not installed\n' "$1"
        exit 0
    fi
}

# An interactive shell that is not in the foreground process group of its
# terminal stops itself. We start it in a new session without a terminal.
_detach() {
    if command -v setsid >/dev/null 2>&1; then
        setsid --wait "$@"
    else
        "$@"
    fi
}

# Runs `asfaload-cli shell ARGS...` with STDIN as input and sets OUT, ERR and CODE.
# HOME and TMPDIR are the directories in TEST_HOME and TEST_TMP, so that the
# configuration of the machine is not loaded. Assignments in the SHELL_ENV array
# are added to the environment.
# Usage: run_cli_shell STDIN [ARGS...]
run_cli_shell() {
    local stdin="$1"
    shift
    local out_file err_file
    out_file="$(mktemp)"
    err_file="$(mktemp)"
    CODE=0
    printf '%s' "$stdin" | _detach env -u ZDOTDIR -u XDG_CONFIG_HOME -u XDG_DATA_HOME \
        HOME="$TEST_HOME" TMPDIR="$TEST_TMP" ${SHELL_ENV[@]+"${SHELL_ENV[@]}"} \
        "$CLI" shell "$@" >"$out_file" 2>"$err_file" || CODE=$?
    OUT="$(cat "$out_file")"
    ERR="$(cat "$err_file")"
    rm -f "$out_file" "$err_file"
}

# Sets TEST_HOME and TEST_TMP to new empty directories, and clears SHELL_ENV.
new_test_env() {
    new_temp_dir TEST_HOME
    new_temp_dir TEST_TMP
    SHELL_ENV=()
}

assert_code() {
    [[ "$CODE" -eq "$1" ]] || fail "expected exit code $1, got $CODE"
}

assert_failure() {
    [[ "$CODE" -ne 0 ]] || fail "expected failure, got exit code 0"
}

# Usage: assert_contains NAME TEXT EXPECTED
assert_contains() {
    [[ "$2" == *"$3"* ]] || fail "$1 does not contain '$3':"$'\n'"$2"
}

# Usage: assert_matches NAME TEXT REGEX
assert_matches() {
    [[ "$2" =~ $3 ]] || fail "$1 does not match '$3':"$'\n'"$2"
}

# Usage: assert_eq NAME ACTUAL EXPECTED
assert_eq() {
    [[ "$2" == "$3" ]] || fail "$1: expected '$3', got '$2'"
}

assert_dir_empty() {
    local entries
    entries="$(ls -A "$1")"
    [[ -z "$entries" ]] || fail "directory $1 not empty: $entries"
}

# Creates the keys dirs and config files of the key completion tests, with fixture keys.
# Sets KEYS_DIR, OTHER_KEYS_DIR, OTHER_CONFIG_FILE, XDG_DATA_DIR, LOCAL_DIR (the current dir of
# the completion), and COMPLETION_ENV, the environment that selects KEYS_DIR and its config file.
new_keys_env() {
    local fixtures="$_REPO_ROOT/core/test_helpers/fixtures/keys" root config_file
    new_temp_dir root
    KEYS_DIR="$root/keys"
    OTHER_KEYS_DIR="$root/other keys"
    OTHER_CONFIG_FILE="$root/other.toml"
    LOCAL_DIR="$root/local"
    config_file="$root/config.toml"
    mkdir -p "$KEYS_DIR" "$OTHER_KEYS_DIR" "$LOCAL_DIR" "$root/home" "$root/xdg/asfaload-cli"
    cp "$fixtures/key_0" "$fixtures/key_0.pub" "$fixtures/key_1" "$fixtures/key_2.pub" "$KEYS_DIR"
    cp "$fixtures/key_3" "$KEYS_DIR/my key"
    cp "$fixtures/key_3.pub" "$KEYS_DIR/my key.pub"
    echo "not a key" >"$KEYS_DIR/notes.txt"
    cp "$fixtures/key_4" "$fixtures/key_4.pub" "$OTHER_KEYS_DIR"
    cp "$fixtures/key_5" "$fixtures/key_5.pub" "$root/xdg/asfaload-cli"
    touch "$LOCAL_DIR/local.key"
    printf '[aliases]\nalice = "%s"\n"bob.k" = "%s"\n' \
        "$(cat "$fixtures/key_0.pub")" "$(cat "$fixtures/key_1.pub")" >"$config_file"
    printf '[aliases]\ncarol = "%s"\n' "$(cat "$fixtures/key_4.pub")" >"$OTHER_CONFIG_FILE"
    XDG_DATA_DIR="$root/xdg"
    COMPLETION_ENV=(-u XDG_DATA_HOME -u XDG_CONFIG_HOME HOME="$root/home"
        ASFALOAD_KEYS_DIR="$KEYS_DIR" ASFALOAD_CONFIG_FILE="$config_file")
}

# Runs the test functions given as arguments, and stops at the first failure.
run_tests() {
    for test_fn in "$@"; do
        "$test_fn"
        printf 'PASS: %s\n' "$test_fn"
    done
}
