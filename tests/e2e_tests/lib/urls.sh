# --- E2E test URL builders ---
# Derives TEST_NAME from the calling script's $0.
# Provides functions to build URLs for the e2e test repo.

E2E_REPO="asfaload/repo_for_e2e_tests"
TEST_NAME="$(basename "$0" .sh)"

# Signers file suffix for the e2e test repo, derived from KEY_TYPE.
case "$KEY_TYPE" in
    asfaload) _SIGNERS_SUFFIX="_asfaload" ;;
    *)
        printf 'urls.sh: unsupported KEY_TYPE: %s\n' "$KEY_TYPE" >&2
        exit 1
        ;;
esac

signers_file() {
    local n="$1"
    echo "https://github.com/${E2E_REPO}/blob/master/${TEST_NAME}/signers_file_${n}${_SIGNERS_SUFFIX}.json"
}

# Raw URL of a signers file, as served by raw.githubusercontent.com.
# A github.com blob URL returns an HTML page with per-request tokens, so two
# fetches of the same blob URL never return the same bytes: no stable digest
# can be computed from it. forge-url maps raw and blob URLs of the same repo
# to the same backend path, so both forms register identically.
signers_file_raw() {
    local n="$1"
    echo "https://raw.githubusercontent.com/${E2E_REPO}/master/${TEST_NAME}/signers_file_${n}${_SIGNERS_SUFFIX}.json"
}

pending_signers_file() {
    echo "https/github.com/443/${E2E_REPO}/asfaload.signers.pending/index.json"
}

release_url() {
    local version="$1"
    echo "https://github.com/${E2E_REPO}/releases/tag/v${version}"
}

release_index() {
    local version="$1"
    echo "https/github.com/443/${E2E_REPO}/releases/tag/v${version}/asfaload.index.json"
}

artifact_url() {
    local version="$1"
    echo "https://github.com/${E2E_REPO}/releases/download/v${version}/artifact.bin"
}
