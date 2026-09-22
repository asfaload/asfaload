# Shared setup functions for manual test environments.
#
# Each tests/manual_tests/<env>/setup script sources this after
# tests/e2e_tests/lib/helpers.sh (which provides the color variables, the
# constants, key_password, and the fixture key paths), then runs its
# scenario-specific steps (fixture generation, tampering, welcome text)
# before calling mt_spawn_shell.
#
# Functions set these variables for the caller:
#   WORK_DIR            temp workspace, removed by mt_cleanup
#   PASSWORD_FILE       file containing the fixture key password
#   CLI                 path to the built asfaload-cli binary
#   FS_ROOT PROJECT_DIR file server root and project dir within it
#   FILE_SERVER_URL     local file server address
#   BACKEND_REPO        backend git repo working tree
#   BACKEND_URL         backend REST API address
#
# Scenario-specific environment variables to expose in the spawned shell can
# be appended to the MT_RC_EXTRA_EXPORTS array before calling mt_spawn_shell.

MT_RC_EXTRA_EXPORTS=()

mt_cleanup() {
    [[ -n "$SERVER_PID" ]] && kill "$SERVER_PID" 2>/dev/null || true
    [[ -n "$FILE_SERVER_PID" ]] && kill "$FILE_SERVER_PID" 2>/dev/null || true
    [[ -n "$SERVER_PID" ]] && wait "$SERVER_PID" 2>/dev/null || true
    [[ -n "$FILE_SERVER_PID" ]] && wait "$FILE_SERVER_PID" 2>/dev/null || true
    [[ -n "$WORK_DIR" ]] && rm -rf "$WORK_DIR"
}

# Create the temp workspace, the password file, and the cleanup trap.
mt_init_workspace() {
    WORK_DIR=$(mktemp -d)
    SERVER_PID=""
    FILE_SERVER_PID=""

    PASSWORD_FILE="$WORK_DIR/password"
    printf '%s' "$key_password" > "$PASSWORD_FILE"
    export ASFALOAD_PASSWORD_FILE="$PASSWORD_FILE"

    trap mt_cleanup EXIT
}

mt_build_binaries() {
    printf '%sBuilding binaries...%s ' "$DIM" "$RESET"
    cargo build --quiet \
        --manifest-path "$REPO_ROOT/Cargo.toml" \
        -p rest-api -p test-file-server -p client-cli 2>&1
    printf '%s✓%s\n' "$GREEN" "$RESET"

    CLI="$REPO_ROOT/target/debug/asfaload-cli"
}

mt_start_file_server() {
    FS_ROOT="$WORK_DIR/fs"
    PROJECT_DIR="$FS_ROOT/project"
    mkdir -p "$PROJECT_DIR"

    FILE_SERVER_LOG="$WORK_DIR/file-server.log"
    "$REPO_ROOT/target/debug/test-file-server" --dir "$FS_ROOT" \
        > "$FILE_SERVER_LOG" 2>&1 &
    FILE_SERVER_PID=$!

    printf '%sStarting file server...%s ' "$DIM" "$RESET"
    FILE_SERVER_PORT=""
    for _i in $(seq 1 30); do
        FILE_SERVER_PORT=$(grep -oP 'LISTENING_PORT=\K[0-9]+' "$FILE_SERVER_LOG" 2>/dev/null || true)
        [[ -n "$FILE_SERVER_PORT" ]] && break
        if ! kill -0 "$FILE_SERVER_PID" 2>/dev/null; then
            printf '%s✗%s\n' "$RED" "$RESET"
            printf '%sFile server process died unexpectedly.%s\n' "$RED" "$RESET" >&2
            exit 1
        fi
        sleep 0.2
    done

    if [[ -z "$FILE_SERVER_PORT" ]]; then
        printf '%s✗%s\n' "$RED" "$RESET"
        printf '%sFile server did not report a port within 6 seconds.%s\n' "$RED" "$RESET" >&2
        exit 1
    fi

    FILE_SERVER_URL="http://localhost:${FILE_SERVER_PORT}"
    printf '%s✓ %s%s\n' "$GREEN" "$FILE_SERVER_URL" "$RESET"
}

mt_start_backend() {
    BACKEND_REPO="$WORK_DIR/repo"
    init_backend_repo "$BACKEND_REPO"
    export ASFALOAD_GIT_REPO_PATH="$BACKEND_REPO"
    export ASFALOAD_GIT_BACKEND="sha256"

    BACKEND_PORT=$((3000 + RANDOM % 1000))
    export ASFALOAD_SERVER_PORT="$BACKEND_PORT"
    BACKEND_URL="http://localhost:${BACKEND_PORT}"

    SERVER_LOG="$WORK_DIR/server.log"
    "$REPO_ROOT/target/debug/rest-api" > "$SERVER_LOG" 2>&1 &
    SERVER_PID=$!

    printf '%sStarting backend...%s ' "$DIM" "$RESET"
    for _i in $(seq 1 30); do
        if curl "$BACKEND_URL" --silent > /dev/null 2>&1; then
            break
        fi
        if ! kill -0 "$SERVER_PID" 2>/dev/null; then
            printf '%s✗%s\n' "$RED" "$RESET"
            printf '%sBackend process died unexpectedly.%s\n' "$RED" "$RESET" >&2
            exit 1
        fi
        sleep 0.5
    done

    if ! curl "$BACKEND_URL" --silent > /dev/null 2>&1; then
        printf '%s✗%s\n' "$RED" "$RESET"
        printf '%sBackend did not become ready within 15 seconds.%s\n' "$RED" "$RESET" >&2
        exit 1
    fi

    printf '%s✓ %s%s\n' "$GREEN" "$BACKEND_URL" "$RESET"
}

# Spawn the interactive shell with the standard connection environment.
# Entries of MT_RC_EXTRA_EXPORTS are exported verbatim in the spawned shell.
mt_spawn_shell() {
    RC_FILE="$WORK_DIR/env.sh"
    {
        printf '[ -f ~/.bashrc ] && source ~/.bashrc\n\n'
        printf 'export ASFALOAD_BACKEND_URL="%s"\n' "$BACKEND_URL"
        printf 'export ASFALOAD_PASSWORD_FILE="%s"\n' "$PASSWORD_FILE"
        printf 'export KEY_0="%s"\n' "$KEY_0"
        printf 'export KEY_1="%s"\n' "$KEY_1"
        printf 'export KEY_2="%s"\n' "$KEY_2"
        printf 'export FILE_SERVER_URL="%s"\n' "$FILE_SERVER_URL"
        printf 'export PATH="%s:$PATH"\n' "$REPO_ROOT/target/debug"
        if [[ ${#MT_RC_EXTRA_EXPORTS[@]} -gt 0 ]]; then
            printf '\n# Scenario-specific exports\n'
            local _export_line
            for _export_line in "${MT_RC_EXTRA_EXPORTS[@]}"; do
                printf 'export %s\n' "$_export_line"
            done
        fi
        printf '\nPS1="[asfaload-dev] \\w\\$ "\n'
    } > "$RC_FILE"

    bash --rcfile "$RC_FILE"
}
