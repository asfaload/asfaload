#!/bin/bash
# `asfaload-cli shell` with bash, and the errors that do not depend on the shell.

. "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

defaults_to_bash_with_completion_and_returns_shell_exit_code() {
    new_test_env
    run_cli_shell 'complete -p asfaload-cli
echo "subshell=$ASFALOAD_SUBSHELL"
exit 3
'
    assert_code 3
    assert_matches stdout "$OUT" 'complete .*-F [^ ]+ asfaload-cli'
    assert_contains stdout "$OUT" "subshell=1"
    assert_contains stderr "$ERR" "Starting bash with asfaload-cli completion"
    assert_dir_empty "$TEST_TMP"
}

loads_user_bashrc_and_keeps_binary_dir_first_on_path() {
    new_test_env
    printf 'export USER_RC_LOADED=yes\nexport PATH=/usr/bin:/bin\n' >"$TEST_HOME/.bashrc"
    run_cli_shell 'echo "rc=$USER_RC_LOADED"
echo "path=$PATH"
exit 0
' --shell bash
    assert_code 0
    assert_contains stdout "$OUT" "rc=yes"
    assert_contains stdout "$OUT" "path=$CLI_DIR:/usr/bin:/bin"
}

fails_when_shell_program_is_not_on_path() {
    new_test_env
    local empty_path
    new_temp_dir empty_path
    SHELL_ENV=("PATH=$empty_path")
    run_cli_shell ''
    assert_failure
    assert_contains stderr "$ERR" "Shell program bash was not found on PATH"
    assert_dir_empty "$TEST_TMP"
}

rejects_unsupported_shell() {
    new_test_env
    run_cli_shell '' --shell powershell
    assert_failure
    assert_contains stderr "$ERR" "invalid value 'powershell'"
}

run_tests \
    defaults_to_bash_with_completion_and_returns_shell_exit_code \
    loads_user_bashrc_and_keeps_binary_dir_first_on_path \
    fails_when_shell_program_is_not_on_path \
    rejects_unsupported_shell
