#!/bin/bash
# `asfaload-cli shell` with zsh.

. "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

skip_unless_installed zsh

loads_user_zshrc_and_registers_completion() {
    new_test_env
    printf 'export USER_RC_LOADED=yes\n' >"$TEST_HOME/.zshrc"
    run_cli_shell 'print -r -- "compdef=${_comps[asfaload-cli]}"
echo "rc=$USER_RC_LOADED"
echo "subshell=$ASFALOAD_SUBSHELL"
exit 3
' --shell zsh
    assert_code 3
    assert_contains stdout "$OUT" "compdef=_asfaload"
    assert_contains stdout "$OUT" "rc=yes"
    assert_contains stdout "$OUT" "subshell=1"
    assert_dir_empty "$TEST_TMP"
}

follows_zdotdir_set_in_user_zshenv() {
    new_test_env
    mkdir "$TEST_HOME/zdot"
    printf 'ZDOTDIR="$HOME/zdot"\n' >"$TEST_HOME/.zshenv"
    printf 'export USER_RC_LOADED=yes\n' >"$TEST_HOME/zdot/.zshrc"
    run_cli_shell 'echo "rc=$USER_RC_LOADED"
echo "zdotdir=$ZDOTDIR"
exit 0
' --shell zsh
    assert_code 0
    assert_contains stdout "$OUT" "rc=yes"
    assert_contains stdout "$OUT" "zdotdir=$TEST_HOME/zdot"
}

run_tests \
    loads_user_zshrc_and_registers_completion \
    follows_zdotdir_set_in_user_zshenv
