#!/bin/bash
# `asfaload-cli shell` with fish.

. "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

skip_unless_installed fish

registers_completion() {
    new_test_env
    # complete -C prints the proposed words, followed by a tab and a description.
    run_cli_shell 'for c in (complete -C "asfaload-cli sh")
    echo "completion="(string replace -r "\t.*" "" -- $c)
end
echo "subshell=$ASFALOAD_SUBSHELL"
exit 3
' --shell fish
    assert_code 3
    assert_contains stdout "$OUT" "completion=share-key"
    assert_contains stdout "$OUT" "completion=shell"
    assert_contains stdout "$OUT" "subshell=1"
    assert_dir_empty "$TEST_TMP"
}

run_tests registers_completion
