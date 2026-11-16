#!/bin/bash
# Bash completion that `asfaload-cli complete --shell bash` generates.

. "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

new_temp_dir WORK_DIR
COMPLETION_SCRIPT="$WORK_DIR/completion.bash"
"$CLI" complete --shell bash >"$COMPLETION_SCRIPT"

# Calls the completion function as bash does when the user presses TAB after the
# last word, and prints the proposed words, sorted. The function name comes from
# `complete -p`, so the test does not depend on the name that clap gives to it.
# Usage: bash_completions WORD...
bash_completions() {
    bash --norc --noprofile -s "$COMPLETION_SCRIPT" "$@" <<'EOF' | sed '/^$/d' | sort
source "$1"; shift
completion_fn=$(complete -p asfaload-cli | sed -E 's/.*-F ([^ ]+).*/\1/')
COMP_WORDS=("$@")
COMP_CWORD=$(($# - 1))
COMP_LINE="$*"
COMP_POINT=${#COMP_LINE}
previous=""
[ $# -ge 2 ] && previous="${@: -2:1}"
"$completion_fn" "$1" "${@: -1}" "$previous"
printf '%s\n' "${COMPREPLY[@]}"
EOF
}

proposes_subcommands_and_their_flags() {
    assert_eq "completions of 'sh'" "$(bash_completions asfaload-cli sh)" $'share-key\nshell'
    assert_eq "completions of 'new-keys --n'" \
        "$(bash_completions asfaload-cli new-keys --n)" "--name"
    assert_eq "completions of 'check-index --b'" \
        "$(bash_completions asfaload-cli check-index --b)" "--backend-url"
}

run_tests proposes_subcommands_and_their_flags
