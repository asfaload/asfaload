#!/bin/bash
# Bash completion that `asfaload-cli complete --shell bash` generates.

. "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

new_temp_dir WORK_DIR
COMPLETION_SCRIPT="$WORK_DIR/completion.bash"
"$CLI" complete --shell bash >"$COMPLETION_SCRIPT"

# Calls the completion function as bash does when the user presses TAB after the
# last word, and prints the proposed words, sorted. The function name comes from
# `complete -p`, so the test does not depend on the name that clap gives to it.
# The completion runs in COMPLETION_DIR, with the environment in COMPLETION_ENV.
# COMPLETION_INDEX selects a word to complete that is not the last word.
# Usage: bash_completions WORD...
bash_completions() {
    (cd "${COMPLETION_DIR:-.}" && env ${COMPLETION_ENV[@]+"${COMPLETION_ENV[@]}"} \
        bash --norc --noprofile -s "$COMPLETION_SCRIPT" "${COMPLETION_INDEX:-}" "$@") \
        <<'EOF' | sed '/^$/d' | LC_ALL=C sort
source "$1"; index="$2"; shift 2
completion_fn=$(complete -p asfaload-cli | sed -E 's/.*-F ([^ ]+).*/\1/')
COMP_WORDS=("$@")
COMP_CWORD=${index:-$(($# - 1))}
COMP_LINE="$*"
COMP_POINT=${#COMP_LINE}
previous=""
[ "$COMP_CWORD" -ge 1 ] && previous="${COMP_WORDS[COMP_CWORD-1]}"
"$completion_fn" "$1" "${COMP_WORDS[COMP_CWORD]}" "$previous"
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

# Usage: assert_completions EXPECTED WORD...
# EXPECTED has one word per line, sorted. The last WORD is the word to complete.
assert_completions() {
    assert_eq "completions of '${*:2}'" "$(bash_completions asfaload-cli "${@:2}")" "$1"
}

proposes_key_names_and_aliases() {
    new_keys_env
    COMPLETION_DIR="$LOCAL_DIR"
    assert_completions $'key_0\nkey_1\nlocal.key\nmy key' sign-pending -K ""
    assert_completions $'key_0\nkey_1' ping --secret-key key_
    # key_1 has no public key, key_2.pub no secret key.
    assert_completions "key_0" share-key key_
    assert_completions "my key" share-key m
    assert_completions "local.key" share-key l
    assert_completions $'alice\nbob.k\nkey_0\nkey_0.pub\nkey_1\nkey_2.pub\nlocal.key\nmy key\nmy key.pub' \
        keys ""
    assert_completions $'alice\nbob.k' new-signers-file -a ""
    # In new-signers-file, -d is --admin-key.
    assert_completions "alice" new-signers-file -A 1 -d a
    # The value of --keys-dir is not the key name.
    assert_completions "local.key" share-key --keys-dir ""
}

uses_the_locations_given_on_the_command_line() {
    new_keys_env
    COMPLETION_DIR="$LOCAL_DIR"
    assert_completions "key_4" share-key -d "$OTHER_KEYS_DIR" key_
    assert_completions "key_4" share-key --keys-dir = "$OTHER_KEYS_DIR" key_
    assert_completions "key_4" share-key -d"$OTHER_KEYS_DIR" key_
    # bash splits -d=DIR in 3 words when '=' is in COMP_WORDBREAKS.
    assert_completions "key_4" share-key -d = "$OTHER_KEYS_DIR" key_
    assert_completions "key_4" share-key -d="$OTHER_KEYS_DIR" key_
    assert_completions "carol" keys -c "$OTHER_CONFIG_FILE" c
    assert_completions "carol" keys -c"$OTHER_CONFIG_FILE" c
    # The options after the word to complete also count.
    COMPLETION_INDEX=2 assert_completions "key_4" share-key key_ -d "$OTHER_KEYS_DIR"
    COMPLETION_INDEX=2 assert_completions "key_4" share-key key_ --keys-dir="$OTHER_KEYS_DIR"
    COMPLETION_INDEX=2 assert_completions "carol" keys c -c "$OTHER_CONFIG_FILE"
    COMPLETION_ENV+=(ASFALOAD_KEYS_DIR="$OTHER_KEYS_DIR")
    assert_completions "key_4" share-key key_
}

uses_the_xdg_data_dir_by_default() {
    new_keys_env
    COMPLETION_DIR="$LOCAL_DIR"
    local entry env=(-u ASFALOAD_KEYS_DIR)
    for entry in "${COMPLETION_ENV[@]}"; do
        [[ $entry == ASFALOAD_KEYS_DIR=* ]] || env+=("$entry")
    done
    COMPLETION_ENV=("${env[@]}" XDG_DATA_HOME="$XDG_DATA_DIR")
    assert_completions "key_5" share-key key_
}

is_silent_without_keys_dir() {
    new_keys_env
    COMPLETION_DIR="$LOCAL_DIR"
    COMPLETION_ENV+=(ASFALOAD_KEYS_DIR="$LOCAL_DIR/missing" ASFALOAD_CONFIG_FILE="$LOCAL_DIR/missing")
    local output
    output="$(bash_completions asfaload-cli keys x 2>&1)"
    assert_eq "output of the completion" "$output" ""
}

# Prints the calls to compopt when the completion function completes the last word. compopt
# works only in a real completion, so a function replaces it.
# Usage: bash_compopt_calls WORD...
bash_compopt_calls() {
    (cd "$COMPLETION_DIR" && env "${COMPLETION_ENV[@]}" \
        bash --norc --noprofile -s "$COMPLETION_SCRIPT" "$@") <<'EOF'
source "$1"; shift
compopt() { printf 'compopt %s\n' "$*"; }
completion_fn=$(complete -p asfaload-cli | sed -E 's/.*-F ([^ ]+).*/\1/')
COMP_WORDS=("$@")
COMP_CWORD=$(($# - 1))
"$completion_fn" "$1" "${@: -1}" "${@: -2:1}"
EOF
}

proposes_no_file_names_for_aliases() {
    new_keys_env
    COMPLETION_DIR="$LOCAL_DIR"
    # Without a matching alias, bash would use its default completion of file names.
    assert_eq "compopt calls for an alias" \
        "$(bash_compopt_calls asfaload-cli new-signers-file -a l)" \
        "compopt +o default +o bashdefault"
    assert_eq "compopt calls for a key" \
        "$(bash_compopt_calls asfaload-cli sign-pending -K l)" "compopt -o filenames"
}

run_tests proposes_subcommands_and_their_flags proposes_key_names_and_aliases \
    uses_the_locations_given_on_the_command_line uses_the_xdg_data_dir_by_default \
    is_silent_without_keys_dir proposes_no_file_names_for_aliases
