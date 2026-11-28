#!/bin/bash
# Fish completion of key names and aliases that `asfaload-cli complete --shell fish` generates.

. "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

skip_unless_installed fish

new_temp_dir WORK_DIR
COMPLETION_SCRIPT="$WORK_DIR/completion.fish"
"$CLI" complete --shell fish >"$COMPLETION_SCRIPT"

# Prints the words that fish proposes for the command line LINE, sorted. The completion runs in
# COMPLETION_DIR, with the environment in COMPLETION_ENV.
# Usage: fish_completions LINE
fish_completions() {
    # complete -C prints the proposed words, followed by a tab and a description.
    (cd "$COMPLETION_DIR" && env "${COMPLETION_ENV[@]}" \
        fish --no-config -c 'source $argv[1]; complete -C $argv[2]' "$COMPLETION_SCRIPT" "$1") |
        cut -f1 | LC_ALL=C sort
}

# complete -C puts the cursor at the end of the line. To complete an other token, a function
# replaces the builtin commandline and gives TOKENS, with the cursor in the token at INDEX
# (from 1). Prints the candidates of __asfaload_cli_keys with ARGS (its arguments, separated by
# spaces), before fish removes those that do not match.
# Usage: fish_keys_at ARGS INDEX TOKEN...
fish_keys_at() {
    (cd "$COMPLETION_DIR" && env "${COMPLETION_ENV[@]}" fish --no-config -c '
        source $argv[1]
        set -g test_index $argv[3]
        set -g test_tokens $argv[4..-1]
        function commandline
            switch "$argv"
                case -op
                    printf "%s\n" $test_tokens
                case -opc
                    printf "%s\n" $test_tokens[1..(math $test_index - 1)]
                case -ct
                    printf "%s\n" $test_tokens[$test_index]
            end
        end
        __asfaload_cli_keys (string split " " -- $argv[2])' "$COMPLETION_SCRIPT" "$@") |
        LC_ALL=C sort
}

# Usage: assert_completions EXPECTED LINE
# EXPECTED has one word per line, sorted.
assert_completions() {
    assert_eq "completions of '$2'" "$(fish_completions "$2")" "$1"
}

proposes_key_names_and_aliases() {
    new_keys_env
    COMPLETION_DIR="$LOCAL_DIR"
    assert_completions $'key_0\nkey_1\nlocal.key\nmy key' "asfaload-cli sign-pending -K "
    assert_completions $'key_0\nkey_1' "asfaload-cli ping --secret-key key_"
    # key_1 has no public key, key_2.pub no secret key.
    assert_completions "key_0" "asfaload-cli share-key key_"
    assert_completions "my key" "asfaload-cli share-key m"
    assert_completions "local.key" "asfaload-cli share-key l"
    assert_completions $'alice\nbob.k\nkey_0\nkey_0.pub\nkey_1\nkey_2.pub\nlocal.key\nmy key\nmy key.pub' \
        "asfaload-cli keys "
    # Public keys: aliases, key pair names and local files.
    assert_completions $'alice\nbob.k\nkey_0\nlocal.key\nmy key' "asfaload-cli new-signers-file -a "
    # In new-signers-file, -d is --admin-key, not the keys dir.
    assert_completions "alice" "asfaload-cli new-signers-file -A 1 -d a"
    assert_completions "key_0" "asfaload-cli new-signers-file -d alice -a key_"
    # The value of --keys-dir is not the key name.
    assert_completions "local.key" "asfaload-cli share-key --keys-dir "
}

uses_the_locations_given_on_the_command_line() {
    new_keys_env
    COMPLETION_DIR="$LOCAL_DIR"
    assert_completions "key_4" "asfaload-cli share-key --keys-dir '$OTHER_KEYS_DIR' key_"
    assert_completions "key_4" "asfaload-cli share-key --keys-dir='$OTHER_KEYS_DIR' key_"
    assert_completions "carol" "asfaload-cli keys -c='$OTHER_CONFIG_FILE' c"
    assert_completions "carol" "asfaload-cli keys -c '$OTHER_CONFIG_FILE' c"
    assert_completions "key_4" "asfaload-cli new-signers-file --keys-dir '$OTHER_KEYS_DIR' -a key_"
    assert_completions "carol" "asfaload-cli keys -c'$OTHER_CONFIG_FILE' c"
    # The options after the token to complete also count.
    assert_eq "pairs with --keys-dir after the cursor" \
        "$(fish_keys_at "--keys-dir --keys-dir --config-file --config-file pairs" 3 \
            asfaload-cli share-key k --keys-dir "$OTHER_KEYS_DIR")" "key_4"
    assert_eq "public keys with -c and --keys-dir after the cursor" \
        "$(fish_keys_at "--keys-dir --keys-dir -c --config-file public_keys" 3 asfaload-cli \
            new-signers-file a -c "$OTHER_CONFIG_FILE" --keys-dir "$OTHER_KEYS_DIR")" $'carol\nkey_4'
    COMPLETION_ENV+=(ASFALOAD_KEYS_DIR="$OTHER_KEYS_DIR")
    assert_completions "key_4" "asfaload-cli share-key key_"
}

uses_the_xdg_data_dir_by_default() {
    new_keys_env
    COMPLETION_DIR="$LOCAL_DIR"
    local entry env=(-u ASFALOAD_KEYS_DIR)
    for entry in "${COMPLETION_ENV[@]}"; do
        [[ $entry == ASFALOAD_KEYS_DIR=* ]] || env+=("$entry")
    done
    COMPLETION_ENV=("${env[@]}" XDG_DATA_HOME="$XDG_DATA_DIR")
    assert_completions "key_5" "asfaload-cli share-key key_"
}

is_silent_without_keys_dir() {
    new_keys_env
    COMPLETION_DIR="$LOCAL_DIR"
    COMPLETION_ENV+=(ASFALOAD_KEYS_DIR="$LOCAL_DIR/missing" ASFALOAD_CONFIG_FILE="$LOCAL_DIR/missing")
    local output
    output="$(fish_completions "asfaload-cli keys x" 2>&1)"
    assert_eq "output of the completion" "$output" ""
}

run_tests proposes_key_names_and_aliases uses_the_locations_given_on_the_command_line \
    uses_the_xdg_data_dir_by_default is_silent_without_keys_dir
