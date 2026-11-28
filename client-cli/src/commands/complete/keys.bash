
# Completion of key names and aliases. The clap function completes all other words.
__asfaload_cli_lister='@LISTER@'

# Prints the value of the option $1 (short) or $2 (long) in the words, but the current word.
__asfaload_cli_option_value() {
    local i value_index word value=""
    for (( i = 1; i < ${#COMP_WORDS[@]}; i++ )); do
        (( i == COMP_CWORD )) && continue
        word=${COMP_WORDS[i]}
        case $word in
            "$1" | "$2")
                # bash splits --opt=value in 3 words when '=' is in COMP_WORDBREAKS.
                value_index=$((i + 1))
                [[ ${COMP_WORDS[value_index]} == "=" ]] && value_index=$((i + 2))
                if (( value_index != COMP_CWORD && value_index < ${#COMP_WORDS[@]} )); then
                    value=${COMP_WORDS[value_index]}
                fi
                ;;
            "$2="*) value=${word#"$2="} ;;
            # A value attached to a short option: -dDIR or -d=DIR.
            "$1"?*)
                if (( ${#1} == 2 )); then
                    value=${word#"$1"}
                    value=${value#=}
                fi
                ;;
        esac
    done
    printf '%s\n' "$value"
}

# Prints the mode of the option $2 of the subcommand $1, or nothing.
__asfaload_cli_option_mode() {
    case "$1 $2" in
@OPTION_CASES@
    esac
}

# Prints the flags of the keys dir and config file options of the subcommand $1: short, long,
# short, long.
__asfaload_cli_location_flags() {
    case $1 in
@LOCATION_CASES@
    esac
}

# Prints the mode when the current word is the first positional of the subcommand $1, which is
# the word at index $2. Prints nothing otherwise.
__asfaload_cli_positional_mode() {
    local mode value_options i word
    case $1 in
@POSITIONAL_CASES@
        *) return 0 ;;
    esac
    for (( i = $2 + 1; i < COMP_CWORD; i++ )); do
        word=${COMP_WORDS[i]}
        if [[ $value_options == *" $word "* || $word == "=" ]]; then
            i=$((i + 1))
            [[ ${COMP_WORDS[i]} == "=" ]] && i=$((i + 1))
            # The current word is the value of the option.
            (( i >= COMP_CWORD )) && return 0
        elif [[ $word != -* ]]; then
            return 0
        fi
    done
    printf '%s\n' "$mode"
}

@WRAPPER@() {
    local cur prev sub="" sub_index=0 i mode="" keys_dir config_file candidate seen=$'\n'
    local keys_dir_short keys_dir_long config_file_short config_file_long
    if [[ "${BASH_VERSINFO[0]}" -ge 4 ]]; then
        cur="$2"
    else
        cur="${COMP_WORDS[COMP_CWORD]}"
    fi
    [[ $cur == "=" ]] && cur=""
    prev="$3"
    if [[ $prev == "=" ]] && (( COMP_CWORD >= 2 )); then
        prev=${COMP_WORDS[COMP_CWORD-2]}
    fi
    for (( i = 1; i < COMP_CWORD; i++ )); do
        if [[ ${COMP_WORDS[i]} != -* ]]; then
            sub=${COMP_WORDS[i]}
            sub_index=$i
            break
        fi
    done
    if [[ -n $sub ]]; then
        mode=$(__asfaload_cli_option_mode "$sub" "$prev")
        if [[ -z $mode && $cur != -* ]]; then
            mode=$(__asfaload_cli_positional_mode "$sub" "$sub_index")
        fi
    fi
    if [[ -z $mode ]]; then
        @CLAP_FUNCTION@ "$@"
        return
    fi
    read -r keys_dir_short keys_dir_long config_file_short config_file_long \
        <<<"$(__asfaload_cli_location_flags "$sub")"
    keys_dir=$(__asfaload_cli_option_value "$keys_dir_short" "$keys_dir_long")
    config_file=$(__asfaload_cli_option_value "$config_file_short" "$config_file_long")
    COMPREPLY=()
    while IFS= read -r candidate; do
        [[ $candidate == "$cur"* && $seen != *$'\n'"$candidate"$'\n'* ]] || continue
        COMPREPLY+=("$candidate")
        seen+="$candidate"$'\n'
    done < <(
        sh -c "$__asfaload_cli_lister" sh "$mode" "$keys_dir" "$config_file" 2>/dev/null
        # Paths relative to the current directory are also accepted.
        compgen -f -- "$cur"
    )
    # Quotes the inserted names, e.g. a name with a space. Not available in bash 3.
    compopt -o filenames 2>/dev/null
    return 0
}

if [[ "${BASH_VERSINFO[0]}" -eq 4 && "${BASH_VERSINFO[1]}" -ge 4 || "${BASH_VERSINFO[0]}" -gt 4 ]]; then
    complete -F @WRAPPER@ -o nosort -o bashdefault -o default @BIN@
else
    complete -F @WRAPPER@ -o bashdefault -o default @BIN@
fi
