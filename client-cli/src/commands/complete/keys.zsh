
# Completion of key names and aliases, called by the specs of the key arguments.
__asfaload_cli_lister='@LISTER@'

# The last argument is the mode. _arguments puts compadd options before it.
# Paths relative to the current directory are also accepted, but for aliases.
__asfaload_cli_keys() {
    local mode=${@[-1]} keys_dir config_file ret=1
    local -a candidates compadd_options
    compadd_options=("${@[1,-2]}")
    keys_dir=${opt_args[@KEYS_DIR_LONG@]:-${opt_args[@KEYS_DIR_SHORT@]}}
    config_file=${opt_args[@CONFIG_FILE_LONG@]:-${opt_args[@CONFIG_FILE_SHORT@]}}
    candidates=(${(f)"$(sh -c "$__asfaload_cli_lister" sh "$mode" "${(Q)keys_dir}" "${(Q)config_file}" 2>/dev/null)"})
    candidates=(${candidates:#})
    (( $#candidates )) && compadd "${compadd_options[@]}" -a candidates && ret=0
    if [[ $mode != aliases ]]; then
        _files && ret=0
    fi
    return ret
}
