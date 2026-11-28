
# Completion of key names and aliases, called by the specs of the key arguments.
__asfaload_cli_lister='@LISTER@'

# The last 5 arguments are the flags of the keys dir and config file options (short, long, short,
# long) and the mode. _arguments puts compadd options before them.
# Paths relative to the current directory are also accepted.
__asfaload_cli_keys() {
    local keys_dir_short=${@[-5]} keys_dir_long=${@[-4]}
    local config_file_short=${@[-3]} config_file_long=${@[-2]}
    local mode=${@[-1]} keys_dir config_file ret=1
    local -a candidates compadd_options
    compadd_options=("${@[1,-6]}")
    keys_dir=${opt_args[$keys_dir_long]:-${opt_args[$keys_dir_short]}}
    config_file=${opt_args[$config_file_long]:-${opt_args[$config_file_short]}}
    candidates=(${(f)"$(sh -c "$__asfaload_cli_lister" sh "$mode" "${(Q)keys_dir}" "${(Q)config_file}" 2>/dev/null)"})
    candidates=(${candidates:#})
    (( $#candidates )) && compadd "${compadd_options[@]}" -a candidates && ret=0
    _files && ret=0
    return ret
}
