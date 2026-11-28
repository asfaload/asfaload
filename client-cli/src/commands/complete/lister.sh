# Prints completion candidates, one per line. Arguments: MODE KEYS_DIR CONFIG_FILE.
# MODE is secret, pairs, names or public_keys. An empty KEYS_DIR or CONFIG_FILE selects the
# location like asfaload-cli does. Errors are silent: completion must not print on the terminal.
mode=$1
keys_dir=$2
config_file=$3

# Like etcetera, a relative XDG dir is ignored.
xdg_dir() {
    case $1 in
        /*) printf '%s\n' "$1" ;;
        *) printf '%s\n' "$HOME/$2" ;;
    esac
}

expand_tilde() {
    case $1 in
        "~/"*) printf '%s\n' "$HOME/${1#"~/"}" ;;
        *) printf '%s\n' "$1" ;;
    esac
}

if [ -n "$keys_dir" ]; then
    keys_dir=$(expand_tilde "$keys_dir")
elif [ -n "${@KEYS_DIR_ENV@:-}" ]; then
    keys_dir=$@KEYS_DIR_ENV@
else
    keys_dir="$(xdg_dir "${XDG_DATA_HOME:-}" .local/share)/asfaload-cli"
fi

if [ -n "$config_file" ]; then
    config_file=$(expand_tilde "$config_file")
elif [ -n "${@CONFIG_FILE_ENV@:-}" ]; then
    config_file=$@CONFIG_FILE_ENV@
else
    config_file="$(xdg_dir "${XDG_CONFIG_HOME:-}" .config)/asfaload-cli/config.toml"
fi

# Prints secret, public or nothing, from the first bytes of the file, like asfaload-cli.
key_kind() {
    head=$(dd if="$1" bs=@HEAD_SIZE@ count=1 2>/dev/null | tr -d '\000')
    head=${head#"${head%%[![:space:]]*}"}
    case $head in
        '@PRIV_PREFIX@'* | '@OPENSSH_HEADER@'*) echo secret ;;
        '@PUB_PREFIX@'* | '@SSH_PREFIX@'*) echo public ;;
    esac
}

list_key_files() {
    for path in "$keys_dir"/* "$keys_dir"/.*; do
        [ -f "$path" ] || continue
        name=${path##*/}
        kind=$(key_kind "$path")
        case $1:$kind in
            secret:secret | names:secret | names:public) printf '%s\n' "$name" ;;
            pairs:secret)
                if [ "$(key_kind "$path.pub")" = public ]; then
                    printf '%s\n' "$name"
                fi
                ;;
        esac
    done
}

list_aliases() {
    [ -f "$config_file" ] || return 0
    awk '
        /^[[:space:]]*\[/ {
            table = $0
            gsub(/[[:space:]"]/, "", table)
            in_aliases = (table == "[aliases]")
            next
        }
        in_aliases && /=/ {
            name = substr($0, 1, index($0, "=") - 1)
            gsub(/[[:space:]"]/, "", name)
            if (name != "") print name
        }
    ' "$config_file" 2>/dev/null
}

case $mode in
    secret | pairs) list_key_files "$mode" ;;
    names)
        list_key_files names
        list_aliases
        ;;
    public_keys)
        list_key_files pairs
        list_aliases
        ;;
esac
