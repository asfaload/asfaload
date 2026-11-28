
# Completion of key names and aliases.
set -g __asfaload_cli_lister '@LISTER@'

# Prints the value of the option $argv[1] (short) or $argv[2] (long) in the tokens, but the
# current token.
function __asfaload_cli_option_value
    set -l tokens (commandline -op)
    set -l count (count $tokens)
    # The tokens have no entry for an empty current token.
    set -l current 0
    set -l current_token (commandline -ct)
    if test -n "$current_token"
        set current (math (count (commandline -opc)) + 1)
    end
    set -l value ""
    for i in (seq 2 $count)
        test $i -eq $current
        and continue
        switch $tokens[$i]
            case $argv[1] $argv[2]
                set -l value_index (math $i + 1)
                if test $value_index -le $count; and test $value_index -ne $current
                    set value $tokens[$value_index]
                end
            case "$argv[2]=*"
                set value (string replace -- "$argv[2]=" "" $tokens[$i])
            # A value attached to a short option: -dDIR or -d=DIR.
            case "$argv[1]*"
                if test (string length -- $argv[1]) -eq 2
                    set value (string sub -s 3 -- $tokens[$i] | string replace -r -- '^=' '')
                end
        end
    end
    printf '%s\n' $value
end

# True when the current token is the first positional of the subcommand. The arguments are the
# options of the subcommand that take a value.
function __asfaload_cli_first_positional
    string match -q -- '-*' (commandline -ct)
    and return 1
    set -l tokens (commandline -opc)
    set -l count (count $tokens)
    set -l i 2
    # The subcommand is the first token that is not an option.
    while test $i -le $count; and string match -q -- '-*' $tokens[$i]
        set i (math $i + 1)
    end
    set i (math $i + 1)
    while test $i -le $count
        if contains -- $tokens[$i] $argv
            set i (math $i + 1)
        else if not string match -q -- '-*' $tokens[$i]
            return 1
        end
        set i (math $i + 1)
    end
    # The current token is the value of an option.
    test $i -eq (math $count + 1)
end

function __asfaload_cli_keys
    set -l keys_dir (__asfaload_cli_option_value @KEYS_DIR_SHORT@ @KEYS_DIR_LONG@)
    set -l config_file (__asfaload_cli_option_value @CONFIG_FILE_SHORT@ @CONFIG_FILE_LONG@)
    sh -c $__asfaload_cli_lister sh $argv[1] "$keys_dir" "$config_file" 2>/dev/null
end

@COMPLETE_LINES@
