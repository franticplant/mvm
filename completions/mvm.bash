# bash completion for mvm(1)

_mvm_cache_names() {
    local dir="${MVM_CACHE_DIR:-$HOME/.cache/mvm}"
    local f
    for f in "$dir"/*.img; do
        [[ -e "$f" ]] || continue
        basename "$f" .img
    done
}

_mvm_completion() {
    local cur prev words cword
    _init_completion 2>/dev/null || {
        COMPREPLY=()
        cur="${COMP_WORDS[COMP_CWORD]}"
        prev="${COMP_WORDS[COMP_CWORD-1]}"
        words=("${COMP_WORDS[@]}")
        cword=$COMP_CWORD
    }

    # Stop completing mvm flags after `--`
    local i
    for ((i = 1; i < cword; i++)); do
        if [[ "${words[i]}" == "--" ]]; then
            COMPREPLY=( $(compgen -f -- "$cur") )
            return 0
        fi
    done

    # Subcommand: mvm cache <subcmd> ...
    if [[ "${words[1]}" == "cache" ]]; then
        case "$cword" in
            2)
                COMPREPLY=( $(compgen -W "ls init import grow rm --help" -- "$cur") )
                return 0
                ;;
            3)
                case "${words[2]}" in
                    grow|rm)
                        COMPREPLY=( $(compgen -W "$(_mvm_cache_names)" -- "$cur") )
                        return 0
                        ;;
                esac
                ;;
            4)
                if [[ "${words[2]}" == "import" ]]; then
                    COMPREPLY=( $(compgen -d -- "$cur") )
                    return 0
                fi
                ;;
        esac
        return 0
    fi

    # Flag value completions
    case "$prev" in
        -o|--out)
            COMPREPLY=( $(compgen -d -- "$cur") )
            return 0
            ;;
        -m|--mem|--memory)
            COMPREPLY=( $(compgen -W "512m 1g 2g 4g 8g" -- "$cur") )
            return 0
            ;;
        -c|--cache)
            local names
            names="$(_mvm_cache_names | sed 's/$/:/')"
            COMPREPLY=( $(compgen -W "$names" -- "$cur") )
            compopt -o nospace 2>/dev/null
            return 0
            ;;
        -i|--image)
            COMPREPLY=( $(compgen -W "docker.io/library/golang:1.27-alpine docker.io/library/rust:1.98-alpine docker.io/library/node:22-alpine docker.io/library/alpine:latest" -- "$cur") )
            return 0
            ;;
    esac

    local opts="cache --go --rust --node --net --rw --no-src --crun -i --image -o --out -m --mem -c --cache -t --tmpfs -e --env -v --volume -h --help --"
    COMPREPLY=( $(compgen -W "$opts" -- "$cur") )
}

complete -F _mvm_completion mvm
