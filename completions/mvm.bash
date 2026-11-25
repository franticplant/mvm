# bash completion for mvm(1)

_mvm_cache_names() {
    local dir="${MVM_CACHE_DIR:-$HOME/.cache/mvm}" f
    for f in "$dir"/*.img; do
        [[ -e "$f" ]] && basename "$f" .img
    done
}

_mvm_completion() {
    local cur="${COMP_WORDS[COMP_CWORD]}" prev="${COMP_WORDS[COMP_CWORD-1]}" i
    for ((i = 1; i < COMP_CWORD; i++)); do
        [[ "${COMP_WORDS[i]}" == "--" ]] && { COMPREPLY=($(compgen -f -- "$cur")); return; }
    done
    if ((COMP_CWORD == 1)); then
        COMPREPLY=($(compgen -W "fetch build run status update cache" -- "$cur"))
        return
    fi
    case "${COMP_WORDS[1]}" in
        fetch) ((COMP_CWORD == 2)) && COMPREPLY=($(compgen -W "go rust node --" -- "$cur")) ;;
        build|run)
            case "$prev" in
                -w) COMPREPLY=($(compgen -d -- "$cur")) ;;
                -i) ;;
                *) local w="-w --it --"
                   [[ "${COMP_WORDS[1]}" == build ]] && w="go rust node $w" || w="-i $w"
                   COMPREPLY=($(compgen -W "$w" -- "$cur")) ;;
            esac ;;
        cache)
            if ((COMP_CWORD == 2)); then
                COMPREPLY=($(compgen -W "rm grow gc" -- "$cur"))
            elif ((COMP_CWORD == 3)) && [[ "${COMP_WORDS[2]}" == rm || "${COMP_WORDS[2]}" == grow ]]; then
                COMPREPLY=($(compgen -W "$(_mvm_cache_names)" -- "$cur"))
            fi ;;
    esac
}

complete -F _mvm_completion mvm
