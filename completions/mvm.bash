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
        [[ "${COMP_WORDS[i]}" == "--" ]] && { mapfile -t COMPREPLY < <(compgen -f -- "$cur"); return; }
    done
    if ((COMP_CWORD == 1)); then
        mapfile -t COMPREPLY < <(compgen -W "fetch build run check status pull update image cache" -- "$cur")
        return
    fi
    case "${COMP_WORDS[1]}" in
        fetch) mapfile -t COMPREPLY < <(compgen -W "go rust node --learn --" -- "$cur") ;;
        check) mapfile -t COMPREPLY < <(compgen -W "--all" -- "$cur") ;;
        build|run)
            case "$prev" in
                -w) mapfile -t COMPREPLY < <(compgen -d -- "$cur") ;;
                -i) ;;
                *) local w="-w --it --"
                   [[ "${COMP_WORDS[1]}" == build ]] && w="go rust node $w" || w="-i $w"
                   mapfile -t COMPREPLY < <(compgen -W "$w" -- "$cur") ;;
            esac ;;
        cache)
            if ((COMP_CWORD == 2)); then
                mapfile -t COMPREPLY < <(compgen -W "rm grow gc" -- "$cur")
            elif ((COMP_CWORD == 3)) && [[ "${COMP_WORDS[2]}" == rm || "${COMP_WORDS[2]}" == grow ]]; then
                mapfile -t COMPREPLY < <(compgen -W "$(_mvm_cache_names)" -- "$cur")
            fi ;;
    esac
}

complete -F _mvm_completion mvm
