# common utilities in this repository

SCRIPTDIR=$(dirname -- $(realpath -- "${BASH_SOURCE[0]}"))

# get a "safe" AKS minor version, i.e., the 2nd latest GA minor version
aksversion() {
    az aks get-versions -l "$1" \
    --query "values[?isPreview!=\`true\`&&contains(capabilities.supportPlan,'KubernetesOfficial')].version" -otsv \
    | sort -rn | head -2 | tail -1
}

# if env.sh exists, import it, otherwise calls makeenv(), then save env
# always use script location, not working directory
: ${GETENV_PATTERN:='^LAB_[0-9a-zA-Z_]+(?==)'}
getenv() {
    if [ -f "$1" ]; then
        . "$1"
    else
        makeenv  # we assume function makeenv exists
        saveenv "$1"
    fi
}

# in case incremental save is needed out of makeenv
saveenv() {
    declare -g | grep -Pe "$GETENV_PATTERN" >"$1"
}

# export all our envs, intended for envsubst
exportenv() {
    local -a vars
    mapfile -t vars <<<$(declare -g | grep -Poe "$GETENV_PATTERN")
    export "${vars[@]}"
}

# ensure aks up and running, create if not existing, start if stopped
# usage: reconcile_aks -g <rg> -n <name> -- <creation-args ...>
ensure_aks_cluster() {
    local -a queryargs
    while :; do
        case "$1" in
            --) shift; break ;;
            *) queryargs+=("$1") ;;
        esac
        shift
    done
    local powerstate
    # create if not existing
    if powerstate=$(az aks show "${queryargs[@]}" --query 'powerState.code' -otsv); then
        echo "cluster already created, powerstate: $powerstate"
        if [ "$powerstate" == "Stopped" ]; then
            az aks start "${queryargs[@]}"
        fi
    elif [[ $? == 3 ]]; then
        az aks create "${queryargs[@]}" "$@" -onone
    else
        echo 'showing aks cluster failed' >&2 && exit 1
    fi
}

ensure_aks_nodepool() {
    local -a queryargs
    while :; do
        case "$1" in
            --) shift; break ;;
            *) queryargs+=("$1") ;;
        esac
        shift
    done
    # create if not existing
    if az aks nodepool show "${queryargs[@]}" -onone; then
        echo "nodepool already created"
    elif [[ $? == 3 ]]; then
        az aks nodepool add "${queryargs[@]}" "$@" -onone
    else
        echo 'showing nodepool failed' && exit 1
    fi
}
