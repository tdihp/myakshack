# common utilities in this repository

SCRIPTDIR=$(dirname -- $(realpath -- "$0"))

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

# ensure a azure resource exists with az <resource> show, create if not existing
# usage: ensure_resource [options] <resource ..> -- [creation-command] <creation-args ...>
# options:
#  -s showcmd   command for show, default to "show"
#  -c createcmd command for create, default to "create"
# example:
#  ensure_resource network private-dns -n my.privatedns.net -g rg
#  ensure_resource network dns -n my.public.net -g rg -- create -p public.net
ensure_resource() {
    local showcmd="show"
    local createcmd="create"
    while [ "$#" -gt 0 ]; do
        case "$1" in
            "-s") showcmd="$2"; shift 2 ;;
            "-c") createcmd="$2"; shift 2 ;;
            *) break ;;
        esac
    done
    local -a resource
    while [ "$#" -gt 0 ]; do
        case "$1" in
            -*) break ;;
            ?*) resource+=("$1"); shift ;;
            *) break ;;
        esac
    done
    local -a queryargs
    while [ "$#" -gt 0 ]; do
        case "$1" in
            --) shift; break ;;
            ?*) queryargs+=("$1"); shift ;;
            *) break ;;
        esac
    done
    # create if not existing
    if az "${resource[@]}" "$showcmd" "${queryargs[@]}" -onone; then
        echo "resource already created"
    elif [[ $? == 3 ]]; then
        az "${resource[@]}" "$createcmd" "${queryargs[@]}" "$@" -onone
    else
        echo 'showing resource failed' && exit 1
    fi
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

# generate a random password
# usage: passgen [length]
passgen() {
    local PASSLEN=16
    if [ -n "$1" ]; then
        PASSLEN="$1"
    fi
    </dev/random tr -dc 'A-Za-z0-9!"#$%&'"'"'()*+,-./:;<=>?@[]^_`{|}~' | head -c "$PASSLEN"
}
