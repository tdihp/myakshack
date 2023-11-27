#!/bin/bash
set -e
set -o pipefail
shopt -s nullglob

HELP="\
build-policy.sh -- build Azure custom Policy for Kubernetes

Usage:
    bash build-policy.sh <policy-name>: build a single policy
    bash build-policy.sh all: build all policies
    (and yes, please do not name the policy as 'all')

Copyright (c) 2023, Ping He.
License: MIT
"

build_policy () {
    policy_name="$1"
    echo "building policy $policy_name"
    <policies/block-storageclass/template.yaml base64 -w0 | jq -R '.' | \
        cat rules.template.json \
            "policies/$policy_name/rule_overrides.json" \
            "policies/$policy_name/extra_params.json" \
            - | \
        jq -s '
            .[0].then.details = .[0].then.details * .[1] 
            | .[0].then.details.values = (
                .[2] | keys |
                reduce .[] as $k ({}; .[$k] = ("[parameters('"'"'"+$k+"'"'"')]"))
            )
            | .[0].then.details.templateInfo.content = .[3]
            | .[0]' >"output/$policy_name.rules.json"
    
    jq -s '
        .[0] += .[1] | .[0]
    ' "params.template.json" "policies/$policy_name/extra_params.json" \
    >"output/$policy_name.params.json"
    echo "policy build done, run below command to publish the policy definition"
    cat - <<EOF
    az policy definition create -n '$policy_name' \\
        --mode "Microsoft.Kubernetes.Data" \\
        --rules "output/$policy_name.rules.json" \\
        --params "output/$policy_name.params.json"
EOF
}

if [ "$1" == "all" ]; then
    echo "building all policies"
    for f in policies/*; do
        [ -d "$f" ] && build_policy "${f##*/}"
    done
elif [ ! -z "$1" ] && [ -d "policies/$1" ]; then
    build_policy "$1"
else
    echo "$HELP"
    exit 1
fi
