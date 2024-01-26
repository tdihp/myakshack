#!/bin/bash
makeenv () {
    # override LAB_REGION if other region needed
    : "${LAB_REGION:=southeastasia}"
    LAB_PURPOSE=caspread
    NOW="$(date -u +%Y%m%d)"
    LAB_AKSNAME="lab-${LAB_PURPOSE}-${NOW}-aks"
    LAB_RG="lab-${LAB_PURPOSE}-${NOW}-rg"
    LAB_VNET_NAME="lab-${LAB_PURPOSE}-${NOW}-vnet"
    LAB_VNET_CIDR="10.0.0.0/8"
    LAB_AKS_SUBNET_CIDR="10.1.0.0/16"
    # make sure we use a cheap size that has predictable CPU allocatable
    LAB_NODE_SIZE="Standard_B2s"
    LAB_AKS_VERSION="1.28"
}

saveenv() {
    declare -g | grep -e '^LAB_'
} >env.sh

if [ ! -f env.sh ]; then
    makeenv
    saveenv
else
    . env.sh
fi
set -x
az group create -l "$LAB_REGION" -n "$LAB_RG"

az network vnet create -g "$LAB_RG" -n "$LAB_VNET_NAME" \
  --address-prefix "$LAB_VNET_CIDR" \
  --subnet-name aks --subnet-prefixes "$LAB_AKS_SUBNET_CIDR"

AKS_SUBNET_ID=$(az network vnet subnet show \
  -g "$LAB_RG" --vnet-name "$LAB_VNET_NAME" -n "aks" \
  --query "id" -otsv)

if az aks show -g "$LAB_RG" -n "$LAB_AKSNAME" --query 'id' -otsv; then
    echo "AKS cluster already created"
elif [[ $? == 3 ]]; then
    set -e
    az aks create -g "$LAB_RG" -n "$LAB_AKSNAME" \
        -c 1 -k "$LAB_AKS_VERSION" --enable-managed-identity \
        --network-plugin azure \
        --vnet-subnet-id "$AKS_SUBNET_ID" \
        --zones 1 2 3 \
        -s "$LAB_NODE_SIZE" \
        --query 'id' -otsv
        # --cluster-autoscaler-profile "balance-similar-node-groups=true" \
    set +e
else
    echo 'showing aks cluster failed' && exit 1
fi

# we provision a multizone nodepool
if az aks nodepool show -g "$LAB_RG" --cluster-name "$LAB_AKSNAME" \
    -n "multizone1" --query 'id' -otsv; then
    echo "multizone1 nodepool already created"
elif [[ $? == 3 ]]; then
    set -e
    az aks nodepool add -g "$LAB_RG" --cluster-name "$LAB_AKSNAME" \
        --enable-cluster-autoscaler --zones 1 2 3 \
        -n "multizone1" -c 1 --min-count 1 --max-count 20 -s "$LAB_NODE_SIZE" \
        --labels "lab_ca=multizone1" \
        --query 'id' -otsv
    set +e
else
    echo "failed listing nodepool multizone1" && exit 1
fi

# we provision a multizone nodepool
if az aks nodepool show -g "$LAB_RG" --cluster-name "$LAB_AKSNAME" \
    -n "multizone0" --query 'id' -otsv; then
    echo "multizone0 nodepool already created"
elif [[ $? == 3 ]]; then
    set -e
    az aks nodepool add -g "$LAB_RG" --cluster-name "$LAB_AKSNAME" \
        --enable-cluster-autoscaler --zones 1 2 3 \
        -n "multizone0" -c 0 --min-count 0 --max-count 20 -s "$LAB_NODE_SIZE" \
        --labels "lab_ca=multizone0" \
        --query 'id' -otsv
    set +e
else
    echo "failed listing nodepool multizone0" && exit 1
fi

if az aks nodepool show -g "$LAB_RG" --cluster-name "$LAB_AKSNAME" \
    -n "singlezone0" --query 'id' -otsv; then
    echo "singlezone0 nodepool already created"
elif [[ $? == 3 ]]; then
    set -e
    az aks nodepool add -g "$LAB_RG" --cluster-name "$LAB_AKSNAME" \
        --enable-cluster-autoscaler --zones 1 \
        -n "singlezone0" -c 0 --min-count 0 --max-count 20 -s "$LAB_NODE_SIZE" \
        --labels "lab_ca=singlezone0" \
        --query 'id' -otsv
    set +e
else
    echo "failed listing nodepool singlezone0" && exit 1
fi

# for zone in {1..3}; do
#     # we provision a AzureLinux nodepool
#     poolname="singlezone$zone"
#     if az aks nodepool show -g "$LAB_RG" --cluster-name "$LAB_AKSNAME" \
#         -n "$poolname" --query 'id' -otsv; then
#         echo "$poolname nodepool already created"
#     elif [[ $? == 3 ]]; then
#         set -e
#         az aks nodepool add -g "$LAB_RG" --cluster-name "$LAB_AKSNAME" \
#             --enable-cluster-autoscaler --zones "$zone" \
#             -n "$poolname" -c 1 --min-count 1 --max-count 20 \
#             -s "$LAB_NODE_SIZE" \
#             --labels "lab_ca=singlezone" \
#             --query 'id' -otsv
#         set +e
#     else
#         echo "failed listing nodepool $poolname" && exit 1
#     fi
# done

az aks get-credentials -g "$LAB_RG" -n "$LAB_AKSNAME" -f "kubeconfig"

KUBECONFIG="`realpath kubeconfig`"

tee access-instructions.md << EOF
To access the AKS cluster via kubectl:
\`\`\`
export KUBECONFIG="$KUBECONFIG"
\`\`\`
EOF
