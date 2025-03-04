#!/bin/bash
. utils.bash

makeenv () {
    # override LAB_REGION if other region needed
    : ${LAB_REGION:=southeastasia}
    : ${LAB_AKS_VERSION:=$(aksversion "$LAB_REGION")}
    LAB_PURPOSE=caspread
    local NOW="$(date -u +%Y%m%d)"
    local PREFIX="lab-$LAB_PURPOSE-$NOW"
    LAB_RG="$PREFIX-rg"
    LAB_AKS_NAME="$PREFIX-aks"
    LAB_VNET_NAME="$PREFIX-vnet"
    LAB_VNET_CIDR="10.0.0.0/8"
    LAB_AKS_SUBNET_CIDR="10.1.0.0/16"
    # make sure we use a cheap size that has predictable CPU allocatable
    # this is not used for the AKS system pool, for that one we use the default
    LAB_NODE_SIZE="Standard_B2s"
    LAB_ZONES=(1 2)  # modify this to be in subscription limit
    LAB_KUBECONFIG="$SCRIPTDIR/.kubeconfig"
}
getenv env.sh
set -xe -o pipefail

if [ ${#LAB_ZONES[@]} -lt 2 ]; then
    echo "need at least 2 availability zones, found ${LAB_ZONES[@]}"
    exit 1
fi

az group create -l "$LAB_REGION" -n "$LAB_RG" -onone

az network vnet create -g "$LAB_RG" -n "$LAB_VNET_NAME" \
  --address-prefix "$LAB_VNET_CIDR" \
  --subnet-name aks --subnet-prefixes "$LAB_AKS_SUBNET_CIDR" -onone

# exit
AKS_SUBNET_ID=$(az network vnet subnet show \
  -g "$LAB_RG" --vnet-name "$LAB_VNET_NAME" -n "aks" \
  --query "id" -otsv)

ensure_aks_cluster -g "$LAB_RG" -n "$LAB_AKS_NAME" -- \
    -c 2 -k "$LAB_AKS_VERSION" --enable-managed-identity \
    --network-plugin azure \
    --vnet-subnet-id "$AKS_SUBNET_ID" \
    --zones "${LAB_ZONES[@]}"

# we provision a multizone nodepool with 1 start node
ensure_aks_nodepool -g "$LAB_RG" --cluster-name "$LAB_AKS_NAME" -n "multizone1" -- \
    --enable-cluster-autoscaler --zones "${LAB_ZONES[@]}" \
    -c 1 --min-count 1 --max-count 20 -s "$LAB_NODE_SIZE" \
    --labels "lab_ca=multizone1"

# we provision a multizone nodepool with 0 start node
ensure_aks_nodepool -g "$LAB_RG" --cluster-name "$LAB_AKS_NAME" -n "multizone0" -- \
    --enable-cluster-autoscaler --zones "${LAB_ZONES[@]}" \
    -c 0 --min-count 0 --max-count 20 -s "$LAB_NODE_SIZE" \
    --labels "lab_ca=multizone0"

# we provision a singlezone nodepool with 0 start node

ensure_aks_nodepool -g "$LAB_RG" --cluster-name "$LAB_AKS_NAME" -n "singlezone0" -- \
    --enable-cluster-autoscaler --zones "${LAB_ZONES[0]}" \
    -c 0 --min-count 0 --max-count 20 -s "$LAB_NODE_SIZE" \
    --labels "lab_ca=singlezone0"

az aks get-credentials -g "$LAB_RG" -n "$LAB_AKS_NAME" -f "$LAB_KUBECONFIG" --overwrite-existing

tee access-instructions.md << EOF
To access the AKS cluster via kubectl:
\`\`\`
export KUBECONFIG="$LAB_KUBECONFIG"
\`\`\`
EOF
