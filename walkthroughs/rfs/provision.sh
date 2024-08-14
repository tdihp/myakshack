#!/bin/bash
makeenv () {
    # override LAB_REGION if other region needed
    : "${LAB_REGION:=southeastasia}"
    LAB_PURPOSE=rfs
    NOW="$(date -u +%Y%m%d)"
    LAB_RG="lab-${LAB_PURPOSE}-${NOW}-rg"
    LAB_NSG_NAME="lab-${LAB_PURPOSE}-${NOW}-aks"
    LAB_VNET_NAME="lab-${LAB_PURPOSE}-${NOW}-vnet"
    LAB_VNET_CIDR="10.0.0.0/8"
    # make sure nodes / VM in the same zone as we are doing perf test
    LAB_PPG_NAME="lab-${LAB_PURPOSE}-${NOW}-ppg"
    LAB_NSG_NAME="lab-${LAB_PURPOSE}-${NOW}-nsg"
    LAB_AKS_NAME="lab-${LAB_PURPOSE}-${NOW}-aks"
    LAB_AKS_VERSION="1.29"
    LAB_AKS_SUBNET_CIDR="10.1.0.0/16"
    # make sure we use a cheap size that has predictable CPU allocatable
    # LAB_AKS_SYSPOOL_NODE_SIZE="Standard_B2s"
    LAB_AKS_SYSPOOL_NODE_SIZE="Standard_D2_v5"
    LAB_AKS_WORKPOOL_NODE_SIZE="Standard_D4ps_v5"
    # LAB_AKS_WORKPOOL_NODE_SIZE="Standard_D2_v5"
    LAB_AKS_STRESSPOOL_NODE_SIZE="Standard_D2_v5"
    LAB_AKS_STRESSPOOL_SIZE=4
    LAB_VM_NAME="lab-${LAB_PURPOSE}-${NOW}-vm"
    LAB_VM_SIZE="Standard_D2_v5"
    LAB_VM_SUBNET_CIDR="10.2.0.0/16"
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
PPG_ID=$(az ppg create -l "$LAB_REGION" -g "$LAB_RG" -n "$LAB_PPG_NAME" \
  -o tsv --query id)

IFS="" read -r -d '' NSG_SPEC <<"EOF"; [[ $? == 1 ]] 
{
    "securityRules": [
        {
            "name": "corpnetssh",
            "properties": {
                "direction": "Inbound",
                "priority": 300,
                "access": "Allow",
                "sourcePortRange": "*",
                "destinationPortRange": "22",
                "protocol": "Tcp",
                "sourceAddressPrefix": "CorpNetPublic",
                "destinationAddressPrefix": "*"
            }
        }
    ]
}
EOF

NSG_ID=$(az resource create \
  --resource-type=Microsoft.Network/networkSecurityGroups \
  -g "$LAB_RG" -n "$LAB_NSG_NAME" -p "$NSG_SPEC" --query 'id' -otsv)

IFS="" read -r -d '' VNET_SPEC <<EOF; [[ $? == 1 ]] 
{
    "addressSpace": {
        "addressPrefixes": ["$LAB_VNET_CIDR"]
    },
    "subnets": [
        {
            "name": "aks",
            "properties": {
                "addressPrefix": "$LAB_AKS_SUBNET_CIDR",
                "networkSecurityGroup": {"id": "$NSG_ID"}
            }
        },
        {
            "name": "vm",
            "properties": {
                "addressPrefix": "$LAB_VM_SUBNET_CIDR",
                "networkSecurityGroup": {"id": "$NSG_ID"}
            }
        }
    ]
}
EOF

az resource create --resource-type=Microsoft.Network/virtualNetworks \
  -g "$LAB_RG" -n "$LAB_VNET_NAME" -p "$VNET_SPEC"

AKS_SUBNET_ID=$(az network vnet subnet show \
  -g "$LAB_RG" --vnet-name "$LAB_VNET_NAME" -n "aks" \
  --query "id" -otsv)

VM_SUBNET_ID=$(az network vnet subnet show \
  -g "$LAB_RG" --vnet-name "$LAB_VNET_NAME" -n "vm" \
  --query "id" -otsv)

if az aks show -g "$LAB_RG" -n "$LAB_AKS_NAME" --query 'id' -otsv; then
    echo "AKS cluster already created"
elif [[ $? == 3 ]]; then
    set -e
    az aks create -g "$LAB_RG" -n "$LAB_AKS_NAME" \
        -c 1 -k "$LAB_AKS_VERSION" --enable-managed-identity \
        --network-plugin azure \
        --vnet-subnet-id "$AKS_SUBNET_ID" \
        --ppg "$PPG_ID" \
        -s "$LAB_AKS_SYSPOOL_NODE_SIZE" \
        --query 'id' -otsv
    set +e
else
    echo 'showing aks cluster failed' && exit 1
fi

# we provision workpool
if az aks nodepool show -g "$LAB_RG" --cluster-name "$LAB_AKS_NAME" \
    -n "workpool" --query 'id' -otsv; then
    echo "workpool nodepool already created"
elif [[ $? == 3 ]]; then
    set -e
    az aks nodepool add -g "$LAB_RG" --cluster-name "$LAB_AKS_NAME" \
        --ppg "$PPG_ID" \
        -n "workpool" -c 1 -s "$LAB_AKS_WORKPOOL_NODE_SIZE" \
        --kubelet-config ./linuxkubeletconfig.json \
        --query 'id' -otsv
    set +e
else
    echo "failed listing nodepool workpool" && exit 1
fi

# we provision stresspool
if az aks nodepool show -g "$LAB_RG" --cluster-name "$LAB_AKS_NAME" \
    -n "stresspool" --query 'id' -otsv; then
    echo "stresspool nodepool already created"
elif [[ $? == 3 ]]; then
    set -e
    az aks nodepool add -g "$LAB_RG" --cluster-name "$LAB_AKS_NAME" \
        --ppg "$PPG_ID" \
        -n "stresspool" -c $LAB_AKS_STRESSPOOL_SIZE \
        -s "$LAB_AKS_STRESSPOOL_NODE_SIZE" \
        --query 'id' -otsv
    set +e
else
    echo "failed listing nodepool stresspool" && exit 1
fi

az aks get-credentials -g "$LAB_RG" -n "$LAB_AKS_NAME" -f "kubeconfig"

KUBECONFIG="`realpath kubeconfig`"

az vm create -g "$LAB_RG" -n "$LAB_VM_NAME" \
  --image Canonical:0001-com-ubuntu-server-jammy:22_04-lts-gen2:latest \
  --size "$LAB_VM_SIZE" \
  --ppg "$PPG_ID" \
  --subnet "$VM_SUBNET_ID" \
  --nsg "$NSG_ID" \
  --custom-data cloud-init.txt \
  --accelerated-networking true

PIPADDR=$(az vm show -g "$LAB_RG" -n "$LAB_VM_NAME" -d \
  --query 'publicIps' -otsv)

tee access-instructions.md << EOF
To access the AKS cluster via kubectl:
\`\`\`
export KUBECONFIG="$KUBECONFIG"
\`\`\`

To access lab VM: ssh ubuntu@$PIPADDR
EOF
