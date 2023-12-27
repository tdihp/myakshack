#!/bin/bash
makeenv () {
    # override LAB_REGION if other region needed
    : "${LAB_REGION:=southeastasia}"
    LAB_PURPOSE=mitmproxy
    NOW="$(date -u +%Y%m%d)"
    LAB_AKSNAME="lab-${LAB_PURPOSE}-${NOW}-aks"
    LAB_RG="lab-${LAB_PURPOSE}-${NOW}-rg"
    LAB_WINDOWS_USERNAME=azureuser
    # see https://learn.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/password-must-meet-complexity-requirements#reference
    LAB_WINDOWS_PASSWD=$(</dev/random tr -dc 'A-Za-z0-9!"#$%&'"'"'()*+,-./:;<=>?@[]^_`{|}~' | head -c 16)
    LAB_NSG_NAME="lab-${LAB_PURPOSE}-${NOW}-nsg"
    LAB_VNET_NAME="lab-${LAB_PURPOSE}-${NOW}-vnet"
    LAB_VNET_CIDR="10.0.0.0/8"
    LAB_AKS_SUBNET_CIDR="10.1.0.0/16"
    LAB_PROXY_SUBNET_CIDR="10.101.101.0/24"
    LAB_PROXY_IP="10.101.101.101"
    # by default we take 2nd latest GA k8s version
    : "${LAB_AKS_VERSION:=$(az aks get-versions -l "$LAB_REGION" --query 'values[?isPreview!=`true`].version' -otsv | sort -rn | head -2 | tail -1)}"
    LAB_VMNAME="lab-${LAB_PURPOSE}-${NOW}-vm"
    LAB_NICNAME="lab-${LAB_PURPOSE}-${NOW}-nic"
    LAB_PIPNAME="lab-${LAB_PURPOSE}-${NOW}-pip"
    LAB_RTNAME="lab-${LAB_PURPOSE}-${NOW}-rt"
    LAB_MITM_MAGIC_IP="100.66.66.66"
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
        },
        {
            "name": "proxy",
            "properties": {
                "direction": "Inbound",
                "priority": 400,
                "access": "Allow",
                "sourcePortRange": "*",
                "destinationPortRange": "*",
                "protocol": "Tcp",
                "sourceAddressPrefix": "VirtualNetwork",
                "destinationAddressPrefix": "*"
            }
        }
    ]
}
EOF

az resource create --resource-type=Microsoft.Network/networkSecurityGroups \
  -g "$LAB_RG" -n "$LAB_NSG_NAME" -p "$NSG_SPEC"

NSG_ID=$(az network nsg show -g "$LAB_RG" -n "$LAB_NSG_NAME" --query 'id' -otsv)

# we create a private zone for mitm.it so we don't fall on mercy of the real
# mitm.it IP address
# the private dns zone doesn't like any other network resource, it doesn't work
# with a template-ish setting
az network private-dns zone create -g "$LAB_RG" -n mitm.it
az network private-dns record-set a create -g "$LAB_RG" -z "mitm.it" -n "@"
az network private-dns record-set a update -g "$LAB_RG" -z "mitm.it" -n "@" \
  --set "aRecords=[{'ipv4Address':'$LAB_MITM_MAGIC_IP'}]"

RT_ID=$(az network route-table create -g "$LAB_RG" -n "$LAB_RTNAME" \
  --query "id" -otsv)
az network route-table route create -g "$LAB_RG" \
  --route-table-name "$LAB_RTNAME" -n "proxy" \
  --next-hop-type "VirtualAppliance" \
  --address-prefix "0.0.0.0/0" \
  --next-hop-ip-address "$LAB_PROXY_IP"

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
                "networkSecurityGroup": {"id": "$NSG_ID"},
                "routeTable": {"id": "$RT_ID"}
            }
        },
        {
            "name": "mitmproxy",
            "properties": {
                "addressPrefix": "$LAB_PROXY_SUBNET_CIDR",
                "networkSecurityGroup": {"id": "$NSG_ID"}
            }
        }
    ]
}
EOF

az resource create --resource-type=Microsoft.Network/virtualNetworks \
  -g "$LAB_RG" -n "$LAB_VNET_NAME" -p "$VNET_SPEC"

az network private-dns link vnet create -g "$LAB_RG" -n "mitm" \
  -v "$LAB_VNET_NAME" -z "mitm.it" -e 1

AKS_SUBNET_ID=$(az network vnet subnet show \
  -g "$LAB_RG" --vnet-name "$LAB_VNET_NAME" -n "aks" \
  --query "id" -otsv)

PROXY_SUBNET_ID=$(az network vnet subnet show \
  -g "$LAB_RG" --vnet-name "$LAB_VNET_NAME" -n "mitmproxy" \
  --query "id" -otsv)

# dynamic IP because cost matters (for a lab at least)
az network public-ip create -g "$LAB_RG" -n "$LAB_PIPNAME"

az network nic create -g "$LAB_RG" -n "$LAB_NICNAME" \
  --network-security-group="$LAB_NSG_NAME" \
  --subnet="$PROXY_SUBNET_ID" \
  --public-ip-address="$LAB_PIPNAME" \
  --private-ip-address="$LAB_PROXY_IP" \
  --ip-forwarding 1

export PIP_ADDR=`az network public-ip show -g "$LAB_RG" -n "$LAB_PIPNAME" \
  -otsv --query 'ipAddress'`

# start the VM in case it is powered off somehow
# az vm create -g "$LAB_RG" -n "$LAB_VMNAME" \
#   --image Canonical:0001-com-ubuntu-server-jammy:22_04-lts-gen2:latest \
#   --nics "$LAB_NICNAME" --custom-data cloud-init.txt
export LAB_MITM_MAGIC_IP
<cloud-init.txt.template envsubst >cloud-init.txt

az vm create -g "$LAB_RG" -n "$LAB_VMNAME" \
  --image Ubuntu2204  \
  --nics "$LAB_NICNAME" --custom-data cloud-init.txt

az vm start -g "$LAB_RG" -n "$LAB_VMNAME"

if az aks show -g "$LAB_RG" -n "$LAB_AKSNAME" --query 'id' -otsv; then
    echo "AKS cluster already created"
elif [[ $? == 3 ]]; then
    set -e
    az aks create -g "$LAB_RG" -n "$LAB_AKSNAME" \
        -c 1 -k "$LAB_AKS_VERSION" --enable-managed-identity \
        --network-plugin azure \
        --windows-admin-username="$LAB_WINDOWS_USERNAME" \
        --windows-admin-password="$LAB_WINDOWS_PASSWD" \
        --vnet-subnet-id "$AKS_SUBNET_ID" \
        --query 'id' -otsv
    set +e
else
    echo 'showing aks cluster failed' && exit 1
fi

# we provision a AzureLinux nodepool
if az aks nodepool show -g "$LAB_RG" --cluster-name "$LAB_AKSNAME" \
    -n "mariner" --query 'id' -otsv; then
    echo "mariner nodepool already created"
elif [[ $? == 3 ]]; then
    set -e
    az aks nodepool add -g "$LAB_RG" --cluster-name "$LAB_AKSNAME" \
        -n "mariner" -c 1 --os-sku AzureLinux --query 'id' -otsv
    set +e
else
    echo "failed listing nodepool mariner" && exit 1
fi

# we provision a Windows nodepool
if az aks nodepool show -g "$LAB_RG" --cluster-name "$LAB_AKSNAME" -n "win" \
    --query 'id' -otsv; then
    echo "win nodepool already created"
elif [[ $? == 3 ]]; then
    set -e
    az aks nodepool add -g "$LAB_RG" --cluster-name "$LAB_AKSNAME" -n "win" \
        -c 1 --os-sku Windows2022 --os-type Windows --query 'id' -otsv
    set +e
else
    echo "failed listing nodepool win" && exit 1
fi

az aks get-credentials -g "$LAB_RG" -n "$LAB_AKSNAME" -f "kubeconfig"

export KUBECONFIG="`realpath kubeconfig`"
export APISERVER_IP=$(dig +short `kubectl config view -o jsonpath='{.clusters[0].cluster.server}' | grep -oP '[^/^:]+\.azmk8s\.io'` | head -n1)
export LAB_AKS_SUBNET_CIDR

<access-instructions.md.template envsubst | tee access-instructions.md
