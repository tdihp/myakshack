set -xe
set -o pipefail

RG=mccni
REGION=southeastasia
AKSNAME=mccni

az group create -n $RG -l $REGION
az aks create -k 1.25.2 -g $RG -n $AKSNAME --network-plugin none
az aks get-credentials -g $RG -n $AKSNAME

az vm create -n $VMNAME -g $RG \
    --size $VMSIZE \
    --image Canonical:0001-com-ubuntu-server-focal:20_04-lts-gen2:latest \
    --nsg $NSGNAME --nsg-rule NONE \
    --vnet-name $VNETNAME --subnet $SUBNETNAME \
    --ssh-key-values ~/.ssh/id_rsa.pub
