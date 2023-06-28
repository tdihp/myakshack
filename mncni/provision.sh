set -xe
set -o pipefail

RG=mncni
REGION=southeastasia
AKSNAME=mncni
VMSIZE=Standard_D2s_v4

az group create -n $RG -l $REGION
az aks create -k 1.25 -g $RG -n $AKSNAME -s $VMSIZE --network-plugin none
az aks get-credentials -g $RG -n $AKSNAME
