set -xe
set -o pipefail

SP_CLIENT_ID=
SP_PASSWORD=
SP_TENANT_ID=`az account show --query "tenantId" -otsv`

RG=labaksudrsync
REGION=southeastasia
AKSNAME=labaksudrsync
RTNAME=target

az group create -n $RG -l $REGION
RTID=`az network route-table create -g $RG -n $RTNAME --query 'id' -otsv`
az role assignment create --assignee $SP_CLIENT_ID --scope="$RTID" --role "Network Contributor"
echo "apiVersion: v1
kind: Secret
metadata:
  name: aksudrsync-cfg
  namespace: kube-system
type: Opaque
stringData:
  tenant: $SP_TENANT_ID
  clientid: $SP_CLIENT_ID
  password: $SP_PASSWORD
  rtid: $RTID
">aksudrsync-cfg-generated.yaml

az aks create -g $RG -n $AKSNAME \
  --node-count 1 \
  -k 1.23 \
  --network-plugin kubenet \
  --enable-managed-identity

az aks get-credentials -g $RG -n $AKSNAME
