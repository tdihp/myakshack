#!/bin/bash
. env.sh
set -xe

az group create -l "$REGION" -n "$AKSRG"

az aks show -otable -g "$AKSRG" -n "$AKSNAME" || \
az aks create -l "$REGION" -g "$AKSRG" -n "$AKSNAME" -c 1 \
    --enable-managed-identity \
    --enable-workload-identity \
    --enable-oidc-issuer

# https://learn.microsoft.com/en-us/azure/aks/use-oidc-issuer#show-the-oidc-issuer-url
OIDC_ISSUER=`az aks show -g "$AKSRG" -n "$AKSNAME" --query "oidcIssuerProfile.issuerUrl" -otsv`
az aks get-credentials -g "$AKSRG" -n "$AKSNAME" -f "$LABKUBECONFIG"
az ad app create --display-name "$NEWAPP"
# https://azure.github.io/azure-workload-identity/docs/topics/federated-identity-credential.html#azure-cli
APPLICATION_OBJECT_ID="$(az ad app list --display-name "$NEWAPP" --query '[0].id' -otsv)"
APP_ID=$(az ad app list --display-name "$NEWAPP" --query '[0].appId' -otsv)
kubectl apply -f- <<EOF
    apiVersion: v1
    kind: ServiceAccount
    metadata:
        name: $SA_NAME
        annotations:
            azure.workload.identity/client-id: "$APP_ID"
EOF

FED_REQ=$(
cat <<EOF
{
    "name": "kubernetes-federated-identity",
    "issuer": "$OIDC_ISSUER",
    "subject": "system:serviceaccount:$K8S_NS:$SA_NAME",
    "description": "Kubernetes service account federated identity",
    "audiences": [
        "api://AzureADTokenExchange"
    ]
}
EOF
)
if [[ `az ad app federated-credential list --id $APPLICATION_OBJECT_ID -o tsv | wc -l` == 0 ]]; then
    az ad app federated-credential create --id $APPLICATION_OBJECT_ID --parameters "$FED_REQ"
fi
az group create -l "$REGION" -n "$DESTRG"
az ad sp create --id "$APP_ID"
az role assignment create --role "Contributor" --assignee "$APP_ID" -g "$DESTRG"
