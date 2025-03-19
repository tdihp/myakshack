#!/bin/bash
. ./utils.bash

makeenv() {
    LAB_SUBSCRIPTION=$(az account show --query 'id' -otsv)  # used in tf
    : ${LAB_REGION:=southeastasia}
    LAB_PURPOSE=wi
    NOW=$(date "+%Y%m%d")
    local PREFIX="lab-$LAB_PURPOSE-$NOW"
    LAB_RG="$PREFIX-rg"
    LAB_AKS_NAME="$PREFIX-aks"
    LAB_DESTRG="$PREFIX-dest"
    LAB_MI="$PREFIX-mi"
    LAB_KUBECONFIG="$SCRIPTDIR/.kubeconfig"
    LAB_K8S_NS=default
    LAB_SA_NAME=foobar
    LAB_FEDERTED_CREDENTIAL_NAME="$PREFIX-fc"
}
getenv ./env.sh
set -xe -o pipefail

az group create -l "$LAB_REGION" -n "$LAB_RG" -onone
az group create -l "$LAB_REGION" -n "$LAB_DESTRG" -onone
APP_ID=$(az identity create -g "$LAB_RG" -n "$LAB_MI" --query 'clientId' -otsv)
# todo: wait until az ad sp show --id $APP_ID valid
# make role assignment as early as possible since this might have a delay
az role assignment create --role "Contributor" --assignee "$APP_ID" \
    --scope "/subscriptions/$LAB_SUBSCRIPTION/resourceGroups/$LAB_DESTRG" \
    -onone

ensure_aks_cluster -g "$LAB_RG" -n "$LAB_AKS_NAME" -- \
    --enable-managed-identity \
    --enable-workload-identity \
    --enable-oidc-issuer

# https://learn.microsoft.com/en-us/azure/aks/use-oidc-issuer#show-the-oidc-issuer-url
OIDC_ISSUER=$(az aks show -g "$LAB_RG" -n "$LAB_AKS_NAME" --query "oidcIssuerProfile.issuerUrl" -otsv)

az identity federated-credential create -onone \
    -g "$LAB_RG" -n "$LAB_FEDERTED_CREDENTIAL_NAME" --identity "$LAB_MI" \
    --issuer "$OIDC_ISSUER" \
    --subject "system:serviceaccount:$LAB_K8S_NS:$LAB_SA_NAME" \
    --audiences "api://AzureADTokenExchange"

az aks get-credentials -g "$LAB_RG" -n "$LAB_AKS_NAME" -f "$LAB_KUBECONFIG" --overwrite-existing
kubectl --kubeconfig="$LAB_KUBECONFIG" apply -f- <<EOF
    apiVersion: v1
    kind: ServiceAccount
    metadata:
        name: $LAB_SA_NAME
        annotations:
            azure.workload.identity/client-id: "$APP_ID"
EOF

(
    exportenv
    export SCRIPTDIR
    <"./main.tf.template" envsubst >"./main.tf"
    <"./access-instructions.md.template" envsubst | tee "./access-instructions.md"
)
