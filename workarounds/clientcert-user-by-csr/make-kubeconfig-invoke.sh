#!/bin/bash
RG="$1"
CLUSTER_NAME="$2"

az aks command invoke -g "$RG" -n "$CLUSTER_NAME" \
  -f make-kubeconfig-incommand.sh \
  -c "bash make-kubeconfig-incommand.sh $CLUSTER_NAME 2>/dev/null 1>/dev/null && cat kubeconfig" \
  | grep -v 'command started' >kubeconfig

FQDN=`az aks show -g "$RG" -n "$CLUSTER_NAME" --query "fqdn" -otsv`

kubectl --kubeconfig=kubeconfig config set \
  clusters."$CLUSTER_NAME".server "https://$FQDN:443"

kubectl --kubeconfig=kubeconfig config set \
  clusters."$CLUSTER_NAME".certificate-authority-data \
  `openssl s_client -connect $FQDN:443 -showcerts </dev/null 2>/dev/null | sed -ne '/-BEGIN CERTIFICATE-/,/-END CERTIFICATE-/p' | base64 -w0`
