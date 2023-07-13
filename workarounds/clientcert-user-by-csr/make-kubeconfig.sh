#!/bin/bash

# This script loosely follows
# https://kubernetes.io/docs/reference/access-authn-authz/certificate-signing-requests/#normal-user
# and generate a complete kubeconfig

openssl genrsa -out myuser.key 2048

cat <<EOF | kubectl apply -f-
apiVersion: certificates.k8s.io/v1
kind: CertificateSigningRequest
metadata:
  name: myuser
spec:
  request: `openssl req -new -key myuser.key -subj "/CN=clusterAdmin" | base64 -w0`
  signerName: kubernetes.io/kube-apiserver-client
  expirationSeconds: 86400  # one day
  usages:
  - client auth
EOF

kubectl certificate approve myuser

CURRENT_CONTEXT=`kubectl config current-context`
CURRENT_CLUSTER=`kubectl config view -o jsonpath="{.contexts[?(@.name == \"$CURRENT_CONTEXT\")].context.cluster}"`

cat <<EOF | tee kubeconfig
apiVersion: v1
kind: Config
current-context: myuser_$CURRENT_CLUSTER
clusters:
- `kubectl config view --raw -o jsonpath="{.clusters[?(@.name == \"$CURRENT_CLUSTER\")]}"`
users:
- name: myuser_$CURRENT_CLUSTER
  user:
    client-certificate-data: `kubectl get csr myuser -o jsonpath='{.status.certificate}'`
    client-key-data: `<myuser.key base64 -w0`
contexts:
- name: myuser_$CURRENT_CLUSTER
  context:
    cluster: $CURRENT_CLUSTER
    user: myuser_$CURRENT_CLUSTER
EOF
