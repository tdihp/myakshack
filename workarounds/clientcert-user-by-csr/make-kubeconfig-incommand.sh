#!/bin/bash
# This script is similar to make-kubeconfig.sh, but is expected to be ran in
# az aks command-invoke
# we expect $1 to be cluster name (used in the kubeconfig yaml parts)

CLUSTER_NAME=$1

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

cat <<EOF >kubeconfig
apiVersion: v1
kind: Config
current-context: myuser_$CLUSTER_NAME
clusters:
- name: $CLUSTER_NAME
  cluster: {}
users:
- name: myuser_$CLUSTER_NAME
  user:
    client-certificate-data: `kubectl get csr myuser -o jsonpath='{.status.certificate}'`
    client-key-data: `<myuser.key base64 -w0`
contexts:
- name: myuser_$CLUSTER_NAME
  context:
    cluster: $CLUSTER_NAME
    user: myuser_$CLUSTER_NAME
EOF
