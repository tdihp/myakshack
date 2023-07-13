This workaround is for having arbitary clientcert for AKS users.

`make-kubeconfig.sh`: make a kubeconfig that is valid for only 1 day, when user
has a working admin kubeconfig.

Example: after running `az aks get-credentials`, simply run
`bash make-kubeconfig.sh`, then find the output in `./kubeconfig` file.

`make-kubeconfig-invoke.sh`: make a kubeconfig by running
`az aks command invoke`.

Example: run `bash make-kubeconfig-invoke.sh <resource-group> <cluster-name>`

Known issues: if certificate key isn't matching, try `kubectl delete csr myuser`
