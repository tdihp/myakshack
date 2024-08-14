. env.sh
set -x
az group delete -n "$LAB_RG"
rm env.sh access-instructions.md kubeconfig
