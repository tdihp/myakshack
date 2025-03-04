. env.sh
set -x
az group delete -n "$LAB_RG" "$@"
