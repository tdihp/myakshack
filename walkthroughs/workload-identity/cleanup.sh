#!/bin/bash
. env.sh
set -x
az group delete -n $AKSRG
az group delete -n $DESTRG
APPLICATION_OBJECT_ID="$(az ad app list --display-name "$NEWAPP" --query '[0].id' -otsv)"
az ad app delete --id "$APPLICATION_OBJECT_ID"
