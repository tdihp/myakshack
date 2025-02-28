#!/bin/bash
. ./env.sh
set -x
az group delete -n "$LAB_RG" "$@"
az group delete -n "$LAB_DESTRG" "$@"
