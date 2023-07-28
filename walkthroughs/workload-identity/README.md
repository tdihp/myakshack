# Workload identity common use cases other than what's covered in doc

This is a example/walkthrough for anyone easily generate a workload-identity
environment and verify. See [env.sh](./env.sh) and
[provision.sh](./provision.sh) on how to initialize and customize.

## Workload Identity with Azure-cli

See also: https://github.com/Azure/azure-cli/issues/26858 which is a tracking of
supporting workload identity directly, and also includes workaround.

```shell
source env.sh
OVERRIDES=$(cat <<EOF
    {
        "metadata": {"labels":{"azure.workload.identity/use": "true"}},
        "spec": {"serviceAccountName": "$SA_NAME"}
    }
EOF
)
kubectl run -n $K8S_NS -it --rm --restart=Never \
    --image=mcr.microsoft.com/azure-cli azure-cli \
    --overrides "$OVERRIDES" \
    -- bash -c \
    '
    az login --federated-token "$(cat $AZURE_FEDERATED_TOKEN_FILE)" --service-principal -u $AZURE_CLIENT_ID -t $AZURE_TENANT_ID
    exec bash
    '
```

## Workload Identity with Terraform+azurerm

```shell
source env.sh
envsubst <main.tf.template >main.tf
kubectl create cm -n $K8S_NS --from-file main.tf tfexample
kubectl replace --force -f- <<EOF
apiVersion: v1
kind: Pod
metadata:
  name: tfexample
  namespace: $K8S_NS
  labels:
    azure.workload.identity/use: "true"
spec:
  terminationGracePeriodSeconds: 0
  serviceAccountName: "$SA_NAME"
  volumes:
  - name: tf
    configMap:
      name: tfexample
  containers:
  - name: tf
    image: mcr.microsoft.com/azure-cli
    volumeMounts:
    - name: tf
      mountPath: /etc/tf
    command:
    - bash
    - -c
    - |
      apk add terraform
      mkdir ~/example
      cd ~/example
      cp /etc/tf/main.tf .
      terraform init
      export ARM_USE_OIDC="true"
      export ARM_OIDC_TOKEN_FILE_PATH="\$AZURE_FEDERATED_TOKEN_FILE"
      export ARM_TENANT_ID="\$AZURE_TENANT_ID"
      export ARM_CLIENT_ID="\$AZURE_CLIENT_ID"
      terraform plan
      echo 'done'
      sleep infinity
EOF
sleep 10
kubectl -n $K8S_NS logs tfexample -f 
```
