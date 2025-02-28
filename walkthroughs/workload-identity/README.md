# Workload identity common use cases other than what's covered in doc

This is a example/walkthrough for anyone easily generate a workload-identity
environment and verify. Run [provision.sh](./provision.sh) in this directory
for provisioning a repeatable configuration which sets up all necessary
components for instructions below.

## Workload Identity with Azure-cli

See also: https://github.com/Azure/azure-cli/issues/26858 which is a tracking of
supporting workload identity directly, and also includes workaround.

```shell
OVERRIDES=$(cat <<EOF
    {
        "metadata": {"labels":{"azure.workload.identity/use": "true"}},
        "spec": {"serviceAccountName": "$LAB_SA_NAME"}
    }
EOF
)
kubectl run -n $LAB_K8S_NS -it --rm --restart=Never \
    --image=mcr.microsoft.com/azure-cli azure-cli \
    --overrides "$OVERRIDES" \
    -- bash -c \
    '
    az login --federated-token "$(cat $AZURE_FEDERATED_TOKEN_FILE)" --service-principal -u $AZURE_CLIENT_ID -t $AZURE_TENANT_ID
    exec bash
    '
```

## Workload Identity with curl

For users who don't want to use SDK for authentication, Getting token with curl
(or a web client) is, with boilerplates but possible in one go following
https://learn.microsoft.com/en-us/entra/identity-platform/v2-oauth2-client-creds-grant-flow#third-case-access-token-request-with-a-federated-credential:

```shell
OVERRIDES=$(cat <<EOF
    {
        "metadata": {"labels":{"azure.workload.identity/use": "true"}},
        "spec": {"serviceAccountName": "$LAB_SA_NAME"}
    }
EOF
)
kubectl run -n $LAB_K8S_NS -it --rm --restart=Never \
    --image=mcr.microsoft.com/azure-cli azure-cli \
    --overrides "$OVERRIDES" \
    -- bash -c \
    '
    SCOPE=https://graph.microsoft.com/.default
    curl \
      "https://login.microsoftonline.com/$AZURE_TENANT_ID/oauth2/v2.0/token" \
      --data-urlencode scope="$SCOPE" \
      --data-urlencode client_id="$AZURE_CLIENT_ID" \
      --data-urlencode client_assertion_type="urn:ietf:params:oauth:client-assertion-type:jwt-bearer" \
      --data-urlencode client_assertion@"$AZURE_FEDERATED_TOKEN_FILE" \
      --data-urlencode grant_type=client_credentials | jq
    '
```

We should see "access_token" and its content in the json output of this command.

## Workload Identity with Terraform+azurerm

Terraform uses different environment variables for federated identity, while
the required things are similar. See
https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/guides/service_principal_oidc.

UPDATE: after this article published, azurerm now implements workload identity
instructions directly. See
https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/guides/aks_workload_identity.
Both authentication methods works.

Authenticating with the new workload identity method:

```shell
kubectl create cm -n $LAB_K8S_NS --from-file "$SCRIPTDIR/main.tf" tfexample
kubectl replace --force -f- <<EOF
apiVersion: v1
kind: Pod
metadata:
  name: tfexample
  namespace: $LAB_K8S_NS
  labels:
    azure.workload.identity/use: "true"
spec:
  terminationGracePeriodSeconds: 0
  serviceAccountName: "$LAB_SA_NAME"
  volumes:
  - name: tf
    configMap:
      name: tfexample
  containers:
  - name: tf
    image: hashicorp/terraform:1.11
    volumeMounts:
    - name: tf
      mountPath: /etc/tf
    command:
    - sh
    - -xc
    - |
      mkdir ~/example
      cd ~/example
      cp /etc/tf/main.tf .
      terraform init
      export ARM_USE_AKS_WORKLOAD_IDENTITY=true
      export ARM_USE_CLI=false
      terraform plan
      terraform apply -auto-approve
      echo 'done'
      sleep infinity
EOF
kubectl wait -n "$LAB_K8S_NS" --for=jsonpath='{.status.phase}'=Running "pod/tfexample"
kubectl -n $LAB_K8S_NS logs tfexample -f
```

Authenticating with the original OIDC method:

```shell
kubectl create cm -n $LAB_K8S_NS --from-file "$SCRIPTDIR/main.tf" tfexample
kubectl replace --force -f- <<EOF
apiVersion: v1
kind: Pod
metadata:
  name: tfexample
  namespace: $LAB_K8S_NS
  labels:
    azure.workload.identity/use: "true"
spec:
  terminationGracePeriodSeconds: 0
  serviceAccountName: "$LAB_SA_NAME"
  volumes:
  - name: tf
    configMap:
      name: tfexample
  containers:
  - name: tf
    image: hashicorp/terraform:1.11
    volumeMounts:
    - name: tf
      mountPath: /etc/tf
    command:
    - sh
    - -xc
    - |
      mkdir ~/example
      cd ~/example
      cp /etc/tf/main.tf .
      terraform init
      export ARM_USE_OIDC="true"
      export ARM_OIDC_TOKEN_FILE_PATH="\$AZURE_FEDERATED_TOKEN_FILE"
      export ARM_TENANT_ID="\$AZURE_TENANT_ID"
      export ARM_CLIENT_ID="\$AZURE_CLIENT_ID"
      terraform plan
      terraform apply -auto-approve
      echo 'done'
      sleep infinity
EOF
kubectl wait -n "$LAB_K8S_NS" --for=jsonpath='{.status.phase}'=Running "pod/tfexample"
kubectl -n $LAB_K8S_NS logs tfexample -f
```
