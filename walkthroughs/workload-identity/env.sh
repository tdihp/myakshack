SUB_ID=$(az account show --query 'id' -otsv)
REGION=southeastasia
AKSRG=witestaks
AKSNAME=witestaks
DESTRG=witestdest
NEWAPP=witestapp
LABKUBECONFIG=.kubeconfig
K8S_NS=default
SA_NAME=foobar
CM_NAME=foobar
export KUBECONFIG=$LABKUBECONFIG
