ZONE=$(kubectl --kubeconfig="$LAB_KUBECONFIG" get node -l "lab_ca=multizone1" -ojson | jq -r '.items[0].metadata.labels["topology.kubernetes.io/zone"]')
echo "using existing zone $ZONE"

kubectl apply -f- << EOF
apiVersion: apps/v1
kind: Deployment
metadata:
  name: scenario1
spec:
  replicas: 10
  selector:
    matchLabels:
      app: scenario1
  template:
    metadata:
      labels:
        app: scenario1
    spec:
      nodeSelector:
        "kubernetes.io/os": linux
        "lab_ca": "multizone1"
        "topology.kubernetes.io/zone": "$ZONE"
      containers:
      - image: alpine
        name: alpine
        resources:
          requests:
            cpu: "500m"  # our node should be able to fit 3
          limits:
            cpu: "500m"
        command: ["sleep", "infinity"]
EOF
