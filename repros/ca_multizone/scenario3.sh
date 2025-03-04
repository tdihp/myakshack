. env.sh
ZONE="$LAB_REGION-${LAB_ZONES[0]}"
echo "using zone $ZONE"

kubectl apply -f- << EOF
apiVersion: apps/v1
kind: Deployment
metadata:
  name: scenario3
spec:
  replicas: 10
  selector:
    matchLabels:
      app: scenario3
  template:
    metadata:
      labels:
        app: scenario3
    spec:
      nodeSelector:
        "kubernetes.io/os": linux
        "lab_ca": "multizone0"
        "topology.kubernetes.io/zone": "$zone"
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
