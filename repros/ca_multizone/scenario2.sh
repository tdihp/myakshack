. env.sh
zone=$(comm -23 \
  <(printf "$LAB_REGION-%s\n" {1..3})\
  <(kubectl get node -l "lab_ca=multizone1" -ojson | jq -r '.items[].metadata.labels["topology.kubernetes.io/zone"]' | sort | uniq)\
  | head -n 1)
echo "using absent zone $zone"

kubectl apply -f- << EOF
apiVersion: apps/v1
kind: Deployment
metadata:
  name: scenario2
spec:
  replicas: 10
  selector:
    matchLabels:
      app: scenario2
  template:
    metadata:
      labels:
        app: scenario2
    spec:
      nodeSelector:
        "kubernetes.io/os": linux
        "lab_ca": "multizone1"
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
