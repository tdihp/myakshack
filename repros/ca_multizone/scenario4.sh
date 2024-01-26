. env.sh
zone=`printf "$LAB_REGION-%s__" {1..3}`
zone="${zone%__}"
echo "using zone $zone"

kubectl apply -f- << EOF
apiVersion: apps/v1
kind: Deployment
metadata:
  name: scenario4
spec:
  replicas: 10
  selector:
    matchLabels:
      app: scenario4
  template:
    metadata:
      labels:
        app: scenario4
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
