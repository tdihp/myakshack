This describes and reproduces a "phantom pod" situation with a bare minimun
kind cluster. kind 0.27.0 is used.

```shell
# provisioning environemnt
cat <<EOF >kind.config
kind: Cluster
apiVersion: kind.x-k8s.io/v1alpha4
nodes:
- role: control-plane
  kubeadmConfigPatches:
  - |
    apiVersion: kubeadm.k8s.io/v1beta3
    kind: ClusterConfiguration
    scheduler:
      extraArgs:
        v: "6"
- role: worker
EOF

kind create cluster -n phantompod --image kindest/node:v1.29.14 --config kind.config
alias k='kubectl --context kind-phantompod'
alias kk='kubectl --context kind-phantompod -n kube-system'
# to make sure we have all components ready
k wait --for='jsonpath={.status.conditions[?(@.type=="Ready")].status}=True' node/phantompod-control-plane
k get node
kk get pods -owide

# we create a deployment with 0 replicas
k apply -f- <<EOF
apiVersion: apps/v1
kind: Deployment
metadata:
  name: phantom
  labels:
    app: phantom
spec:
  replicas: 0
  selector:
    matchLabels:
      app: phantom
  template:
    metadata:
      labels:
        app: phantom
    spec:
      nodeSelector:
        kubernetes.io/hostname: phantompod-worker
      containers:
      - name: phantom
        image: busybox:1.37-musl
        command: [sleep, infinity]
        resources:
          requests:
            cpu: 2
EOF
sleep 1
# we take etcd snapshot
kk exec -it etcd-phantompod-control-plane -- sh -c 'ETCDCTL_API=3 etcdctl --endpoints=https://127.0.0.1:2379 \
  --cacert=/etc/kubernetes/pki/etcd/ca.crt --cert=/etc/kubernetes/pki/etcd/peer.crt --key=/etc/kubernetes/pki/etcd/peer.key \
  snapshot save /backup1.data'
k scale --replicas 3 deployment/phantom
# k get deploy phantom
k rollout status deployment/phantom

# we exec into the docker node, pause etcd, remove data of /var/lib/etcd/member,
# restore, then bounce etcd
docker exec -it phantompod-control-plane bash -xc '
containerid=$(crictl ps --name etcd -o json | jq -r ".containers[0].id")
runc --root /run/containerd/runc/k8s.io pause "$containerid"
rm -rf /var/lib/etcd/member
ls /var/lib/etcd
ETCDCTL_API=3 nsenter -m -t $(pgrep etcd) etcdctl --data-dir /var/lib/etcd snapshot restore /backup1.data
runc --root /run/containerd/runc/k8s.io kill "$containerid" KILL
'

sleep 3
# we verify if deployment gets restored to 0 replicas
k get deploy 

# we bounce kube-apiserver kube-scheduler and kube-controller-manager
# but not kubelet
docker exec -it phantompod-control-plane bash -xc '
bounce() {
    local cid=$(crictl ps --name "$1" -o json | jq -r ".containers[0].id")
    crictl stop -t 5 "$cid"
}
bounce kube-apiserver
sleep 20
bounce kube-scheduler
sleep 20
bounce kube-controller-manager
sleep 20
'
k get deploy

sleep 10
kk get pod

k apply -f- <<EOF
apiVersion: apps/v1
kind: Deployment
metadata:
  name: culprit
  labels:
    app: culprit
spec:
  replicas: 3
  selector:
    matchLabels:
      app: culprit
  template:
    metadata:
      labels:
        app: culprit
    spec:
      nodeSelector:
        kubernetes.io/hostname: phantompod-worker
      containers:
      - name: culprit
        image: busybox:1.37-musl
        command: [sleep, infinity]
        resources:
          requests:
            cpu: 2
EOF

sleep 5
k get pods -owide
```

One should see repro like below on the get pod:

```
NAME                       READY   STATUS     RESTARTS   AGE   IP       NODE                NOMINATED NODE   READINESS GATES
culprit-6646dbb846-28b2p   0/1     OutOfcpu   0          4s    <none>   phantompod-worker   <none>           <none>
culprit-6646dbb846-2gmnn   0/1     OutOfcpu   0          1s    <none>   phantompod-worker   <none>           <none>
culprit-6646dbb846-4kpfn   0/1     OutOfcpu   0          0s    <none>   phantompod-worker   <none>           <none>
...
```
