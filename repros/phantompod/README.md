# Phantom pod -- phantom pain, but with lost pods

This describes and reproduces a "phantom pod" situation with a bare minimun
kind cluster.

In one of our kubernetes cluster investigations, a deployment gets scheduled
to a node, then kubelet complains with "OutOfcpu". We followed a lead that
kubelet keeps logging 'pod "{podname}" not found' in token_manager, and found
a pod that "disappeared". We then noticed etcd was restored to a previous state
right after the pod creation. This is an effort to consolidate and validate
our theory that a "phantom" pod due to etcd restore will be lingered on kubelet
without restarting, and cause validation errors on entring kubelet.

Follow up: as suggested by https://github.com/kubernetes/kubernetes/issues/131115#issuecomment-2781283619,
adding `--bump-revision 1000000000 --mark-compacted` seem to help.

## Reproduction steps

The steps below requires bash, kubectl, docker and kind, validated on
kind 0.27.0, with below node images so far:

* kindest/node:v1.29.14
* kindest/node:v1.30.10
* kindest/node:v1.31.6
* kindest/node:v1.32.2

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
  kubeadmConfigPatches:
  - |
    kind: JoinConfiguration
    nodeRegistration:
      kubeletExtraArgs:
        v: "4"
EOF
# kind create cluster -n phantompod --image kindest/node:v1.29.14 --config kind.config --kubeconfig phantompod.kubeconfig
# kind create cluster -n phantompod --image kindest/node:v1.30.10 --config kind.config --kubeconfig phantompod.kubeconfig
# kind create cluster -n phantompod --image kindest/node:v1.31.6 --config kind.config --kubeconfig phantompod.kubeconfig
kind create cluster -n phantompod --image kindest/node:v1.32.2 --config kind.config --kubeconfig phantompod.kubeconfig
export KUBECONFIG="$PWD/phantompod.kubeconfig"

# just in case I want to fiddle around with my shortcuts
alias k='kubectl --context kind-phantompod'
alias kk='kubectl --context kind-phantompod -n kube-system'

# to make sure we have all components ready
kubectl wait --for='jsonpath={.status.conditions[?(@.type=="Ready")].status}=True' node/phantompod-control-plane
kubectl get node
kubectl -n kube-system get pods -owide

# we use half of node CPU capacity so the node can only take 1, not 2 pods
NODECPUS=$(kubectl get node phantompod-worker -ojsonpath='{.status.capacity.cpu}')
DEPLOYMENT_TEMPLATE=$(cat <<EOF
apiVersion: apps/v1
kind: Deployment
metadata:
  name: "\$APP"
  labels:
    app: "\$APP"
spec:
  replicas: \$REPLICAS
  selector:
    matchLabels:
      app: "\$APP"
  template:
    metadata:
      labels:
        app: "\$APP"
    spec:
      containers:
      - name: "\$APP"
        image: busybox:1.37-musl
        command: [sleep, infinity]
        resources:
          requests:
            cpu: $((NODECPUS/2))
EOF
)
APP=phantom REPLICAS=0 envsubst <<<"$DEPLOYMENT_TEMPLATE" | kubectl apply -f-
sleep 1
# we take etcd snapshot
kubectl -n kube-system exec -it etcd-phantompod-control-plane -- sh -c 'ETCDCTL_API=3 etcdctl --endpoints=https://127.0.0.1:2379 \
  --cacert=/etc/kubernetes/pki/etcd/ca.crt --cert=/etc/kubernetes/pki/etcd/peer.crt --key=/etc/kubernetes/pki/etcd/peer.key \
  snapshot save /backup1.data'

# we then introduce the phantom pod
kubectl scale --replicas 1 deployment/phantom
# kubectl get deploy phantom
kubectl rollout status deployment/phantom

# we exec into the docker node, pause etcd, remove data of /var/lib/etcd/member,
# restore, then bounce etcd
docker exec -it phantompod-control-plane bash -xc '
containerid=$(crictl ps --name etcd -o json | jq -r ".containers[0].id")
runc --root /run/containerd/runc/k8s.io pause "$containerid"
rm -rf /var/lib/etcd/member
ls /var/lib/etcd
# REPRO
ETCDCTL_API=3 nsenter -m -t $(pgrep etcd) etcdctl --data-dir /var/lib/etcd snapshot restore /backup1.data
# NO-REPRO
# ETCDCTL_API=3 nsenter -m -t $(pgrep etcd) etcdctl --data-dir /var/lib/etcd snapshot restore /backup1.data --bump-revision 1000000000 --mark-compacted
runc --root /run/containerd/runc/k8s.io kill "$containerid" KILL
'

sleep 3
# we verify if deployment gets restored to 0 replicas
kubectl get deploy 

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

# we visually verify if control plane components restarted and working
kubectl -n kube-system get pod

# we introduce a "culprit pod" that should trigger OutOfcpu
APP=culprit REPLICAS=1 envsubst <<<"$DEPLOYMENT_TEMPLATE" | kubectl apply -f-
sleep 10  # allow controllers to breathe
kubectl get pods -owide
```

One should see repro like below on the get pod:

```
NAME                       READY   STATUS     RESTARTS   AGE   IP       NODE                NOMINATED NODE   READINESS GATES
culprit-6646dbb846-28b2p   0/1     OutOfcpu   0          4s    <none>   phantompod-worker   <none>           <none>
culprit-6646dbb846-2gmnn   0/1     OutOfcpu   0          1s    <none>   phantompod-worker   <none>           <none>
culprit-6646dbb846-4kpfn   0/1     OutOfcpu   0          0s    <none>   phantompod-worker   <none>           <none>
...
```
