# Quickack CNI plugin

This is a CNI plugin that enables quickack on the default route of the pod
network.

Tested on AKS Azure CNI configuration.

## Installation

```
kubectl create cm -n kube-system quickack --from-file=conf
kubectl apply -f deploy.yaml
```

If this CNI plugin is only needed for some specific nodepool, configure
nodeSelector.

## Usage

See [testpod](./testpod.yaml) for a example pod.

Note that the hostPath is given to block pod from being started before CNI
patching.
