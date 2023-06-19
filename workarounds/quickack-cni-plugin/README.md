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

Quick ack will only be applied to pods that has annotation `enable-quickack`,
once the CNI patch is applied.

The CNI patch puts file `/var/run/quickack-enabled`. User can mount this file
to block pod from being started before CNI patching.

See [testpod](./testpod.yaml) for an example pod.
