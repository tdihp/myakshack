# Quickack CNI plugin

This is a CNI plugin that enables quickack on the default route of the pod
network.

Tested on AKS Azure CNI configuration.

## Detecting delayed ack

It is possible by using ebpf. See
[trace_delayed_acks.py](./trace_delayed_acks.py) for a working tracing script,
that prints tcp_send_delayed_ack timings, to be able to match what's observed
in tcpdump.

## Reproduction

See [delayed-ack-repro](./delayed-ack-repro) directory for a full reproduction.
use deploy.sh and cleanup.sh to install/remove the repro app.

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
