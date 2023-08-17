# Quickack CNI plugin

This is a CNI plugin that enables quickack on the default route of the pod
network.

Tested on AKS Azure CNI configuration.

## What's wrong with no quickack?

A Linux kernel change
https://lore.kernel.org/all/20220721204404.388396-1-weiwan@google.com/ changed
pingpong mode threshold from 3 to 1. Pingpong mode is a flag that indicates
the connection currently has frequent incoming packets getting acked. When
activated, [delayed ack](https://datatracker.ietf.org/doc/html/rfc1122#page-96)
will be fired instead of a instant ack. This means Linux TCP stack now more
easily sends a delayed ack, instead of sending acks instantly.

Delayed ack is usually fine, however when the opposite side has Nagle's
algorithm enabled, communication can enter a "standoff", i.e., one side decide
to send a delayed ack, while on the other side the Nagle's algorithm need to
wait for all outstanding acks before it sends anything else. This "standoff"
costs considerable delay (~40ms by default) and is harmful for latency-sensitive
workloads.

## How to detect the "delayed ack"?

"delayed ack" will generally show in tcpdump as an ack packet that took longer
to send.

To precisely see if the delayed ack logic in Linux kernel is involved, It is
possible by using ebpf. See [trace_delayed_acks.py](./trace_delayed_acks.py) for
a working tracing script that prints tcp_send_delayed_ack timings, with IP, port
and seq, to be able to match what's observed in tcpdump.

## Reproduction

See [delayed-ack-repro](./delayed-ack-repro) directory for a full reproduction.
use deploy.sh and cleanup.sh to install/remove the repro app. Noting Nagle's
algorithm is added at client side which triggers the standoff. If we remove
`--nagle` for the client deployment, the latency improves significantly.

## How to eliminate the "standoff"?

To eliminate the standoff, below alternatives can be considered:

1. On a Linux application, flag TCP_NODELAY, which disables Nagle's algorithm.
   This prevents the TCP stack unnecessarily waiting for a (potentially delayed)
   ack packet to proceed. This option generally needs code change of the
   application.
2. On a Linux networking environment, enable "quickack" route option. This
   overrides the "pingpong" logic and always send ack immediately.

On Linux environment, the 2nd option is achieved by using:

```shell
ip route change <routename> ...... quickack 1
```

On Kubernetes environments, such option must be enabled in the network namespace
of the pod. This is because the TCP stack only take action inside the network
namespace.

This can be achieved with below options:

1. Configure a init container which runs ip route
2. Configure a daemonset that monitors all pod namespaces, then apply the route
   change as needed.
3. Configure a CNI plugin which apply the change when pod starts on demand
   (this approach).

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
