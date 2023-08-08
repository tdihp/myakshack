# Mitmproxy on Components of AKS

[Mitmproxy](https://docs.mitmproxy.org/) is a great tool on sniffing http(s)
connections. Sometimes such approach is necessary due to limitations causing
unclear reason of failed api calls, while most http(s) clients are compatible
with http_proxy and https_proxy environemnt variables.

This walkthrough guides several common scenarios:

1. Capturing https traffic of a modifiable pod;
2. Capturing https traffic of Kubernetes node components.

We won't cover how to review mitmproxy outputs in this walkthrough. Exploring
by simply trying it out is recommended.

We are only going to go through regular proxy use cases, not transparent proxy.
This is because transparent proxy requires similar amount of work, while regular
proxy mode gives more room for explicit control. Noting the only drawback is
that we won't be able to capture without restarting the application. If no
restarting is important, follow 
[here](https://docs.mitmproxy.org/stable/howto-transparent/) in addition to what
we learned.

## Capturing https traffic of a pod

Any AKS setup (well, actually most k8s setup) given sufficient k8s access should
be compatible with this part. We deploy mitmproxy as a single pod proxy, then
configure the application to pass https traffic through it.

### Step 1: deploy mitmproxy as a service

Deploy mitmproxy in a pod:

```shell
kubectl run -it --rm --restart=Never --image mitmproxy/mitmproxy mitmproxy -- bash
```

After entering the terminal, run `mitmproxy` on the terminal. We should see the
mitmproxy capturing interface. Instead of directly run `mitmproxy` This extra
step is needed so mitmproxy can get the correct tty detail.

Expose the pod as a service:

```shell
kubectl expose pod mitmproxy --port 8080
```

### Step 2: Setting up client pod

In this part we assue we are targeting curl as the testing application, so we
assume curl needs to be installed. Unless otherwise mentioned, after the
commands ran, a shell prompt will show, and if run any curl command such as
`curl https://bing.com/`, the traffic will be traced and shown in the mitmproxy
terminal.

#### For Alpine based images (and the azure-cli image)

```shell
kubectl run -it --rm --restart=Never --image=alpine:3.18 alpine -- sh -c '
apk add curl
curl --proxy http://mitmproxy:8080 http://mitm.it/cert/pem -o /usr/local/share/ca-certificates/mitmproxy.crt
update-ca-certificates
export https_proxy=http://mitmproxy:8080
exec sh
'
```

A special note for azure-cli: azure-cli [needs extra configuration](
https://docs.microsoft.com/cli/azure/use-cli-effectively#work-behind-a-proxy)
and doesn't use system's ca-certs. With the below command, the created azure-cli
pod shall be able to run `az` commands with proxy.
See [certifi](https://pypi.org/project/certifi/) on how we locate the cert
bundle to replace.

```shell
kubectl run -it --rm --restart=Never --image=mcr.microsoft.com/azure-cli azure-cli -- bash -c '
curl --proxy http://mitmproxy:8080 http://mitm.it/cert/pem -o /usr/local/share/ca-certificates/mitmproxy.crt
update-ca-certificates
export https_proxy=http://mitmproxy:8080
cp /etc/ssl/certs/ca-certificates.crt "$(python -m certifi)"
exec bash
'
```

#### For Debian/Ubuntu based images

```shell
kubectl run -it --rm --restart=Never --image=debian:bookworm-slim debian -- bash -c '
apt-get update && apt-get install curl -y
curl --proxy http://mitmproxy:8080 http://mitm.it/cert/pem -o /usr/local/share/ca-certificates/mitmproxy.crt
update-ca-certificates
export https_proxy=http://mitmproxy:8080
exec bash
'
```

Same script also tested with `--image=ubuntu:22.04` and `--image=ubuntu:18.04`.

#### For REHL/Fedora/CentOS/AzureLinux/CBL-Mariner based images

```shell
kubectl run -it --rm --restart=Never --image=fedora:38 fedora -- bash -c '
curl --proxy http://mitmproxy:8080 http://mitm.it/cert/pem -o /etc/pki/ca-trust/source/anchors/mitmproxy.crt
update-ca-trust
export https_proxy=http://mitmproxy:8080
exec bash
'
```

Same script also tested with `--image=centos:7`.and
`--image=mcr.microsoft.com/cbl-mariner/base/core:2.0`

#### For Windows images

TBD
<!-- certutil -user -addstore "Root"  -->

## Capturing https traffic of Kubernetes node components

TBD
<!-- This part is specific to AKS. Follow [env.sh](./env.sh) and
[provision.sh](./provision.sh) -->
