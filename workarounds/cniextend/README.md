# cniextend - extending CNI conflist to include more CNI plugins

This is a simple daemonset that:

1. Periodically checks the first `/etc/cni/net.d/*.conflist` file
2. Extend the plugins list configured in `CNIEXTEND_PLUGINS` key of configMap
   `cniextend-conf`, configurable in kustomization.yaml 
3. Writes a file `/etc/cni/net.d/00-cniextend.conflist` with merged result.
   Containerd should now consider using this one if it takes precedence.
4. Write a file `/var/run/cniextend-enabled-$CNICONFIG_VERSION`, which can be
   used to validate if the CNI latest configuration has been applied.

## Installation

Installing with no extensions is not useful. See [bandwidth](./bandwidth)
directory for an example appending the
[bandwidth plugin](https://www.cni.dev/plugins/current/meta/bandwidth/).

With this repository cloned, simply cd to the directory and run
`kubectl apply -k .` under the bandwidth directory.
