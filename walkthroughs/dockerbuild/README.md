# How to build image in a pod (in progress)

This article aims to list landscape of building a Linux image from a Dockerfile
inside a Kubernetes Linux pod at the time of writing (May 2025), to the best of
my knowledge.

The examples provided are for demonstration purpose only, and by no means
production ready. Corners are cut aiming for e.g., using existing images instead
of building the solution from Dockerfile to shorten the length, and tests are
done under a recent Kubernetes distribution with a relatively recent Linux
distribution with default settings. You may find different results or better
alternatives given different context.

Tested on May 2025, Kubernetes v1.31, Ubuntu 22.04, Linux 5.15, Containerd 1.7,
runc 1.2.

## Cloud Managed Solutions

[ACR Task](https://learn.microsoft.com/en-us/azure/container-registry/container-registry-tasks-overview)
is a cloud solution that uploads docker build context to remote and eventually
pushes to registries.

## BuildKit

[BuildKit](https://github.com/moby/buildkit/tree/master) is a solution
specifically for building images, and is internally used by Docker. Both
[privileged](https://github.com/moby/buildkit/blob/master/examples/kubernetes/job.privileged.yaml)
and
[rootless](https://github.com/moby/buildkit/blob/master/examples/kubernetes/job.rootless.yaml)
solutions are given by official examples.

[RootlessKit](https://github.com/rootless-containers/rootlesskit) is the
solution adopted by buildkit for user_namespace, mount_namespace and
network_namespace isolation, without neededing root. This does not mean the
container doesn't need any capabilities, however. `newuidmap` and `newgidmap`
ran by rootlesskit requires `cap_setuid` and `cap_setgid` respectively. Those
two capabilities are granted by default if not explicitly dropped.  In
kubernetes, Seccomp and AppArmor profiles are both set to "unconfined" to ensure
mounts can be run. See also:
[buildkit doc on rootless](https://github.com/moby/buildkit/blob/master/docs/rootless.md)
for details.

Notice that by the time of writing, buildkit image (v0.21.1-rootless) applies
no network isolation, while this can be fine given we are already somewhat
isolated from host, although not isolated from the runtime and their potential
sidecars.

## Dockerd

It is possible to deploy [dockerd](https://hub.docker.com/_/docker) as a sidecar
for the container image building environment. This is an easy approach for
migrating existing docker build farms to kubernetes. See:

* [dind-sidecar.yaml](./dind-sidecar.yaml) for privileged job
* [dind-sidecar-rootless.yaml](./dind-sidecar-rootless.yaml) for rootless job

Notice that the while doesn't require root UID, the rootless approach still
requires privilege, which is a known issue tracked by docker.

Overall, while user can expect seamless Docker cli in build scripts, rootless
and container security context enforcement can be limiting at the moment.

Running dind isn't the only solution for building in kubernetes. It is also
possible to use
[buildx with kubernetes driver](https://docs.docker.com/build/builders/drivers/kubernetes/),
however the docker way of managing "builder" might work better on a desktop
experience rather than automation scenario. The builder pods runs buildkit,
so for automation situations, directly run buildkit might prove to be simpler.

## Podman

[Podman](https://podman.io/) is a Docker alternative by Red Hat. While there's
no official Kubernetes yaml found on how to use it to build in Kubernetes, the
configuration should be straight-forward even with rootless. See
[podman-rootless.yaml](./podman-rootless.yaml) for a rootless build example.

## Buildah

[Buildah](https://buildah.io/) is a "sister product" of Podman that has more
focus on building image. While Buildah claim to be rootless-configurable, able to build image with the stock image, I'm
not able to configure a rootless build example. See
https://github.com/containers/buildah/issues/5456 that current Buildah may need
further fine tuning to achieve what podman build already can in a restricted
environment. See [buildah-privileged](./buildah-privileged.yaml) for an
privileged build example.

See also: https://docs.gitlab.com/ci/docker/buildah_rootless_tutorial/

## Thoughts

In all the mentioned rootless solutions, user_namespace is used to isolate
UID/GID, so process running inside build will see different UID (like root/1),
while it is running a different UID on the OS level. Kubernetes now also
support
[user namespace](https://kubernetes.io/docs/concepts/workloads/pods/user-namespaces/).
This can be used to eliminate need of invoking user_namespace configurations
by the builders, like buildkit presents with the "userns" examples. 
