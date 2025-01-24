How to make a multi-functional AzureDisk backed ZFS->NFS server on AKS

To run the server, clone this repository, cd to this directory and run in AKS
(or any kubernetes platform with Ubuntu node and AzureDisk CSI driver):

    kubectl apply -k .

For basic test nfs clients to showcase what's available in the exposed nfs:

    kubectl apply -f client.yaml

Review [kustomization.yaml](./kustomization.yaml) on how to switch between
qemu/KVM and regular container based implemnetation.

For qemu, to access the guest inside pod:

    kubectl exec -it zfsserver-0 -- picocom /dev/pts/0
    # to exit: C-a then C-x following picocom practice

in case the exec session terminated prematurely:

    kubectl exec zfsserver-0 -- pkill picocom

# FAQ

> Why running a VM inside a pod for this?

See [statefulset-pod.yaml] on how many ugly workarounds needed if we are to
leverage today's openzfs in a container with a PV-provided block device.
It is also worth noting that during testing, I found Linux kernel can be
unexpectedly having hanging zfs processes, which, while potential kernel bug,
a Kubernetes user might want to isolate this. So either use a dedicate VM for
ZFS, or wrap a VM inside VM, will be a better approach.

> I can see the QEMU logic here installs alpine, not using a prepared OS image,
  why?

So my example can be as-is without saving the image elsewhere.
Feel free to use a prepared OS image to save the hassle.
