# SECCOMP scenarios

## Filtering syscall args

Seccomp "profile" json that filters syscall args.

To run this:

    kubectl apply -f seccomp.ds.yaml  # installs the profile with a daemonset
    kubectl apply -f ipv4tcpaudit.yaml  # Adds a testing pod

Once exec to the pod, try to run `apk add curl` and etc, and check
`strace -fetrace=socket curl http://bing.com`, compare with
`dmesg -w | grep audit` ran on node, and see that only the ipv4 TCP sockets are
audited, while the DNS queries are not.
