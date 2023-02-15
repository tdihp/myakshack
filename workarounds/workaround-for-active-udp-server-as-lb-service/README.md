Workaround for active UDP server as LB service
==============================================

This repo gives a simple repro of the problem and gives a mitigation of it.

The Problem
-----------

For k8s services using iptables implementation of loadbalancer based service,
conntrack can be destroyed after some time. If the server makes calls to clients
after a long time, the UDP packet is considered a new connection and doesn't go
through the original path. 

The Reproduction
----------------

The issue can be trivially reproduced. In `deploy.yaml` and `delaysvc.py`, a
client/server pair can be provisioned. The protocol simply sends ascii numbers,
and the opposite side should respond with `n+1` if the number is under
threshold. See further detail in `delaysvc.py`. The server sends a `1` packet
after a period of time, we should observe the server sends the packet, and in
case the server is hosted in a pod behind LB, we should see client cannot
receive it.

The mitigation
--------------

We add a SNAT rule that pins the outbound IP to the LBIP. See `mitigation.yaml`.

