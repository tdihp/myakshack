UDRSync -- A independent UDR updater for AKS "kubenet" routes
=============================================================

This is an example for updating UDR entry to a given UDR.
Note that this is a POC example, optimization will likely be needed on every
level for any production use.

How to use
----------

### Prerequisites

* bash
* azure-cli
* azure account, subscription with sufficient permission.
* knowledge and courage to understand files in this directory

### Instruction

1. Alter `provision.sh` to update SP/tenant detail.
2. `bash provision.sh`, observe AKS and sample UDR being created.
3. `kubectl apply -f aksudrsync-cfg-generated.yaml`, note this file is generated
   by executing `provision.sh`.
4. `kubectl aply -f aksudrsync-cronjob.yaml`.
5. scale / fiddle the cluster and observe target UDR. It should be updated every
   minute.
