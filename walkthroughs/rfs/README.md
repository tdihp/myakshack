# Configure RFS or aRFS on AKS

https://www.kernel.org/doc/html/latest/networking/scaling.html

This walkthrough goes through how to enable aRFS or RFS on AKS nodes, and
does a benchmark with ab.

## Instructions

To provision Azure environment: review and run provision.sh

To provision test apps, configuration and monitoring: `kubectl apply -k .`

To switch user nodes to use either arfs or rfs, find env variable "CONFIGURE_VM"
in [kustomization.yml](./kustomization.yml), modify and run
`kubectl apply -k .`. Valid options are mapped as below:

* vanilla: default node settingw without rfs
* rfs: rfs configured
* rfs-noirqbalance: rfs with irqbalance disabled
* arfs: arfs configured, this option implies no irqbalance

See [rfsconfig.sh](./rfsconfig.sh) for detail on what's configured.

To review Prometheus metrics:

run `kubectl port-forward svc/prometheus 9090`

then visit:
http://localhost:9090/graph?g0.expr=rate(node_interrupts_total%7Bdevices%3D~%22.*mlx.*%22%7D%5B1m%5D)&g0.tab=0&g0.stacked=0&g0.show_exemplars=0&g0.range_input=30m&g1.expr=rate(node_cpu_seconds_total%7Bmode%3D~%22softirq%7Cuser%7Csystem%22%7D%5B1m%5D)&g1.tab=0&g1.stacked=0&g1.show_exemplars=0&g1.range_input=30m&g2.expr=rate(label_replace(%7B__name__%3D~%22node_ethtool_cpu%5C%5Cd%2B_received_packets%22%7D%2C%20%22cpu%22%2C%20%22%241%22%2C%20%22__name__%22%2C%20%22node_ethtool_cpu(%5C%5Cd%2B)_received_packets%22)%5B5m%3A%5D)&g2.tab=0&g2.stacked=0&g2.show_exemplars=0&g2.range_input=30m&g3.expr=rfsconfig&g3.tab=0&g3.stacked=0&g3.show_exemplars=0&g3.range_input=30m&g4.expr=label_join(ab_time%2C%20%22run%22%2C%20%22%2C%22)&g4.tab=0&g4.stacked=0&g4.show_exemplars=0&g4.range_input=1h&g5.expr=label_join(ab_rps%2C%20%22run%22%2C%20%22%2C%22)&g5.tab=0&g5.stacked=0&g5.show_exemplars=0&g5.range_input=1h&g6.expr=label_join(ab_failed%2C%20%22run%22%2C%20%22%2C%22)&g6.tab=0&g6.stacked=0&g6.show_exemplars=0&g6.range_input=1h

stress workload is already configured in kubernetes, but to run stresstest from
test VM manually, run `ab -c4 -n 5000000 -k http://<nginx-pod-ip>/` after
logging into the node.

## Infrastructure Configuration

See [provision.sh](./provision.sh) for details.

A AKS cluster with three pools (system, workpool and stresspool) is provisioned,
additionally, a test VM is provisioned for any auxilary tasks/tests.

Workpool is configured with cpuManagerPolicy=static so pods can have CPU
affinity out-of-box. We are assuming the server takes one exact CPU, note
however real world examples might not satisfy this requirement, making CPU
affinity configuration more complicated inside pod.

## Kubernetes Configuration

Several components are deployed:

* rfsconfig -- enable/disable rfs/arfs according to configmap
* Monitoring components:
    * Prometheus/pushgateway -- for monitoring
    * node-exporter -- for extracting workpool CPU/interrupt metrics
* nginx -- dummy server with 1 worker configuration
* stress -- monitors all nginx pods, and run ab against all of them.

