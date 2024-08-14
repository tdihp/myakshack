#!/bin/bash
# finds the accelerated nic on VM
find_eth () {
    basename -a /sys/class/net/* | grep -E 'eth1|^en'
}

# find all interrupts that we care
find_interrupts() {
    </proc/interrupts grep -oP '\d+(?=:.*mlx5_comp)'
}

# find all cpuids we might want to spread interrupts
find_cpuids() {
    # we cut corners to only show the IDs, assuming they are all online
    # lscpu --extended=cpu,node,socket,core
    lscpu --extended=cpu | tail -n+2
}

spread_irqs() {
    paste <(find_interrupts) <(find_cpuids) | while read -r irq cpuid
    do
        printf "%x" "$((1<<$cpuid))" > /proc/irq/$irq/smp_affinity
    done
}

# https://docs.nvidia.com/networking/display/mlnxofedv23070512/flow+steering
enable_rfs() {
    echo 32768 > /proc/sys/net/core/rps_sock_flow_entries
    ETH="${1:-$(find_eth)}"
    NUM_CHANNELS=`ethtool -l $ETH | grep "Combined:" | tail -1 | awk '{print $2}'`
    for f in `seq 0 $((NUM_CHANNELS-1))`; do echo 32768 > "/sys/class/net/$ETH/queues/rx-$f/rps_flow_cnt"; done
}

enable_arfs() {
    ETH="${1:-$(find_eth)}"
    enable_rfs "$ETH"
    ethtool -K "$ETH" ntuple on
}

# you may alternatively want to configure irqbalance --policyscript instead
# while how best to permanent configure this is out of scope here.
noirqbalance() {
    systemctl stop irqbalance
    systemctl disable irqbalance
    spread_irqs
}

# configuring rfs shouldn't require irqbalance, which we should find out
configure_vm_rfs() {
    enable_rfs
}

configure_vm_arfs() {
    noirqbalance
    enable_arfs
}

configure_vm_vanilla() {
    systemctl enable irqbalance
    ETH="$(find_eth)"
    NUM_CHANNELS=`ethtool -l $ETH | grep "Combined:" | tail -1 | awk '{print $2}'`
    for f in `seq 0 $((NUM_CHANNELS-1))`; do echo 0 > "/sys/class/net/$ETH/queues/rx-$f/rps_flow_cnt"; done
    ethtool -K "$ETH" ntuple off
}

if [ -n "$CONFIGURE_VM" ]; then
    echo "configure VM with setting $CONFIGURE_VM"
    set -x
    METRIC=0
    configure_vm_vanilla
    case "$CONFIGURE_VM" in
        vanilla)
            ;;
        rfs)
            METRIC="1"
            configure_vm_rfs
            ;;
        rfs-noirqbalance)
            METRIC="2"
            noirqbalance
            configure_vm_rfs
            ;; 
        arfs)
            METRIC="3"
            configure_vm_arfs
            ;;
        *)
            echo "unknown config $CONFIGURE_VM"
            METRIC="NaN"
            exit 1
            ;;
    esac
    if [ -n "$METRIC_PATH" ]; then
        mkdir -p "$METRIC_PATH"
        echo "rfsconfig{} $METRIC" >"$METRIC_PATH"/rfsconfig.prom.$$
        mv "$METRIC_PATH"/rfsconfig.prom.$$ "$METRIC_PATH"/rfsconfig.prom
    fi
    sleep inf
fi
