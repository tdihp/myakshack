#!/bin/bash
# stress all running nginx pods in parallel

stressloop() {
    local counter=1
    while grep -xFq "$1" remotes; do
        local tags="by=\"$HOSTNAME\",dest=\"$1\",run=\"$counter\",abargs=\"$AB_ARGS\""
        ab $AB_ARGS "http://$1/" | sed -rn \
            -e 's/Time taken for tests:\s+([0-9.]+)\s+seconds/'"# TYPE ab_time gauge\nab_time{$tags} \\1/p" \
            -e 's/Requests per second:\s+([0-9.]+)\s+.*/'"# TYPE ab_rps gauge\nab_rps{$tags} \\1/p" \
            -e 's/Complete requests:\s+([0-9]+)/'"# TYPE ab_complete gauge\nab_complete{$tags} \\1/p" \
            -e 's/Failed requests:\s+([0-9]+)/'"# TYPE ab_failed gauge\nab_failed{$tags} \\1/p" \
        | tee /dev/stderr | curl --data-binary @- http://prometheus:9091/metrics/job/stress
        counter=$(($counter + 1))
    done
    echo "stopped"
}

discovery() {
    touch remotes
    while : ; do
        dig +search +short nginx | sort -n | ([[ -n $STRESS_FIRSTN ]] && head -n $STRESS_FIRSTN || cat -) >remotes.next
        comm -13 remotes remotes.next >remotes.new
        mv remotes.next remotes
        while IFS="" read -r remote || [ -n "$remote" ]; do
            echo "discovered new remote $remote, starting stress"
            stressloop "$remote" &
        done <remotes.new
        sleep 10
    done
}

apt-get update && apt-get install -y dnsutils apache2-utils curl
discovery
