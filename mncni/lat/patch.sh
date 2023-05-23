#!/bin/sh
set -xe

cd /etc/cni/net.d
while [ 1 ]
do
    TGT=`ls -1 *.conflist | head -n 1`
    if [ ! -z "$TGT" ]; then
        oldhash=`md5sum "$TGT" | cut -f 1 -d " "`
        <"$TGT" jq '.plugins |= (.|map(select(.type!="lat"))) + [{"type":"lat","capabilities":{"io.kubernetes.cri.pod-annotations":true}}]' >"${TGT}.new"
        newhash=`md5sum "${TGT}.new" | cut -f 1 -d " "`
        if [ "$oldhash" != "$newhash" ]; then
            cp "$TGT" "${TGT}.backup"
            mv "${TGT}.new" "$TGT"
        fi
    fi
    sleep 30
done