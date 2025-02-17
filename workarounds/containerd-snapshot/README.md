# Containerd Snapshot to Image mapping

This effort locates overlay snapshot path to images. This should help if some
security scanner located suspectable binary in snapshot paths, without knowing
which image it belongs to.

Tested on Containerd 1.7.25

## Install bbolt

Containerd uses [bbolt](https://github.com/etcd-io/bbolt/tree/main) for storing
data. Unfortunately, containerd doesn't provide similar feature to expose its
snapshot status. bbolt database will be extracted to get a layer to id mapping.
See https://github.com/containerd/containerd/blob/e82d201b3ffb87c15d2b7be2eb2e0c7bfa99d114/snapshots/storage/bolt.go.

``` shell
# download golang to /usr/local, assuming a fresh installation
export PATH=$PATH:/usr/local/go/bin:~/go/bin
curl -Ls https://go.dev/dl/go1.24.0.linux-amd64.tar.gz | tar zx -C /usr/local 
go install go.etcd.io/bbolt/cmd/bbolt@v1.4.0
```

## Extract snapshot sha to ID mapping

``` shell
uvarint() {
  local buf=$1
  local x=0
  local s=0
  while [ $buf ]; do
    local b=$((0x${buf:0:2}))
    buf=${buf:2}

    if [ $b -lt $((0x80)) ]; then
       echo -n $(( x | ( b << s ) ))
       return 0
    fi
    : $(( x |= ((b & 0x7f) << s) ))
    : $(( s += 7 ))
    # echo "buf=$buf b=$b s=$s x=$x"
  done
}
# make a copy of metadata.db, this is needed as otherwise containerd locks the
# file
cp /var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/metadata.db .
KEYPREFIX="v1 snapshots"
layer2id() {
  for snapshot in $(bbolt keys "metadata.db" $KEYPREFIX ); do
    local hexid=$(bbolt get --format=hex "metadata.db" $KEYPREFIX $snapshot id)
    echo "${snapshot##*/} $(uvarint $hexid)"
  done
}
layer2id | sort -t " " -k 1 >layer2id.txt
```

## Extract image to snapshot sha mapping

``` shell
image2layers() {
  for image in $(ctr -n k8s.io i ls | cut -d" " -f1 | tail -n+2); do
    for layer in $(ctr -n k8s.io i usage $image | cut -d" " -f1 | tail -n+2); do
      echo "$image $layer"
    done
  done
}
image2layers | sort -t " " -k 2 >image2layers.txt
```

## Join them together

Run below to find those columns: layer hash, image hash, layer snapshot id.

The layer id should map to file path under
`/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/`.

``` shell
join -t " " -12 -21 image2layers.txt layer2id.txt
```
