# jbd2frown

This is an effort investigating jbd2 discard based freeze on AKS with Ubuntu
18.04.

## Prerequisite

* Linux (tested on 5.4)
* ext4 with -o discard
* Azure VM with Azure disk

## How to trigger

1. Generate a highly fragmented file. See [jbd2frown.py](./jbd2frown.py) for a
   repro script, but any method that generates high amount of extents in a
   single file works. Fragments of a file can be observed by
   `filefrag <filename>`
2. remove the file.
3. Observe jbd2 process stuck in D state and fsync operations stuck for a while.
