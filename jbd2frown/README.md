# jbd2frown

This is an effort investigating jbd2 discard based freeze on AKS with Ubuntu
18.04.

See https://lore.kernel.org/all/20210830075246.12516-5-jianchao.wan9@gmail.com/
which explains and also fixes this problem.

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

## Tracing

``` shell
python3 jbd2frown.py -s 128M foobar.dat
# biosnoop gives us a per bio request latency which is nice.
python3 /usr/share/bcc/tools/biosnoop >biosnoop.log &
sleep 10  # this is needed as biosnoop compiling is sometimes slow
date --utc --rfc-3339=ns >ts.txt
# we trace a remove operation, and stop when a dd triggered fsync unblocks.
trace-cmd record \
	-e ext4:ext4_discard_blocks \
	-e block:block_bio_* \
	-e block:block_rq_* \
	-e scsi \
	sh -c "rm foobar.dat && dd bs=1M count=1 if=/dev/zero of=foobar conv=fsync"
# kill biosnoop
kill $(jobs -p)
trace-cmd report >trace-cmd-report.log
# cleanup file produced by dd
rm foobar
```
