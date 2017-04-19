#!/bin/bash

mkfs.xfs -f /dev/nvme0n1
mount -o noatime /dev/nvme0n1 /mnt/btrfs-test
mkdir /mnt/btrfs-test/0
mkdir /mnt/btrfs-test/1
mkdir /mnt/btrfs-test/2
mkdir /mnt/btrfs-test/reads

./fs_mark -n 1000000 -L 1 -s0 -d /mnt/btrfs-test/0 -d /mnt/btrfs-test/1 \
	-d /mnt/btrfs-test/2
grep xfs_inode /proc/slabinfo

dd if=/dev/zero of=/mnt/btrfs-test/reads/file1 bs=1M seek=100000 count=1

./read-dir /mnt/btrfs-test/0 &
PID1=$!
./read-dir /mnt/btrfs-test/1 &
PID2=$!
./read-dir /mnt/btrfs-test/2 &
PID3=$!
python watch-alloc-inode.py $PID1 $PID2 $PID3 &
PID4=$!

cat /mnt/btrfs-test/reads/file1 > /dev/null
/usr/bin/kill -SIGINT $PID1 $PID2 $PID3
wait -n $PID1 $PID2 $PID3
/usr/bin/kill -SIGINT $PID4
wait -n $PID4
grep xfs_inode /proc/slabinfo
#/usr/bin/kill -SIGINT $BCCPID
#wait
#grep xfs_inode /proc/slabinfo
umount /mnt/btrfs-test
