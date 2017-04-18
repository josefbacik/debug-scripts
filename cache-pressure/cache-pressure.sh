#!/bin/bash

mkfs.xfs -f /dev/nvme0n1
mount -o noatime /dev/nvme0n1 /mnt/btrfs-test
mkdir /mnt/btrfs-test/0
mkdir /mnt/btrfs-test/1
mkdir /mnt/btrfs-test/reads

dd if=/dev/zero of=/mnt/btrfs-test/reads/file1 bs=1M count=6500 &
dd if=/dev/zero of=/mnt/btrfs-test/reads/file2 bs=1M count=6500 &
wait

./read-file /mnt/btrfs-test/reads/file1 &
PID1=$!
./read-file /mnt/btrfs-test/reads/file2 &
PID2=$!

sleep 5
./fs_mark  -D  5000  -S0  -n  100000 -s 0  -L  20 \
        -d /mnt/btrfs-test/0  -d /mnt/btrfs-test/1
/usr/bin/kill -SIGINT $PID1 $PID2
wait -n $PID1
wait -n $PID2
grep SReclaimable /proc/meminfo
umount /mnt/btrfs-test
