#!/bin/bash

SCRATCH_DEV=/dev/vg0/lv0
SCRATCH_MNT=/mnt/test
FSSTRESS_PROG=/root/xfstests-dev/ltp/fsstress

mount $SCRATCH_DEV $SCRATCH_MNT || exit 1

btrfs balance start --full-balance $SCRATCH_MNT
while [ 1 ]
do
	btrfs ba status $SCRATCH_MNT && break
    sleep 1
done

while [ 1 ]
do
    umount $SCRATCH_MNT && break
done
