#!/bin/bash

SCRATCH_DEV=/dev/sdb
SCRATCH_MNT=/mnt/test
FSSTRESS_PROG=/root/xfstests-dev/ltp/fsstress

_cleanup() {
	pkill -9 fsstress
	while [ 1 ]
	do
		ps auxw | grep fsstress | grep -v grep > /dev/null 2>&1 || break
		sleep 1
	done
}
trap _cleanup EXIT

mount $SCRATCH_DEV $SCRATCH_MNT || exit 1

$FSSTRESS_PROG -n 10000 -l 0 -p 4 -d $SCRATCH_MNT &
wait
