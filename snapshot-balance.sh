#!/bin/bash

COMPILEBENCH=/root/compilebench-0.6/
DEV=/dev/nvme1n1
MNT=/mnt/test
SNAP_INTERVAL=1
NUM_SNAPS=10

_fail() {
	echo $1
	exit 1
}

_snap_thread() {
	local i=0
	local del=0
	local DEL_MOD=$(( NUM_SNAPS * 2 ))
	local DEL_SNAPS=$NUM_SNAPS
	while [ 1 ]
	do
		sleep $SNAP_INTERVAL
		btrfs sub snap $MNT $MNT/snaps/snap$i > /dev/null || \
				_fail "failed to create snap$i"
		i=$(( i + 1 ))
		if [ "$(( i % DEL_MOD))" -eq "0" ]
		then
			for c in $(seq 1 $DEL_SNAPS)
			do
				btrfs subvolume delete $MNT/snaps/snap$del || \
					_fail "failed to delete snap$del"
				del=$((del + 1 ))
			done
			btrfs balance start --full-balance --bg $MNT
			DEL_SNAPS=20
		fi
	done
}

_balance_thread() {
	while [ 1 ]
	do
		sleep $SNAP_INTERVAL
		btrfs balance start --full-balance $MNT || \
			_fail "failed to balance"
	done
}

mkfs.btrfs -f -n 4096 $DEV || _fail "couldn't mkfs"
mount $DEV $MNT || _fail "couldn't mount"

mkdir $MNT/snaps
_snap_thread &
SNAP_PID=$!

cd $COMPILEBENCH
for i in $(seq 0 100)
do
	./compilebench -i 300 -m -D $MNT || break
done

[ "$?" -ne "0"] && echo "compilebench failed"

btrfs balance cancel $MNT
kill -9 $SNAP_PID

wait
