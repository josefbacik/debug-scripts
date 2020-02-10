#!/bin/bash

echo $$ > /sys/fs/cgroup/error-injection/cgroup.procs

SCRATCH_DEV=/dev/sdb
SCRATCH_MNT=/mnt/test
FSSTRESS_PROG=/root/xfstests-dev/ltp/fsstress
FIO_PROG=fio
RUN_TIME=20
NUM_JOBS=4
BLK_DEV_SIZE=`blockdev --getsz $SCRATCH_DEV`
FILE_SIZE=$((BLK_DEV_SIZE * 512))
fio_config=/tmp/blah.fio

mount $SCRATCH_DEV $SCRATCH_MNT || exit 1

cat >$fio_config <<EOF
###########
# $seq test's fio activity
# Filenames derived from jobsname and jobid like follows:
# ${JOB_NAME}.${JOB_ID}.${ITERATION_ID}
[global]
ioengine=libaio
bs=4k
directory=${SCRATCH_MNT}
filesize=${FILE_SIZE}
size=9999T
continue_on_error=write
ignore_error=EIO,ENOSPC:EIO
error_dump=0

[stress_dio_aio_activity]
create_on_open=1
fallocate=none
iodepth=128*${LOAD_FACTOR}
direct=1
buffered=0
numjobs=${NUM_JOBS}
rw=randwrite
runtime=40+${RUN_TIME}
time_based

[stress_mmap_activity]
ioengine=mmap
create_on_open=0
fallocate=1
fdatasync=40960
filesize=8M
size=9999T
numjobs=${NUM_JOBS}
rw=randwrite
runtime=40+${RUN_TIME}
time_based

EOF

# Disable all sync operations to get higher load
FSSTRESS_AVOID="$FSSTRESS_AVOID"

_workout()
{
	out=$SCRATCH_MNT/fsstress.$$
	args="-p 4 -n999999999 -f setattr=0 $FSSTRESS_AVOID -d $out"
	echo ""
	echo "Start fsstress.."
	echo ""
	$FSSTRESS_PROG $args > /dev/null 2>&1 &
#	$FSSTRESS_PROG $args &
	fs_pid=$!
	echo "Start fio.."
	$FIO_PROG $fio_config > /dev/null 2>&1 &
#	$FIO_PROG $fio_config &
	fio_pid=$!

	# Let's it work for awhile, and force device failure
	sleep $RUN_TIME

	kill $fs_pid &> /dev/null
	kill $fio_pid &> /dev/null
	wait $fs_pid
	wait $fio_pid
}

_workout
