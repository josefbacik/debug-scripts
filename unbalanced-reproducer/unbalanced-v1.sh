#!/bin/bash

CGROUP_MAIN=/sys/fs/cgroup/cpuacct
CGROUP_DIR=$CGROUP_MAIN/foo
CGROUP_BASE=$CGROUP_DIR/interactive

_isolate_run()
{
	name=$1
	shift
	echo "running '$*'"
	echo $BASHPID > $name/cgroup.procs
	$*
}

if [ -d "$CGROUP_DIR" ]
then
	rmdir $CGROUP_BASE/small
	rmdir $CGROUP_BASE/large
	rmdir -p $CGROUP_BASE
fi

mkdir -p $CGROUP_BASE/small
mkdir $CGROUP_BASE/large
echo 102400 > $CGROUP_BASE/small/cpu.shares
echo 102400 > $CGROUP_BASE/large/cpu.shares

_isolate_run $CGROUP_BASE/small rt-app new-unbalanced.json &
RTPID=$!

_isolate_run $CGROUP_BASE/large stress -c 48 &
wait $RTPID
pkill -9 stress
wait
echo "Small usage"
cat $CGROUP_BASE/small/cpuacct.usage
echo "Large usage"
cat $CGROUP_BASE/large/cpuacct.usage
