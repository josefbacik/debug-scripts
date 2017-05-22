#!/bin/bash

CGROUP_MAIN=/sys/fs/cgroup
CGROUP_DIR=$CGROUP_MAIN/foo
CGROUP_BASE=$CGROUP_DIR/interactive

_mkdir() {
	mkdir $1
	echo "+cpu" > $1/cgroup.subtree_control
}

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

echo "+cpu" > $CGROUP_MAIN/cgroup.subtree_control
_mkdir $CGROUP_DIR
_mkdir $CGROUP_BASE
mkdir $CGROUP_BASE/small
mkdir $CGROUP_BASE/large
echo 10000 > $CGROUP_BASE/small/cpu.weight
echo 10000 > $CGROUP_BASE/large/cpu.weight

_isolate_run $CGROUP_BASE/small rt-app new-unbalanced.json &
#_isolate_run $CGROUP_BASE/small /root/schbench/schbench -r 60 -m 16 -t 350 -s 1000 &
RTPID=$!

_isolate_run $CGROUP_BASE/large stress -c 48 &
wait $RTPID
pkill -9 stress
wait
echo "Small usage"
cat $CGROUP_BASE/small/cpu.stat
echo "Large usage"
cat $CGROUP_BASE/large/cpu.stat
