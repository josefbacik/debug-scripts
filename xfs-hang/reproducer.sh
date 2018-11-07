#!/bin/bash

for i in $(cat xfs-log-paths.txt)
do
	func=$(grep " $i" /proc/kallsyms | awk '{ print $3 }')
	[ "$func" == "" ] && continue
	echo "testing $func";
	python inject-error.py -t $func -o should_fail_bio -r 1 -d 20 -T 20 ./test.sh
	pkill -9 fsstress
	while [ $(lsof /mnt/test | wc -l) -gt 0 ]
	do
		sleep 10
	done
	umount /mnt/test
done
