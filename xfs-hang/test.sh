#!/bin/bash

mkfs.xfs -Kf /dev/nvme0n1
mount /dev/nvme0n1 /mnt/test
~/xfstests/ltp/fsstress -d /mnt/test -n 10000 -p 16 -l 0 -fattr_set=1 -fattr_remove=1
