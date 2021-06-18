#!/bin/bash

mkfs.btrfs -f /dev/nvme0n1 -b 100g
mount /dev/nvme0n1 /mnt/scratch
./enospc-stress /mnt/scratch
btrfs fi usage /mnt/scratch
umount /mnt/scratch
