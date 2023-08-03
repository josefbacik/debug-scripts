#!/bin/bash

dmesg | grep -E -q -e "kernel BUG at" \
	     -e "WARNING:" \
	     -e "\bBUG:" \
	     -e "Oops:" \
	     -e "possible recursive locking detected" \
	     -e "Internal error" \
	     -e "(INFO|ERR): suspicious RCU usage" \
	     -e "INFO: possible circular locking dependency detected" \
	     -e "general protection fault:" \
	     -e "BUG .* remaining" \
	     -e "UBSAN:" \
             -e "leaked"

[ "$?" -eq 0 ] &&  exit 1

umount /mnt/test
btrfs device scan --forget
exit 0
