#!/bin/bash

dmesg | egrep -q -e "kernel BUG at" \
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

[ "$?" -eq 0 ] && ~/push.sh "got something" && exit 1

btrfs device scan --forget
exit 0
