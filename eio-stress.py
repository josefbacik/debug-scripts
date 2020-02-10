from bcc import BPF
from time import sleep
from subprocess import Popen
import argparse
import sys
import os
import ctypes as ct

bpf_text = """
#include <uapi/linux/ptrace.h>
#include <linux/bio.h>
#include <linux/blkdev.h>

BPF_CGROUP_ARRAY(cgroup, 1);
BPF_HASH(seen, u64);
BPF_ARRAY(enabled, u64, 1);
BPF_PERF_OUTPUT(events);
BPF_STACK_TRACE(stack_traces, 10240);

int override_function(struct pt_regs *ctx, struct bio *bio)
{
    unsigned long rc = RCVAL;

    if (bio->bi_disk->major != 8 || bio->bi_disk->first_minor != 16)
        return 0;

    /* Make sure we're ready to inject errors. */
    int index = 0;
    u64 *e = enabled.lookup(&index);
    if (!e || *e == 0)
        return 0;
    if (*e > 1)
        goto fail;

    /* Have we seen this stacktrace yet? */
    u64 key = stack_traces.get_stackid(ctx, BPF_F_REUSE_STACKID);
    u64 zero = 0;
    u64 *val = seen.lookup_or_init(&key, &zero);
    if (*val == 1)
        return 0;
    lock_xadd(val, 1);
    lock_xadd(e, 1);

    events.perf_submit(ctx, &key, sizeof(key));
    bpf_trace_printk("overrding something\\n");
fail:
    bpf_override_return(ctx, rc);
    return 0;
}
"""

error_tripped = 0

parser = argparse.ArgumentParser()
parser.add_argument("-o", "--override", required=True,
                    help="The function to override")
parser.add_argument("-r", "--retval", type=str, help="The return value to use")
parser.add_argument("-e", "--executable", type=str, required=True,
                    help="The command to run")
parser.add_argument("-c", "--cgroup", type=str, required=True,
                    help="Path to the cgroup we'll be using for this")

args = parser.parse_args()
retval = "NULL"

if args.retval is not None:
    retval = args.retval

bpf_text = bpf_text.replace("RCVAL", retval)

fd = os.open(args.cgroup, os.O_RDONLY)

print("Loading error injection")
b = BPF(text=bpf_text)

# Load the cgroup id into the table
t = b.get_table("cgroup")
t[0] = fd

# Load the kretprobe first, because we want the delete guy to be in place before
# the add guy is in place, otherwise we could error out pids that are no longer
# in our path and cause unfortunate things to happen.
b.attach_kprobe(event=args.override, fn_name="override_function")

def handle_error(cpu, data, size):
    stackid = ct.cast(data, ct.POINTER(ct.c_ulonglong)).contents
    stack_traces = b.get_table("stack_traces")
    stack = stack_traces.walk(stackid.value)
    print("Injected error here")
    for addr in stack:
        print("  %s" % b.ksym(addr))
    globals()['error_tripped'] = 1

b["events"].open_perf_buffer(handle_error)

while 1:
    print("Running command")
    error_tripped = 0
    t = b.get_table("enabled")
    t[0] = ct.c_int(1)

    p = Popen(args.executable)

    while error_tripped == 0:
        b.kprobe_poll(timeout=10)
        if p.poll() is not None:
            print("The command exited, breaking")
            break

    print("Waiting for the command to exit")
    p.wait()

    p = Popen(["umount", "/mnt/test"])
    p.wait()

    if error_tripped == 0:
        print("Error injection didn't trip anything, exiting")
        break

    t[0] = ct.c_int(0)

    p = Popen("./check.sh")
    if p.wait() == 1:
        print("Things went wrong, breaking")
        break

# We have to remove in this order otherwise we could end up with a half
# populated hasmap and overrding legitimate things.
b.detach_kprobe(args.override)
print("Exiting")

