from bcc import BPF
from time import sleep
from subprocess import Popen
import argparse
import sys

bpf_text = """
#include <uapi/linux/ptrace.h>
#include <linux/bio.h>

BPF_CGROUP_ARRAY(cgroup, 1);
BPF_HASH(seen, u64);
BPF_ARRAY(enabled, 1);
BPF_PERF_OUTPUT(events);
BPF_STACK_TRACE(stack_traces, 10240);

int override_function(struct pt_regs *ctx)
{
    /* Filter on our cgroup. */
    if (cgroup.check_current_task(0) <= 0)
        return 0;

    /* Make sure we're ready to inject errors. */
    u64 key = 0;
    u64 *val = enabled.lookup(&key);
    if (!val || *val == 0)
        return 0;

    /* Have we seen this stacktrace yet? */
    key = stack_traces.get_stackid(ctx, BPF_F_REUSE_STACKID);
    val = seen.lookup_or_init(&key, 0);
    if (*val == 1)
        return 0;
    lock_xadd(val, 1);

    bpf_trace_printk("overrding something\\n");
    unsigned long rc = RCVAL;
    bpf_override_return(ctx, rc);
    return 0;
}
"""

error_tripped = 0

def handle_error(cpu, data, size):
    error_tripped = 1

parser = argparse.ArgumentParser()
parser.add_argument("-o", "--override", required=True,
                    help="The function to override")
parser.add_argument("-r", "--retval", type=str, help="The return value to use")
parser.add_argument("-e", "--exec", type=str, required=True,
                    help="The command to run")
parser.add_argument("-c", "--cgroup", type=str, required=True,
                    help="Path to the cgroup we'll be using for this")

args = parser.parse_args()
retval = "NULL"

bpf_text = bpf_text.replace("RCVAL", retval)

f = open(args.cgroup)

print("Loading error injection")
b = BPF(text=bpf_text)

# Load the cgroup id into the table
t = b.get_table("cgroup")
t[0] = f.fileno()

b["events"].open_perf_buffer(handle_error)

# Load the kretprobe first, because we want the delete guy to be in place before
# the add guy is in place, otherwise we could error out pids that are no longer
# in our path and cause unfortunate things to happen.
b.attach_kprobe(event=args.override, fn_name="override_function")

while 1:
    print("Running command")
    p = Popen(args.COMMAND)

    while tripped_error == 0:
        b.kprobe_poll()
        if p.poll() is not None:
            print("The command exited, breaking")

    print("Waiting for the command to exit")
    p.wait()

    if tripped_error == 0:
        print("Error injection didn't trip anything, exiting")
        break

# We have to remove in this order otherwise we could end up with a half
# populated hasmap and overrding legitimate things.
b.detach_kprobe(args.override)
print("Exiting")

