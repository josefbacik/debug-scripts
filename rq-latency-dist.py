#!/usr/bin/python

from bcc import BPF
import argparse
from time import sleep

bpf_text = """
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>

typedef struct pid_key_s {
    u64 id;
    u64 slot;
} pid_key_t;

BPF_HASH(start, u64);
STORAGE

int woke(struct pt_regs *ctx, struct task_struct *p)
{
    u32 pid = p->pid;
    u32 tgid = p->tgid;
    u64 key = (u64)tgid << 32 | pid;

    if (FILTER)
        return 0;
    u64 val = bpf_ktime_get_ns();
    start.update(&key, &val);
    return 0;
}

int oncpu(struct pt_regs *ctx)
{
    u64 key = bpf_get_current_pid_tgid();
    u32 pid = key;
    u64 *tsp = start.lookup(&key);
    if (!tsp)
        return 0;
    u64 delta = bpf_ktime_get_ns() - *tsp;
    STORE
    return 0;
}
"""


parser = argparse.ArgumentParser(
    description="Track the time processes spend on the runqueue before starting execution")
parser.add_argument("-t", "--tgid", help="trace this TGID only")
parser.add_argument("-p", "--pid", help="trace this PID only")
parser.add_argument("-d", "--duration", nargs="?", default=9999999)
args = parser.parse_args()

section = ""

if args.pid:
    bpf_text = bpf_text.replace('FILTER', "pid != {}".format(args.pid))
elif args.tgid:
    bpf_text = bpf_text.replace('FILTER', "tgid != {}".format(args.tgid))
else:
    bpf_text = bpf_text.replace('FILTER', '0')

if args.pid or args.tgid:
    section = "pid"
    bpf_text = bpf_text.replace('STORAGE', 'BPF_HISTOGRAM(dist, pid_key_t);')
    bpf_text = bpf_text.replace('STORE',
        'pid_key_t pid_key = { .id = pid, .slot = bpf_log2l(delta)}; ' +
        'dist.increment(pid_key);')
else:
    bpf_text = bpf_text.replace('STORAGE', 'BPF_HISTOGRAM(dist);')
    bpf_text = bpf_text.replace('STORE', 'dist.increment(bpf_log2l(delta));')

b = BPF(text=bpf_text)
b.attach_kprobe(event='finish_task_switch', fn_name='oncpu')
b.attach_kprobe(event='try_to_wake_up', fn_name='woke')

print("Tracing")
try:
    sleep(int(args.duration))
except KeyboardInterrupt:
    print("interrupted, dumping info")

dist = b.get_table("dist")

def pid_to_comm(pid):
    try:
        comm = open("/proc/%d/comm" % pid, "r").read()
        return "%d %s" % (pid, comm)
    except IOError:
        return str(pid)

dist.print_log2_hist("nsecs", section, section_print_fn=pid_to_comm)
