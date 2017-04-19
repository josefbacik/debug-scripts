from bcc import BPF
from time import sleep
import signal
import argparse

def signal_ignore(signal, frame):
    print()

class SignalInterrupt(Exception):
    def __init__(self, message):
        super(SignalInterrupt, self).__init__(message)

def signal_stop(signal, frame):
    raise SignalInterrupt("Interrupted!")

bpf_text = """
#include <uapi/linux/ptrace.h>
#include <linux/fs.h>

BPF_HASH(alloc_count, u32);

int trace_alloc_inode(struct pt_regs *ctx)
{
    u32 pid = (u32)bpf_get_current_pid_tgid();
    u64 zero = 0, *val;

    FILTER_PID
    val = alloc_count.lookup_or_init(&pid, &zero);
    (*val)++;
    return 0;
}
"""

parser = argparse.ArgumentParser()
parser.add_argument('pids', metavar='PID', type=int, nargs='+',
                    help='the pids to filter on')
args = parser.parse_args()

filters = []
for pid in args.pids:
    filters.append("pid != {}".format(pid))
filter_str = "if ({}) return 0;".format(" && ".join(filters))

bpf_text = bpf_text.replace('FILTER_PID', filter_str)
b = BPF(text=bpf_text)
b.attach_kprobe(event="alloc_inode", fn_name="trace_alloc_inode")

signal.signal(signal.SIGINT, signal_stop)
print("Tracing, hit Ctrl+C to exit")
signal.signal(signal.SIGINT, signal_stop)
try:
    sleep(99999999)
except SignalInterrupt:
    signal.signal(signal.SIGINT, signal_ignore)
except KeyboardInterrupt:
    signal.signal(signal.SIGINT, signal_ignore)

alloc_count = b.get_table("alloc_count")
count = 0
for k,v in alloc_count.items():
    count += v.value
print("Total of {} inodes were allocated during the run".format(count))
