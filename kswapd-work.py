from bcc import BPF
from time import sleep
import signal

def signal_ignore(signal, frame):
    print()

class SignalInterrupt(Exception):
    def __init__(self, message):
        super(SignalInterrupt, self).__init__(message)

def signal_stop(signal, frame):
    raise SignalInterrupt("Interrupted!")

bpf_text = """
#include <uapi/linux/ptrace.h>
#include <linux/vmpressure.h>

#define SCANNED_ID 1
#define RECLAIMED_ID 2
#define WAKEUPS 3

BPF_HASH(counts, int);

/* We use vmpressure because struct scan_control is internal to vmscan.c, so we
 * use vmpressure as an analog.
 */
int trace_vmpressure(struct pt_regs *ctx, gfp_t gfp, struct mem_cgroup *memcg,
                     bool tree, unsigned long scanned, unsigned long reclaimed)
{
    int id;
    u64 zero = 0, *val;

    id = SCANNED_ID;
    val = counts.lookup_or_init(&id, &zero);
    (*val) += scanned;
    id = RECLAIMED_ID;
    val = counts.lookup_or_init(&id, &zero);
    (*val) += reclaimed;
    return 0;
}

/* We can hit this via direct reclaim, but my test cases never hit direct
 * reclaim, so I'm taking the easy way out.
 */
int trace_shrink_node(struct pt_regs *ctx)
{
    int id = WAKEUPS;
    u64 zero = 0, *val;
    val = counts.lookup_or_init(&id, &zero);
    (*val)++;
    return 0;
}
"""

b = BPF(text=bpf_text)
b.attach_kprobe(event="vmpressure", fn_name="trace_vmpressure")
b.attach_kprobe(event="shrink_node", fn_name="trace_shrink_node")

print("Tracing, hit Ctrl+C to exit")
signal.signal(signal.SIGINT, signal_stop)
try:
    sleep(99999999)
except SignalInterrupt:
    signal.signal(signal.SIGINT, signal_ignore)
except KeyboardInterrupt:
    signal.signal(signal.SIGINT, signal_ignore)

counts = b.get_table("counts")
scanned = 0
reclaimed = 0
wakeups = 0
for k,v in counts.items():
    if k.value == 1:
        scanned = v.value
    if k.value == 2:
        reclaimed = v.value
    if k.value == 3:
        wakeups = v.value

print("Total wake ups: {}".format(wakeups))
print("Total scanned: {}".format(scanned))
print("Total reclaimed: {}".format(reclaimed))
if wakeups > 0:
    print("Avg scanned per run: {}".format(float(scanned) / wakeups))
    print("Avg reclaimed per run: {}".format(float(reclaimed) / wakeups))
