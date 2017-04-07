from bcc import BPF
import glob
import os
import re
import time
import argparse
from time import sleep
import signal

debug = 0

def signal_ignore(signal, frame):
    print()

class SignalInterrupt(Exception):
    def __init__(self, message):
        super(SignalInterrupt, self).__init__(message)

def signal_stop(signal, frame):
    raise SignalInterrupt("Interrupted!")

bpf_text = """
#include <uapi/linux/ptrace.h>
#include <linux/blkdev.h>
#include <linux/genhd.h>
#include <linux/device.h>
#include <linux/kdev_t.h>

typedef struct dev_key_s {
    u64 dev;
    u64 slot;
} dev_key_t;

BPF_HISTOGRAM(reads, dev_key_t);
BPF_HISTOGRAM(writes, dev_key_t);
BPF_HISTOGRAM(discards, dev_key_t);

// This sucks, but we have no better solution
static dev_t get_devt(struct request *req)
{
    struct gendisk *disk = req->rq_disk;
    return disk->part0.__dev.devt;
}

// time block I/O
int trace_req_start(struct pt_regs *ctx, struct request *req)
{
    dev_t device = get_devt(req);
    int major = MAJOR(device);
    int minor = MINOR(device);

    if (req->__data_len == 0)
        return 0;

    if (!(CONDITIONALS))
        return 0;

    dev_key_t key = {
        .dev = device,
        .slot = bpf_log2l(req->__data_len),
    };

    if (req->cmd_flags & REQ_DISCARD)
        discards.increment(key);
    else if ((req->cmd_flags & 1) != 0)
        writes.increment(key);
    else
        reads.increment(key);
    return 0;
}
"""

parser = argparse.ArgumentParser()
parser.add_argument("-d", "--device",
    help="Trace this device only")
args = parser.parse_args()

disks = []
if args.device:
    disks.append({'name': os.path.basename(args.device)})
else:
    dev_patterns = ['sd.*', 'nvme.*', 'nbd.*', 'md.*', "fio*", "etherd*"]
    for device in glob.glob("/sys/block/*"):
        for pattern in dev_patterns:
            if re.compile(pattern).match(os.path.basename(device)):
                if pattern == "etherd*":
                    disks.append({'name': os.path.basename(device).replace('!', '/')})
                else:
                    disks.append({'name': os.path.basename(device)})
if debug:
    print(disks)

first = True
conditional_template = "(major == MAJOR && minor == MINOR)"
conditionals = ""
for disk in disks:
    stinfo = os.stat('/dev/{}'.format(disk['name']))
    disk['major'] = os.major(stinfo.st_rdev)
    disk['minor'] = os.minor(stinfo.st_rdev)
    tmp = conditional_template.replace('MAJOR', "{}".format(disk['major']))
    tmp = tmp.replace('MINOR', "{}".format(disk['minor']))
    if not first:
        conditionals += " || "
    first = False
    conditionals += tmp

if conditionals == "":
    conditionals = "1"
bpf_text = bpf_text.replace('CONDITIONALS', conditionals)

if debug:
    print(bpf_text)

# load BPF program
b = BPF(text=bpf_text)
b.attach_kprobe(event="blk_start_request", fn_name="trace_req_start")
b.attach_kprobe(event="blk_mq_start_request", fn_name="trace_req_start")

reads = b.get_table("reads")
writes = b.get_table("writes")
discards= b.get_table("discards")

print("Tracing, hit Ctrl+C to exit")
signal.signal(signal.SIGINT, signal_stop)
try:
    sleep(99999999)
except SignalInterrupt:
    signal.signal(signal.SIGINT, signal_ignore)
except KeyboardInterrupt:
    signal.signal(signal.SIGINT, signal_ignore)

def print_device(dev):
    MINORBITS = 20
    MINORMASK = (1 << MINORBITS) - 1
    major = dev >> MINORBITS
    minor = dev & MINORMASK
    for disk in disks:
        if disk['major'] == major and disk['minor'] == minor:
            return disk['name']
    return "%d-%d" % (major, minor)

reads.print_log2_hist("Reads", "dev", section_print_fn=print_device)
writes.print_log2_hist("Writes", "dev", section_print_fn=print_device)
discards.print_log2_hist("Discards", "dev", section_print_fn=print_device)
