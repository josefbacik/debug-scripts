from bcc import BPF
import glob
import os
import re
import time
import argparse
from time import sleep
import signal
import ctypes as ct

debug = 0

bpf_text = """
#include <uapi/linux/ptrace.h>
#include <linux/blkdev.h>
#include <linux/genhd.h>
#include <linux/device.h>
#include <linux/kdev_t.h>
#include <linux/uio.h>

typedef struct request_size_s {
    u64 size;
    u64 read;
} request_size_t;

BPF_PERF_OUTPUT(bio_events);
BPF_PERF_OUTPUT(iter_events);
BPF_PERF_OUTPUT(req_events);
BPF_PERF_OUTPUT(split_events);

// This sucks, but we have no better solution
static dev_t get_devt(struct request *req)
{
    struct gendisk *disk = req->rq_disk;
    return disk->part0.__dev.devt;
}

int trace_req_start(struct pt_regs *ctx, struct request *req)
{
    dev_t device = get_devt(req);
    int major = MAJOR(device);
    int minor = MINOR(device);

    if (!(CONDITIONALS))
        return 0;
    request_size_t data = {
        .size = req->__data_len,
        .read = !(req->cmd_flags & 1),
    };
    req_events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}

int trace_bio_split(struct pt_regs *ctx, struct bio *bio, int nr_sectors)
{
    dev_t device = bio->bi_bdev->bd_disk->part0.__dev.devt;
    int major = MAJOR(device);
    int minor = MINOR(device);

    if (!(CONDITIONALS))
        return 0;
    request_size_t data = {
        .size = nr_sectors << 9,
        .read = !(bio->bi_opf & 1),
    };
    split_events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}

int trace_submit_bio(struct pt_regs *ctx, struct bio *bio)
{
    dev_t device = bio->bi_bdev->bd_disk->part0.__dev.devt;
    int major = MAJOR(device);
    int minor = MINOR(device);
    u64 count = bio->bi_iter.bi_size;

    if (!(CONDITIONALS))
        return 0;
    request_size_t data = {
        .size = count,
        .read = !(bio->bi_opf & 1),
    };
    bio_events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}

typedef struct bio_storage_s {
    struct bio *bio;
} bio_storage_t;

BPF_HASH(bios, u64, bio_storage_t);

int trace_bio_iov_iter_get_pages(struct pt_regs *ctx, struct bio *bio)
{
    u64 pid = bpf_get_current_pid_tgid();
    bio_storage_t data = {
        .bio = bio,
    };
    bios.update(&pid, &data);
    return 0;
}

int trace_bio_iov_iter_get_pages_ret(struct pt_regs *ctx)
{
    u64 pid = bpf_get_current_pid_tgid();
    bio_storage_t *data;

    data = bios.lookup(&pid);
    if (!data)
        return 0;

    u64 opf;
    request_size_t req = {};
    bpf_probe_read(&req.size, sizeof(u64), &data->bio->bi_iter.bi_size);
    bpf_probe_read(&opf, sizeof(u64), &data->bio->bi_opf);
    req.read = !(opf & 1);
    iter_events.perf_submit(ctx, &req, sizeof(req));
    bios.delete(&pid);
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

# load BPF program
b = BPF(text=bpf_text)
b.attach_kprobe(event="submit_bio", fn_name="trace_submit_bio")
b.attach_kprobe(event="bio_iov_iter_get_pages", fn_name="trace_bio_iov_iter_get_pages")
b.attach_kretprobe(event="bio_iov_iter_get_pages", fn_name="trace_bio_iov_iter_get_pages_ret")
b.attach_kprobe(event="blk_start_request", fn_name="trace_req_start")
b.attach_kprobe(event="blk_mq_start_request", fn_name="trace_req_start")
b.attach_kprobe(event="bio_split", fn_name="trace_bio_split")

class RequestSize(ct.Structure):
    _fields_ = [
        ("size", ct.c_ulonglong),
        ("read", ct.c_ulonglong),
    ]

def print_size(prestr, event):
    iostr = "write"
    if event.read == 1:
        iostr = "read"
    print("{} {}: {}".format(prestr, iostr, event.size))

def print_bio_size(cpu, data, size):
    event = ct.cast(data, ct.POINTER(RequestSize)).contents
    print_size("bio", event)

def print_iter_size(cpu, data, size):
    event = ct.cast(data, ct.POINTER(RequestSize)).contents
    print_size("iter", event)

def print_req_size(cpu, data, size):
    event = ct.cast(data, ct.POINTER(RequestSize)).contents
    print_size("req", event)

def print_split_size(cpu, data, size):
    event = ct.cast(data, ct.POINTER(RequestSize)).contents
    print_size("split", event)

b["bio_events"].open_perf_buffer(print_bio_size)
b["iter_events"].open_perf_buffer(print_iter_size)
b["req_events"].open_perf_buffer(print_req_size)
b["split_events"].open_perf_buffer(print_split_size)
while 1:
    b.kprobe_poll()
