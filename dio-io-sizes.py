from __future__ import print_function
from bcc import BPF
import ctypes as ct

bpf_text = """
#include <uapi/linux/ptrace.h>
#include <linux/blkdev.h>
#include <linux/buffer_head.h>

typedef struct block_data_s {
	struct buffer_head *map_bh;
	u64 b_orig_size;
	u64 b_found_size;
	u64 b_state;
} block_data_t;

typedef struct read_data_s {
	u64 count;
	u64 b_orig_size;
	u64 b_found_size;
	u64 b_state;
} read_data_t;

typedef struct event_data_s {
	u64 pid;
	u64 time;
	char op[16];
} event_data_t;

BPF_HASH(buffers, u64, block_data_t);
BPF_HASH(reads, u64, read_data_t);
BPF_HASH(read_traces, u64);
BPF_STACK_TRACE(stack_traces, 1024);
BPF_PERF_OUTPUT(read_events);
BPF_PERF_OUTPUT(block_events);
BPF_PERF_OUTPUT(events);

int trace_get_blocks(struct pt_regs *ctx, struct inode *inode,
		     sector_t block, struct buffer_head *map_bh,
		     int create)
{
	if (create)
		return 0;
	u64 pid = bpf_get_current_pid_tgid();
	buffers.delete(&pid);

	block_data_t key = {
		.map_bh = map_bh,
		.b_orig_size = map_bh->b_size,
	};
	buffers.update(&pid, &key);
	
	pid = bpf_get_current_pid_tgid();
	read_data_t *data = reads.lookup(&pid);
	if (!data) {
		event_data_t edata = {
			.op = "get_blocks_miss",
			.pid = pid,
			.time = bpf_ktime_get_ns(),
		};
		events.perf_submit(ctx, &edata, sizeof(edata));
		return 0;
	}
/*		
	event_data_t edata = {
		.op = "get_blocks_hit",
		.pid = pid,
		.time = bpf_ktime_get_ns(),
	};
	events.perf_submit(ctx, &edata, sizeof(edata));
*/
	if (data->count == map_bh->b_size)
		return 0;

	read_data_t out = {
		.count = data->count,
		.b_orig_size = map_bh->b_size,
		.b_found_size = 0,
	};
	block_events.perf_submit(ctx, &out, sizeof(out));

	return 0;
}

int trace_exit_get_blocks(struct pt_regs *ctx)
{
	u64 pid = bpf_get_current_pid_tgid();
	block_data_t *data;

	data = buffers.lookup(&pid);
	if (!data)
		return 0;

	u64 size,state;
	
	// the rewriter doesn't recognize this as needing a probe read, so do
	// it ourselves
	bpf_probe_read(&size, sizeof(u64), &data->map_bh->b_size);
	bpf_probe_read(&state, sizeof(u64), &data->map_bh->b_state);

	data->b_found_size = size;
	data->b_state = state;

	if (data->b_found_size != data->b_orig_size) {
		read_data_t out = {
			.count = 0,
			.b_orig_size = data->b_orig_size,
			.b_found_size = data->b_found_size,
		};
		block_events.perf_submit(ctx, &out, sizeof(out));
	}
	return 0;
}

int trace_vfs_read(struct pt_regs *ctx, struct file *file, char *buf, size_t count)
{
	u64 magic = file->f_mapping->host->i_sb->s_magic;
	if (magic != 0x58465342)
		return 0;
	read_data_t data = {
		.count = count,
	};
	u64 pid = bpf_get_current_pid_tgid();
	reads.update(&pid, &data);
/*
	event_data_t edata = {
		.op = "read",
		.pid = pid,
		.time = bpf_ktime_get_ns(),
	};
	events.perf_submit(ctx, &edata, sizeof(edata));
*/
	return 0;
}

int trace_vfs_read_ret(struct pt_regs *ctx)
{
	u64 pid = bpf_get_current_pid_tgid();
	read_data_t *data = reads.lookup(&pid);
	if (!data)
		return 0;
	reads.delete(&pid);
/*
	event_data_t edata = {
		.op = "read exit",
		.pid = pid,
		.time = bpf_ktime_get_ns(),
	};
	events.perf_submit(ctx, &edata, sizeof(edata));
*/
	return 0;
}

int trace_submit_bio(struct pt_regs *ctx, int rw, struct bio *bio)
{
	if ((rw & 1) == 1)
		return 0;
	if (bio->bi_iter.bi_size != 4096)
		return 0;
	u64 pid = bpf_get_current_pid_tgid();
	read_data_t *data = reads.lookup(&pid);
	if (!data)
		return 0;
	block_data_t *bdata = buffers.lookup(&pid);
	if (!bdata)
		return 0;
	u64 stackid = stack_traces.get_stackid(ctx, BPF_F_REUSE_STACKID);
	data->b_orig_size = bdata->b_orig_size;
	data->b_found_size = bdata->b_found_size;
	data->b_state = bdata->b_state;
	read_traces.update(&pid, &stackid);
	read_events.perf_submit(ctx, data, sizeof(read_data_t));
	return 0;
}
"""

b = BPF(text=bpf_text)
b.attach_kprobe(event="xfs_get_blocks_direct", fn_name="trace_get_blocks")
b.attach_kretprobe(event="xfs_get_blocks_direct", fn_name="trace_exit_get_blocks")
b.attach_kprobe(event="vfs_read", fn_name="trace_vfs_read")
b.attach_kretprobe(event="vfs_read", fn_name="trace_vfs_read_ret")
b.attach_kprobe(event="submit_bio", fn_name="trace_submit_bio")

class ReadData(ct.Structure):
    _fields_ = [
        ("count", ct.c_ulonglong),
	("b_orig_size", ct.c_ulonglong),
	("b_found_size", ct.c_ulonglong),
    ]

class EventData(ct.Structure):
    _fields_ = [
        ("pid", ct.c_ulonglong),
        ("time", ct.c_ulonglong),
	("op", ct.c_char * 16),
    ]
def print_data(cpu, data, size):
    event = ct.cast(data, ct.POINTER(ReadData)).contents
    print("wrong bio size for read %s, map wanted size %s, map found size %s" % (event.count, event.b_orig_size, event.b_found_size))

def print_block(cpu, data, size):
    event = ct.cast(data, ct.POINTER(ReadData)).contents
    print("wrong map size for read %s, map wanted size %s, map found size %s" % (event.count, event.b_orig_size, event.b_found_size))

def print_events(cpu, data, size):
    event = ct.cast(data, ct.POINTER(EventData)).contents
    print("%s op %s pid %s" % (event.time, event.op, event.pid))

b["read_events"].open_perf_buffer(print_data)
b["block_events"].open_perf_buffer(print_block)
b["events"].open_perf_buffer(print_events)
read_traces = b.get_table("read_traces")
stack_traces = b.get_table("stack_traces")

while 1:
    b.kprobe_poll()
#    for k,v in read_traces.items():
#        stack = stack_traces.walk(v.value)
#        print("Pid %d" % (k.value))
#        for addr in stack:
#            print("  %s" % b.ksym(addr))
#        print("\n")
    read_traces.clear()
