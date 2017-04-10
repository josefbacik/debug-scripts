from __future__ import print_function
from bcc import BPF
import ctypes as ct

bpf_text = """
#include <uapi/linux/ptrace.h>
#include <linux/mm_types.h>
#include <linux/blkdev.h>

typedef struct actor_s {
	u64 pid;
	u64 stackid;
	u64 read_size;
} actor_t;

BPF_HASH(plugs, u64);
BPF_HASH(writes, u64);
BPF_HASH(traces, actor_t);
BPF_HASH(reads, u64);
BPF_HASH(readahead, u64);
BPF_PERF_OUTPUT(events);
BPF_STACK_TRACE(stack_traces, 1024);
BPF_PERF_OUTPUT(read_events);

int trace_blk_start_plug(struct pt_regs *ctx)
{
	u64 pid = bpf_get_current_pid_tgid();
	u64 tmp = 12345;

	plugs.update(&pid, &tmp);
	return 0;
}

int trace_blk_finish_plug(struct pt_regs *ctx)
{
	u64 pid = bpf_get_current_pid_tgid();
	plugs.delete(&pid);
	return 0;
}

int trace_vfs_write(struct pt_regs *ctx)
{
	u64 pid = bpf_get_current_pid_tgid();
	u64 tmp = 12345;

	writes.update(&pid, &tmp);
	return 0;
}

int trace_vfs_read(struct pt_regs *ctx, struct file *file, char *buf,
			size_t count)
{
	u64 pid = bpf_get_current_pid_tgid();
	u64 tmp = count;
	reads.update(&pid, &tmp);
	return 0;
}

int trace_vfs_read_ret(struct pt_regs *regs)
{
	u64 pid = bpf_get_current_pid_tgid();
	reads.delete(&pid);
	return 0;
}

int trace_vfs_write_ret(struct pt_regs *ctx)
{
	u64 pid = bpf_get_current_pid_tgid();
	writes.delete(&pid);
	return 0;
}

int trace_add_to_page_cache_locked(struct pt_regs *ctx, struct page *page,
				   struct address_space *mapping, pgoff_t offset)
{
	u64 magic = mapping->host->i_sb->s_magic;

	if (magic != 0x58465342)
		return 0;

	u64 pid = bpf_get_current_pid_tgid();
	u64 read_size = 0;
	u64 *tmp;

	tmp = writes.lookup(&pid);
	if (tmp)
		return 0;

	tmp = plugs.lookup(&pid);
	if (tmp)
		return 0;

	tmp = reads.lookup(&pid);
	if (tmp)
		read_size = *tmp;
	u64 stackid = stack_traces.get_stackid(ctx, BPF_F_REUSE_STACKID);
	u64 index = offset;
	u64 zero = 0;

	actor_t actor = {
		.pid = pid >> 32,
		.stackid = stackid,
		.read_size = read_size,
	};
	tmp = traces.lookup_or_init(&actor, &zero);
	(*tmp)++;	
	events.perf_submit(ctx, &index, sizeof(index));
	return 0;
}

int trace_ondemand_readahead(struct pt_regs *ctx, struct address_space *mapping,
			     struct file_ra_state *ra, struct file *filp,
			     bool hit_readahead_marker, pgoff_t offset)
{
	u64 magic = mapping->host->i_sb->s_magic;

	if (hit_readahead_marker)
		return 0;
	if (magic != 0x58465342)
		return 0;
	u64 pid = bpf_get_current_pid_tgid();
	u64 read_offset = offset;
	readahead.update(&pid, &read_offset);
	return 0;
}

int trace_do_page_cache_readahead(struct pt_regs *ctx, struct address_space *mapping,
				  struct file *filep, pgoff_t start, unsigned long nr_to_read)
{
	u64 pid = bpf_get_current_pid_tgid();
	u64 *tmp;
	tmp = readahead.lookup(&pid);
	if (!tmp)
		return 0;
	if (*tmp != start) {
		actor_t actor = {
			.pid = pid,
			.stackid = start,
			.read_size = *tmp,
		};
		read_events.perf_submit(ctx, &actor, sizeof(actor));
	}
	readahead.delete(&pid);
	return 0;
}
"""

b = BPF(text=bpf_text)
b.attach_kprobe(event="blk_start_plug", fn_name="trace_blk_start_plug")
b.attach_kprobe(event="blk_finish_plug", fn_name="trace_blk_finish_plug")
b.attach_kprobe(event="__vfs_write", fn_name="trace_vfs_write")
b.attach_kretprobe(event="__vfs_write", fn_name="trace_vfs_write_ret")
b.attach_kprobe(event="vfs_writev", fn_name="trace_vfs_write")
b.attach_kretprobe(event="vfs_writev", fn_name="trace_vfs_write_ret")
b.attach_kprobe(event="__vfs_read", fn_name="trace_vfs_read")
b.attach_kretprobe(event="__vfs_read", fn_name="trace_vfs_read_ret")
b.attach_kprobe(event="__add_to_page_cache_locked", fn_name="trace_add_to_page_cache_locked")
b.attach_kprobe(event="ondemand_readahead", fn_name="trace_ondemand_readahead")
b.attach_kprobe(event="__do_page_cache_readahead", fn_name="trace_do_page_cache_readahead")

class Actor(ct.Structure):
    _fields_ = [
        ("pid", ct.c_ulonglong),
        ("stackid", ct.c_ulonglong),
        ("read_size", ct.c_ulonglong),
    ]

def print_data(cpu, data, size):
    event = ct.cast(data, ct.POINTER(ct.c_ulonglong)).contents
    print("added page out of band index %s" % (event.value))

def print_read_events(cpu, data, size):
    event = ct.cast(data, ct.POINTER(Actor)).contents
    print("mismatch offset, wanted %s, got %s, pid %s" % (event.read_size, event.stackid, event.pid))

b["events"].open_perf_buffer(print_data)
b["read_events"].open_perf_buffer(print_read_events)
traces = b.get_table("traces")
stack_traces = b.get_table("stack_traces")
while 1:
    b.kprobe_poll()
    for k,v in traces.items():
        stack = stack_traces.walk(k.stackid)
        print("Pid %d read %d" % (k.pid, k.read_size))
        for addr in stack:
            print("  %s" % b.ksym(addr))
        print("\n")
    traces.clear()
