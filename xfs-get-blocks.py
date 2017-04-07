from __future__ import print_function
from bcc import BPF
import ctypes as ct

debug = 0

bpf_text = """
#include <uapi/linux/ptrace.h>
#include <linux/buffer_head.h>
#include <linux/mm_types.h>

typedef struct rkey_s {
	u64 read_size;
	u64 bio_size;
	u64 num_bios;
	u64 add_to_page_cache_failures;
} rkey_t;

typedef struct bkey_s {
	struct buffer_head *map_bh;
	u64 b_size;
	u64 b_orig_state;
} bkey_t;

typedef struct data_s {
	u64 readpages_size;
	u64 bio_size;
	u64 num_bios;
	u64 add_to_page_cache_failures;
} data_t;

typedef struct bdata_s {
	u64 b_size;
	u64 b_found_size;
	u64 b_state;
	u64 b_orig_state;
} bdata_t;

typedef struct read_data_s {
	u64 bio_ptr;
	u64 last_block_in_bio;
	u64 first_logical_block;
	u64 max_vecs;
	u64 page_index;
} read_data_t;

BPF_HASH(mappings, u64, rkey_t);
BPF_HASH(buffers, u64, bkey_t);
BPF_HASH(readhash, u64, read_data_t);
BPF_PERF_OUTPUT(events);
BPF_PERF_OUTPUT(bevents);
BPF_PERF_OUTPUT(revents);

int trace_mpage_readpages(struct pt_regs *ctx, struct address_space *mapping,
			  struct list_head *pages, unsigned nr_pages)
{
	u64 magic = mapping->host->i_sb->s_magic;
	if (magic != 0x58465342)
		return 0;

	rkey_t key = {
		.read_size = nr_pages << PAGE_SHIFT,
	};
	u64 pid = bpf_get_current_pid_tgid();
	mappings.update(&pid, &key);
	return 0;
}

int trace_mpage_readpages_return(struct pt_regs *ctx)
{
	rkey_t *key;
	u64 pid = bpf_get_current_pid_tgid();

	key = mappings.lookup(&pid);
	if (!key)
		return 0;

	data_t data = {
		.readpages_size = key->read_size,
		.num_bios = key->num_bios,
		.bio_size = key->bio_size,
		.add_to_page_cache_failures = key->add_to_page_cache_failures,
	};
	events.perf_submit(ctx, &data, sizeof(data));
	mappings.delete(&pid);
	return 0;
}

int trace_exit_add_to_page_cache_lru(struct pt_regs *ctx)
{
	u64 pid = bpf_get_current_pid_tgid();
	rkey_t *key;

	key = mappings.lookup(&pid);
	if (!key)
		return 0;
	if (PT_REGS_RC(ctx) != 0)
		key->add_to_page_cache_failures++;
	return 0;
}

int trace_submit_bio(struct pt_regs *ctx, int rw, struct bio *bio)
{
	if ((rw & 1) == 1)
		return 0;
	rkey_t *key;
	u64 pid = bpf_get_current_pid_tgid();

	key = mappings.lookup(&pid);
	if (!key)
		return 0;
	key->num_bios++;
	key->bio_size += bio->bi_iter.bi_size;
	return 0;
}

int trace_get_blocks(struct pt_regs *ctx, struct inode *inode,
		     sector_t block, struct buffer_head *map_bh,
		     int create)
{
	if (create)
		return 0;
	u64 pid = bpf_get_current_pid_tgid();
	rkey_t *rkey;

	rkey = mappings.lookup(&pid);
	if (!rkey)
		return 0;

	bkey_t key = {
		.map_bh = map_bh,
		.b_size = map_bh->b_size,
		.b_orig_state = map_bh->b_state,
	};
	buffers.update(&pid, &key);
	return 0;
}

int trace_exit_get_blocks(struct pt_regs *ctx)
{
	u64 pid = bpf_get_current_pid_tgid();
	bkey_t *key;
	rkey_t *rkey;

	key = buffers.lookup(&pid);
	if (!key)
		return 0;

	u64 size, state;
	
	// the rewriter doesn't recognize this as needing a probe read, so do
	// it ourselves
	bpf_probe_read(&size, sizeof(u64), &key->map_bh->b_size);
	bpf_probe_read(&state, sizeof(u64), &key->map_bh->b_state);

	bdata_t data = {
		.b_size = key->b_size,
		.b_found_size = size,
		.b_state = state,
		.b_orig_state = key->b_orig_state,
	};
	bevents.perf_submit(ctx, &data, sizeof(data));	
	buffers.delete(&pid);
	return 0;
}

int trace_do_mpage_readpage(struct pt_regs *ctx, struct bio *bio, struct page *page,
			    unsigned nr_pages, sector_t *last_block_in_bio,
			    struct buffer_head *map_bh, unsigned long *first_logical_block)
{
	u64 pid = bpf_get_current_pid_tgid();
	rkey_t *rkey;

	rkey = mappings.lookup(&pid);
	if (!rkey)
		return 0;

	read_data_t data = {
		.max_vecs = bio->bi_max_vecs,
		.last_block_in_bio = *last_block_in_bio,
		.first_logical_block = *first_logical_block,
	};
	unsigned long *ptr = (unsigned long *)((void *)page + offsetof(struct page, index));
	bpf_probe_read(&data.page_index, sizeof(u64), ptr);
	readhash.update(&pid, &data);
	return 0;
}

int trace_exit_do_mpage_readpage(struct pt_regs *ctx)
{
	read_data_t *data;
	u64 pid = bpf_get_current_pid_tgid();

	data = readhash.lookup(&pid);
	if (!data)
		return 0;
	data->bio_ptr = PT_REGS_RC(ctx);
	revents.perf_submit(ctx, data, sizeof(*data));
	readhash.delete(&pid);
	return 0;
}
"""

if debug:
    print(bpf_text)

# load BPF program
b = BPF(text=bpf_text)
b.attach_kprobe(event="xfs_get_blocks", fn_name="trace_get_blocks")
b.attach_kretprobe(event="xfs_get_blocks", fn_name="trace_exit_get_blocks")
b.attach_kprobe(event="mpage_readpages", fn_name="trace_mpage_readpages")
b.attach_kretprobe(event="mpage_readpages", fn_name="trace_mpage_readpages_return")
b.attach_kprobe(event="submit_bio", fn_name="trace_submit_bio")
b.attach_kprobe(event="do_mpage_readpage", fn_name="trace_do_mpage_readpage")
b.attach_kretprobe(event="do_mpage_readpage", fn_name="trace_exit_do_mpage_readpage")
b.attach_kretprobe(event="add_to_page_cache_lru", fn_name="trace_exit_add_to_page_cache_lru")

class Data(ct.Structure):
    _fields_ = [
        ("readpages_size", ct.c_ulonglong),
        ("bio_size", ct.c_ulonglong),
        ("num_bios", ct.c_ulonglong),
        ("page_cache_failures", ct.c_ulonglong),
    ]

class BData(ct.Structure):
    _fields_ = [
        ("b_size", ct.c_ulonglong),
        ("b_found_size", ct.c_ulonglong),
	("b_state", ct.c_ulonglong),
	("b_orig_state", ct.c_ulonglong),
    ]

class RData(ct.Structure):
    _fields_ = [
        ("bio_ptr", ct.c_ulonglong),
        ("last_block_in_bio", ct.c_ulonglong),
        ("first_logical_block", ct.c_ulonglong),
        ("max_vecs", ct.c_ulonglong),
        ("page_index", ct.c_ulonglong),
    ]

print("%-14s %-14s %-14s" % ("READPAGES SIZE", "BIO SIZE", "NUM BIOS"))

def print_data(cpu, data, size):
    event = ct.cast(data, ct.POINTER(Data)).contents

    print("%-14s %-14s %-14s %-14s" % (event.readpages_size, event.bio_size,
                                 event.num_bios, event.page_cache_failures))

def print_rdata(cpu, data, size):
    event = ct.cast(data, ct.POINTER(RData)).contents

    print("\treadpage\t%-14s %-14s %-14s %-14s %-14s" % (event.bio_ptr, event.last_block_in_bio,
                                 event.first_logical_block, event.page_index, event.max_vecs))

def print_bdata(cpu, data, size):
    event = ct.cast(data, ct.POINTER(BData)).contents

    print("\tget_block\t%-14s %-14s %-14s %-14s" % (event.b_size, event.b_found_size, event.b_state, event.b_orig_state))

b["events"].open_perf_buffer(print_data)
b["bevents"].open_perf_buffer(print_bdata)
b["revents"].open_perf_buffer(print_rdata)
while 1:
    b.kprobe_poll()
