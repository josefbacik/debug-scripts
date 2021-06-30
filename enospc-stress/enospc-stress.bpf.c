#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include "common.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024);
} rb SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, 1);
	__type(value, struct event);
} heap SEC(".maps");

SEC("tp/btrfs/btrfs_fail_all_tickets")
int handle_fail_all_tickets(struct trace_event_raw_btrfs_dump_space_info *ctx)
{
	struct event *e;
	int zero = 0;

	e = bpf_map_lookup_elem(&heap, &zero);
	if (!e)
		return 0;

	e->flags = ctx->flags;
	e->total_bytes = ctx->total_bytes;
	e->bytes_used = ctx->bytes_used;
	e->bytes_pinned = ctx->bytes_pinned;
	e->bytes_may_use = ctx->bytes_may_use;
	e->bytes_reserved = ctx->bytes_reserved;
	e->bytes_readonly = ctx->bytes_readonly;
	e->global_rsv = ctx->global_reserved;
	e->trans_rsv = ctx->trans_reserved;
	e->delayed_refs_rsv = ctx->delayed_refs_reserved;
	e->delayed_rsv = ctx->delayed_reserved;

	bpf_ringbuf_output(&rb, e, sizeof(*e), 0);
	return 0;
}
