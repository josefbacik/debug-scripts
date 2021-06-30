#ifndef __COMMON_H
#define __COMMON_H

#ifndef u64
#define u64 uint64_t
#endif

struct event {
	u64 flags;
	u64 total_bytes;
	u64 bytes_used;
	u64 bytes_pinned;
	u64 bytes_may_use;
	u64 bytes_reserved;
	u64 bytes_readonly;
	u64 global_rsv;
	u64 trans_rsv;
	u64 delayed_refs_rsv;
	u64 delayed_rsv;
};

#endif
