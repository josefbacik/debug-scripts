from bcc import BPF
from time import sleep

bpf_text = """
#include <uapi/linux/ptrace.h>
#include <linux/kernel.h>

#define MAX_STACKS 8
struct btrfs_inode;
typedef struct action_s {
    u64 inode;
    u64 stackid;
    u64 num_bytes;
    u64 offset;
    u64 type;
} action_t;

typedef struct info_s {
    u64 inode;
    u64 stackid;
    u64 num_bytes;
    u64 offset;
} info_t;

BPF_HASH(infohash, u64, info_t);
BPF_HASH(actions, action_t, u64, 100000);
BPF_HASH(csums, u64, u64);
BPF_STACK_TRACE(stack_traces, 10240);


int trace_btrfs_reserve_metadata_bytes(struct pt_regs *ctx,
                                       struct btrfs_inode *inode,
                                       u64 offset,
                                       u64 num_bytes)
{
    u64 pid = bpf_get_current_pid_tgid();
    u64 bytes = ALIGN(num_bytes, 4096);
    info_t info = {
        .inode = (u64)inode,
        .stackid = stack_traces.get_stackid(ctx, BPF_F_REUSE_STACKID),
        .num_bytes = bytes,
        .offset = offset,
    };
    infohash.update(&pid, &info);
    return 0;
}

int trace_btrfs_reserve_metadata_bytes_ret(struct pt_regs *ctx)
{
    u64 pid = bpf_get_current_pid_tgid();
    u64 rc = PT_REGS_RC(ctx);
    if (rc != 0)
        return 0;
    info_t *info = infohash.lookup(&pid);
    if (!info)
        return 0;
    action_t action = {
        .stackid = info->stackid,
        .inode = info->inode,
        .num_bytes = info->num_bytes,
        .offset = info->offset,
        .type = (u64)1,
    };
    u64 zero = 0;
    u64 bytes = info->num_bytes;
    u64 inode = info->inode;
    u64 *val = actions.lookup_or_init(&action, &zero);
    lock_xadd(val, 1);
    u64 *ival = csums.lookup_or_init(&inode, &zero);
    lock_xadd(ival, bytes);
    infohash.delete(&pid);
    return 0;
}

int trace_btrfs_delalloc_release_metadata(struct pt_regs *ctx,
                                          struct btrfs_inode *inode,
                                          u64 offset,
                                          u64 num_bytes)
{
    u64 ino = (u64)inode;
    u64 bytes = ALIGN(num_bytes, 4096);
    action_t action = {
        .stackid = stack_traces.get_stackid(ctx, BPF_F_REUSE_STACKID),
        .inode = ino,
        .num_bytes = bytes,
        .offset = offset,
        .type = (u64)0,
    };
    u64 zero = 0;
    u64 *val = actions.lookup_or_init(&action, &zero);
    lock_xadd(val, 1);
    u64 *ival = csums.lookup(&ino);
    if (!ival)
        return 0;
    lock_xadd(ival, -bytes);
    return 0;
}
"""

b = BPF(text=bpf_text)
b.attach_kprobe(event="btrfs_delalloc_reserve_metadata",
                fn_name="trace_btrfs_reserve_metadata_bytes")
b.attach_kretprobe(event="btrfs_delalloc_reserve_metadata",
                   fn_name="trace_btrfs_reserve_metadata_bytes_ret")
b.attach_kprobe(event="btrfs_delalloc_release_metadata",
                fn_name="trace_btrfs_delalloc_release_metadata")

print("Tracing")
try:
    sleep(1000000000)
except KeyboardInterrupt:
    print("interrupted, dumping info")

stack_traces = b.get_table("stack_traces")
csums = b.get_table("csums")
actions = b.get_table("actions")

MAX_STACKS = 8
for k,v in csums.items():
    if v.value == 0:
        continue
    print("inode {} has {} bytes left over".format(k.value, v.value))
    for action,num_entries in actions.items():
        if action.inode != k.value:
            continue
        if action.type == 1:
            print("Get off={} bytes={} times={}".format(action.offset,
                                                        action.num_bytes,
                                                        num_entries.value))
        else:
            print("Put off={} bytes={} times={}".format(action.offset,
                                                        action.num_bytes,
                                                        num_entries.value))
        stack = stack_traces.walk(action.stackid)
        for addr in stack:
            print("  {}".format(b.ksym(addr, True, True)))
        print("\n")
