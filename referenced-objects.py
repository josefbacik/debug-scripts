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
#include <linux/dcache.h>
#include <linux/fs.h>

#define INODE_ID 1
#define DENTRY_ID 2

typedef struct dentry_storage_s {
    struct dentry *dentry;
} dentry_storage_t;

typedef struct inode_storage_s {
    struct inode *inode;
} inode_storage_t;

BPF_HASH(dentries, u64, dentry_storage_t);
BPF_HASH(inodes, u64, inode_storage_t);
BPF_HASH(referenced, u64);

static int inc_referenced(u64 id)
{
    u64 *val, zero = 0;
    val = referenced.lookup_or_init(&id, &zero);
    lock_xadd(val, 1);
    return 0;
}

int trace_dentry_lru_add(struct pt_regs *ctx, struct dentry *dentry)
{
    u64 pid = bpf_get_current_pid_tgid();
    if (dentry->d_flags & DCACHE_REFERENCED)
        return 0;
    dentry_storage_t data = {
        .dentry = dentry,
    };
    dentries.update(&pid, &data);
    return 0;
}

int trace_dentry_lru_add_ret(struct pt_regs *ctx)
{
    u64 pid = bpf_get_current_pid_tgid();
    unsigned int flags;
    dentry_storage_t *data;

    data = dentries.lookup(&pid);
    if (!data)
        return 0;
    bpf_probe_read(&flags, sizeof(unsigned int), &data->dentry->d_flags);
    if (flags & DCACHE_REFERENCED)
        inc_referenced(DENTRY_ID);
    dentries.delete(&pid);
    return 0;
}

int trace_inode_lru_list_add(struct pt_regs *ctx, struct inode *inode)
{
    u64 pid = bpf_get_current_pid_tgid();
    if (inode->i_state & I_REFERENCED)
        return 0;
    inode_storage_t data = {
        .inode = inode,
    };
    inodes.update(&pid, &data);
    return 0;
}

int trace_inode_lru_list_add_ret(struct pt_regs *ctx)
{
    u64 pid = bpf_get_current_pid_tgid();
    unsigned long state;
    inode_storage_t *data;

    data = inodes.lookup(&pid);
    if (!data)
        return 0;
    bpf_probe_read(&state, sizeof(unsigned long), &data->inode->i_state);
    if (state & I_REFERENCED)
        inc_referenced(INODE_ID);
    inodes.delete(&pid);
    return 0;
}
"""

b = BPF(text=bpf_text)
b.attach_kprobe(event="inode_lru_list_add", fn_name="trace_inode_lru_list_add")
b.attach_kretprobe(event="inode_lru_list_add", fn_name="trace_inode_lru_list_add_ret")
b.attach_kprobe(event="dentry_lru_add", fn_name="trace_dentry_lru_add")
b.attach_kretprobe(event="dentry_lru_add", fn_name="trace_dentry_lru_add_ret")

print("Tracing, hit Ctrl+C to exit")
signal.signal(signal.SIGINT, signal_stop)
try:
    sleep(99999999)
except KeyboardInterrupt:
    signal.signal(signal.SIGINT, signal_ignore)
except SignalInterrupt:
    signal.signal(signal.SIGINT, signal_ignore)

referenced_table = b.get_table("referenced")

for k,v in referenced_table.items():
    if k.value == 1:
        print("referenced inodes: {}".format(v.value))
    else:
        print("referenced dentries: {}".format(v.value))

