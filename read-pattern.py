from __future__ import print_function
from bcc import BPF
import ctypes as ct

debug = 0

bpf_text = """
#include <uapi/linux/ptrace.h>
#include <linux/fs.h>
#include <linux/uio.h>

typedef struct read_data_s {
	u64 pos;
	u64 count;
	char name[32];
} read_data_t;

BPF_PERF_OUTPUT(reads);

int trace_generic_file_read_iter(struct pt_regs *ctx, struct kiocb *iocb, struct iov_iter *i)
{
	u64 magic = iocb->ki_filp->f_mapping->host->i_sb->s_magic;
	if (magic != 0x58465342)
		return 0;
	u64 count = i->count;
	u64 pos = iocb->ki_pos;
	struct dentry *dentry = iocb->ki_filp->f_path.dentry;

	read_data_t data = {
		.count = count,
		.pos = pos,
	};
	bpf_probe_read(&data.name, sizeof(data.name), (void *)dentry->d_name.name);
	reads.perf_submit(ctx, &data, sizeof(data));
	return 0;	
}
"""
b = BPF(text=bpf_text)
b.attach_kprobe(event="generic_file_read_iter", fn_name="trace_generic_file_read_iter")

class ReadData(ct.Structure):
    _fields_ = [
        ("pos", ct.c_ulonglong),
        ("count", ct.c_ulonglong),
        ("name", ct.c_char * 32),
    ]

files = {}

def print_read_data(cpu, data, size):
    event = ct.cast(data, ct.POINTER(ReadData)).contents
    if event.name not in files:
        files[event.name] = []
    l = [ {'pos': int(event.pos), 'count': int(event.count)} ]
    files[event.name].extend(l)

count = 0
b['reads'].open_perf_buffer(print_read_data)
while 1:
    b.kprobe_poll()
    count += 1
    if count > 100:
       break

print("Checking for overlapping areas")
for f in files.keys():
    pos = []
    lens = []
    for l in files[f]:
        pos.append(l['pos'])
        lens.append(l['count'])
    for i in range(0, len(pos)):
        cur_pos = pos[i]
        cur_len = lens[i]
        for c in range(i+1, len(pos)):
            test_pos = pos[c]
            test_len = lens[c]
            if cur_pos >= (test_pos + test_len) or test_pos >= (cur_pos + cur_len):
                continue
            print("OVERLAP file %s, %d-%d %d-%d" % (f, cur_pos, cur_len, test_pos, test_len))

