from bcc import BPF
import ctypes as ct

bpf_text = """
#include <uapi/linux/ptrace.h>

typedef struct data_s {
    u64 pid;
    u64 read_duration;
    u64 get_extent_duration;
    u64 lock_and_flush_duration;
    u64 submit_bio_duration;
    u64 csum_duration;
    u64 csum_count;
    u64 read_eb_duration;
    u64 read_eb_count;
    u64 io_schedule_duration;
    u64 bio_duration;
    u64 req_duration;
} data_t;

typedef struct bio_data_s {
    u64 ts;
    u64 pid;
} bio_data_t;

BPF_HASH(read_time, u64, u64);
BPF_HASH(get_extent_time, u64, u64);
BPF_HASH(get_extent_start, u64, u64);
BPF_HASH(lock_and_flush_start, u64, u64);
BPF_HASH(lock_and_flush_time, u64, u64);
BPF_HASH(submit_bio_start, u64, u64);
BPF_HASH(submit_bio_time, u64, u64);
BPF_HASH(csum_start, u64, u64);
BPF_HASH(csum_time, u64, u64);
BPF_HASH(csum_count, u64, u64);
BPF_HASH(read_eb_start, u64, u64);
BPF_HASH(read_eb_time, u64, u64);
BPF_HASH(read_eb_count, u64, u64);
BPF_HASH(io_sched_start, u64, u64);
BPF_HASH(io_sched_time, u64, u64);
BPF_HASH(bio_start, struct bio *, bio_data_t);
BPF_HASH(bio_time, u64, u64);
BPF_HASH(req_tmp, u64, struct bio *);
BPF_HASH(req_start, struct request *, bio_data_t);
BPF_HASH(req_time, u64, u64);
BPF_PERF_OUTPUT(events);

int trace_blk_mq_get_request_ret(struct pt_regs *ctx)
{
    u64 pid = bpf_get_current_pid_tgid();
    u64 *val;

    val = read_eb_start.lookup(&pid);
    if (!val)
        return 0;
    bio_data_t d = {
        .pid = pid,
        .ts = bpf_ktime_get_ns(),
    };

    struct request *rq = (struct request *)PT_REGS_RC(ctx);
    req_start.update(&rq, &d);
    return 0;
}

int trace_blk_mq_end_request(struct pt_regs *ctx, struct request *rq)
{
    bio_data_t *d = req_start.lookup(&rq);
    if (!d)
        return 0;
    u64 pid = d->pid;
    u64 zero = 0;
    u64 *val = req_time.lookup_or_init(&pid, &zero);
    lock_xadd(val, bpf_ktime_get_ns() - d->ts);
    return 0;
}

int trace_submit_one_bio(struct pt_regs *ctx, struct bio *bio)
{
    u64 pid = bpf_get_current_pid_tgid();
    u64 *val;

    val = read_eb_start.lookup(&pid);
    if (!val)
        return 0;

    bio_data_t d = {
        .ts = bpf_ktime_get_ns(),
        .pid = pid,
    };
    bio_start.update(&bio, &d);
    return 0;
}

int trace_end_bio_extent_readpage(struct pt_regs *ctx, struct bio *bio)
{
    bio_data_t *d = bio_start.lookup(&bio);
    if (!d)
        return 0;
    u64 zero = 0;
    u64 pid = d->pid;
    u64 *val = bio_time.lookup_or_init(&pid, &zero);
    lock_xadd(val, bpf_ktime_get_ns() - d->ts);
    return 0;
}

int trace_start_io_sched(struct pt_regs *ctx) {
    u64 pid = bpf_get_current_pid_tgid();
    u64 ts = bpf_ktime_get_ns();

    io_sched_start.update(&pid, &ts);
    return 0;
}

int trace_stop_io_sched(struct pt_regs *ctx) {
    u64 pid = bpf_get_current_pid_tgid();
    u64 delta, zero = 0;
    u64 *val;

    val = io_sched_start.lookup(&pid);
    if (!val)
        return 0;

    delta = bpf_ktime_get_ns() - *val;
    val = io_sched_time.lookup_or_init(&pid, &zero);
    lock_xadd(val, delta);

    return 0;
}
int trace_start_read_eb(struct pt_regs *ctx) {
    u64 pid = bpf_get_current_pid_tgid();
    u64 ts = bpf_ktime_get_ns();

    read_eb_start.update(&pid, &ts);
    return 0;
}

int trace_stop_read_eb(struct pt_regs *ctx) {
    u64 pid = bpf_get_current_pid_tgid();
    u64 delta, zero = 0;
    u64 *val;

    val = read_eb_start.lookup(&pid);
    if (!val)
        return 0;

    delta = bpf_ktime_get_ns() - *val;
    val = read_eb_time.lookup_or_init(&pid, &zero);
    lock_xadd(val, delta);

    val = read_eb_count.lookup_or_init(&pid, &zero);
    lock_xadd(val, 1);
    return 0;
}

int trace_start_csum(struct pt_regs *ctx) {
    u64 pid = bpf_get_current_pid_tgid();
    u64 ts = bpf_ktime_get_ns();

    csum_start.update(&pid, &ts);
    return 0;
}

int trace_stop_csum(struct pt_regs *ctx) {
    u64 pid = bpf_get_current_pid_tgid();
    u64 delta, zero = 0;
    u64 *val;

    val = csum_start.lookup(&pid);
    if (!val)
        return 0;

    delta = bpf_ktime_get_ns() - *val;
    val = csum_time.lookup_or_init(&pid, &zero);
    lock_xadd(val, delta);

    val = csum_count.lookup_or_init(&pid, &zero);
    lock_xadd(val, 1);
    return 0;
}

int trace_start_submit_bio(struct pt_regs *ctx) {
    u64 pid = bpf_get_current_pid_tgid();
    u64 ts = bpf_ktime_get_ns();

    submit_bio_start.update(&pid, &ts);
    return 0;
}

int trace_stop_submit_bio(struct pt_regs *ctx) {
    u64 pid = bpf_get_current_pid_tgid();
    u64 delta, zero = 0;
    u64 *val;

    val = submit_bio_start.lookup(&pid);
    if (!val)
        return 0;

    delta = bpf_ktime_get_ns() - *val;
    val = submit_bio_time.lookup_or_init(&pid, &zero);
    lock_xadd(val, delta);
    return 0;
}

int trace_start_lock_and_flush(struct pt_regs *ctx) {
    u64 pid = bpf_get_current_pid_tgid();
    u64 ts = bpf_ktime_get_ns();

    lock_and_flush_start.update(&pid, &ts);
    return 0;
}

int trace_stop_lock_and_flush(struct pt_regs *ctx) {
    u64 pid = bpf_get_current_pid_tgid();
    u64 delta, zero = 0;
    u64 *val;

    val = lock_and_flush_start.lookup(&pid);
    if (!val)
        return 0;

    delta = bpf_ktime_get_ns() - *val;
    val = lock_and_flush_time.lookup_or_init(&pid, &zero);
    lock_xadd(val, delta);
    return 0;
}

int trace_start_get_extent(struct pt_regs *ctx) {
    u64 pid = bpf_get_current_pid_tgid();
    u64 ts = bpf_ktime_get_ns();

    get_extent_start.update(&pid, &ts);
    return 0;
}

int trace_stop_get_extent(struct pt_regs *ctx) {
    u64 pid = bpf_get_current_pid_tgid();
    u64 delta, zero = 0;
    u64 *val;

    val = get_extent_start.lookup(&pid);
    if (!val)
        return 0;

    delta = bpf_ktime_get_ns() - *val;
    val = get_extent_time.lookup_or_init(&pid, &zero);
    lock_xadd(val, delta);
    return 0;
}

int trace_start_read(struct pt_regs *ctx) {
    u64 pid = bpf_get_current_pid_tgid();
    u64 ts = bpf_ktime_get_ns();
    u64 zero = 0;
    u64 tgid = pid >> 32;

    if (tgid != 665225)
        return 0;

    read_time.update(&pid, &ts);
    get_extent_time.update(&pid, &zero);
    lock_and_flush_time.update(&pid, &zero);
    submit_bio_time.update(&pid, &zero);
    csum_time.update(&pid, &zero);
    csum_count.update(&pid, &zero);
    read_eb_time.update(&pid, &zero);
    read_eb_count.update(&pid, &zero);
    io_sched_time.update(&pid, &zero);
    bio_time.update(&pid, &zero);
    req_time.update(&pid, &zero);
    return 0;
}

int trace_stop_read(struct pt_regs *ctx) {
    u64 pid = bpf_get_current_pid_tgid();
    u64 delta;
    u64 *val;

    val = read_time.lookup(&pid);
    if (!val)
        return 0;

    delta = bpf_ktime_get_ns() - *val;
    if (delta < 1000000L) {
        bpf_trace_printk("latency was %llu\\n", delta);
        return 0;
    }

    data_t d = {
        .pid = pid,
        .read_duration = delta,
    };

    val = get_extent_time.lookup(&pid);
    if (val)
        d.get_extent_duration = *val;

    val = lock_and_flush_time.lookup(&pid);
    if (val)
        d.lock_and_flush_duration = *val;

    val = submit_bio_time.lookup(&pid);
    if (val)
        d.submit_bio_duration = *val;

    val = csum_time.lookup(&pid);
    if (val)
        d.csum_duration = *val;

    val = csum_count.lookup(&pid);
    if (val)
        d.csum_count = *val;

    val = read_eb_time.lookup(&pid);
    if (val)
        d.read_eb_duration = *val;

    val = read_eb_count.lookup(&pid);
    if (val)
        d.read_eb_count = *val;

    val = io_sched_time.lookup(&pid);
    if (val)
        d.io_schedule_duration = *val;

    val = bio_time.lookup(&pid);
    if (val)
        d.bio_duration = *val;

    val = req_time.lookup(&pid);
    if (val)
        d.req_duration = *val;

    events.perf_submit(ctx, &d, sizeof(d));
    return 0;
}
"""

b = BPF(text=bpf_text)
b.attach_kprobe(event="extent_readpages", fn_name="trace_start_read")
b.attach_kretprobe(event="extent_readpages", fn_name="trace_stop_read")
b.attach_kprobe(event="btrfs_get_extent", fn_name="trace_start_get_extent")
b.attach_kretprobe(event="btrfs_get_extent", fn_name="trace_stop_get_extent")
b.attach_kprobe(event="btrfs_lock_and_flush_ordered_range", fn_name="trace_start_lock_and_flush")
b.attach_kretprobe(event="btrfs_lock_and_flush_ordered_range", fn_name="trace_stop_lock_and_flush")
b.attach_kprobe(event="submit_one_bio", fn_name="trace_start_submit_bio")
b.attach_kretprobe(event="submit_one_bio", fn_name="trace_stop_submit_bio")
b.attach_kprobe(event="btrfs_lookup_csum", fn_name="trace_start_csum")
b.attach_kretprobe(event="btrfs_lookup_csum", fn_name="trace_stop_csum")
b.attach_kprobe(event="read_extent_buffer_pages", fn_name="trace_start_read_eb")
b.attach_kretprobe(event="read_extent_buffer_pages", fn_name="trace_stop_read_eb")
b.attach_kprobe(event="io_schedule", fn_name="trace_start_io_sched")
b.attach_kretprobe(event="io_schedule", fn_name="trace_stop_io_sched")
b.attach_kprobe(event="submit_bio", fn_name="trace_submit_one_bio")
b.attach_kprobe(event="end_workqueue_bio", fn_name="trace_end_bio_extent_readpage")
b.attach_kretprobe(event="blk_mq_get_request", fn_name="trace_blk_mq_get_request_ret")
b.attach_kprobe(event="blk_mq_end_request", fn_name="trace_blk_mq_end_request")

def print_data(cpu, data, size):
    event = b['events'].event(data)
    print("{} took {} ns to read".format(event.pid, event.read_duration))
    print("\t{} ns {}% get extent".format(event.get_extent_duration,
        float(event.get_extent_duration / event.read_duration * 100)))
    print("\t{} ns {}% lock and flush".format(event.lock_and_flush_duration,
        float(event.lock_and_flush_duration / event.read_duration * 100)))
    print("\t{} ns {}% submit_bio".format(event.submit_bio_duration,
        float(event.submit_bio_duration / event.read_duration * 100)))
    print("\t{} ns {}% io_schedule".format(event.io_schedule_duration,
        float(event.io_schedule_duration / event.read_duration * 100)))
    print("\t{} ns {}% csum count {}".format(event.csum_duration,
        float(event.csum_duration / event.read_duration * 100),
        event.csum_count))
    print("\t{} ns {}% read_eb count {}".format(event.read_eb_duration,
        float(event.read_eb_duration / event.read_duration * 100),
        event.read_eb_count))
    print("\t{} ns {}% bio io time".format(event.bio_duration,
        float(event.bio_duration / event.read_duration * 100)))
    print("\t{} ns {}% req io time".format(event.req_duration,
        float(event.req_duration / event.read_duration * 100)))

b["events"].open_perf_buffer(print_data)

print("tracing...")
while True:
    try:
        print("probing")
        b.kprobe_poll()
    except KeyboardInterrupt:
        exit()
