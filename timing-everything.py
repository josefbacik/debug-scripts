from bcc import BPF
import ctypes as ct
import argparse
import subprocess

bpf_text = """
#include <uapi/linux/ptrace.h>
"""

sections = {}
sections['struct'] = "typedef struct data_s {\nu64 pid;\n"
sections['hashes'] = "BPF_PERF_OUTPUT(events);\n"
sections['funcs'] = ""
sections['end_func'] = ""
sections['start_func'] = ""
to_attach = []

def sanitize_name(func):
    # Some function names get optimized to include .isra in their name, which
    # makes everything puke, so sanitize these names into something different.
    if '.' in func:
        return func.split('.')[0]
    return func

def add_main_func(func_name, thresh, sections, attach):
    name = sanitize_name(func_name)
    sections['struct'] += "u64 {}_duration;\n".format(name)
    sections['hashes'] += "BPF_HASH({}_time, u64, u64);\n".format(name)
    sections['start_func'] = """
int trace_start_NAME(struct pt_regs *ctx) {
    u64 pid = bpf_get_current_pid_tgid();
    u64 ts = bpf_ktime_get_ns();
    u64 zero = 0;

    NAME_time.update(&pid, &ts);
""".replace('NAME', name)

    sections['end_func'] = """
int trace_stop_NAME(struct pt_regs *ctx) {
    u64 pid = bpf_get_current_pid_tgid();
    u64 delta;
    u64 *val;

    val = NAME_time.lookup(&pid);
    if (!val)
        return 0;

    delta = bpf_ktime_get_ns() - *val;
    if (delta < THRESHOLDL)
        return 0;

    data_t d = {
        .pid = (u32)pid,
        .NAME_duration = delta,
    };
""".replace('NAME', name).replace('THRESHOLD', str(thresh))
    attach.append((name, func_name))

    return "{}_duration".format(name)

def add_function(func_name, sections, attach, siblings):
    name = sanitize_name(func_name)
    siblings.append("{}_duration".format(name))
    sections['struct'] += "u64 {}_duration;\n".format(name)
    sections['hashes'] += "BPF_HASH({}_start, u64, u64);\n".format(name)
    sections['hashes'] += "BPF_HASH({}_time, u64, u64);\n".format(name)
    sections['funcs'] += """
int trace_start_NAME(struct pt_regs *ctx) {
    u64 pid = bpf_get_current_pid_tgid();
    u64 ts = bpf_ktime_get_ns();

    NAME_start.update(&pid, &ts);
    return 0;
}

int trace_stop_NAME(struct pt_regs *ctx) {
    u64 pid = bpf_get_current_pid_tgid();
    u64 delta, zero = 0;
    u64 *val;

    val = NAME_start.lookup(&pid);
    if (!val)
        return 0;

    delta = bpf_ktime_get_ns() - *val;
    val = NAME_time.lookup_or_init(&pid, &zero);
    lock_xadd(val, delta);
    return 0;
}
""".replace('NAME', name)

    sections['end_func'] += """
    val = NAME_time.lookup(&pid);
    if (val)
        d.NAME_duration = *val;
    """.replace('NAME', name)

    sections['start_func'] += """
    NAME_time.update(&pid, &zero);
    """.replace('NAME', name)

    attach.append((name, func_name))

siblings = []

parser = argparse.ArgumentParser(description="Trace some bullshit")
parser.add_argument('--children', type=str, nargs='+', default=[],
                    help="Any children you want to trace under the main function")
parser.add_argument('--main', type=str, required=True,
                    help="The main function to trace")
parser.add_argument('--threshold', type=int, default=1000000,
                    help="Only worry about events that take X ns, defaults to 1ms")
args = parser.parse_args()

main = add_main_func(args.main, args.threshold, sections, to_attach)
for c in args.children:
    add_function(c, sections, to_attach, siblings)

sections['end_func'] += """
    events.perf_submit(ctx, &d, sizeof(d));
    return 0;
}
"""

sections['start_func'] += """
    return 0;
}
"""

sections['struct'] += "} data_t;\n"

bpf_text += sections['struct'] + sections['hashes'] + sections['funcs']
bpf_text += sections['start_func'] + sections['end_func']
print(bpf_text)
b = BPF(text=bpf_text)

for n,f in to_attach:
    b.attach_kretprobe(event=f, fn_name="trace_stop_{}".format(n))
    b.attach_kprobe(event=f, fn_name="trace_start_{}".format(n))

def print_val(event, name):
    val = getattr(event, name)
    main_val = getattr(event, main)
    print("\t{} ns {}% {}".format(val, float(val / main_val * 100), name))

def print_data(cpu, data, size):
    event = b['events'].event(data)
    print("{} took {} ns".format(event.pid, getattr(event, main)))
    for n in siblings:
        print_val(event, n)
    subprocess.run(['kernelctl', 'walker'])

b["events"].open_perf_buffer(print_data)

print("tracing...")
while True:
    try:
        print("probing")
        b.kprobe_poll()
    except KeyboardInterrupt:
        exit()
