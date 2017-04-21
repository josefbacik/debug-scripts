# The purpose of this is to print out how long all the processes are spending in
# the various scheduler state.  I used this to figure out exactly how badly
# kswapd was fucking fs_mark during a heavy slab usage run.
from bcc import BPF
from time import sleep
import argparse
import signal

def signal_ignore(signal, frame):
    print()

class SignalInterrupt(Exception):
    def __init__(self, message):
        super(SignalInterrupt, self).__init__(message)

def signal_stop(signal, frame):
    raise SignalInterrupt("Interrupted!")

def pretty_time(value):
    if value < 1000000:
        return "{} ns".format(value)
    value /= 1000000
    if value < 1000:
        return "{} ms".format(value)
    value /= 1000
    return "{} secs".format(value)

bpf_text = """
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>

typedef struct sleep_event_s {
    u64 pid;
    u64 sleep_state;
} sleep_event_t;

typedef struct sleep_data_s {
    u64 time_spent;
    u64 num_events;
} sleep_data_t;

typedef struct comm_name_s {
   char name[TASK_COMM_LEN];
} comm_name_t;

BPF_HASH(process_names, u64, comm_name_t);
BPF_HASH(start, u64);
BPF_HASH(runtime, u64, sleep_data_t);
BPF_HASH(sleepreason, u64, sleep_event_t);
BPF_HASH(sleeptime, sleep_event_t, sleep_data_t);

static u64 task_pid_tgid(struct task_struct *task)
{
    return (u64)task->tgid << 32 | task->pid;
}

int oncpu(struct pt_regs *ctx, struct task_struct *prev)
{
    u64 pid = task_pid_tgid(prev);
    u64 ts = bpf_ktime_get_ns(), *tsp;
    u64 delta;
    sleep_data_t *d;
    sleep_event_t *e;
    sleep_data_t zero = {};
    sleep_event_t event = {
        .sleep_state = prev->state,
    };

    ADJUST_PID
    event.pid = pid;

    tsp = start.lookup(&pid);
    if (tsp) {
        delta = ts - *tsp;
        d = runtime.lookup_or_init(&pid, &zero);
        d->time_spent += delta;
        d->num_events++;
    }
    start.update(&pid, &ts);
    sleepreason.update(&pid, &event);

    pid = bpf_get_current_pid_tgid();

    ADJUST_PID

    tsp = start.lookup(&pid);
    if (!tsp) {
        comm_name_t name;
        bpf_get_current_comm(&name.name, sizeof(name.name));
        process_names.update(&pid, &name);
        goto out;
    }

    ts = bpf_ktime_get_ns();
    delta = ts - *tsp;

    event.pid = pid;
    e = sleepreason.lookup(&pid);
    if (!e) {
        /* this probably shouldn't happen, but if it does put a bogus sleep
           state value in there so we know it happened. */
        event.sleep_state = 10;
    } else {
        event.sleep_state = e->sleep_state & 3;
    }
    d = sleeptime.lookup_or_init(&event, &zero);
    d->time_spent += delta;
    d->num_events++;
out:
    start.update(&pid, &ts);
    return 0;
}
"""

parser = argparse.ArgumentParser()
parser.add_argument("-g", "--group", action='store_true',
    help="Group child threads together in the output")
args = parser.parse_args()

if args.group:
    bpf_text = bpf_text.replace('ADJUST_PID', 'pid = (u32)pid;')
else:
    bpf_text = bpf_text.replace('ADJUST_PID', '')

b = BPF(text=bpf_text)
b.attach_kprobe(event="finish_task_switch", fn_name="oncpu")

print("Tracing, hit Ctrl+C to exit")
signal.signal(signal.SIGINT, signal_stop)
try:
    sleep(99999999)
except KeyboardInterrupt:
    signal.signal(signal.SIGINT, signal_ignore)
except SignalInterrupt:
    signal.signal(signal.SIGINT, signal_ignore)

sleep_table = b.get_table("sleeptime")
run_table = b.get_table("runtime")
process_names = b.get_table("process_names")

processes = []
proc_names = {}

for k,v in sorted(run_table.items(), key=lambda run: run[1].time_spent, reverse=True):
    process = {}
    process['pid'] = k.value
    process['runtime'] = v.time_spent
    process['switches'] = v.num_events
    process['sleeptime'] = {}
    process['threads'] = 0

    name = "{}".format(process['pid'] >> 32)
    for k,v in process_names.items():
        if process['pid'] == k.value:
            name = v.name
            break
    process['name'] = name
    for k,v in sleep_table.items():
        if process['pid'] == k.pid:
            process['sleeptime'][k.sleep_state] = {}
            process['sleeptime'][k.sleep_state]['time'] = v.time_spent
            process['sleeptime'][k.sleep_state]['switches'] = v.num_events
    if args.group and name in proc_names:
        tmp = proc_names[name]
        tmp['runtime'] += process['runtime']
        tmp['switches'] += process['switches']
        tmp['threads'] += 1
        for k,v in process['sleeptime'].items():
            if k in tmp['sleeptime']:
                tmp['sleeptime'][k]['time'] += v['time']
                tmp['sleeptime'][k]['switches'] += v['switches']
            else:
                tmp['sleeptime'][k] = {}
                tmp['sleeptime'][k]['time'] = v['time']
                tmp['sleeptime'][k]['switches'] = v['switches']
    else:
        proc_names[name] = process
        processes.append(process)

if args.group:
    processes = []
    for k,v in sorted(proc_names.items(), key=lambda proc: proc[1]['runtime'], reverse=True):
        processes.append(v)

for process in processes:
    name = process['name']
    pid = process['pid']
    runtime = process['runtime']
    switches = process['switches']
    output = "Proces {} (pid {}) contains {} ran for {} and was switched {} times".format(name,
        pid, process['threads'], pretty_time(runtime), switches)
    for k,v in process['sleeptime'].items():
        output += ", slept in state {} {} times for {}".format(k, v['switches'],
            pretty_time(v['time']))
    print(output)
