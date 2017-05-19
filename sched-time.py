from bcc import BPF
import argparse
from time import sleep
import json

bpf_text = """
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>

typedef struct val_s {
    u32 pid;
    u32 tgid;
    u64 run_time;
    u64 preempt_time;
    u64 sleep_time;
    u64 io_time;
    u64 short_lived;
} val_t;

typedef struct sleep_val_s {
    u64 ts;
    u64 state;
} sleep_val_t;

BPF_HASH(tasks, u64, val_t);
BPF_HASH(start, u64);
BPF_HASH(end, u64, sleep_val_t);

int oncpu(struct pt_regs *ctx, struct task_struct *prev)
{
    u64 pid_key = bpf_get_current_pid_tgid();
    u32 pid = pid_key;
    u32 tgid = pid_key >> 32;
    u64 ts, *tsp;

    if (PID_FILTER) {
        sleep_val_t *sval;
        ts = bpf_ktime_get_ns();
        start.update(&pid_key, &ts);
        val_t zero = {
            .pid = pid,
            .tgid = tgid,
        };
        val_t *info = tasks.lookup_or_init(&pid_key, &zero);
        sval = end.lookup(&pid_key);
        if (sval) {
            u64 sleep_delta = ts - sval->ts;
            if (sval->state == TASK_RUNNING)
                info->preempt_time += sleep_delta;
            else if (sval->state & TASK_INTERRUPTIBLE)
                info->sleep_time += sleep_delta;
            else if (sval->state & TASK_UNINTERRUPTIBLE)
                info->io_time += sleep_delta;
        }
        end.delete(&pid_key);
    }

    pid = prev->pid;
    tgid = prev->tgid;
    pid_key = (u64)tgid << 32 | pid;

    if (!(PID_FILTER))
        return 0;
    tsp = start.lookup(&pid_key);
    if (tsp) {
        u64 run_delta = bpf_ktime_get_ns() - *tsp;
        start.delete(&pid_key);
        val_t zero = {
            .pid = pid,
            .tgid = tgid,
        };
        val_t *info = tasks.lookup_or_init(&pid_key, &zero);
        info->run_time += run_delta;
    }
    sleep_val_t sleep_val = {
        .ts = bpf_ktime_get_ns(),
        .state = prev->state,
    };
    end.update(&pid_key, &sleep_val);
    return 0;
}

int trace_do_exit(struct pt_regs *ctx)
{
    u64 pid = bpf_get_current_pid_tgid();
    val_t *info = tasks.lookup(&pid);
    if (!info)
        return 0;
    u64 ts = bpf_ktime_get_ns(), *tsp;
    tsp = start.lookup(&pid);
    if (tsp) {
        u64 delta = ts - *tsp;
        info->run_time += delta;
        start.delete(&pid);
    }
    info->short_lived = 1;
    return 0;
}

"""

parser = argparse.ArgumentParser(description="Summarize cpu usage of a task")
parser.add_argument("--pids", metavar='P', type=int, nargs='+',
                    help="List of pids to trace")
parser.add_argument("--tgids", metavar='T', type=int, nargs='+',
                    help="List of pids to trace")
parser.add_argument("--duration", default=99999999,
                    type=int, help="duration of trace, in seconds")
parser.add_argument("--rtapp", type=bool, default=False,
                    help="Output an rt-app config for the run")
args = parser.parse_args()
if not args.pids and not args.tgids:
    print("Must specify tgid's or pids")
    exit(1)
if args.pids and args.tgids:
    print("Cannot specify tgid's and pidss")
    exit(1)
duration = int(args.duration)
filter_str = ""
pids = []
tgids = []
if args.pids:
    pids = args.pids
if args.tgids:
    tgids = args.tgids
for p in pids:
    this_str = "pid == {}".format(p)
    if len(filter_str):
        filter_str += "|| {}".format(this_str)
    else:
        filter_str = this_str
for p in tgids:
    this_str = "tgid == {}".format(p)
    if len(filter_str):
        filter_str += "|| {}".format(this_str)
    else:
        filter_str = this_str
bpf_text = bpf_text.replace('PID_FILTER', filter_str)

b = BPF(text=bpf_text)
b.attach_kprobe(event="finish_task_switch", fn_name="oncpu")

try:
    sleep(duration)
except KeyboardInterrupt:
    pass

tasks = b.get_table("tasks")
last_tgid = 0
threads_dict = {}
global_dict = {"duration": args.duration}
counter = 0
for k,v in sorted(tasks.items(), key=lambda run: run[1].tgid, reverse=True):
    if args.rtapp:
        tdict = {}
        tdict['instance'] = 1
        total_time = 1000000
        if v.short_lived == 1:
            tdict['loop'] = 1
            total_time *= args.duration
        else:
            tdict['loop'] = -1
        runtime = v.run_time + v.preempt_time
        sleeptime = v.sleep_time + v.io_time
        tdict['run'] = (runtime * total_time) / (runtime + sleeptime)
        if sleeptime > 0:
            tdict['sleep'] = (sleeptime * total_time) / (runtime + sleeptime)
        if last_tgid != v.tgid:
            if last_tgid != 0:
                print(json.dumps(threads_dict, indent=4))
            threads_dict = {}
            threads_dict["global"] = global_dict
            threads_dict["tasks"] = {}
            counter = 0
            last_tgid = v.tgid
        name = "thread{}".format(counter)
        counter += 1
        threads_dict["tasks"][name] = tdict
        continue
    out_str = "Pid {} tgid {} runtime {} sleeptime {} iotime {} preemttime {}".format(
        v.pid, v.tgid, v.run_time, v.sleep_time, v.io_time, v.preempt_time)
    if last_tgid != v.tgid:
        print(out_str)
        last_tgid = v.tgid
    else:
        print("\t{}".format(out_str))
if args.rtapp:
    print(json.dumps(threads_dict, indent=4))
