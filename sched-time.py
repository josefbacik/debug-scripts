#!/usr/bin/python3

from bcc import BPF
import argparse
from time import sleep
import json
import copy
from collections import OrderedDict

def print_tasks(tasks):
    last_tgid = 0
    for k,v in tasks:
        out_str = "Pid {} tgid {} runtime {} sleeptime {} iotime {} preemttime {}".format(
            v.pid, v.tgid, v.run_time, v.sleep_time, v.io_time, v.preempt_time)
        if last_tgid != v.tgid:
            print(out_str)
            last_tgid = v.tgid
        else:
            print("\t{}".format(out_str))

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
    u64 run_events;
    u64 sleep_events;
    u32 short_lived;
    u32 priority;
} val_t;

typedef struct sleep_val_s {
    u64 ts;
    u64 state;
} sleep_val_t;

typedef struct wake_dep_s {
    u32 waker_pid;
    u32 sleeper_pid;
    u32 tgid;
} wake_dep_t;

BPF_HASH(tasks, u64, val_t);
BPF_HASH(wake_deps, wake_dep_t);
BPF_HASH(start, u64);
BPF_HASH(end, u64, sleep_val_t);
BPF_HASH(futexes, u64);

int waker(struct pt_regs *ctx, struct task_struct *p)
{
    u32 pid = p->pid;
    u32 tgid = p->tgid;

    if (!(PID_FILTER))
        return 0;
    u64 pid_key = bpf_get_current_pid_tgid();
    pid = pid_key;
    tgid = pid_key >> 32;
    if (tgid != p->tgid)
        return 0;
    if (!(PID_FILTER))
        return 0;
    u64 *val = futexes.lookup(&pid_key);
    if (!val)
        return 0;
    wake_dep_t info = {
        .waker_pid = pid,
        .sleeper_pid = p->pid,
        .tgid = tgid,
    };
    u64 zero = 0;
    val = wake_deps.lookup_or_init(&info, &zero);
    (*val)++;
    return 0;
}

int enter_futex(struct pt_regs *ctx)
{
    u64 pid_key = bpf_get_current_pid_tgid();
    u64 zero = 0;
    futexes.lookup_or_init(&pid_key, &zero);
    return 0;
}

int exit_futex(struct pt_regs *ctx)
{
    u64 pid_key = bpf_get_current_pid_tgid();
    futexes.delete(&pid_key);
    return 0;
}

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
            else if (sval->state & TASK_INTERRUPTIBLE) {
                info->run_events++;
                info->sleep_time += sleep_delta;
            } else if (sval->state & TASK_UNINTERRUPTIBLE) {
                info->run_events++;
                info->io_time += sleep_delta;
            }
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
        info->priority = prev->prio;
        info->sleep_events++;
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
if args.rtapp:
    b.attach_kprobe(event="try_to_wake_up", fn_name="waker")
    b.attach_kprobe(event="do_futex", fn_name="enter_futex")
    b.attach_kretprobe(event="do_futex", fn_name="exit_futex")

try:
    sleep(duration)
except KeyboardInterrupt:
    pass

tasks = b.get_table("tasks")
sorted_tasks = sorted(tasks.items(), key=lambda run: run[1].tgid, reverse=True)
if not args.rtapp:
    print_tasks(sorted_tasks)
    exit(0)

waker_deps = b.get_table("wake_deps")
waker_sets = {}
for k,v in waker_deps.items():
    waker = k.waker_pid
    sleeper = k.sleeper_pid
    # we add our waker to our list because consumers may wake producers to
    # indicate they have completed their task
    if waker not in waker_sets:
        waker_sets[waker] = set([sleeper])
    elif sleeper not in waker_sets[waker]:
        waker_sets[waker].update([sleeper])

def reduce(waker_sets):
    need_loop = True
    groups = {}
    counter = 0
    while need_loop:
        need_loop = False
        producer = None
        for pid,wakeset in waker_sets.items():
            found = False
            need_break = False
            for name,base in groups.items():
                if wakeset.issubset(base):
                    found = True
                    break
                elif wakeset.issuperset(base):
                    found = True
                    groups[pid] = wakeset.copy()
                    groups.pop(name, None)
                    need_break = True
                    break
                elif len(wakeset.intersection(base)):
                    need_break = True
                    waker_sets[pid] -= base
                    break
            if need_break:
                need_loop = True
                break
            if not found:
                groups[pid] = wakeset.copy()
                need_loop = True
    return groups

groups = {}
loops = 0
while True or loops > 10:
    loops += 1
    blah = reduce(waker_sets)
    if len(groups) != len(blah):
        groups = blah
        waker_sets = blah
    else:
        break

for k,v in groups.items():
    if len(v) == 1:
        groups.pop(k, None)

last_tgid = 0
threads_dict = {}
global_dict = {"duration": args.duration}
threads_list = []
for k,v in sorted_tasks:
    if last_tgid != v.tgid:
        if last_tgid != 0:
            for name,actions in threads_dict['tasks'].items():
                if actions['instance'] > 1:
                    actions['run'] /= actions['instance']
            threads_list.append(copy.copy(threads_dict))
        threads_dict = {}
        threads_dict["global"] = global_dict
        threads_dict["tasks"] = {}
        last_tgid = v.tgid
    total_time = 1000000
    runtime = v.run_time + v.preempt_time
    runevents = v.run_events
    sleeptime = v.sleep_time + v.io_time
    tdict = {}
    if v.pid in groups:
        tdict['loop'] = -1
        tdict['instance'] = 1
        if v.priority != 120:
            tdict['priority'] = v.priority - 120
        tdict['lock'] = 'mutex{}'.format(v.pid)
        tdict['broad'] = 'shared{}'.format(v.pid)
        tdict['unlock'] = 'mutex{}'.format(v.pid)
        tdict['sleep'] = 0
        threads_dict["tasks"][v.pid] = tdict

    found = False
    for pid,pidset in groups.items():
        if v.pid in pidset:
            found = True
            name = "threads{}".format(pid)
            priority = 0
            if v.priority != 120:
                priority = v.priority - 120
                name = "threads{}priority{}".format(pid, priority)
            if name not in threads_dict["tasks"]:
                threads_dict["tasks"][name] = tdict
                tdict['instance'] = 0
                tdict['loop'] = -1
                if v.priority != 120:
                    tdict['priority'] = v.priority - 120
                tdict['lock'] = 'mutex{}'.format(pid)
                tdict['wait'] = { 'ref': 'shared{}'.format(pid),
                                  'mutex': 'mutex{}'.format(pid) }
                tdict['unlock'] = 'mutex{}'.format(pid)
                tdict['run'] = 0
            else:
                tdict = threads_dict["tasks"][name]
            tdict['run'] += (runtime / 1000) / runevents
            tdict['instance'] += 1
            break

    if found:
        continue
    tdict['instance'] = 1
    tdict['loop'] = -1
    tdict['run'] = (runtime * total_time) / (runtime + sleeptime)
    if sleeptime > 0:
        tdict['sleep'] =  (sleeptime * total_time) / (runtime + sleeptime)
    threads_dict["tasks"][v.pid] = tdict

# we need to load the wake deps into our dicts.  This isn't super awesome
# because rt-app only does pthreads, so we'll lose any process->process wakeups,
# but those shouldn't matter too much.  We also have to search all the task
# lists, because I'm shit at python and don't know a better way to do this
for name,actions in threads_dict['tasks'].items():
    if actions['instance'] > 1:
        actions['run'] /= actions['instance']
threads_list.append(threads_dict)


#    for task in threads_list:
#        if waker in task["tasks"] and sleeper in task["tasks"]:
#            task["tasks"][waker].append(('resume', sleeper))
#            if sleeper not in suspends:
#                task["tasks"][sleeper].append(('suspend', sleeper))
#                suspends.append(sleeper)
#            break

# Now we have to sort our output.  rt-app expects the thread instructions to be
# in the order that they are executed.  We don't have to worry about sorting the
# threads themselves, just the actions.  I shamelessly stole this from SO.
#
# The ordering for the waker should be
#
# loop->run->resume->sleep
#
# This is to simulate the producer getting a request, waking up the worker, and
# going to sleep until the next thing shows up.  The ordering for the worker
# should be
#
# loop->suspend->run->sleep
#
# This simulates the thread waiting to be given work, waking up and then going
# back to sleep to wait for the next work set.
for task in threads_list:
    sort_order = ['instance', 'loop', 'priority', 'lock', 'wait', 'broad', 'unlock', 'run',
                    'sleep']
    for name,actions in task['tasks'].items():
        task['tasks'][name] = OrderedDict(sorted(actions.iteritems(),
                    key=lambda (k, v): sort_order.index(k)))
    print(json.dumps(task, indent=4))
