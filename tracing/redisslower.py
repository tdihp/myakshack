#!/usr/bin/python
# -*- coding: utf-8 -*-

"""
Ad-hoc script for identifying root cause direction of redis slowlog.

EXAMPLES

* Capture all redis-server process for 10 seconds, use default settings
  otherwise
$ python3 redisslower.py 10

* Capture given process indefinitely, with 99HZ stack sampling, show first 4
  stack samples, show only calls slower than 10ms 
$ python3 redisslower.py -p 12345 -f 99 --max-samples 4 -m 10000

* Capture sortCommand function, instead of "call" function
$ python3 redisslower.py --func sortCommand

Copyright (c) 2023, Ping He.
License: MIT
"""
import os
import sys
import time
import datetime
import threading
from pathlib import Path
import ctypes as ct
from bcc import BPF, PerfType, PerfSWConfig


bpf_text = r'''
#include <uapi/linux/ptrace.h>
#include <uapi/linux/bpf_perf_event.h>
#include <linux/sched.h>

%(EXTRA_MACROS)s

struct sample_t {
    int user_stack_id;
    int kernel_stack_id;
};

struct state_t {
    u64 start_ns;
    unsigned long nvcsw;
    unsigned long nivcsw;
    u32 softirq_cnt;
    u32 hardirq_cnt;
    u32 hits;
    struct sample_t samples[MAXSAMPLES];
};

BPF_HASH(statetable, u64, struct state_t);

struct msg_t {
    u64 tgid_pid;
    u64 start_ns;
    u64 stop_ns;
    /* we don't put latency here */
    unsigned long nvcsw_diff;
    unsigned long nivcsw_diff;
    u32 softirq_cnt;
    u32 hardirq_cnt;
    u32 hits;
    struct sample_t samples[MAXSAMPLES];
};

BPF_PERF_OUTPUT(events);

TRACEPOINT_PROBE(irq, softirq_entry)
{
    u64 tgid_pid = bpf_get_current_pid_tgid();
    FILTER_PID;
    struct state_t *state = statetable.lookup(&tgid_pid);
    if (!state) {
        return 0;
    }
    state->softirq_cnt += 1;
    return 0;
}

TRACEPOINT_PROBE(irq, irq_handler_entry)
{
    u64 tgid_pid = bpf_get_current_pid_tgid();
    FILTER_PID;
    struct state_t *state = statetable.lookup(&tgid_pid);
    if (!state) {
        return 0;
    }
    state->hardirq_cnt += 1;
    return 0;
}

BPF_STACK_TRACE(stack_traces, STACK_STORAGE_SIZE);

int do_perf_event(struct bpf_perf_event_data *ctx) {
    u64 tgid_pid = bpf_get_current_pid_tgid();
    FILTER_PID;
    struct state_t *state = statetable.lookup(&tgid_pid);
    if (!state) {
        return 0;
    }
    if (state->hits < MAXSAMPLES) {
        struct sample_t *sample = &state->samples[state->hits];
        sample->user_stack_id = stack_traces.get_stackid(&ctx->regs, BPF_F_USER_STACK);
        sample->kernel_stack_id = stack_traces.get_stackid(&ctx->regs, 0);
    }
    state->hits++;
    return 0;
}
int trace_entry(struct pt_regs *ctx)
{
    u64 tgid_pid = bpf_get_current_pid_tgid();
    FILTER_PID;
    struct state_t zero = {};
    struct state_t *state = statetable.lookup_or_try_init(&tgid_pid, &zero);
    if (!state) {
        return 0;
    }
    state->start_ns = bpf_ktime_get_ns();
    struct task_struct *task = bpf_get_current_task();
    state->nvcsw = task->nvcsw;
    state->nivcsw = task->nivcsw;
    return 0;
}

int trace_return(struct pt_regs *ctx)
{
    u64 tgid_pid = bpf_get_current_pid_tgid();
    FILTER_PID;
    struct state_t *state = statetable.lookup(&tgid_pid);
    if (!state) {
        return 0;
    }
    struct msg_t msg = {};
    msg.start_ns = state->start_ns;
    msg.stop_ns = bpf_ktime_get_ns();
    if ((msg.stop_ns - msg.start_ns) < MINLAT) {
        goto recycle;
    }
    msg.tgid_pid = tgid_pid;
    struct task_struct *task = bpf_get_current_task();
    msg.nvcsw_diff = task->nvcsw - state->nvcsw;
    msg.nivcsw_diff = task->nivcsw - state->nivcsw;
    msg.softirq_cnt = state->softirq_cnt;
    msg.hardirq_cnt = state->hardirq_cnt;
    msg.hits = state->hits;
    __builtin_memcpy(&msg.samples, &state->samples, sizeof(msg.samples));
    events.perf_submit(ctx, &msg, sizeof(msg));
recycle:
    statetable.delete(&tgid_pid);
    return 0;
}
'''


def discover_redis_server():
    """this function find all pids having comm as redis-server"""
    for p in Path('/proc').iterdir():
        if not p.name.isdigit():
            continue

        try:
            comm = p.joinpath('comm').read_bytes()
        except FileNotFoundError as e:
            continue
        
        if comm.strip(b'\n') == b'redis-server':
            pid = int(p.name)
            yield pid


import argparse
parser = argparse.ArgumentParser(
    description=__doc__,
    formatter_class=argparse.RawDescriptionHelpFormatter)
parser.add_argument('-p', '--pid', type=int,
                    help='pid for tracing, by default all processes are'
                         'triggered, noting in that case the first '
                         'redis-server process will be used for uprobe symtom')
parser.add_argument('--binary-path', type=Path,
                    help='binary path to use. When absolute path given, the '
                         'path is directly used for uprobe symbol discovery; '
                         'when relative path given, "/proc/<pid>/root/" will '
                         'be prefixed automatically; by default it uses '
                         '`readlink -f /proc/<pid>/exe` under /proc/<pid>/root')
parser.add_argument('-f', '--frequency', type=int,
                    help='enable sampling with frequency')
parser.add_argument('--max-samples', type=int, default=2,
                    help='max samples when sampling is enabled. 2 by default')
parser.add_argument('--func', default='call',
                    help='redis function to trace, "call" by default')
parser.add_argument('-m', '--min-lat', default=1000, type=int,
                    help='min latency to display in microseconds (us), default '
                    'to 1000us (1ms)')
parser.add_argument('--stack-storage-size', default=16384, type=int,
                    help='stack storage size used in stack sampling, default '
                         'to 16384')
parser.add_argument('duration', type=int, nargs='?',
                     help='capture duration in seconds, use keyboard '
                          'interrput when not specified')
args = parser.parse_args()

pid = None
absolute_binary_path = None
uprobe_pid = None
func = args.func

frequency = args.frequency
sampling = bool(frequency)
max_samples = args.max_samples

if args.binary_path and args.binary_path.is_absolute():
    absolute_binary_path = args.binary_path

if args.pid:
    pid = args.pid
    uprobe_pid = pid

if not absolute_binary_path:
    if not uprobe_pid:
        try:
            uprobe_pid = next(discover_redis_server())
        except StopIteration:
            raise Exception('No redis-server found')

        print('pid not provided, using pid %d for uprobe' % uprobe_pid,
            file=sys.stderr)

    root = Path('/proc/%d/root' % uprobe_pid)
    binary_path = args.binary_path \
        or Path(os.readlink('/proc/%d/exe' % uprobe_pid)).relative_to('/')
    absolute_binary_path = root / binary_path

if not Path(absolute_binary_path).exists():
    raise Exception('specified absolute binary path %s not found'
                    % absolute_binary_path)


class sample_t(ct.Structure):
    _fields_ = [
        ('user_stack_id',   ct.c_int),
        ('kernel_stack_id', ct.c_int),
    ]

class msg_t(ct.Structure):
    _fields_ = [
        ('tgid_pid',    ct.c_uint64),
        ('start_ns',    ct.c_uint64),
        ('stop_ns',     ct.c_uint64),
        ('nvcsw_diff',  ct.c_ulong),
        ('nivcsw_diff', ct.c_ulong),
        ('softirq_cnt', ct.c_uint32),
        ('hardirq_cnt', ct.c_uint32),
        ('hits',        ct.c_uint32),
        ('samples',     sample_t * max_samples),
    ]

extra_defs = {
    'MINLAT': args.min_lat * 1000,
    'MAXSAMPLES': max_samples,
    'STACK_STORAGE_SIZE': args.stack_storage_size,
    'FILTER_PID': 'if (tgid_pid>>32 != %d) return 0;' % pid if pid else ""
}

bpf_text_rendered = bpf_text % {'EXTRA_MACROS': '\n'.join('#define %s %s' % pair for pair in extra_defs.items())}

b = BPF(text=bpf_text_rendered)
first_ts = BPF.monotonic_time()
first_ts_real = time.time()

def reltime(ts_ns):
    return 1e-9 * (ts_ns - first_ts)


def clocktime(ts_ns):
    return reltime(ts_ns) + first_ts_real

library=str(absolute_binary_path)
b.attach_uprobe(name=library, sym=func, fn_name="trace_entry")
b.attach_uretprobe(name=library, sym=func, fn_name="trace_return")

if sampling:
    b.attach_perf_event(ev_type=PerfType.SOFTWARE,
        ev_config=PerfSWConfig.CPU_CLOCK, fn_name="do_perf_event",
        sample_freq=frequency)


def format_stack(tgid_pid, user_stack_id, kernel_stack_id):
    stack_traces = b.get_table("stack_traces")
    user_stack_str = ''
    kernel_stack_str = ''
    if user_stack_id > 0:
        user_stack = list(stack_traces.walk(user_stack_id))
        user_stack_str = '>'.join(
            b.sym(addr, tgid_pid).decode('utf-8', 'replace')
            for addr in reversed(user_stack))

    if kernel_stack_id > 0:
        kernel_stack = list(stack_traces.walk(kernel_stack_id))
        kernel_stack_str = '>'.join(
            b.ksym(addr).decode('utf-8', 'replace')
            for addr in reversed(kernel_stack)
        )
    return kernel_stack_str + ':' + user_stack_str


print("%15s %7s/%-7s %10s %5s %5s %5s %5s %3s" % (
    'TIMESTAMP', 'PID', 'TID', 'LATENCY_MS', 'SW', 'ISW', 'SOFT', 'HARD', 'HIT',
))


def callback(cpu, data, size, timefmt="%H:%M:%S.%f"):
    # event = b["events"].event(data)
    event = ct.cast(data, ct.POINTER(msg_t)).contents
    latency = (event.stop_ns - event.start_ns) / 1000000
    tgid = event.tgid_pid >> 32
    pid = event.tgid_pid & 0xffffffff
    print("%s %7d/%-7d %10.3f %5d %5d %5d %5d %3d" % (
        datetime.datetime.fromtimestamp(clocktime(event.start_ns)).strftime(timefmt),
        tgid, pid,
        latency,
        event.nvcsw_diff,
        event.nivcsw_diff,
        event.softirq_cnt,
        event.hardirq_cnt,
        event.hits,
    ))
    if event.hits:
        for i in range(min(max_samples, event.hits)):
            sample = event.samples[i]
            print(format_stack(event.tgid_pid,
                               sample.user_stack_id,
                               sample.kernel_stack_id))


def _callback(cpu, data, size, **kw):
    # this wrapper is needed to avoid blocking of ctrl-c.
    global running
    if not running:
        return
    try:
        callback(cpu, data, size, **kw)
    except KeyboardInterrupt:
        running = 0
        raise

b["events"].open_perf_buffer(_callback, page_cnt=64)
running = 1
def on_duration():
    global running
    running = 0

if args.duration:
    t = threading.Timer(args.duration, on_duration)
    t.daemon = True
    t.start()

while running:
    try:
        b.perf_buffer_poll()
    except KeyboardInterrupt:
        exit()
