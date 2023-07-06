#!/usr/bin/python
# -*- coding: utf-8 -*-

"""
Ad-hoc script for identifying root cause direction of redis latency.
This script captures each eventloop and count all calls inside.

EXAMPLES

* Capture all redis-server process for 10 seconds, use default settings
  otherwise
$ python3 redisloopcalls.py 10

* Capture given process indefinitely, show only calls slower than 10ms
$ python3 redisloopcalls.py -p 12345 -m 10000

* Filter with only oncpu time larger than 1ms
$ python3 redisloopcalls.py --min-oncpu 1000

* Sample with 99hz frequency and print first 4 stack samples hit
$ python3 redisloopcalls.py -f99 --max-samples 4

CHANGELOG

2023-07-05 Initial script
2023-07-06 Add oncpu time and switch count, add --min-oncpu flag
           Add perf sampling 

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

struct redisCommand {
    char *name;
    void *proc;
    int arity;
    char *sflags;
    int flags;
};

/* a copy from redis 5 */
struct client {
    uint64_t id;
    int fd;
    void *db;
    void *name;
    void *querybuf;
    size_t qb_pos;
    void *pending_querybuf;
    size_t querybuf_peak;
    int argc;
    void *argv;
    struct redisCommand *cmd;
};

%(EXTRA_MACROS)s

struct call_state_t {
    u64 start_ns;
    u32 cmdid;
};

struct call_stats_t {
    u64 lat_sum_ns;
    u64 lat_max_ns;
    u32 count;
};

struct sample_t {
    int user_stack_id;
    int kernel_stack_id;
};

struct loop_state_t {
    u64 start_ns;
    u64 sched_ns;
    u64 oncpu_ns;
    u32 sw;
    u32 overflow;
    u32 hits;
    struct call_stats_t call_stats[MAX_COMMANDS];
    struct sample_t samples[MAXSAMPLES];
};

struct command_key_t {
    u32 pid;
    struct redisCommand *cmd;
};

struct command_info_t {
    int flags;
    char name[MAX_NAMELEN];
};

struct command_info_table_t {
    u32 count;
    struct command_info_t command_info[MAX_COMMANDS];
};


BPF_HASH(command_index, struct command_key_t, u32);
BPF_HASH(command_info_table_map, u32, struct command_info_table_t);
BPF_HASH(loop_state_map, u32, struct loop_state_t);
BPF_HASH(call_state_map, u32, struct call_state_t);
BPF_STACK_TRACE(stack_traces, STACK_STORAGE_SIZE);

struct msg_t {
    u32 tgid;
    u32 pid;
    u64 start_ns;
    u64 stop_ns;
    u64 oncpu_ns;
    u32 sw;
    u32 overflow;
    u32 hits;
    struct call_stats_t call_stats[MAX_COMMANDS];
    struct sample_t samples[MAXSAMPLES];
};

BPF_PERF_OUTPUT(events);

int trace_loop_entry(struct pt_regs *ctx)
{
    u64 tgid_pid = bpf_get_current_pid_tgid();
    FILTER_PID;
    u32 tgid = tgid_pid >> 32;
    u32 pid = tgid_pid;
    u64 now = bpf_ktime_get_ns();
    struct loop_state_t state = {now, now};
    loop_state_map.update(&pid, &state);
    return 0;
}

int trace_loop_return(struct pt_regs *ctx)
{
    u64 tgid_pid = bpf_get_current_pid_tgid();
    FILTER_PID;
    u32 pid = tgid_pid;
    u64 now = bpf_ktime_get_ns();
    struct loop_state_t *loop_state = loop_state_map.lookup(&pid);
    if (!loop_state) return 0;
    u64 dt = now - loop_state->start_ns;
    if (dt < MINLAT) {
        goto recycle;
    }
    loop_state->oncpu_ns += (now - loop_state->sched_ns);
#ifdef MINONCPU
    if (loop_state->oncpu_ns < MINONCPU) {
        goto recycle;
    }
#endif
    struct msg_t msg = {};
    msg.tgid = tgid_pid >> 32;
    msg.pid = pid;
    msg.start_ns = loop_state->start_ns;
    msg.stop_ns = now;
    msg.oncpu_ns = loop_state->oncpu_ns;
    msg.sw = loop_state->sw;
    msg.overflow = loop_state->overflow;
    msg.hits = loop_state->hits;
    __builtin_memcpy(&msg.call_stats,
                     &loop_state->call_stats,
                     sizeof(msg.call_stats));
    __builtin_memcpy(&msg.samples, &loop_state->samples, sizeof(msg.samples));
    events.perf_submit(ctx, &msg, sizeof(msg));
recycle:
    loop_state_map.delete(&pid);
    return 0;
}

int trace_call_entry(struct pt_regs *ctx)
{
    u64 tgid_pid = bpf_get_current_pid_tgid();
    FILTER_PID;
    u32 pid = tgid_pid;
    struct client *c = (struct client *)PT_REGS_PARM1(ctx);
    /* ensure the command is registered */
    if (!c) return 0;
    struct redisCommand *cmd = c->cmd;
    if (!cmd) return 0;
    struct command_key_t command_key = {};
    command_key.pid = pid;
    command_key.cmd = cmd;
    u32 *command_id_p = command_index.lookup(&command_key);
    u32 command_id = 0;
    if (!command_id_p) {
        struct command_info_table_t citzero = {};
        struct command_info_table_t *command_info_table =
            command_info_table_map.lookup_or_try_init(&pid, &citzero);
        if (!command_info_table) return 0;
        command_id = command_info_table->count;
        command_info_table->count += 1;
        command_index.update(&command_key, &command_id);
        if (command_id < MAX_COMMANDS) {
            struct command_info_t *command_info = &command_info_table->command_info[command_id];
            command_info->flags = cmd->flags;
            bpf_probe_read_user_str(&command_info->name, MAX_NAMELEN, cmd->name);
        }
    } else {
        command_id = *command_id_p;
    }
    u64 now = bpf_ktime_get_ns();
    /* struct call_state_t state = {now, command_id}; */
    struct call_state_t state = {};
    state.start_ns = now;
    state.cmdid = command_id;
    call_state_map.update(&pid, &state);
    return 0;
}

int trace_call_return(struct pt_regs *ctx)
{
    u64 tgid_pid = bpf_get_current_pid_tgid();
    FILTER_PID;
    u32 pid = tgid_pid;
    struct call_state_t *call_state = call_state_map.lookup(&pid);
    if (!call_state) return 0;
    struct loop_state_t *loop_state = loop_state_map.lookup(&pid);
    if (!loop_state) return 0;
    u32 command_id = call_state->cmdid;
    if (command_id >= MAX_COMMANDS) {
        loop_state->overflow++;
    } else {
        u64 now = bpf_ktime_get_ns();
        u64 dt = now - call_state->start_ns;
        struct call_stats_t *call_stats = &loop_state->call_stats[command_id];
        call_stats->lat_sum_ns += dt;
        if (dt > call_stats->lat_max_ns) {
            call_stats->lat_max_ns = dt;
        }
        call_stats->count++;
    }
    call_state_map.delete(&pid);
    return 0;
}

TRACEPOINT_PROBE(sched, sched_switch) {
    u32 pid = args->prev_pid;
    struct loop_state_t *loop_state = loop_state_map.lookup(&pid);
    if (!loop_state) return 0;
    u64 now = bpf_ktime_get_ns();
    loop_state->oncpu_ns += (now - loop_state->sched_ns);
    loop_state->sched_ns = now;
    loop_state->sw += 1;
    return 0;
}

TRACEPOINT_PROBE(sched, sched_wakeup) {
    u32 pid = args->pid;
    struct loop_state_t *loop_state = loop_state_map.lookup(&pid);
    if (!loop_state) return 0;
    u64 now = bpf_ktime_get_ns();
    loop_state->sched_ns = now;
    return 0;
}

int do_perf_event(struct bpf_perf_event_data *ctx) {
    u64 tgid_pid = bpf_get_current_pid_tgid();
    FILTER_PID;
    u32 pid = tgid_pid;
    struct loop_state_t *loop_state = loop_state_map.lookup(&pid);
    if (!loop_state) {
        return 0;
    }
    if (loop_state->hits < MAXSAMPLES) {
        struct sample_t *sample = &loop_state->samples[loop_state->hits];
        sample->user_stack_id = stack_traces.get_stackid(&ctx->regs, BPF_F_USER_STACK);
        sample->kernel_stack_id = stack_traces.get_stackid(&ctx->regs, 0);
    }
    loop_state->hits++;
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
parser.add_argument('-m', '--min-lat', default=1000, type=int,
                    help='min latency to display in microseconds (us), default '
                    'to 1000us (1ms)')
parser.add_argument('--min-oncpu', type=int,
                    help='min oncpu time to display in microseconds (us)')
parser.add_argument('-f', '--frequency', type=int,
                    help='enable sampling with frequency')
parser.add_argument('--max-samples', type=int, default=2,
                    help='max samples when sampling is enabled. 2 by default')
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
max_namelen = 16
max_commands = 16

frequency = args.frequency
sampling = bool(frequency)
max_samples = args.max_samples if sampling else 0

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


class command_info_t(ct.Structure):
    _fields_ = [
        ('flags',   ct.c_int),
        ('name',    ct.c_char * max_namelen)
    ]

class command_info_table_t(ct.Structure):
    _fields_ = [
        ('count',           ct.c_uint32),
        ('command_info',    command_info_t * max_commands),
    ]

class call_stats_t(ct.Structure):
    _fields_ = [
        ('lat_sum_ns',  ct.c_uint64),
        ('lat_max_ns',  ct.c_uint64),
        ('count',       ct.c_uint32),
    ]

class sample_t(ct.Structure):
    _fields_ = [
        ('user_stack_id',   ct.c_int),
        ('kernel_stack_id', ct.c_int),
    ]

class msg_t(ct.Structure):
    _fields_ = [
        ('tgid',        ct.c_uint32),
        ('pid',         ct.c_uint32),
        ('start_ns',    ct.c_uint64),
        ('stop_ns',     ct.c_uint64),
        ('oncpu_ns',    ct.c_uint64),
        ('sw',          ct.c_uint32),
        ('overflow',    ct.c_uint32),
        ('hits',        ct.c_uint32),
        ('call_stats',  call_stats_t * max_commands),
        ('samples',     sample_t * max_samples)
    ]


extra_defs = {
    'MINLAT': args.min_lat * 1000,
    'MAX_COMMANDS': max_commands,
    'MAX_NAMELEN': max_namelen,
    'MAXSAMPLES': max_samples,
    'STACK_STORAGE_SIZE': args.stack_storage_size,
    'FILTER_PID': 'if (tgid_pid>>32 != %d) return 0;' % pid if pid else "",
}

if args.min_oncpu:
    extra_defs['MINONCPU'] = args.min_oncpu * 1000

bpf_text_rendered = bpf_text % {'EXTRA_MACROS': '\n'.join('#define %s %s' % pair for pair in extra_defs.items())}

b = BPF(text=bpf_text_rendered)
first_ts = BPF.monotonic_time()
first_ts_real = time.time()

def reltime(ts_ns):
    return 1e-9 * (ts_ns - first_ts)


def clocktime(ts_ns):
    return reltime(ts_ns) + first_ts_real

library=str(absolute_binary_path)
b.attach_uprobe(name=library,
                sym='aeProcessEvents', fn_name="trace_loop_entry")
b.attach_uretprobe(name=library,
                   sym='aeProcessEvents', fn_name="trace_loop_return")
b.attach_uprobe(name=library, sym='call', fn_name="trace_call_entry")
b.attach_uretprobe(name=library, sym='call', fn_name="trace_call_return")
if sampling:
    b.attach_perf_event(ev_type=PerfType.SOFTWARE,
        ev_config=PerfSWConfig.CPU_CLOCK, fn_name="do_perf_event",
        sample_freq=frequency)

print("%15s %7s/%-7s %10s %10s %8s %8s %4s" % (
    'TIMESTAMP', 'PID', 'TID', 'LATENCY_MS', 'ONCPU_MS', 'SW', 'OVERFLOW', 'HITS'
))


def format_stack(pid, user_stack_id, kernel_stack_id):
    stack_traces = b.get_table("stack_traces")
    user_stack_str = ''
    kernel_stack_str = ''
    if user_stack_id > 0:
        user_stack = list(stack_traces.walk(user_stack_id))
        user_stack_str = '>'.join(
            b.sym(addr, pid).decode('utf-8', 'replace') + ':' + hex(addr)
            for addr in reversed(user_stack))

    if kernel_stack_id > 0:
        kernel_stack = list(stack_traces.walk(kernel_stack_id))
        kernel_stack_str = '>'.join(
            b.ksym(addr).decode('utf-8', 'replace')
            for addr in reversed(kernel_stack)
        )
    return kernel_stack_str + '|' + user_stack_str


def callback(cpu, data, size, timefmt="%H:%M:%S.%f"):
    event = ct.cast(data, ct.POINTER(msg_t)).contents
    latency = (event.stop_ns - event.start_ns) / 1000000
    oncpu = event.oncpu_ns / 1000000
    print("%s %7d/%-7d %10.3f %10.3f %8d %8d %4d" % (
        datetime.datetime.fromtimestamp(clocktime(event.start_ns)).strftime(timefmt),
        event.tgid, event.pid,
        latency,
        oncpu,
        event.sw,
        event.overflow,
        event.hits,
    ))
    try:
        command_info_table = b['command_info_table_map'][ct.c_uint32(event.pid)]
    except KeyError:
        # maybe into table is not ready (?)
        return

    for i, (command_info, call_stats) in enumerate(zip(command_info_table.command_info, event.call_stats)):
        if i >= command_info_table.count:
            break

        if call_stats.count == 0:
            continue
        
        print("%16s %6d %10.3f %10.3f" % (
              command_info.name.decode('utf8'),
              call_stats.count,
              call_stats.lat_sum_ns / 1000000,
              call_stats.lat_max_ns / 1000000,))
    
    if sampling:
        for i in range(min(max_samples, event.hits)):
            sample = event.samples[i]
            print(format_stack(event.pid,
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

b["events"].open_perf_buffer(_callback, page_cnt=256)
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
