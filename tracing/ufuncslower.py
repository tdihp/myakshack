#!/usr/bin/python
# -*- coding: utf-8 -*-

"""
Script for identifying root cause of any userspace function slow.

It:

* Discovers program by running process comm
* Collects switch counts
* Optional perf sampling
* Embedded offwaketime

EXAMPLES

* Capture all redis-server process for `call` function for 10 seconds, use
  default settings
$ python3 ufuncslower.py -c redis-server call 10

* Capture given process indefinitely, with 99HZ stack sampling, show first 4
  stack samples, show only calls slower than 10ms 
$ python3 ufuncslower.py -c redis-server -p 12345 -f 99 --max-samples 4 -m 10000 call 

* To identify redis-server cause aofWrite slowness
$ python3 ufuncslower.py -c redis-server --min-lat=50 --min-offcpu-lat=10 aofWrite 

CHANGELOG

2025-01-03 Copied and authored

Copyright (c) 2024, Ping He.
License: MIT
"""
import os
import sys
import time
from datetime import datetime
import threading
from pathlib import Path
import ctypes as ct
import math
from bcc import BPF, PerfType, PerfSWConfig


bpf_text = r'''
#include <uapi/linux/ptrace.h>
#include <uapi/linux/bpf_perf_event.h>
#include <linux/sched.h>

%(EXTRA_MACROS)s

#ifdef TGID
    #define MATCH_TGID (tgid != TGID)
    #define MATCH_TGID_PID (tgid_pid>>32 != TGID)
    #define FILTER_TGID if (MATCH_TGID) return 0
    #define FILTER_TGID_PID if (MATCH_TGID_PID) return 0
#else
    #define MATCH_TGID true
    #define MATCH_TGID_PID true
    #define FILTER_TGID
    #define FILTER_TGID_PID
#endif /* TGID */

BPF_STACK_TRACE(stack_traces, STACK_STORAGE_SIZE);

#ifdef ENABLE_SAMPLING
struct sample_t {
    int user_stack_id;
    int kernel_stack_id;
};
#endif /* ENABLE_SAMPLING */

#ifdef ENABLE_OFFCPU
struct offcpu_entry_t {
    u64 duration_ns;
    char waker_name[TASK_COMM_LEN];
    u32 waker_pid;
    int waker_kernel_stack_id;
    int woken_user_stack_id;
    int woken_kernel_stack_id;
};
#endif /* ENABLE_OFFCPU */
struct state_t {
    u64 start_ns;
    u64 utime;
    u64 stime;
    u32 nvcsw;
    u32 nivcsw;
#ifdef ENABLE_IRQ
    u32 softirq_cnt;
    u32 hardirq_cnt;
#endif /* ENABLE_IRQ */
#ifdef ENABLE_SAMPLING
    u32 hits;
    struct sample_t samples[MAXSAMPLES];
#endif /* ENABLE_SAMPLING */
#ifdef ENABLE_OFFCPU
    /*struct offcpu_entry_t sleeping;*/
    u64 sum_off_time_ns;
    u64 sleep_ns;
    char waker_name[TASK_COMM_LEN];
    u32 off_cnt;
    u32 off_ecnt; /* entries meets criteria, can go over maxentries */
    struct offcpu_entry_t offcpu_entries[MAXENTRIES];
#endif /* ENABLE_OFFCPU */
};

BPF_HASH(statetable, u32, struct state_t);

struct msg_t {
    u64 start_ns;
    u64 stop_ns;
    u64 utime;
    u64 stime;
    u32 nvcsw;
    u32 nivcsw;
    u32 pid;
#ifdef ENABLE_IRQ
    u32 softirq_cnt;
    u32 hardirq_cnt;
#endif /* ENABLE_IRQ */
#ifdef ENABLE_SAMPLING
    u32 hits;
    struct sample_t samples[MAXSAMPLES];
#endif /* ENABLE_SAMPLING */
#ifdef ENABLE_OFFCPU
    u64 sum_off_time_ns;
    u32 off_cnt;
    u32 off_ecnt; /* entries meets criteria, can go over maxentries */
    struct offcpu_entry_t offcpu_entries[MAXENTRIES];
#endif /* ENABLE_OFFCPU */
};

BPF_PERF_OUTPUT(events);

#ifdef ENABLE_IRQ
TRACEPOINT_PROBE(irq, softirq_entry)
{
    u64 tgid_pid = bpf_get_current_pid_tgid();
    FILTER_TGID_PID;
    u32 pid = tgid_pid;
    struct state_t *state = statetable.lookup(&pid);
    if (!state) {
        return 0;
    }
    state->softirq_cnt += 1;
    return 0;
}

TRACEPOINT_PROBE(irq, irq_handler_entry)
{
    u64 tgid_pid = bpf_get_current_pid_tgid();
    FILTER_TGID_PID;
    u32 pid = tgid_pid;
    struct state_t *state = statetable.lookup(&pid);
    if (!state) {
        return 0;
    }
    state->hardirq_cnt += 1;
    return 0;
}
#endif /* ENABLE_IRQ */

#ifdef ENABLE_SAMPLING
int do_perf_event(struct bpf_perf_event_data *ctx) {
    u64 tgid_pid = bpf_get_current_pid_tgid();
    FILTER_TGID_PID;
    u32 pid = tgid_pid;
    struct state_t *state = statetable.lookup(&pid);
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
#endif /* ENABLE_SAMPLING */

#ifdef ENABLE_OFFCPU
/* https://github.com/iovisor/bcc/blob/master/tools/offwaketime.py */
int waker(struct pt_regs *ctx, struct task_struct *p) {
    /* PID and TGID of the target Process to be waken */
    u32 pid = p->pid;
    u32 tgid = p->tgid;

    FILTER_TGID;

    struct state_t *state = state = statetable.lookup(&pid);
    if (!state) {
        return 0;
    }
    if (state->off_ecnt >= MAXENTRIES) {
        return 0;
    }
    struct offcpu_entry_t *entry = &state->offcpu_entries[state->off_ecnt];
    // Construct information about current (the waker) Process
    bpf_get_current_comm(&entry->waker_name, sizeof(entry->waker_name));
    entry->waker_pid = bpf_get_current_pid_tgid();
    entry->waker_kernel_stack_id = stack_traces.get_stackid(ctx, 0);
    return 0;
}

int oncpu(struct pt_regs *ctx, struct task_struct *p) {
    /* PID and TGID of the previous Process (Process going into waiting) */
    u32 pid = p->pid;
    u32 tgid = p->tgid;
    u64 ts = bpf_ktime_get_ns();
    struct state_t *state;
    struct offcpu_entry_t* entry;
    /* Record timestamp for the previous Process (Process going into waiting) */
    if (MATCH_TGID) {
        state = statetable.lookup(&pid);
        if (state) {
            state->sleep_ns = ts;
        }
    }

    /* Record wakeup time */
    u64 tgid_pid = bpf_get_current_pid_tgid();
    FILTER_TGID_PID;
    pid = tgid_pid;
    state = statetable.lookup(&pid);
    if (!state) {
        return 0;
    }
    u64 delta = ts - state->sleep_ns;
    state->sum_off_time_ns += delta;
    state->off_cnt += 1;
    if (delta < MINOFFCPULAT) {
        return 0;
    }
    if (state->off_ecnt < MAXENTRIES) {
        entry = &state->offcpu_entries[state->off_ecnt];
        entry->duration_ns = delta;
        entry->woken_user_stack_id = stack_traces.get_stackid(ctx, BPF_F_USER_STACK);
        entry->woken_kernel_stack_id = stack_traces.get_stackid(ctx, 0);
    }
    state->off_ecnt += 1;
    return 0;
}
#endif /* ENABLE_OFFCPU */

int trace_entry(struct pt_regs *ctx)
{
    u64 tgid_pid = bpf_get_current_pid_tgid();
    FILTER_TGID_PID;
    struct state_t zero = {};
    int pid = tgid_pid;
    struct state_t *state = statetable.lookup_or_try_init(&pid, &zero);
    if (!state) {
        return 0;
    }
    state->start_ns = bpf_ktime_get_ns();
    struct task_struct *task = (void*)bpf_get_current_task();
    state->utime = task->utime;
    state->stime = task->stime;
    state->nvcsw = task->nvcsw;
    state->nivcsw = task->nivcsw;
    return 0;
}

int trace_return(struct pt_regs *ctx)
{
    u64 tgid_pid = bpf_get_current_pid_tgid();
    FILTER_TGID_PID;
    int pid = tgid_pid;
    struct state_t *state = statetable.lookup(&pid);
    if (!state) {
        return 0;
    }
    struct msg_t msg = {};
    msg.start_ns = state->start_ns;
    msg.stop_ns = bpf_ktime_get_ns();
    if ((msg.stop_ns - msg.start_ns) < MINLAT) {
        goto recycle;
    }
    struct task_struct *task = (void*)bpf_get_current_task();
    msg.utime = task->utime - state->utime;
    msg.stime = task->stime - state->stime;
    msg.nvcsw = task->nvcsw - state->nvcsw;
    msg.nivcsw = task->nivcsw - state->nivcsw;
    msg.pid = pid;
#ifdef ENABLE_IRQ
    msg.softirq_cnt = state->softirq_cnt;
    msg.hardirq_cnt = state->hardirq_cnt;
#endif
#ifdef ENABLE_SAMPLING
    msg.hits = state->hits;
    __builtin_memcpy(&msg.samples, &state->samples, sizeof(msg.samples));
#endif /* ENABLE_SAMPLING */
#ifdef ENABLE_OFFCPU
    msg.sum_off_time_ns = state->sum_off_time_ns;
    msg.off_cnt = state->off_cnt;
    msg.off_ecnt = state->off_ecnt;
    __builtin_memcpy(&msg.offcpu_entries,
        &state->offcpu_entries, sizeof(msg.offcpu_entries));
#endif /* ENABLE_OFFCPU */
    events.perf_submit(ctx, &msg, sizeof(msg));
recycle:
    statetable.delete(&pid);
    return 0;
}
'''


def discover_comm(comm):
    """this function find all pids having exact same comm"""
    for p in Path('/proc').iterdir():
        if not p.name.isdigit():
            continue

        try:
            if comm == p.joinpath('comm').read_text().strip('\n'):
                yield int(p.name)
        except FileNotFoundError as e:
            continue


import argparse
parser = argparse.ArgumentParser(
    description=__doc__,
    formatter_class=argparse.RawDescriptionHelpFormatter)
# path discovering
parser.add_argument('--binary-path', type=Path,
                    help='binary path to use. When absolute path given, the '
                         'path is directly used for uprobe symbol discovery; '
                         'when relative path given, "/proc/<pid>/root/" will '
                         'be prefixed automatically; by default it uses '
                         '`readlink -f /proc/<pid>/exe` under /proc/<pid>/root')
parser.add_argument('-p', '--pid', type=int,
                    help='pid for tracing, by default all processes are'
                         'triggered, noting in that case the first '
                         'redis-server process will be used for uprobe symtom')
parser.add_argument('-c', '--comm', help='search all process with this comm')
# irq
parser.add_argument('--irq', action='store_true', help='enable irq counting')
# samping
parser.add_argument('-f', '--frequency', type=int,
                    help='enable sampling with frequency')
parser.add_argument('--max-samples', type=int, default=2,
                    help='max samples when sampling is enabled. 2 by default')
# offcpu
parser.add_argument('--min-offcpu-lat', default=-1, type=int,
                    help='min latency displaying offcpu kernel stacks in '
                        'microseconds (us), by default offcpu not enabled')
parser.add_argument('--max-entries', default=2, type=int,
                    help='offcpu stack entries. 2 by default')
# rigid feature
parser.add_argument('-m', '--min-lat', default=1000, type=int,
                    help='min latency to display in microseconds (us), default '
                    'to 1000us (1ms)')
parser.add_argument('--stack-storage-size', default=16384, type=int,
                    help='stack storage size used in stack sampling, default '
                         'to 16384')
parser.add_argument('func', help='function to trace')
parser.add_argument('duration', type=int, nargs='?',
                     help='capture duration in seconds, use keyboard '
                          'interrput when not specified')
args = parser.parse_args()

extra_defs = {
    'MINLAT': args.min_lat * 1000,
    'STACK_STORAGE_SIZE': args.stack_storage_size,
    'MAXSAMPLES': args.max_samples,
}


# seeking binary path
absolute_binary_path = None
uprobe_pid = None
if args.pid:
    extra_defs['TGID'] = str(args.pid)
    uprobe_pid = args.pid

if args.binary_path and args.binary_path.is_absolute():
    absolute_binary_path = args.binary_path

if not absolute_binary_path:
    print('discovering absolute binary path', file=sys.stderr)
    if not uprobe_pid and args.comm:
        try:
            uprobe_pid = next(discover_comm(args.comm))
        except StopIteration:
            parser.exit('when discovering pid with comm, '
                        f'no proc with comm {args.comm} found.')

    if not uprobe_pid:
        parser.error('no uprobe_pid to discover absolute binary path')

    print(f'using pid {uprobe_pid} for uprobe', file=sys.stderr)
    proc = Path(f'/proc/{uprobe_pid}')
    if not proc.exists():
        parser.error(f'specified pid {uprobe_pid} not exist, '
                     'needed for binary path')

    exepath = Path(os.readlink('/proc/%d/exe' % uprobe_pid)).relative_to('/')
    binary_path = args.binary_path or exepath
    absolute_binary_path = proc / 'root' / binary_path

if not absolute_binary_path:
    parser.error('not able to identify absolute binary path')

print(f'absolute binary path: {absolute_binary_path}', file=sys.stderr)

if not Path(absolute_binary_path).exists():
    parser.exit('specified absolute binary path not found')

# irq
if args.irq:
    extra_defs['ENABLE_IRQ'] = ''

# samping
if args.frequency:
    extra_defs['ENABLE_SAMPLING'] = ''
    extra_defs['MAXSAMPLES'] = args.max_samples

# offcpu
if args.min_offcpu_lat >= 0:
    extra_defs['ENABLE_OFFCPU'] = ''
    extra_defs['MINOFFCPULAT'] = args.min_offcpu_lat * 1000
    extra_defs['MAXENTRIES'] = args.max_entries

bpf_text_rendered = bpf_text % {'EXTRA_MACROS': '\n'.join('#define %s %s' % pair for pair in extra_defs.items())}


class sample_t(ct.Structure):
    _fields_ = [
        ('user_stack_id',   ct.c_int),
        ('kernel_stack_id', ct.c_int),
    ]

class offcpu_entry_t(ct.Structure):
    _fields_ = [
        ('duration_ns',             ct.c_uint64),
        ('waker_name',              ct.c_char * 16),
        ('waker_pid',               ct.c_uint32),
        ('waker_kernel_stack_id',   ct.c_int),
        ('woken_user_stack_id',     ct.c_int),
        ('woken_kernel_stack_id',   ct.c_int),
    ]

def build_msg_t(defs):
    fields = [
        ('start_ns',    ct.c_uint64),
        ('stop_ns',     ct.c_uint64),
        ('utime',       ct.c_uint64),
        ('stime',       ct.c_uint64),
        ('nvcsw',       ct.c_uint32),
        ('nivcsw',      ct.c_uint32),
        ('pid',         ct.c_uint32)
    ]
# print("%15s %7s/%-7s %10s %5s %5s %5s %5s %3s" % (
#     'TIMESTAMP', 'PID', 'TID', 'LATENCY_MS', 'SW', 'ISW', 'SOFT', 'HARD', 'HIT',
# ))
    template = '{timestamp:<15} {pid:>7} {latms:>5.0f} {utimems:>5.0f} {stimems:>5.0f} {nvcsw:>3d} {nivcsw:>3d}'
    headers = 'TIMESTAMP           PID LATMS  USER   SYS  SW ISW'
    if 'ENABLE_IRQ' in defs:
        fields.extend([
            ('softirq_cnt', ct.c_uint32),
            ('hardirq_cnt', ct.c_uint32),
        ])
        template += ' {softirq_cnt:>3d} {hardirq_cnt:>3d}'
        headers += ' SRQ IRQ'

    if 'ENABLE_SAMPLING' in defs:
        fields.extend([
            ('hits', ct.c_uint32),
            ('samples', sample_t * defs['MAXSAMPLES'])
        ])
        template += ' {hits:>3d}'
        headers += ' HIT'
        sample_digits = int(math.log10(defs['MAXSAMPLES'])) + 1
        # "SAMPLE01: <KERNEL>|<USR>"
        sample_template = f'SAMPLE{{:0{sample_digits}d}}: ' '{}|{}'

    if 'ENABLE_OFFCPU' in defs:
        fields.extend([
            ('sum_off_time_ns', ct.c_uint64),
            ('off_cnt',         ct.c_uint32),
            ('off_ecnt',        ct.c_uint32),
            ('offcpu_entries',  offcpu_entry_t * defs['MAXENTRIES']),
        ])
        template += ' {off_ecnt:>3d} {sum_off_time_ms:>5.0f}'
        headers += ' OEC OCLAT'
        entry_digits = int(math.log10(defs['MAXENTRIES'])) + 1
        # "ENTRY01: <LATENCY> <PID>-<COMM> <KERNEL> >> <KERNEL>|<USR>"
        entry_template = f'ENTRY{{:0{entry_digits}d}}: ' '{:>7}-{:<16} {} >> {}|{}'

    class msg_t(ct.Structure):
        _fields_ = fields
        def getlines(self):
            lines = [template.format(**self.translate())]
            if 'ENABLE_SAMPLING' in defs:
                for i in range(min(defs['MAXSAMPLES'], self.hits)):
                    sample = self.samples[i]
                    lines.append(
                        sample_template.format(
                            i,
                            format_ustack(self.pid, sample.user_stack_id),
                            format_kstack(sample.kernel_stack_id),
                        )
                    )
            if 'ENABLE_OFFCPU' in defs:
                for i in range(min(defs['MAXENTRIES'], self.off_ecnt)):
                    entry = self.offcpu_entries[i]
                    lines.append(
                        entry_template.format(
                            i,
                            entry.waker_pid,
                            entry.waker_name.decode('utf-8', 'replace'),
                            format_kstack(entry.waker_kernel_stack_id),
                            format_ustack(self.pid, entry.woken_user_stack_id),
                            format_kstack(entry.woken_kernel_stack_id),
                        )
                    )
            return lines

        @staticmethod
        def get_headers():
            return headers

        def translate(self, timefmt="%H:%M:%S.%f"):
            """return a dict able to be used in format"""
            d = dict((k, getattr(self, k)) for k, _ in self._fields_)
            dt = datetime.fromtimestamp(clocktime(d['stop_ns']))
            d.update({
                'timestamp': dt.strftime(timefmt),
                'latms': (d['stop_ns'] - d['start_ns']) / 1e6,
                'utimems': d['utime'] / 1e6,
                'stimems': d['stime'] / 1e6,
            })
            if 'ENABLE_OFFCPU' in defs:
                d.update({
                    'sum_off_time_ms': d['sum_off_time_ns'] / 1e6
                })
            return d

    return msg_t


msg_t = build_msg_t(extra_defs)

b = BPF(text=bpf_text_rendered)
first_ts = BPF.monotonic_time()
first_ts_real = time.time()

def reltime(ts_ns):
    return 1e-9 * (ts_ns - first_ts)


def clocktime(ts_ns):
    return reltime(ts_ns) + first_ts_real

library=str(absolute_binary_path)

b.attach_uprobe(name=library, sym=args.func, fn_name="trace_entry")
b.attach_uretprobe(name=library, sym=args.func, fn_name="trace_return")

if args.frequency:
    b.attach_perf_event(ev_type=PerfType.SOFTWARE,
        ev_config=PerfSWConfig.CPU_CLOCK, fn_name="do_perf_event",
        sample_freq=args.frequency)

if args.min_offcpu_lat >= 0:
    b.attach_kprobe(event_re=r'^finish_task_switch$|^finish_task_switch\.isra\.\d$',
                    fn_name="oncpu")
    b.attach_kprobe(event="try_to_wake_up", fn_name="waker")


def stack2str(stackid, resolve):
    if stackid <= 0:
        return ''
    stack_traces = b.get_table("stack_traces")
    return '>'.join(reversed(list(stack_traces.walk(stackid, resolve=resolve))))


def format_ustack(pid, user_stack_id):
    def resolve(addr):
        return b.sym(addr, pid).decode('utf-8', 'replace') + ':' + hex(addr)

    return stack2str(user_stack_id, resolve)


def format_kstack(kernel_stack_id):
    def resolve(addr):
        return b.ksym(addr).decode('utf-8', 'replace') + ':' + hex(addr)

    return stack2str(kernel_stack_id, resolve)


print(msg_t.get_headers())


def callback(cpu, data, size, timefmt="%H:%M:%S.%f"):
    # event = b["events"].event(data)
    event = ct.cast(data, ct.POINTER(msg_t)).contents
    for line in event.getlines():
        print(line)


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
