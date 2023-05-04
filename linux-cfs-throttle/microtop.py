"""This script prints runtime per pid, with waker/woken kernel callstack
for each cfs bandwidth refill. This currently only works on Linux 5.4, the goal
is to aid investigation of CPU throttling in k8s similar to
https://github.com/kubernetes/kubernetes/issues/97445, under assumption that
microscopic CPU spikes under 100ms can trigger throttling.

This needs a minimized Linux 5.4 kernel/sched/sched.h to function. A copy
should be named sched.5.4.h neighboring this script.

Examples:

Filter by container, display last 3 cycles when this cycle is lower than 50%
of quota:
 microtop.py --container <container-id> --lead-cycles 2 --min-remaining-perc 50

Dump everything in csv files:
 microtop.py --csv-path ./output

Copyright (c) 2023, Ping He.
License: MIT
"""


import time
import datetime
import argparse
from pathlib import Path
from functools import partial
import threading
from bcc import BPF
from fractions import Fraction

MSGTYPE = ['', 'ACCOUNT', 'RETURN']
CGROUP_PATH='/sys/fs/cgroup/cpu,cpuacct/kubepods'

# define BPF program
bpf_text = r'''
/* hack: this makes container_of work */
#define BUILD_BUG_ON_MSG(cond, msg)

BPF_STACK_TRACE(stack_traces, 65536);

/* arrays are zero filled, no need to initialize */
BPF_HASH(cycle_counter, u32, u32, 4096);

static inline u32 cycle_counter_get(u32 key) {
    u32 one = 1; /* we init counter as 1 so we can use 0 as invalid value */
    u32 *cycle_p = cycle_counter.lookup_or_try_init(&key, &one);
    if (!cycle_p) {
        return 0;
    }
    return *cycle_p;
}

static inline u32 cycle_counter_increment(u32 key) {
    u32 one = 1; /* we init counter as 1 so we can use 0 as invalid value */
    u32* cycle_p = cycle_counter.lookup_or_try_init(&key, &one);
    if (!cycle_p) {
        return 0;
    }
    (*cycle_p)++;
    return *cycle_p;
}

struct pid_stack_info_t {
    int waker_stackid;
    int woken_stackid;
};

BPF_HASH(pid_stack_map, u32, struct pid_stack_info_t, 65536);
struct stats_key_t {
    u32 cgroup_ino; /* inode of cpu cgroup */
    u32 cycle;      /* monotonic cycle for refill */
    u32 pid;
    int waker_stackid;
    int woken_stackid;
};

struct stats_t {
    /* u64 first_wakeup; */
    /* u64 last_wakeup; */
    u64 update_time;    /* only used for maintenance */
    u64 total_runtime;
    /* u32 wakeup_count; */
    u32 runtime_count;
    char comm[TASK_COMM_LEN];
};

/* we hope 64k is sufficient for saving at least 3~5 cycles */
BPF_HASH(stats_map, struct stats_key_t, struct stats_t, 65536);
struct msg_t {
    u32 cgroup_ino;
    u32 cycle;
    u64 ts_ns;
    u64 cfs_b_runtime;
    u64 cfs_b_quota;
};

BPF_PERF_OUTPUT(events);

static inline bool filter_cgroup(u32 cgroup_ino) {
#ifdef FILTER_CGROUP_INO
    return cgroup_ino == FILTER_CGROUP_INO;
#else
    return 1;
#endif
}

static inline bool filter_bandwidth_basic(struct cfs_bandwidth *cfs_b) {
    u64 quota = cfs_b->quota;
    if (cfs_b->quota == RUNTIME_INF) { /* never record if the cfs_b doesn't have quota */
        return 0;
    }
    return 1;
}

static inline bool filter_bandwidth_timer(struct cfs_bandwidth *cfs_b) {
    if (!filter_bandwidth_basic(cfs_b)) {
        return 0;
    }
    u64 runtime = cfs_b->runtime;
#ifdef FILTER_BW_MIN_RUNTIME
    if (runtime >= FILTER_BW_MIN_RUNTIME) {
        return 0;
    }
#endif
#ifdef FILTER_BW_N
    u64 quota = cfs_b->quota;
    /* runtime >= quota * (n/d) --> d*runtime >= n*quota */
    if (runtime * FILTER_BW_D >= quota * FILTER_BW_N) {
        return 0;
    }
#endif
    return 1;
}

static inline void dbg(struct pt_regs *ctx, u64 val) {
    struct msg_t msg = {};
    msg.cgroup_ino = 999;
    msg.cycle = val;
    msg.ts_ns = bpf_ktime_get_ns();
    msg.cfs_b_runtime = val;
    events.perf_submit(ctx, &msg, sizeof(msg));
}

int kprobe__sched_cfs_period_timer(struct pt_regs *ctx, struct hrtimer *timer)
{
    struct cfs_bandwidth *cfs_b =
        container_of(timer, struct cfs_bandwidth, period_timer);
    struct task_group *tg = 
        container_of(cfs_b, struct task_group, cfs_bandwidth);
    u32 cgroup_ino = tg->css.cgroup->kn->id.ino;
    if (!filter_cgroup(cgroup_ino)) {
        return 0;
    }
    if (!filter_bandwidth_timer(cfs_b)) {
        return 0;
    }
    u32 cycle = cycle_counter_increment(cgroup_ino);
    if (!cycle) {
        return 0;
    }
    struct msg_t msg = {};
    msg.cgroup_ino = cgroup_ino;
    msg.cycle = cycle;
    msg.ts_ns = bpf_ktime_get_ns();
    msg.cfs_b_runtime = cfs_b->runtime;
    msg.cfs_b_quota = cfs_b->quota;
    events.perf_submit(ctx, &msg, sizeof(msg));
    return 0;
}

int waker(struct pt_regs *ctx, struct task_struct *p) {
    /* we cannot filter by cgroup for the waker
    struct task_group *tg = p->sched_task_group;
    u32 cgroup_ino = tg->css.cgroup->kn->id.ino;
    if (!filter_cgroup(cgroup_ino)) {
        return 0;
    }
    struct cfs_bandwidth *cfs_b = &tg->cfs_bandwidth;
    if (!filter_bandwidth_basic(cfs_b)) {
        return 0;
    }
    */
    u32 pid = p->pid;
    struct pid_stack_info_t zero = {};
    struct pid_stack_info_t *stack_info = pid_stack_map.lookup_or_try_init(&pid, &zero);
    if (!stack_info) {
        return 0;
    }
    stack_info->waker_stackid = stack_traces.get_stackid(ctx, 0);
}

int oncpu(struct pt_regs *ctx, struct task_struct *prev) {
    struct task_struct *p = (struct task_struct *)bpf_get_current_task();
    struct task_group *tg = p->sched_task_group;
    u32 cgroup_ino = tg->css.cgroup->kn->id.ino;
    u32 pid = p->pid;
    struct pid_stack_info_t *stack_info = pid_stack_map.lookup(&pid);
    if (!stack_info) {
        return 0;
    }
    if (!filter_cgroup(cgroup_ino)) {
        goto recycle;
    }
    struct cfs_bandwidth *cfs_b = &tg->cfs_bandwidth;
    if (!filter_bandwidth_basic(cfs_b)) {
        goto recycle;
    }
    /* we can safely assume it is initiated before */
    stack_info->woken_stackid = stack_traces.get_stackid(ctx, 0);
    return 0;
recycle:
    /* we only recycle those not in concern, hoping app uses thread pool */
    pid_stack_map.delete(&pid);
    return 0;
}


static inline int account(struct pt_regs *ctx,
                          struct task_group *tg,
                          struct task_struct *p,
                          u64 delta_exec)
{
    u32 cgroup_ino = tg->css.cgroup->kn->id.ino;
    if (!filter_cgroup(cgroup_ino)) {
        return 0;
    }
    struct cfs_bandwidth *cfs_b = &tg->cfs_bandwidth;
    if (!filter_bandwidth_basic(cfs_b)) {
        return 0;
    }
}


RAW_TRACEPOINT_PROBE(sched_stat_runtime) {
    struct task_struct *p = (struct task_struct *)ctx->args[0];
    struct task_group *tg = p->sched_task_group;
// int kprobe____account_cfs_rq_runtime(struct pt_regs *ctx, struct cfs_rq *cfs_rq, u64 delta_exec) {
//     if (!cfs_rq->runtime_enabled) {
//         return 0;
//     }
//     if (!delta_exec) {
//         return 0;
//     }
//     struct task_group *tg = cfs_rq->tg;
    u32 cgroup_ino = tg->css.cgroup->kn->id.ino;
    if (!filter_cgroup(cgroup_ino)) {
        return 0;
    }
    struct cfs_bandwidth *cfs_b = &tg->cfs_bandwidth;
    if (!filter_bandwidth_basic(cfs_b)) {
        return 0;
    }
    // dbg(ctx, 888);
    u64 delta_exec = ctx->args[1];
    u32 pid = p->pid;
    int waker_stackid = -2; /* ENOENT */
    int woken_stackid = -2;
    struct pid_stack_info_t *stack_info_p = pid_stack_map.lookup(&pid);
    if (stack_info_p) {
        waker_stackid = stack_info_p->waker_stackid;
        woken_stackid = stack_info_p->woken_stackid;
    }
    u32 cycle = cycle_counter_get(cgroup_ino);
    if (!cycle) {
        return 0;
    }
    struct stats_key_t stats_key = {};
    stats_key.cgroup_ino = cgroup_ino;
    stats_key.cycle = cycle_counter_get(cgroup_ino);
    stats_key.pid = pid;
    stats_key.waker_stackid = waker_stackid;
    stats_key.woken_stackid = woken_stackid;
    struct stats_t zero = {};
    struct stats_t *stats = stats_map.lookup_or_try_init(&stats_key, &zero);
    if (!stats) {
        return 0;
    }
    stats->update_time = bpf_ktime_get_ns();
    if (stats->runtime_count == 0) {
        bpf_probe_read_kernel_str(&stats->comm, sizeof(stats->comm), &p->comm);
    }
    stats->total_runtime += delta_exec;
    // stats->runtime_count++;
}
'''

parser = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter)
ino_group = parser.add_mutually_exclusive_group()
ino_group.add_argument('--cgroup-ino', type=int,
                       help='filter by inode of cpu,cpuacct cgroup',
                       )
ino_group.add_argument('--k8s-container', help='filter by container ID')
thresh_group = parser.add_mutually_exclusive_group()
thresh_group.add_argument('--min-remaining-ms', type=int,
                          help='only trigger output when remaining credit lower than specified value')
thresh_group.add_argument('--min-remaining-perc', type=int,
                          help='only trigger output when remaining credit lower than percentage of quota')
parser.add_argument('--period', type=int,
                    help='capture period in seconds, default to forever')
parser.add_argument('--lead-cycles', type=int, default=0,
                    help='print additional previous cycles on a busy cycle')
parser.add_argument('--csv-path', type=Path,
                    help='outputs with csv mode on separate files, '
                         'this changes the default output behavior. '
                         '3 files will be written: '
                         '<path>/microtop.cycle.csv, '
                         '<path>/microtop.proc.csv, '
                         '<path>/microtop.stack.csv.')
parser.add_argument('--csv-no-header', action='store_true',
                    help='do not write csv header when in csv mode')
parser.add_argument('--bpf', action='store_true', help='print bpf code')
args = parser.parse_args()
extra_macros = []

lead_cycles = args.lead_cycles
if lead_cycles < 0:
    raise ValueError('lead_cycles(%s) < 0' % lead_cycles)

if args.cgroup_ino:
    extra_macros.append('#define FILTER_CGROUP_INO %d' % args.cgroup_ino)
elif args.k8s_container:
    try:
        found = next(Path(CGROUP_PATH).glob('**/' + args.k8s_container))
    except Exception as e:
        raise FileNotFoundError("cgroup file for k8s_container %s doesn't exist" % args.k8s_container) from e
    cgroup_ino = found.stat().st_ino
    extra_macros.append('#define FILTER_CGROUP_INO %d' % cgroup_ino)

if args.min_remaining_ms:
    extra_macros.append('#define FILTER_BW_MIN_RUNTIME %d' % (args.min_remaining_ms * 1000000))
elif args.min_remaining_perc:
    #XXX: validation
    f = Fraction(args.min_remaining_perc, 100)
    extra_macros.append('#define FILTER_BW_N %d' % f.numerator)
    extra_macros.append('#define FILTER_BW_D %d' % f.denominator)

# initialize BPF
header = Path(__file__).parent.joinpath('sched.5.4.h').read_text()
src = header + '\n'.join(extra_macros) + bpf_text
if args.bpf:
    print(src)
b = BPF(text=src)
b.attach_kprobe(event="try_to_wake_up", fn_name="waker")
b.attach_kprobe(event_re="^finish_task_switch$|^finish_task_switch\.isra\.\d$",
                fn_name="oncpu")  # copied from tools/offwaketime.py
first_ts = BPF.monotonic_time()
first_ts_real = time.time()


def reltime(ts_ns):
    return 1e-9 * (ts_ns - first_ts)


def clocktime(ts_ns):
    return reltime(ts_ns) + first_ts_real

TIMEFMT_TEXT = "%H:%M:%S.%f"
TIMEFMT_CSV = "%Y-%m-%d %H:%M:%S.%f"
CYCLE_FMT_TEXT = '%s ino=%-6d cyc=%-7d runtime=%-9d quota=%-9d'
CYCLE_FMT_CSV = '%s,%d,%d,%d,%d'
PROC_FMT_TEXT = ' ' * 25 + '> ino=%-6d cyc=%-7d pid=%-9d comm=%-16s waker=%-6d woken=%-6d runtime=%-9d count=%-5d'
PROC_FMT_CSV = '%d,%d,%d,%s,%d,%d,%d,%d'
STACK_FMT_TEXT = ' ' * 24 + '>> stackid %6d: %s'
STACK_FMT_CSV = '%d,%s'
STACK_SPLITTER_TEXT = '\n' + ' ' * 43
STACK_SPLITTER_CSV = '>'


def format_cycle_text(msg, f=None, timefmt=TIMEFMT_TEXT, fmt=CYCLE_FMT_TEXT):
    print(fmt % 
          (datetime.datetime.fromtimestamp(clocktime(msg.ts_ns)).strftime(timefmt),
           msg.cgroup_ino,
           msg.cycle,
           msg.cfs_b_runtime,
           msg.cfs_b_quota,
          ), file=f)


def format_proc_text(k, v, f=None, fmt=PROC_FMT_TEXT):
    print(fmt % (
        k.cgroup_ino, k.cycle, k.pid, v.comm.decode(), k.waker_stackid, 
        k.woken_stackid, v.total_runtime, v.runtime_count
    ), file=f)


def format_stack_text(stack_traces, stackid, f=None, fmt=STACK_FMT_TEXT,
                      splitter=STACK_SPLITTER_TEXT):
    try:
        stackstr = splitter.join((b.ksym(addr).decode('utf-8'))
                                for addr in stack_traces.walk(stackid))
    except Exception as e:
        stackstr = 'error:' + str(e)
    print(fmt % (stackid, stackstr), file=f)


seen_cycles = {}
seen_stacks = set()

def callback(cpu, data, size,
             timefmt="%Y-%m-%d %H:%M:%S.%f",
             lead_cycles=0,
             keep_secs=3,  # make sure lead_cycles * cfs_b period doesn't go over this
             format_cycle=format_cycle_text,
             format_proc=format_proc_text,
             format_stack=format_stack_text,
             unique_stacks=False,
             ):
    global seen_stacks
    msg = b["events"].event(data)
    cgroup_ino = msg.cgroup_ino
    cycle = msg.cycle - 1
    format_cycle(msg)
    keep_since = msg.ts_ns - keep_secs * 1000000000
    min_cycle = cycle - lead_cycles
    min_cycle = max(min_cycle, seen_cycles.get(cgroup_ino, min_cycle))
    seen_cycles[cgroup_ino] = cycle
    stats_map = b['stats_map']
    items = list(stats_map.items())
    matches = [(k, v) for k, v in items
               if k.cgroup_ino == cgroup_ino and min_cycle <= k.cycle <= cycle]
    matches = sorted(matches, key=lambda x: (x[0].cycle, x[0].pid, x[1].total_runtime))
    for k, v in matches:
        format_proc(k, v)

    waker_stacks = set(k.waker_stackid for k, v in matches if k.waker_stackid >= 0)
    woken_stacks = set(k.woken_stackid for k, v in matches if k.woken_stackid >= 0)

    stacks = (waker_stacks | woken_stacks) - seen_stacks
    stack_traces = b['stack_traces']
    for stackid in sorted(stacks):
        format_stack(stack_traces, stackid)

    if unique_stacks:
        seen_stacks |= stacks

    to_delete = [k for k, v in items if v.update_time<keep_since]
    for k in to_delete:
        del stats_map[k]


events_callback = partial(callback, lead_cycles=lead_cycles)

if args.csv_path:
    csv_path = args.csv_path
    csv_path.mkdir(parents=True, exist_ok=True) 
    cycle_f = Path(csv_path, 'microtop.cycle.csv').open('w')
    proc_f = Path(csv_path, 'microtop.proc.csv').open('w')
    stack_f = Path(csv_path, 'microtop.stack.csv').open('w')
    if not args.csv_no_header:
        print('timestamp,ino,cyc,runtime,quota', file=cycle_f)
        print('ino,cyc,pid,waker,woken,runtime,count', file=proc_f)
        print('stackid,stack', file=stack_f)

    events_callback = partial(callback,
                              lead_cycles=lead_cycles,
                              unique_stacks=True,
                              format_cycle=partial(format_cycle_text, f=cycle_f,
                                                   timefmt=TIMEFMT_CSV,
                                                   fmt=CYCLE_FMT_CSV),
                              format_proc=partial(format_proc_text, f=proc_f,
                                                  fmt=PROC_FMT_CSV),
                              format_stack=partial(format_stack_text, f=stack_f,
                                                   fmt=STACK_FMT_CSV,
                                                   splitter=STACK_SPLITTER_CSV))

b["events"].open_perf_buffer(events_callback, page_cnt=1024 * 16)
running = 1
def on_period():
    global running
    running = 0

if args.period:
    t = threading.Timer(args.period, on_period)
    t.daemon = True
    t.start()

while running:
    try:
        b.perf_buffer_poll(timeout=1)
        time.sleep(.005)
    except KeyboardInterrupt:
        exit()
