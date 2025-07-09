#!/usr/bin/python
# -*- coding: utf-8 -*-

"""
Tracing script that snoops LSM hook activities, inspired by
https://github.com/cilium/pwru and https://github.com/lumontec/lsmtrace

EXAMPLES:

* Capture all security evaluations for 10 seconds, for any security failures
$ python3 lsmsnoop.py -f -t 10 --found-level=security

* Capture indefinitely for a given pid
$ python3 lsmsnoop.py -p 1234

* Capture only functions relevant to settime for syscall clock_settime, with
  detailed btf data
$ python3 lsmsnoop.py -s clock_settime --hook-func settime --security-func settime -d

CHANGELOG

2025-07-08 Initial script
2025-07-09 add --found-level

Copyright (c) 2025, Ping He.
License: MIT
"""

import time
from bcc import BPF
import os
import re
from datetime import datetime
import subprocess
import json
import ctypes as ct
import resource
import logging
import threading
import errno
import heapq

from bcc.syscall import syscalls, syscall_name
logger = logging.getLogger()


def get_btf():
    proc = subprocess.run(
        ["bpftool", "btf", "dump", "file", "/sys/kernel/btf/vmlinux", "-j"],
        check=True, capture_output=True, text=True)
    return dict((d['id'], d) for d in json.loads(proc.stdout)['types'])


def btf_deref_type(btf, type_id):
    t = btf[type_id]
    if(t['kind'] != 'PTR'):
        return 0

    try:
        t = btf[t['type_id']]
        if(t['kind'] == 'CONST'):
            t = btf[t['type_id']]

        if t['kind'] == 'STRUCT':
            return t['id']
    except KeyError:
        return 0
    return 0

def find_all_security_hook_defs(btf):
    security_list_options = next(
        d for d in btf.values()
        if d['name'] == 'security_list_options'
        and d['kind'] == 'UNION'
    )
    func2proto = dict((d['id'], d['type_id'])
                      for d in btf.values() if d['kind'] == 'FUNC')
    proto2funcs = dict()
    for fid, pid in func2proto.items():
        proto2funcs.setdefault(pid, [])
        proto2funcs[pid].append(fid)

    key2hooks = {}
    func_key = lambda func: (func['ret_type_id'],
                             tuple(p['type_id'] for p in func['params']))
    # func_key = lambda func: (func['id'])

    for h in security_list_options['members']:
        ptr = btf[h['type_id']]
        assert ptr['kind'] == 'PTR'
        func = btf[ptr['type_id']]
        assert func['kind'] == 'FUNC_PROTO'
        hook_k = func_key(func)

        key2hooks.setdefault(hook_k, [])
        key2hooks[hook_k].append(h['name'])

    for pid, fids in proto2funcs.items():
        fkey = func_key(btf[pid])
        if fkey in key2hooks:
            for fid in fids:
                f = btf[fid]
                fname = f['name']
                if fname.startswith('security_'):
                    continue

                if fname.startswith('_'):
                    continue

                for hook_name in key2hooks[fkey]:
                    if fname.endswith(hook_name) and fname != hook_name:
                        logger.info("found hook %s func %s", hook_name, fname)
                        yield (fname, fid) + fkey
                        break


def find_all_security_funcs(btf):
    KNOWN_EXCEPTIONS = {'security_add_hooks', 'security_init'}
    for d in btf.values():
        if d['kind'] != 'FUNC':
            continue

        if not d['name'].startswith('security_'):
            continue

        if d['name'] in KNOWN_EXCEPTIONS:
            continue

        ft = btf[d['type_id']]
        assert ft['kind'] == 'FUNC_PROTO'
        yield (
            d['name'], d['id'], ft['ret_type_id'],
            [p['type_id'] for p in ft['params']]
        )

bpf_text = r'''
#include <uapi/linux/ptrace.h>
#include <uapi/linux/bpf_perf_event.h>
/* For older versions of bcc/libbpf, supports up to PT_REGS_PARM5 */
#ifndef MAX_PT_REGS_ARGS
#error "must define MAX_PT_REGS_ARGS"
#endif
#ifndef MAX_SYSCALL_ARGS
#error "must define MAX_SYSCALL_ARGS"
#endif
#ifndef MAX_ARGS
#error "must define MAX_ARGS"
#endif
#if MAX_ARGS < MAX_SYSCALL_ARGS || MAX_ARGS < MAX_PT_REGS_ARGS
#error "MAX_ARGS too small"
#endif
#ifndef ARG_BTF_BYTES
#error "must define ARG_BTF_BYTES"
#endif
#ifndef TRACE_BYTES
#error "must define TRACE_BYTES"
#endif

#ifndef FILTER_SYSCALL_NR
#define FILTER_SYSCALL_NR(id)
#endif
#ifndef FILTER_PID
#define FILTER_PID(pid)
#endif


/* GONE means for any reason we no longer track this syscall anymore.
 * Some syscalls, such as execve, never return on a successful run, others like
 * poll will be pending for a while, none are useful for our situation.
 * We may want to extend this in future so we won't keep everything until
 * syscall complete.
 */
#define TYPEMASK_LEVEL      3

#define TYPE_SYSCALL        1
#define TYPE_SECURITY       2
#define TYPE_HOOK           3

#define TYPEMASK_DIR        3<<2

#define TYPE_ENTER          1<<2
#define TYPE_EXIT           2<<2

#define TYPE_TRACE          255

#define COUNTER_SYSCALL     0
#define COUNTER_SECURITY    1

BPF_PERCPU_ARRAY(counters_arr, u32, 4);

/* gets a 64 bit unique call id */
static inline u64 counters_inc(unsigned key) {
    u64 result = bpf_get_smp_processor_id() << 32;
    // u64 result = CUR_CPU_IDENTIFIER << 32;
    u32 *count_p = counters_arr.lookup(&key);
    if (!count_p)
        return 0;
    (*count_p) += 1;
    result |= *count_p;
    return result;
}

struct ctx_t {
    u64 ctx_id;
    u64 time;
    u64 id;  /* syscall id or btf FUNC id */
    unsigned long long args[MAX_ARGS];
};

struct ctx_stack_t {
    struct ctx_t levels[3];
};

struct msg_t {
    u32 type;
    u32 reserved;
    u64 time;
    u32 tgid;
    u32 pid;
    u32 gid;
    u32 uid;
    char comm[TASK_COMM_LEN];
    struct ctx_stack_t ctx_stack;
    int retval;
    union {
        char args_btf_detail[MAX_PT_REGS_ARGS][ARG_BTF_BYTES];
        char text[TRACE_BYTES];
    };
};

BPF_PERCPU_ARRAY(scratch_arr, struct msg_t, 1);

static inline struct msg_t *get_scratch() {
    int key = 0;
    return scratch_arr.lookup(&key);
}

BPF_PERF_OUTPUT(events);

static inline void fill_msg(struct msg_t *msg) {
    if (!msg) return;
    msg->time = bpf_ktime_get_ns();
    u64 pid_tgid = bpf_get_current_pid_tgid();
    msg->tgid = pid_tgid >> 32;
    msg->pid = (u32)pid_tgid;
    u64 uid_gid = bpf_get_current_uid_gid();
    msg->gid = uid_gid >> 32;
    msg->uid = (u32)uid_gid;
    bpf_get_current_comm(&msg->comm, sizeof(msg->comm));
}

BPF_PERCPU_ARRAY(tracefmt, struct msg_t, 1);

static inline void trace(void *ctx, const char *text) {
    struct msg_t *msg = get_scratch();
    if (!msg)
        return;
    msg->type = TYPE_TRACE;
    fill_msg(msg);
    if (!text)
        return;
    for (u32 i = 0; i < TRACE_BYTES; i++) {
        msg->text[i] = text[i];
        if (!text[i])
            break;
    }
    events.perf_submit(ctx, msg, sizeof(*msg));
}

/* pid to syscall detail */

BPF_HASH(ctxstack, u32, struct ctx_stack_t, 65536);

static inline struct ctx_stack_t *get_context(u32 pid) {
    struct ctx_stack_t zero = {};
    return ctxstack.lookup_or_try_init(&pid, &zero);
}

static inline void fill_context(struct ctx_t *ctx_p, int level, u32 id) {
    ctx_p->ctx_id = counters_inc(level);
    ctx_p->time = bpf_ktime_get_ns();
    ctx_p->id = id;
    /* we expect external to fill ctx */
}

TRACEPOINT_PROBE(raw_syscalls, sys_enter) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 tgid = pid_tgid >> 32;
    u32 pid = (u32)pid_tgid;
FILTER_SYSCALL_NR(args->id);
FILTER_PID(tgid);
    struct ctx_stack_t stack = {};
    struct ctx_t* ctx_p = &stack.levels[0];
    fill_context(ctx_p, 0, args->id);
    /* we copy all args without verifying how many */
    for (unsigned i = 0; i < MAX_SYSCALL_ARGS; i++) {
        ctx_p->args[i] = args->args[i];
    }
    ctxstack.update(&pid, &stack);

#ifdef SEND_SYSCALL_ENTER
    struct msg_t *msg = get_scratch();
    if (!msg)
        return 0;
    msg->type = TYPE_SYSCALL | TYPE_ENTER;
    fill_msg(msg);
    msg->ctx_stack = stack;
    events.perf_submit(args, msg, sizeof(*msg));
#endif
    return 0;
}

TRACEPOINT_PROBE(raw_syscalls, sys_exit) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 tgid = pid_tgid >> 32;
    u32 pid = (u32)pid_tgid;
#ifdef SEND_SYSCALL_EXIT
    struct ctx_stack_t *stack_p = ctxstack.lookup(&pid);
    if (!stack_p)
        return 0;
    if (stack_p->levels[0].id != args->id)
        /* we might have mistaken, not the same syscall */
        goto cleanup;
#ifdef FAILURE_ONLY
    if(args->ret >= 0)
        goto cleanup;
#endif
    struct msg_t *msg = get_scratch();
    if (!msg)
        goto cleanup;
    msg->type = TYPE_SYSCALL | TYPE_EXIT;
    fill_msg(msg);
    msg->ctx_stack = *stack_p;

    msg->retval = args->ret;
    events.perf_submit(args, msg, sizeof(*msg));
#endif
cleanup:
    /* we just remove the ctx here */
    ctxstack.delete(&pid);
    /* Shall we support syscall based conditional display? */
    return 0;
}

#define ___ptregsarr(ctx) {\
    (unsigned long long)PT_REGS_PARM1(ctx),\
    (unsigned long long)PT_REGS_PARM2(ctx),\
    (unsigned long long)PT_REGS_PARM3(ctx),\
    (unsigned long long)PT_REGS_PARM4(ctx),\
    (unsigned long long)PT_REGS_PARM5(ctx)\
}

BPF_HASH(security_hash, u32, struct ctx_t, 65536);

struct btf_argdef_t {
    u32 type_id;
    u32 deref_type_id;
};

/* we assume ctx is already done */
static inline void fill_btf_params(
        struct msg_t *msg,
        const int argc, unsigned long long *argv, const struct btf_argdef_t *typev) {
    for (unsigned i = 0; i < MAX_PT_REGS_ARGS; i++) {
        msg->args_btf_detail[i][0] = 0;
        if(i < argc) {
            struct btf_ptr btfdata;
            if (typev[i].deref_type_id) {
                btfdata = (struct btf_ptr){
                    .ptr = (void *)argv[i],
                    .type_id = typev[i].deref_type_id
                };
            } else {
                btfdata = (struct btf_ptr){
                    .ptr = &argv[i],
                    .type_id = typev[i].type_id
                };
            }
            bpf_snprintf_btf(&msg->args_btf_detail[i][0], ARG_BTF_BYTES, &btfdata, sizeof(btfdata), BTF_F_COMPACT);
        }
    }
}

static inline int func_enter(
        struct pt_regs *ctx,
        const unsigned level, const unsigned id, const unsigned msgtype,
        const int argc, const struct btf_argdef_t *typev) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 tgid = pid_tgid >> 32;
    u32 pid = (u32)pid_tgid;
    /* we only check those with stack, skipping filters */
    struct ctx_stack_t *stack_p = ctxstack.lookup(&pid);
    if (!stack_p)
        return 0;

    /* upper level function not captured */
    if (level - 1 > 0 && !stack_p->levels[level - 1].ctx_id)
        return 0;

    struct ctx_t *ctx_p = &stack_p->levels[level];

    /* the original stack isn't cleaned up, cowardly quit */
    if(ctx_p->ctx_id) 
        return 0;
    fill_context(ctx_p, level, id);
    unsigned long long argv[] = ___ptregsarr(ctx);
    for (unsigned i = 0; i < min(MAX_PT_REGS_ARGS, argc); i++) {
        ctx_p->args[i] = argv[i];
    }
    if (msgtype) {
        struct msg_t *msg = get_scratch();
        if (!msg)
            return 0;
        msg->type = msgtype;
        fill_msg(msg);
        msg->ctx_stack = *stack_p;
#ifdef BTF_DETAIL
        fill_btf_params(msg, argc, &ctx_p->args[0], typev);
#endif
        events.perf_submit(ctx, msg, sizeof(*msg));
    }
    return 0;
}


static inline int func_exit(
        struct pt_regs *ctx,
        const unsigned level, const unsigned id, const unsigned msgtype,
        const int argc, const struct btf_argdef_t *typev) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 tgid = pid_tgid >> 32;
    u32 pid = (u32)pid_tgid;
    struct ctx_stack_t *stack_p = ctxstack.lookup(&pid);
    if (!stack_p)
        return 0;

    struct ctx_t *ctx_p = &stack_p->levels[level];

    /* bail if stack empty */
    if(!ctx_p->ctx_id) 
        return 0;

    /* bail if not our id */
    if(ctx_p->id != id)
        return 0;

    int retval = (int)PT_REGS_RC(ctx);
#ifdef FAILURE_ONLY
    if(retval >= 0)
        /* this is to work around "jump out of range" compiler issue*/
        goto cleanup;
#endif
    if(msgtype) {
        struct msg_t *msg = get_scratch();
        if (!msg)
            goto cleanup;
        msg->type = msgtype;
        fill_msg(msg);
        msg->ctx_stack = *stack_p;
        msg->retval = retval;
#ifdef BTF_DETAIL
        fill_btf_params(msg, argc, &ctx_p->args[0], typev);
#endif
        events.perf_submit(ctx, msg, sizeof(*msg));
    }
cleanup:
    *ctx_p = (struct ctx_t){};
    return 0;
}

#ifdef SEND_SECURITY_ENTER
#define SECURITY_ENTER_MSGTYPE (TYPE_SECURITY | TYPE_ENTER)
#else
#define SECURITY_ENTER_MSGTYPE 0
#endif
#define DEF_SECURITY(name, id, btfrtn, btfargs...)                          \
int security_enter_##name(struct pt_regs *ctx) {                            \
    const struct btf_argdef_t typev[] = {btfargs};                          \
    return func_enter(                                                      \
        ctx, 1, id, SECURITY_ENTER_MSGTYPE, sizeof(typev) / sizeof(struct btf_argdef_t), typev);\
}


LIST_SECURITY();
#undef DEF_SECURITY

#ifdef SEND_SECURITY_EXIT
#define SECURITY_EXIT_MSGTYPE (TYPE_SECURITY | TYPE_EXIT)
#else
#define SECURITY_EXIT_MSGTYPE 0
#endif
#define DEF_SECURITY(name, id, btfrtn, btfargs...)                          \
int security_exit_##name(struct pt_regs *ctx) {                             \
    const struct btf_argdef_t typev[] = {btfargs};                          \
    return func_exit(                                                       \
        ctx, 1, id, SECURITY_EXIT_MSGTYPE, sizeof(typev) / sizeof(struct btf_argdef_t), typev);\
}

LIST_SECURITY();
#undef DEF_SECURITY

BPF_HASH(hook_hash, u32, struct ctx_t, 65536);

#ifdef SEND_HOOK_ENTER
#define HOOK_ENTER_MSGTYPE (TYPE_HOOK | TYPE_ENTER)
#else
#define HOOK_ENTER_MSGTYPE 0
#endif
#define DEF_HOOK(name, id, btfrtn, btfargs...)                              \
int hook_enter_##name(struct pt_regs *ctx) {                                \
    const struct btf_argdef_t typev[] = {btfargs};                          \
    return func_enter(                                                      \
        ctx, 2, id, HOOK_ENTER_MSGTYPE, sizeof(typev) / sizeof(struct btf_argdef_t), typev);\
}

LIST_HOOK();
#undef DEF_HOOK

#ifdef SEND_HOOK_EXIT
#define HOOK_EXIT_MSGTYPE (TYPE_HOOK | TYPE_EXIT)
#else
#define HOOK_EXIT_MSGTYPE 0
#endif
#define DEF_HOOK(name, id, btfrtn, btfargs...)                              \
int hook_exit_##name(struct pt_regs *ctx) {                                 \
    const struct btf_argdef_t typev[] = {btfargs};                          \
    return func_exit(                                                       \
        ctx, 2, id, HOOK_EXIT_MSGTYPE, sizeof(typev) / sizeof(struct btf_argdef_t), typev);\
}

LIST_HOOK();
#undef DEF_HOOK

'''

def get_msg_t(
        max_pt_regs_args,
        max_args,
        arg_btf_bytes,
        trace_bytes,
        **kwargs):

    class ctx_t(ct.Structure):
        _fields_ = [
            ('ctx_id',  ct.c_uint64),
            ('time',    ct.c_uint64),
            ('id',      ct.c_uint64),
            ('args',    ct.c_ulonglong * max_args),
        ]

    class _U(ct.Union):
        _fields_ = [
            ('args_btf_detail',  ct.c_char * arg_btf_bytes * max_pt_regs_args),
            ('text',  ct.c_char * trace_bytes),
        ]

    class msg_t(ct.Structure):
        _anonymous_ = ['u']
        _fields_ = [
            ('type',            ct.c_uint32),
            ('reserved',        ct.c_uint32),
            ('time',            ct.c_uint64),
            ('tgid',            ct.c_uint32),
            ('pid',             ct.c_uint32),
            ('gid',             ct.c_uint32),
            ('uid',             ct.c_uint32),
            ('comm',            ct.c_char * 16),
            ('levels',          ctx_t * 3),
            # ('syscall_ctx',     ctx_t),
            # ('security_ctx',    ctx_t),
            # ('hook_ctx',        ctx_t),
            ('retval',          ct.c_int),
            ('u',               _U),
        ]
        class t(object):
            __slots__ = ();
            TYPEMASK_LEVEL  = 3
            TYPE_SYSCALL    = 1
            TYPE_SECURITY   = 2
            TYPE_HOOK       = 3
            TYPEMASK_DIR    = 3<<2
            TYPE_ENTER      = 1<<2
            TYPE_EXIT       = 2<<2
            TYPE_TRACE      = 255

    return msg_t

class BPFNoLimit(BPF):
    def _check_probe_quota(self, num_new_probes):
        pass


class ForgettableIndex(object):
    """add or lookup keys in index, remember a integer value entry,
    forget all items once when value entry small than a given number
    """
    def __init__(self):
        self._heap = []
        self._set = set()
        self._lock = threading.Lock()

    def insert(self, key, version):
        with self._lock:
            if key not in self._set:
                logger.debug('added %s at %s', key, version)
                heapq.heappush(self._heap, (version, key))
                self._set.add(key)

    def __contains__(self, key):
        with self._lock:
            return key in self._set

    __setitem__ = insert

    def forget(self, version):
        """forget all entries with value smaller than version"""
        with self._lock:
            while self._heap and self._heap[0][0] <= version:
                v, k = heapq.heappop(self._heap)
                self._set.discard(k)
                logger.debug('forgot %s', k)


def main():
    import argparse
    parser = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument('-p', '--pid', type=int,
                        help='pid for tracing, by default all processes, '
                        'XXX: multiple pids can be added')
    parser.add_argument('-s', '--syscall',
                        help='complete name or octal ID of a Linux syscall to '
                        'capture, XXX: multiple syscalls can be added')
    # parser.add_argument('-c', '--comm',
    #                     help='trace only when comm of the process equals to '
    #                     'given value')
    parser.add_argument('--security-func',
                        help='security function name regex pattern')
    parser.add_argument('--hook-func',
                        help='security hook function name regex pattern')
    parser.add_argument('-f', '--failure-only', action='store_true',
                        help='capture failures only '
                        'by default this tool captures all LSM relevant '
                        'function calls, even those with void return type')
    parser.add_argument('--found-level', choices=('security', 'hook'),
                        help='only print calls when security or hook context '
                        'found, choices are "security" and "hook"')
    parser.add_argument('-t', '--timeout', type=int, help='seconds to capture '
                        'before quiting')
    parser.add_argument('-d', '--btf-detail', action='store_true',
                        help='include expanded btf detail')
    parser.add_argument('--bpf', action='store_true',
                        help='print bpf code and quit')
    parser.add_argument('-v', '--verbose', action='store_true',
                        help='show debug logs')
    args = parser.parse_args()
    if args.verbose:
        logger.setLevel(logging.DEBUG)
    btf = get_btf()
    # int_type_id = next(for d in btf.values() if d[])
    # list(find_all_security_hook_defs(btf))
    security_funcs = list(find_all_security_funcs(btf))
    hook_funcs = list(find_all_security_hook_defs(btf))
    # import json
    # # print(json.dumps(collect_int_rettype_funcs()))
    # btf = get_btf()
    # list(find_all_security_hook_defs(btf))
    # bpf_text_rendered = bpf_text
    bpfargs = {
        'max_pt_regs_args': 5,
        'max_syscall_args': 6,
        'max_args': 6,
        'arg_btf_bytes': 4096,
        'trace_bytes': 128,
        'list_hook()': '',
        'list_security()': '',
    }
    # bpfargs['send_syscall_enter'] = ''
    bpfargs['send_syscall_exit'] = ''
    # bpfargs['send_security_enter'] = ''
    bpfargs['send_security_exit'] = ''
    # bpfargs['send_hook_enter'] = ''
    bpfargs['send_hook_exit'] = ''
    if args.pid:
        bpfargs['FILTER_PID(tgid)'] = f'if(tgid!={args.pid}) return 0;'

    # return
    if args.syscall:
        try:
            syscall_nr = int(args.syscall)
        except ValueError:
            syscall_nr = dict((v.decode('ascii'), k) for k, v in syscalls.items())[args.syscall]

        bpfargs['FILTER_SYSCALL_NR(id)'] = f'if(id != {syscall_nr}) return 0;'

    if args.security_func:
        security_funcs = [t for t in security_funcs if re.search(args.security_func, t[0])]

    if args.hook_func:
        hook_funcs = [t for t in hook_funcs if re.search(args.hook_func, t[0])]

    if args.failure_only:
        # we remove all void calls
        security_funcs = [(n, _i, ri, _a) for (n, _i, ri, _a) in security_funcs if ri != 0]
        hook_funcs = [(n, _i, ri, _a) for (n, _i, ri, _a) in hook_funcs if ri != 0]
        bpfargs['FAILURE_ONLY'] = ''

    # print(security_funcs)
    # return
    bpfargs['LIST_SECURITY()'] = '\\\n'.join(
        'DEF_SECURITY({}, {}, {}, {})'.format(n, _i, ri, ', '.join("{{{}, {}}}".format(t, btf_deref_type(btf, t)) for t in _a))
        for (n, _i, ri, _a) in security_funcs)

    bpfargs['LIST_HOOK()'] = '\\\n'.join(
        'DEF_HOOK({}, {}, {}, {})'.format(n, _i, ri, ', '.join("{{{}, {}}}".format(t, btf_deref_type(btf, t)) for t in _a))
        for (n, _i, ri, _a) in hook_funcs)

    if args.btf_detail:
        bpfargs['btf_detail'] = 1

    msg_t = get_msg_t(**bpfargs)
    bpf_text_rendered = '\n'.join(
        "#define {} {}".format(k if k.endswith(')') else k.upper(), v)
        for k, v in bpfargs.items()) + bpf_text
    if args.bpf:
        print(bpf_text_rendered)
        return 0
    # import bcc
    # b = BPF(text=bpf_text_rendered, debug=bcc.DEBUG_SOURCE)
    b = BPFNoLimit(text=bpf_text_rendered)
    first_ts = BPF.monotonic_time()
    first_ts_real = time.time()
    
    probecnt = len(security_funcs) + len(hook_funcs)
    # each probe seem to consume around 4 fds
    fdneeded = probecnt * 4 + 64
    logger.debug('probecnt: %s', probecnt)
    nofile_soft, nofile_hard = resource.getrlimit(resource.RLIMIT_NOFILE)
    logger.debug("need %s fd, soft %s, hard %s", fdneeded, nofile_soft, nofile_hard)

    if fdneeded > nofile_soft:
        new_nofile_soft = min(nofile_hard, fdneeded)
        if new_nofile_soft > nofile_soft:
            logger.info("changing soft nofile to %s", new_nofile_soft)
            resource.setrlimit(resource.RLIMIT_NOFILE, (new_nofile_soft, nofile_hard))
        if new_nofile_soft < fdneeded:
            logger.info("current RLIMIT_NOFILE may still be not enough")

    if not security_funcs:
        logger.warning('no security_funcs found!')

    for t in security_funcs:
        logger.info('attaching %s', t[0])
        try:
            b.attach_kprobe(event=t[0], fn_name='security_enter_' + t[0])
            b.attach_kretprobe(event=t[0], fn_name='security_exit_' + t[0])
        except Exception:
            logger.exception('failed to attach %s', t[0])

    if not hook_funcs:
        logger.warning('no hook_funcs found!')

    for t in hook_funcs:
        logger.info('attaching %s', t[0])
        try:
            b.attach_kprobe(event=t[0], fn_name='hook_enter_' + t[0])
            b.attach_kretprobe(event=t[0], fn_name='hook_exit_' + t[0])
        except Exception:
            logger.exception('failed to attach %s', t[0])

    ctxid_tracker = ForgettableIndex() if args.found_level else None
    found_level = {'hook': msg_t.t.TYPE_HOOK, 'security': msg_t.t.TYPE_SECURITY}.get(args.found_level)
    recent_time = 0
    TRACKER_GAP = int(5 * 1e9)  # we keep ctx_id for 5 seconds

    def reltime(ts_ns):
        return 1e-9 * (ts_ns - first_ts)

    def clocktime(ts_ns):
        return reltime(ts_ns) + first_ts_real

    def callback(cpu, data, size, timefmt="%H:%M:%S.%f"):
        nonlocal ctxid_tracker, recent_time, found_level
        event = ct.cast(data, ct.POINTER(msg_t)).contents

        # for each event, we print:
        # 1 header line, including retval
        # 1 line of parameters for each context in long long hex
        # 1 optional block, 1 parameter each line
        HEADERFMT = '{time} {tgid:>9} {pid:>9} {uid:>5} {gid:>5} {comm:<16} {dir}{level} {name:<36} {ret}'
        LEVELSTR = {event.t.TYPE_SYSCALL: 'SYS', event.t.TYPE_SECURITY: 'SEC', event.t.TYPE_HOOK: 'HOK'}
        DIRSTR = {event.t.TYPE_ENTER: '>', event.t.TYPE_EXIT: '<'}
        direction = event.type & event.t.TYPEMASK_DIR
        level = event.type & event.t.TYPEMASK_LEVEL

        recent_time = max(event.time, recent_time)
        if found_level:
            if level >= found_level:
                for i in range(level-1):
                    l = event.levels[i]
                    ctxid_tracker[(i + 1, l.ctx_id)] = l.time
            else:
                if (level, event.levels[level-1].ctx_id) not in ctxid_tracker:
                    logger.debug('ignore ctx_id %s, %s', level, event.levels[level-1].ctx_id)
                    return

        header = {
            'time': datetime.fromtimestamp(clocktime(event.time)).strftime(timefmt),
            'comm': event.comm.decode('ascii'),
            'dir': DIRSTR[direction],
            'level': LEVELSTR[level],
            'ret': '',
        }
        for k in ['tgid', 'pid', 'uid', 'gid']:
            header[k] = getattr(event, k)

        if level == event.t.TYPE_SYSCALL:
            header['name'] = syscall_name(event.levels[0].id).decode('ascii')
        else:
            header['name'] = btf[event.levels[level-1].id]['name']

        if direction == event.t.TYPE_EXIT:
            errstr = str(event.retval)
            if event.retval < 0:
                try:
                    errstr += '({})'.format(errno.errorcode[-event.retval])
                except KeyError:
                    pass
            header['ret'] = errstr
        # print(repr(header))
        print(HEADERFMT.format(**header))

        CTXFMT = ' ' * 16 + '{level} {ctx_id:>016x} {name:>36}({params})'
        PARAMFMT = '{:>016x}'
        for i in range(level):
            ctxdata = event.levels[i]
            ctx = {
                'level': LEVELSTR[i+1],
                'ctx_id': ctxdata.ctx_id,
                # 'name': syscall_name(ctxdata.id).decode('ascii') if i==0 else fd['name'],
            }
            if i == 0:
                nargs = bpfargs['max_syscall_args']
                ctx['name'] = syscall_name(ctxdata.id).decode('ascii')
            else:
                # print(ctxdata.id)
                fd = btf[ctxdata.id]
                nargs = min(btf[fd['type_id']]['vlen'], bpfargs['max_pt_regs_args'])
                ctx['name'] = fd['name']
            # we try to wrap on 120 line width, put 3rd arg on next line
            ctxargs = list(ctxdata.args)[:nargs]
            argl0 = ctxargs[:2]
            argl1 = ctxargs[2:]
            params = ', '.join(map(PARAMFMT.format, argl0))
            if argl1:
                params += ',\n' + ' ' * 38 + ', '.join(map(PARAMFMT.format, argl1))

            ctx['params'] = params
            print(CTXFMT.format(**ctx))
        
        if args.btf_detail and level != event.t.TYPE_SYSCALL:
            fd = btf[event.levels[level-1].id]
            argnames = [p['name'] for p in btf[fd['type_id']]['params']][:bpfargs['max_pt_regs_args']]
            for argname, detail in zip(argnames, event.args_btf_detail):
                print(' ' * 15 + argname + ' = ' + detail.value.decode('ascii')) 

    running = 1
    def _callback(cpu, data, size, **kw):
        # this wrapper is needed to avoid blocking of ctrl-c.
        try:
            nonlocal running
            if not running:
                return
            callback(cpu, data, size, **kw)
        except KeyboardInterrupt:
            logger.warning('callback interrupted')
            running = 0
            raise

    b["events"].open_perf_buffer(_callback, page_cnt=256)
    def timeout():
        nonlocal running
        running = 0
        logger.debug('reaching timeout')

    timer = None
    if args.timeout:
        timer = threading.Timer(args.timeout, timeout)
        timer.start()

    logger.info('all attached')
    logger.debug('opened fd count: %d', len(os.listdir('/proc/self/fd')))
    while running:
        try:
            b.perf_buffer_poll(timeout=100)
            if ctxid_tracker and recent_time:
                ctxid_tracker.forget(recent_time - TRACKER_GAP)
        except KeyboardInterrupt:
            logger.info('loop interrupted')
            exit()


if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO)
    try:
        main()
    finally:
        logger.info('ending execution, this can take a while')
