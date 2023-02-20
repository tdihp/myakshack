#!/usr/bin/python
# -*- coding: utf-8 -*-

"""
A latency evaluation tool for REPL-ish protocols such as Redis or http <2.

We assume the client is not multiplexed, i.e. only one thread that is
either doing read or write for both the REPL client and server, and only one
request ongoing over the socket. i.e., client won't send more requests if it
doesn't receive the current response, and server won't read more tha one request
or produce more than one response.

A client sends "requests" by having multiple writes, followed by multiple reads
for getting the response.

A server receives "requests" by multiple reads, then after processing, sends
several writes for the response. 

Glossary:

W,WT,WRT  writing call from start to end
  WS,WTS  start of write call
  WE,WTE  end of write call
  WA,WTA  write buffer available timing
  FA,FAK  all written packets are properly acked
  UW,UAW  unacked write, meaning fullack did not happen for this write
     UWS  unacked write start
  WS,WSQ  write sequence from start to end
     WSS  write sequence start, equal to first WTS
     WSE  write sequence end, equal to last WTE 
R,RD,RAD  reading call from start to end
  RS,RDS  start of read call
  RE,RDE  end of read call
  RA,RDA  incoming data available timing
  RS,RSQ  read sequence from start to end
     RSS  read sequence start, equal to first RDS
     RSE  read sequence end, equal to last RDE
H,HS,HNS  handshake of TCP  
     HSS  handshake start
     HSE  handshake established
     ANY  From any state
     CLS  any closing state
     UNK  any unknown state

Reading sequence messages
macroscope: [WSS2RSS                                        [WSE2RSS
             RSS2WSS]                                       |
             RSE2WSS]                                       |
mesoscope : [WSS2WSE                                          ]
            [UWS2FAK                        ]         [UWS2FAK      ]
            |                                         |     |     [FAK2RDA
microscope: [WTS2WTE]         [WTS2WTE]               [WTS2WTE]   |
            |     [WTE2WTA]   |     [WTE2WTA      ]   |     |     |
            |     |     [WTA2WTS]   |          [WTA2WTS]    |     |
timings   : WTS-->WTE-->WTA-->WTS-->WTE-->FAK-->WTA-->WTS-->WTE-->FAK

Writing sequence messages
macroscope:      [RSS2WSS                                      [RSE2WSS
                  WSS2RSS]                                 |
                  WSE2RSS]                                 |
mesoscope :            [RSS2RSE                              ]
            FAK2RDA]                                       |
microscope:            [RDS2RDE]   [RDS2RDE]         [RDS2RDE]
                       |                 [RDE2RDA]
                 [RDA2RDS]                     [RDA2RDS]
timings   :      RDA-->RDS-->RDE-->RDS-->RDE-->RDA-->RDS-->RDE


Notes:

* For each scope, we have count and (total) size of read/write calls.
* we don't record actual skbs sent/retransmitted, etc.
* we don't record io errors, those should be done in application already.
* Scopes are:
  * microscope:
    * WTS2WTE write start to end
    * RDS2RDE
    * latest read/write end to available
    * read/write available to read/write
  * mesoscope:
    * unacked write start to fully acked
    * reads writes, from first start to last end.
    * writes fully acked to read available
  * macroscpoe:
    * writes start to reads start
    * writes end to reads start
    * reads start to writes start
    * reads end to writes start

Copyright (c) 2023, Ping He.
License: MIT
"""

__author__  = "Ping He"
__license__ = "MIT"

from bcc import BPF
import argparse
import time
# from time import strftime, gmtime, localtime
import datetime
from ipaddress import ip_address
import struct

TCP_STATES = [
    "",  # pretty smart huh?
    "ESTABLISHED",
    "SYN_SENT",
    "SYN_RECV",
    "FIN_WAIT1",
    "FIN_WAIT2",
    "TIME_WAIT",
    "CLOSE",
    "CLOSE_WAIT",
    "LAST_ACK",
    "LISTEN",
    "CLOSING",
    "NEW_SYN_RECV",
]

MSG_TYPES = [
    "",
    "HSS2HSE",
    "ANY2CLS",
    "ANY2UNK",
    "WTS2WTE",
    "RDS2RDE",
    "RDA2RDS",
    "WSS2WSE",
    "RSS2RSE",
    "UWS2FAK",
    "WSE2RSS",
    "WSS2RSS",
    "RSE2WSS",
    "RSS2WSS",
    "FAK2RDA",
    "TRACEIT",
]

parser = argparse.ArgumentParser(
    description="Trace tcp sock for timings slower than a threshold",
)

parser.add_argument("--ebpf", action="store_true")
parser.add_argument("--service-port", type=int, default=443,
                    help="service port, default to 443")
parser.add_argument("--service-ip", type=ip_address,
                    help="service IP address, default to not filtering")
parser.add_argument("--no-client", dest="client", action="store_false",
                    help="disable tapping for clients")
parser.add_argument("--no-server", dest="server", action="store_false",
                    help="disable tapping for clients")
parser.add_argument("latms", type=int, help="min latency in milliseconds")
args = parser.parse_args()

# pid = args.pid
debug = 1

# define BPF program
bpf_text = """
#include <linux/sched.h>
#include <linux/tcp.h>
#include <net/sock.h>
#include <net/tcp_states.h>

#define MAX_SOCKS 65536

enum state {
    MON,  /* only happens after HNS */
    HNS,
    WSQ,
    RSQ,
};

enum mode {
    CLIENT,
    SERVER,
};

struct sock_state_t {
    u64 seqstart_ns;  /* shared start time for HSS, WSS and RSS */
    u64 start_ns;   /* shared start time for WTS, RDS */
    u64 end_ns;   /* shared end time for WTE, RDE, used for marking WSE, RSE */
    u64 uws_ns;
    u64 fak_ns;
    u64 rda_ns;
    u32 seqsize;
    u32 seqcalls;
    u32 uwssize;
    u32 uwscalls;
    // u64 readable_ns;  /* first readable before a read */
    // u64 writable_ns;  /* first writable before a write */
    // u64 latest_ns;  /* latest write/read */
    // u64 latest_done_ns;  /* latest done write/read */
    enum state state;
    enum mode mode;
};

enum msgtype {
    HSS2HSE=1,
    ANY2CLS,
    ANY2UNK,
    WTS2WTE,
    RDS2RDE,
    RDA2RDS,
    WSS2WSE,
    RSS2RSE,
    UWS2FAK,
    WSE2RSS,
    WSS2RSS,
    RSE2WSS,
    RSS2WSS,
    FAK2RDA,
    TRACEIT,
};

struct msg_t {
    //msginfo
    enum msgtype msgtype;
    u64 ts_ns;
    u64 lat_ns;
    u32 bytes;
    u32 calls;
    // int last_state;
    // int state;
    //netinfo
    u32 saddr;
    u32 daddr;
    u16 lport;
    u16 dport;
};

BPF_HASH(sockstatemap, struct sock *, struct sock_state_t, MAX_SOCKS);
BPF_HASH(callmap, u32, struct sock *);
BPF_PERF_OUTPUT(events);


static inline bool is_client(struct sock *sk) {
    u16 lport = sk->__sk_common.skc_num;
    u16 dport = sk->__sk_common.skc_dport;
    u32 saddr = sk->__sk_common.skc_rcv_saddr;
    u32 daddr = sk->__sk_common.skc_daddr;
    dport = ntohs(dport);
    return IS_CLIENT_COND;
}

static inline bool is_server(struct sock *sk) {
    u16 lport = sk->__sk_common.skc_num;
    u16 dport = sk->__sk_common.skc_dport;
    u32 saddr = sk->__sk_common.skc_rcv_saddr;
    u32 daddr = sk->__sk_common.skc_daddr;
    dport = ntohs(dport);
    return IS_SERVER_COND;
}

static inline bool should_send(enum msgtype msgtype, u64 lat) {
    return lat >= MIN_LAT_NS;
}

static inline struct sock_state_t *try_tap(struct sock *sk, bool try_client, bool try_server) {
    enum mode mode;
    struct sock_state_t *sockstate = NULL;
    struct sock_state_t zero = {};
    if (try_client && is_client(sk)) {
        mode = CLIENT;
    } else if (try_server && is_server(sk)) {
        mode = SERVER;
    } else {
        return NULL;
    }
    sockstate = sockstatemap.lookup_or_try_init(&sk, &zero);
    if (sockstate != NULL) {
        sockstate->mode = mode;
    }
    return sockstate;
}

static inline void fill_msg(struct sock *sk, struct msg_t *msg) {
    // msg->last_state = sk->sk_state;
    // msg->state = sk->sk_state;
    msg->saddr = sk->__sk_common.skc_rcv_saddr;
    msg->daddr = sk->__sk_common.skc_daddr;
    msg->lport = sk->__sk_common.skc_num;
    u16 dport = sk->__sk_common.skc_dport;
    msg->dport = ntohs(dport);
}

static inline void on_hss(struct pt_regs *ctx, struct sock *sk, struct sock_state_t *sockstate, u64 now) {
    sockstate->seqstart_ns = now;
    sockstate->state = HNS;
}

static inline void on_hse(struct pt_regs *ctx, struct sock *sk, struct sock_state_t *sockstate, u64 now) {
    if (sockstate->state != HNS) {  /* we ignore if we are not in handshake */
        return;
    }
    u64 lat = now - sockstate->seqstart_ns;
    sockstate->seqstart_ns = 0;  /* reset timer, ss doesn't make sense for MON state */
    sockstate->state = MON;
    if (!should_send(HSS2HSE, lat)) {
        return;
    }
    struct msg_t msg = {};
    msg.msgtype = HSS2HSE;
    msg.ts_ns = now;
    msg.lat_ns = lat;
    fill_msg(sk, &msg);
    events.perf_submit(ctx, &msg, sizeof(msg));
}

static inline void on_cls(struct pt_regs *ctx, struct sock *sk, struct sock_state_t *sockstate, u64 now, int state) {
    enum msgtype msgtype;
    u64 lat = 0;
    switch (state) {
        case TCP_CLOSE:  // close
        case TCP_FIN_WAIT1:  // proactive close
        case TCP_CLOSE_WAIT:  // got fin from remote
        case TCP_LAST_ACK:
            msgtype = ANY2CLS;
            break;
        default:
            msgtype = ANY2UNK;
    }
    if (sockstate->state != MON) {
        lat = now - sockstate->seqstart_ns;
    }
    sockstatemap.delete(&sk);
    sockstate = NULL;
    if (!should_send(msgtype, lat)) {
        return;
    }
    struct msg_t msg = {};
    msg.msgtype = msgtype;
    msg.ts_ns = now;
    msg.lat_ns = lat;
    fill_msg(sk, &msg);
    events.perf_submit(ctx, &msg, sizeof(msg));
}

static inline void on_wts(struct pt_regs *ctx, struct sock *sk, struct sock_state_t *sockstate, u64 now) {
    u64 lat = 0;
    struct msg_t msg = {};
    if (sockstate->state != WSQ) {
        if (sockstate->state == RSQ) {
            /* RSS2RSE */
            lat = sockstate->end_ns - sockstate->seqstart_ns;
            if (should_send(RSS2RSE, lat)) {
                msg.msgtype = RSS2RSE;
                msg.ts_ns = sockstate->end_ns;
                msg.lat_ns = lat;
                msg.bytes = sockstate->seqsize;
                msg.calls = sockstate->seqcalls;
                fill_msg(sk, &msg);
                events.perf_submit(ctx, &msg, sizeof(msg));
            }
            /* RSE2WSS */
            lat = now - sockstate->end_ns;
            if (sockstate->mode == SERVER && should_send(RSE2WSS, lat)) {
                msg.msgtype = RSE2WSS;
                msg.ts_ns = now;
                msg.lat_ns = lat;
                msg.bytes = 0;
                msg.calls = 0;
                fill_msg(sk, &msg);
                events.perf_submit(ctx, &msg, sizeof(msg));
            }
            /* RSS2WSS */
            lat = now - sockstate->seqstart_ns;
            if (sockstate->mode == SERVER && should_send(RSS2WSS, lat)) {
                msg.msgtype = RSS2WSS;
                msg.ts_ns = now;
                msg.lat_ns = lat;
                msg.bytes = sockstate->seqsize;
                msg.calls = sockstate->seqcalls;
                fill_msg(sk, &msg);
                events.perf_submit(ctx, &msg, sizeof(msg));
            }
        }
        sockstate->state = WSQ;
        sockstate->seqstart_ns = now;
        sockstate->seqcalls = 0;
        sockstate->seqsize = 0;
    }
    sockstate->start_ns = now;
    sockstate->seqcalls += 1;
    if (!sockstate->uws_ns) {
        sockstate->uws_ns = now;
    }
    sockstate->uwscalls += 1;
}

static inline void on_wte(struct pt_regs *ctx, struct sock *sk, struct sock_state_t *sockstate, u64 now, int rtn) {
    sockstate->end_ns = now;
    u32 size = 0;
    if (rtn > 0) {
        size = rtn;
    }
    sockstate->seqsize += size;
    sockstate->uwssize += size;
    /* deliver WTS2WTE */
    u64 lat = now - sockstate->start_ns;
    if (!should_send(WTS2WTE, lat)) {
        return;
    }
    struct msg_t msg = {};
    msg.msgtype = WTS2WTE;
    msg.ts_ns = now;
    msg.lat_ns = lat;
    msg.bytes = size;
    msg.calls = 1;
    fill_msg(sk, &msg);
    events.perf_submit(ctx, &msg, sizeof(msg));
}

static inline void on_rds(struct pt_regs *ctx, struct sock *sk, struct sock_state_t *sockstate, u64 now) {
    u64 lat = 0;
    struct msg_t msg = {};
    if (sockstate->state != RSQ) {
        if (sockstate->state == WSQ) {
            /* WSS2WSE */
            lat = sockstate->end_ns - sockstate->seqstart_ns;
            if (should_send(WSS2WSE, lat)) {
                msg.msgtype = WSS2WSE;
                msg.ts_ns = sockstate->end_ns;
                msg.lat_ns = lat;
                msg.bytes = sockstate->seqsize;
                msg.calls = sockstate->seqcalls;
                fill_msg(sk, &msg);
                events.perf_submit(ctx, &msg, sizeof(msg));
            }
            /* WSE2RSS */
            lat = now - sockstate->end_ns;
            if (sockstate->mode == CLIENT && should_send(WSE2RSS, lat)) {
                msg.msgtype = WSE2RSS;
                msg.ts_ns = now;
                msg.lat_ns = lat;
                msg.bytes = 0;
                msg.calls = 0;
                fill_msg(sk, &msg);
                events.perf_submit(ctx, &msg, sizeof(msg));
            }
            /* WSS2RSS */
            lat = now - sockstate->seqstart_ns;
            if (sockstate->mode == CLIENT && should_send(WSS2RSS, lat)) {
                msg.msgtype = WSS2RSS;
                msg.ts_ns = now;
                msg.lat_ns = lat;
                msg.bytes = sockstate->seqsize;
                msg.calls = sockstate->seqcalls;
                fill_msg(sk, &msg);
                events.perf_submit(ctx, &msg, sizeof(msg));
            }
        }
        sockstate->state = RSQ;
        sockstate->seqstart_ns = now;
        sockstate->seqcalls = 0;
        sockstate->seqsize = 0;
    }
    sockstate->start_ns = now;
    sockstate->seqcalls += 1;
    /* RDA2RDS */
    if (!sockstate->rda_ns) {
        return;
    }
    lat = now - sockstate->rda_ns;
    sockstate->rda_ns = 0;
    if (!should_send(RDA2RDS, lat)) {
        return;
    }
    msg.msgtype = RDA2RDS;
    msg.ts_ns = now;
    msg.lat_ns = lat;
    fill_msg(sk, &msg);
    events.perf_submit(ctx, &msg, sizeof(msg));
}

static inline void on_rde(struct pt_regs *ctx, struct sock *sk, struct sock_state_t *sockstate, u64 now, int rtn) {
    sockstate->end_ns = now;
    u32 size = 0;
    if (rtn > 0) {
        size = rtn;
    }
    sockstate->seqsize += size;
    sockstate->rda_ns = 0;
    /* deliver RDS2RDE */
    u64 lat = now - sockstate->start_ns;
    if (!should_send(RDS2RDE, lat)) {
        return;
    }
    struct msg_t msg = {};
    msg.msgtype = RDS2RDE;
    msg.ts_ns = now;
    msg.lat_ns = lat;
    msg.bytes = size;
    msg.calls = 1;
    fill_msg(sk, &msg);
    events.perf_submit(ctx, &msg, sizeof(msg));
}

static inline void on_rda(struct pt_regs *ctx, struct sock *sk, struct sock_state_t *sockstate, u64 now) {
    /* FAK2RDA */
    if (sockstate->fak_ns) {
        u64 lat = now - sockstate->fak_ns;
        sockstate->fak_ns = 0;
        if (sockstate->mode == CLIENT && should_send(FAK2RDA, lat)) {
            struct msg_t msg = {};
            msg.msgtype = FAK2RDA;
            msg.ts_ns = now;
            msg.lat_ns = lat;
            fill_msg(sk, &msg);
            events.perf_submit(ctx, &msg, sizeof(msg));
        }
    }
    if (!sockstate->rda_ns) {
        sockstate->rda_ns = now;
    }
}

static inline void on_fak(struct pt_regs *ctx, struct sock *sk, struct sock_state_t *sockstate, u64 now) {
    sockstate->fak_ns = now;
    if (sockstate->uws_ns) {
        u64 lat = now - sockstate->uws_ns;
        if (should_send(UWS2FAK, lat)) {
            struct msg_t msg = {};
            msg.msgtype = UWS2FAK;
            msg.ts_ns = now;
            msg.lat_ns = lat;
            msg.bytes = sockstate->uwssize;
            msg.calls = sockstate->uwscalls;
            fill_msg(sk, &msg);
            events.perf_submit(ctx, &msg, sizeof(msg));
        }
        sockstate->uws_ns = 0;
        sockstate->uwssize = 0;
        sockstate->uwscalls = 0;
    }
}

/* checkpoint for HSS */
int trace_tcp_connect(struct pt_regs *ctx, struct sock *sk) {
    if (sk->__sk_common.skc_family != AF_INET) {
        return 0;
    }
    u64 now = bpf_ktime_get_ns();
    struct sock_state_t * sockstate = NULL;

    sockstate = try_tap(sk, true, false);
    if (sockstate != NULL) {
        on_hss(ctx, sk, sockstate, now);
    }
    return 0;
}

/* checkpoint for HSS, HSE, CLS, UNK */
int trace_tcp_set_state(struct pt_regs *ctx, struct sock *sk, int state) {
    if (sk->__sk_common.skc_family != AF_INET) {
        return 0;
    }
    u64 now = bpf_ktime_get_ns();
    u64 lat = 0;
    bool force_send = false;
    struct msg_t msg = {};
    struct sock_state_t * sockstate = sockstatemap.lookup(&sk);

    switch (state) {
        case TCP_ESTABLISHED:
            if (sockstate != NULL) {
                on_hse(ctx, sk, sockstate, now);
            }
            return 0;
        case TCP_SYN_SENT:
            return 0;
        case TCP_SYN_RECV:
            sockstate = try_tap(sk, false, true);
            if (sockstate != NULL) {
                on_hss(ctx, sk, sockstate, now);
            }
            return 0;
        default:
            if (sockstate != NULL) {
                on_cls(ctx, sk, sockstate, now, state);
            }
            return 0;
    }
    return 0;
}

/* checkpoint for WTS */
int trace_tcp_sendmsg_locked(struct pt_regs *ctx, struct sock *sk, struct msghdr *msg, size_t size) {
    if (sk->__sk_common.skc_family != AF_INET) {
        return 0;
    }
    u64 now = bpf_ktime_get_ns();
    struct sock_state_t * sockstate = sockstatemap.lookup(&sk);
    if (sockstate == NULL) {
        sockstate = try_tap(sk, true, true);
        if (sockstate == NULL) {
            return 0;
        }
    }
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 tid = pid_tgid;
    callmap.insert(&tid, &sk);
    on_wts(ctx, sk, sockstate, now);
    return 0;
}

/* checkpoint for WTE */
int trace_ret_tcp_sendmsg_locked(struct pt_regs *ctx) {
    u64 now = bpf_ktime_get_ns();
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 tid = pid_tgid;
    struct sock **skp = callmap.lookup(&tid);
    if (skp == NULL) {
        return 0;
    }
    struct sock *sk = *skp;
    callmap.delete(&tid);
    int ret = PT_REGS_RC(ctx);
    struct sock_state_t *sockstate = sockstatemap.lookup(&sk);
    if (sockstate == NULL) {
        return 0;  // apparantly we don't care anymore
    }
    on_wte(ctx, sk, sockstate, now, ret);
    return 0;
}

/* checkpoint for RDS */
int trace_tcp_recvmsg(struct pt_regs *ctx, struct sock *sk) {
    if (sk->__sk_common.skc_family != AF_INET) {
        return 0;
    }
    u64 now = bpf_ktime_get_ns();
    struct sock_state_t * sockstate = sockstatemap.lookup(&sk);
    if (sockstate == NULL) {
        sockstate = try_tap(sk, true, true);
        if (sockstate == NULL){
            return 0;
        }
    }
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 tid = pid_tgid;
    callmap.insert(&tid, &sk);
    on_rds(ctx, sk, sockstate, now);
    return 0;
}

/* checkpoint for RDE */
int trace_ret_tcp_recvmsg(struct pt_regs *ctx) {
    u64 now = bpf_ktime_get_ns();
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 tid = pid_tgid;
    struct sock **skp = callmap.lookup(&tid);
    if (skp == NULL) {
        return 0;
    }
    struct sock *sk = *skp;
    callmap.delete(&tid);
    int ret = PT_REGS_RC(ctx);
    struct sock_state_t *sockstate = sockstatemap.lookup(&sk);
    if (sockstate == NULL) {
        return 0;  // apparantly we don't care anymore
    }
    on_rde(ctx, sk, sockstate, now, ret);
    return 0;
}

/* checkpoint for RDA */
int trace_sock_def_readable(struct pt_regs *ctx, struct sock *sk) {
    if (sk->__sk_common.skc_family != AF_INET) {
        return 0;
    }
    u64 now = bpf_ktime_get_ns();
    struct sock_state_t * sockstate = sockstatemap.lookup(&sk);
    if (sockstate == NULL) {
        return 0; /* we don't try to tap here, it might tap closing socks */
    }
    on_rda(ctx, sk, sockstate, now);
    return 0;
}

/* checkpoint for FAK */ 
int trace_tcp_check_space(struct pt_regs *ctx, struct sock *sk) {
    if (sk->__sk_common.skc_family != AF_INET) {
        return 0;
    }
    u64 now = bpf_ktime_get_ns();
    struct sock_state_t * sockstate = sockstatemap.lookup(&sk);
    if (sockstate == NULL) {
        return 0;
    }
    struct tcp_sock *tp = tcp_sk(sk);

    if (tp->snd_una >= tp->snd_nxt) {
        on_fak(ctx, sk, sockstate, now);
    }
    return 0;
}

#if 0
/* checkpoint for WTA */
int trace_writable(struct pt_regs *ctx, struct sock *sk) {
    if (sk->__sk_common.skc_family != AF_INET) {
        return 0;
    }
    u64 now = bpf_ktime_get_ns();
    struct sock_state_t * sockstate = sockstatemap.lookup(&sk);
    if (sockstate == NULL) {
        return 0;
    }
    if (sockstate->writable_ns) {
        return 0;  /* only need first */
    }
    sockstate->writable_ns = now;
    return 0;
}
#endif
"""

macros = {
    "IS_SERVER_COND": "false",
    "IS_CLIENT_COND": "false",
    "MIN_LAT_NS": str(args.latms * 1000000) + 'ull',
}

if args.server:
    if args.service_ip:
        if args.service_ip.version != 4:
            raise ValueError('service ip has to be ipv4, got %r' % args.service_ip)
        macros["IS_SERVER_COND"] = "(lport == %d) && (saddr == %du)" % (args.service_port, struct.unpack("I", args.service_ip.packed)[0])
    else:
        macros["IS_SERVER_COND"] = "lport == %d" % args.service_port

if args.client:
    if args.service_ip:
        if args.service_ip.version != 4:
            raise ValueError('service ip has to be ipv4, got %r' % args.service_ip)
        macros["IS_CLIENT_COND"] = "(dport == %d) && (daddr == %du)" % (args.service_port, struct.unpack("I", args.service_ip.packed)[0])
    else:
        macros["IS_CLIENT_COND"] = "dport == %d" % args.service_port

macros_text = "\n".join("#define %s %s" % (k, v) for k, v in macros.items())
bpf_text = macros_text + bpf_text

if debug or args.ebpf:
    print(bpf_text)
    if args.ebpf:
        exit()


# initialize BPF
b = BPF(text=bpf_text)
first_ts = BPF.monotonic_time()
first_ts_real = time.time()


def reltime(ts_ns):
    return 1e-9 * (ts_ns - first_ts)


def clocktime(ts_ns):
    return reltime(ts_ns) + first_ts_real


def print_event(cpu, data, size, timefmt="%H:%M:%S.%f"):
    # print(data.msgtype, data.ts_ns)
    event = b["events"].event(data)
    # time, type, pid, comm, src, dest, state, lat
    print("%s %7s %15s:%-5d %15s:%-5d %9d/%-3d %8.3f" % (
        # strftime(timefmt, localtime(clocktime(event.ts_ns))),
        datetime.datetime.fromtimestamp(clocktime(event.ts_ns)).strftime(timefmt),
        MSG_TYPES[event.msgtype],
        # event.pid, event.comm.decode(), "%9d %16s" TODO: pid
        ip_address(struct.pack("I", event.saddr)), event.lport,
        ip_address(struct.pack("I", event.daddr)), event.dport,
        # ip_address(event.saddr), event.lport,
        # ip_address(event.daddr), event.dport,
        event.bytes, event.calls,
        # TCP_STATES[event.last_state], TCP_STATES[event.state],
        1e-6*event.lat_ns,
    ))
    # print("%12s|%-12s" % (TCP_STATES[event.last_state], TCP_STATES[event.state]))
    # print("%-5d.%09d" % (event.ts_ns // 1000000000, event.ts_ns % 1000000000))
    # print(event.msgtype, event.lat_ns)

b.attach_kprobe(event="tcp_connect", fn_name="trace_tcp_connect")
b.attach_kprobe(event="tcp_set_state", fn_name="trace_tcp_set_state")
b.attach_kprobe(event="tcp_sendmsg_locked", fn_name="trace_tcp_sendmsg_locked")
b.attach_kretprobe(event="tcp_sendmsg_locked", fn_name="trace_ret_tcp_sendmsg_locked")
b.attach_kprobe(event="tcp_recvmsg", fn_name="trace_tcp_recvmsg")
b.attach_kretprobe(event="tcp_recvmsg", fn_name="trace_ret_tcp_recvmsg")
b.attach_kprobe(event="sock_def_readable", fn_name="trace_sock_def_readable")
b.attach_kprobe(event="tcp_check_space", fn_name="trace_tcp_check_space")
# b.attach_kprobe(event="sk_stream_write_space", fn_name="trace_writable")
# read events
b["events"].open_perf_buffer(print_event, page_cnt=64)
print("%15s %7s %15s:%-5s %15s:%-5s %9s/%-3s %13s" % (
    "TIMESTAMP", "MSGTYPE",
    "SADDR", "LPORT", "DADDR", "DPORT",
    "BYTES", "CNT", "LATENCY(ms)"
))
while 1:
    try:
        b.perf_buffer_poll()
    except KeyboardInterrupt:
        exit()
