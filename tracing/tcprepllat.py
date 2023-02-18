#!/usr/bin/python
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

Following events are shown:



===  ======  ===================================================================
msg  mode    Description
===  ======  ===================================================================
C2E  both    connect to established
CLS  both    close
X2X  both    state failure, always delivered
I2R  both    incoming to read
W2I  client  write to incoming data
R2W  server  first read to first write
===  ======  ===================================================================

Glossary:

W,WT,WRT  writing call from start to end
  WS,WTS  start of write call
  WE,WTE  end of write call
  WA,WTA  write buffer available timing
  FA,FAK  all written packets are properly acked
  UW,UAW  unacked write, meaning fullack did not happen for this write
     UWS  unacked write start
     WSS  write sequence start, equal to first WTS
     WSE  write sequence end, equal to last WTE 
R,RD,RAD  reading call from start to end
  RS,RDS  start of read call
  RE,RDE  end of read call
  RA,RDA  incoming data available timing
     RSS  read sequence start, equal to first RDS
     RSE  read sequence end, equal to last RDE

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



WTA->WTS->WE->[WA->WT->WE...]->FA

reading payload:

[RA->]RD->RE->[RA->RD->RE...]

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

* FA can happen multiple times during a write, we should capture latency and
  write size and count of writes for it
* 

"""

from bcc import BPF
import argparse
import time
# from time import strftime, gmtime, localtime
import datetime
from ipaddress import ip_address

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
    "C2E", #/* connect to established */
    "CLS", #/* any close */
    "X2X", #/* any state failure */
    "I2R", #/* incoming to read */
    "W2I", #/* first write to incoming available */
    "R2W", #/* first read to first write */
]

parser = argparse.ArgumentParser(
    description="Trace tcp sock for timings slower than a threshold",
)

parser.add_argument("--ebpf", action="store_true")
args = parser.parse_args()

# pid = args.pid
debug = 1

# define BPF program
bpf_text = """
#include <linux/sched.h>
#include <net/sock.h>
#include <net/tcp_states.h>

#define MAX_SOCKS 65536
#define MIN_LAT_NS 0

enum state {
    MON,
    WRITING, // in writing, we don't update ts for any following writes
    READING,
};

enum mode {
    CLIENT,
    SERVER,
};

struct sock_state_t {
    u64 ts_ns;      
    u64 start_ns;  /* reused for connect and first write and first read */
    u64 readable_ns;  /* first readable before a read */
    u64 writable_ns;  /* first writable before a write */
    u64 latest_ns;  /* latest write/read */
    u64 latest_done_ns;  /* latest done write/read */
    enum state state;
    enum mode mode;
};

enum msgtype {
    C2E = 1, /* connect to established */
    CLS, /* any close */
    X2X, /* any state failure */
    I2R, /* incoming to read */
    W2I, /* first write to incoming available */
    R2W, /* first read to first write */
    D2W, /* last read to first write */
};

struct msg_t {
    //msginfo
    enum msgtype msgtype;
    u64 ts_ns;
    u64 lat_ns;
    u32 counts;
    u32 bytes;
    int last_state;
    int state;
    //netinfo
    u32 saddr;
    u32 daddr;
    u16 lport;
    u16 dport;
};

BPF_HASH(sockstatemap, struct sock *, struct sock_state_t, MAX_SOCKS);
BPF_HASH(writestatemap, u32, struct write_state_t);
BPF_PERF_OUTPUT(events);


static inline bool is_client(struct sock *sk) {
    u16 lport = sk->__sk_common.skc_num;
    u16 dport = sk->__sk_common.skc_dport;
    dport = ntohs(dport);
    if (dport == 443) { // TODO: make it arbitary condition
        return true;
    }
    return false;
}

static inline bool is_server(struct sock *sk) {
    return false;
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
    msg->last_state = sk->sk_state;
    msg->state = sk->sk_state;
    msg->saddr = sk->__sk_common.skc_rcv_saddr;
    msg->daddr = sk->__sk_common.skc_daddr;
    msg->lport = sk->__sk_common.skc_num;
    u16 dport = sk->__sk_common.skc_dport;
    msg->dport = ntohs(dport);
}

int trace_tcp_connect(struct pt_regs *ctx, struct sock *sk) {
    if (sk->__sk_common.skc_family != AF_INET) {
        return 0;
    }
    u64 now = bpf_ktime_get_ns();
    struct sock_state_t * sockstate = NULL;

    sockstate = try_tap(sk, true, false);
    if (sockstate != NULL) {
        sockstate->start_ns = now;
        sockstate->state = MON;
    }
    return 0;
}

int trace_tcp_set_state(struct pt_regs *ctx, struct sock *sk, int state) {
    if (sk->__sk_common.skc_family != AF_INET) {
        return 0;
    }
    u64 now = bpf_ktime_get_ns();
    u64 lat = 0;
    bool force_send = false;
    struct msg_t msg = {};
    struct sock_state_t * sockstate = sockstatemap.lookup(&sk);

    if (sockstate && sockstate->start_ns) {
        lat = now - sockstate->start_ns;
    }

    switch (state) {
        case TCP_ESTABLISHED:
            if (sockstate == NULL) {
                return 0;
            }
            sockstate->start_ns = 0;
            msg.msgtype = C2E;
            break;
        case TCP_SYN_SENT:
            return 0;
        case TCP_SYN_RECV:
            sockstate = try_tap(sk, false, true);
            if (sockstate != NULL) {
                sockstate->start_ns = now;
                sockstate->state = MON;
                sockstate->mode = SERVER;
            }
            return 0;
        case TCP_CLOSE:  // close
        case TCP_FIN_WAIT1:  // proactive close
        case TCP_CLOSE_WAIT:  // got fin from remote
        case TCP_LAST_ACK:
            if (sockstate == NULL) {
                return 0;
            }
            msg.msgtype = CLS;
            force_send = true;
            sockstatemap.delete(&sk);
            break;
        default:
            if (sockstate == NULL) {
                return 0;
            }
            msg.msgtype = X2X;
            force_send = true;
            // stop tracking as it is out of control
            sockstatemap.delete(&sk);
            break;
    }
    sockstate = NULL;
    if (lat >= MIN_LAT_NS || force_send) {
        // we fill in rest of the info here
        fill_msg(sk, &msg);
        msg.ts_ns = now;
        msg.lat_ns = lat;
        msg.state = state;
        events.perf_submit(ctx, &msg, sizeof(msg));
    }
    return 0;
}

int trace_tcp_sendmsg_locked(struct pt_regs *ctx, struct sock *sk, struct msghdr *msg, size_t size) {
    if (sk->__sk_common.skc_family != AF_INET) {
        return 0;
    }
    u64 now = bpf_ktime_get_ns();
    u64 lat = 0;
    struct sock_state_t * sockstate = sockstatemap.lookup(&sk);
    if (sockstate == NULL) {
        sockstate = try_tap(sk, true, true);
        if (sockstate == NULL) {
            return 0;
        }
    }
    if (sockstate->state != WRITING) {
        enum state last_state = sockstate->state;
        sockstate->state = WRITING;
        sockstate->start_ns = now;
        // TODO: for server, this need to add read to write msg
    }
    sockstate->latest_ns = now;
    // struct write_state_t writestate = {sk, size};
    // u64 pid_tgid = bpf_get_current_pid_tgid();
    // u32 tid = pid_tgid;
    // writestatemap.update(&tid, &writestate);
    return 0;
}

int trace_readable(struct pt_regs *ctx, struct sock *sk) {
    if (sk->__sk_common.skc_family != AF_INET) {
        return 0;
    }
    u64 now = bpf_ktime_get_ns();
    struct sock_state_t * sockstate = sockstatemap.lookup(&sk);
    if (sockstate == NULL) {
        return 0; /* we don't try to tap here, it might tap closing socks */
    }
    if (sockstate->readable_ns) {
        return 0;  /* only need first */
    }
    sockstate->readable_ns = now;
    u64 lat = 0;
    if (sockstate->start_ns) {
        lat = now - sockstate->start_ns;
    }
    if (lat > 0 && lat >= MIN_LAT_NS && sockstate->mode == CLIENT) {
        struct msg_t msg = {};
        msg.ts_ns = now;
        msg.msgtype = W2I;
        msg.lat_ns = lat;
        fill_msg(sk, &msg);
        events.perf_submit(ctx, &msg, sizeof(msg));
    }
    return 0;
}

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
    u64 lat = 0;
    if (sockstate->readable_ns) {
        lat = now - sockstate->readable_ns;
        sockstate->readable_ns = 0;
        if (lat >= MIN_LAT_NS) {
            struct msg_t msg = {};
            msg.ts_ns = now;
            msg.msgtype = I2R;
            msg.lat_ns = lat;
            fill_msg(sk, &msg);
            events.perf_submit(ctx, &msg, sizeof(msg));
        }
    }

    if (sockstate->state != READING) {
        enum state last_state = sockstate->state;
        /*
        if (sockstate->mode == CLIENT && last_state == WRITING)
        {
            lat = 0;
            if (sockstate->startns) {
                lat = now - sockstate->startns;
            }
            if (lat >= MIN_LAT_NS) {
                struct msg_t msg = {};
                msg.ts_ns = now;
                msg.msgtype = W2R;
                msg.lat_ns = lat;
                fill_msg(sk, &msg);
                events.perf_submit(ctx, &msg, sizeof(msg));
            }
        }
        */
        sockstate->state = READING;
        sockstate->start_ns = now;
    }
    sockstate->latest_ns = now;
    return 0;
}


/*
int trace_ret_tcp_sendmsg_locked(struct pt_regs *ctx) {
    u64 now = bpf_ktime_get_ns();
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 tid = pid_tgid;
    int ret = PT_REGS_RC(ctx);

    struct write_state_t *writestate = writestatemap.lookup(&tid);
    if (writestate == NULL) {
        return 0;
    }
    struct sock *sk = writestate->sk;
    size_t write_size = writestate->size;
    writestatemap.delete(&tid);
    struct sock_state_t *sockstate = sockstatemap.lookup(&writestate->sk);
    if (sockstate == NULL) {
        return 0;  // apparantly we don't care anymore
    }
    u64 lat = now - sockstate->start_ns;
    if (write_size == ret) {

    }
}
*/
"""


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
    print("%s %3s %15s:%-5d %15s:%-5d %12s|%-12s %8.3f" % (
        # strftime(timefmt, localtime(clocktime(event.ts_ns))),
        datetime.datetime.fromtimestamp(clocktime(event.ts_ns)).strftime(timefmt),
        MSG_TYPES[event.msgtype],
        # event.pid, event.comm.decode(), "%9d %16s" TODO: pid
        ip_address(event.saddr), event.lport,
        ip_address(event.daddr), event.dport,
        TCP_STATES[event.last_state], TCP_STATES[event.state],
        1e-6*event.lat_ns,
    ))
    # print("%12s|%-12s" % (TCP_STATES[event.last_state], TCP_STATES[event.state]))
    # print("%-5d.%09d" % (event.ts_ns // 1000000000, event.ts_ns % 1000000000))
    # print(event.msgtype, event.lat_ns)

b.attach_kprobe(event="tcp_connect", fn_name="trace_tcp_connect")
b.attach_kprobe(event="tcp_set_state", fn_name="trace_tcp_set_state")
b.attach_kprobe(event="tcp_sendmsg_locked", fn_name="trace_tcp_sendmsg_locked")
b.attach_kprobe(event="sock_def_readable", fn_name="trace_readable")
b.attach_kprobe(event="sk_stream_write_space", fn_name="trace_writable")
b.attach_kprobe(event="tcp_recvmsg", fn_name="trace_tcp_recvmsg")
# read events
b["events"].open_perf_buffer(print_event, page_cnt=64)
while 1:
    try:
        b.perf_buffer_poll()
    except KeyboardInterrupt:
        exit()
