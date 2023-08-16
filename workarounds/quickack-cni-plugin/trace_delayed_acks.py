#!/usr/bin/python
# -*- coding: utf-8 -*-

"""
Script aiding identifying a delayed ack on Linux.

Copyright (c) 2023, Ping He.
License: MIT
"""

import argparse
from ipaddress import ip_address, v6_int_to_packed
import socket
import time
import datetime
import threading
import ctypes as ct
from bcc import BPF


bpf_text = r"""
#include <net/sock.h>
#include <linux/socket.h>
#include <net/inet_connection_sock.h>
#include <linux/tcp.h>

BPF_PERF_OUTPUT(events);

struct data_t {
    /* general info */
    u64 timestamp_ns;
    u16 family;
    u16 sport;
    u16 dport;
    u16 reserved_general;
    u32 saddr;
    u32 daddr;
    u8 saddr6[16];
    u8 daddr6[16];
    /* 64bit aligned */
    /* inet_csk */
    u8 quick;
    u8 pingpong;
    u16 reserved_inet_csk;
    /* 32bit aligned */
    /* tcp_sk */
    u32 snd_nxt;
    u32 rcv_nxt;
};

static inline bool filter_sport(struct sock *sk) {
#ifdef FILTER_SPORT
    return sk->sk_num != FILTER_SPORT;
#endif
    return false;
}

static inline bool filter_dport(struct sock *sk) {
#ifdef FILTER_DPORT
    return sk->sk_dport != htons(FILTER_DPORT);
#endif
    return false;
}

static inline bool filter_ipv4(struct sock *sk) {
    /* we provide the BE unsigned representation */
#ifdef FILTER_IPV4_SADDR
    if (sk->sk_rcv_saddr != FILTER_IPV4_SADDR) return true;
#endif
#ifdef FILTER_IPV4_DADDR
    if (sk->sk_daddr != FILTER_IPV4_DADDR) return true;
#endif
    return false;
}

static inline bool ipv6cmp(struct in6_addr *addr1, struct in6_addr *addr2) {
#if __UAPI_DEF_IN6_ADDR_ALT
    for (int i = 0; i < 4; ++i) {
        if (addr1->s6_addr32[i] != addr2->s6_addr32[i])
            return true;
    }
#else
    for (int i = 0; i < 16; ++i) {
        if (addr1->s6_addr[i] != addr2->s6_addr[i])
            return true;
    }
#endif
    return false;
}

static inline bool filter_ipv6(struct sock *sk) {
#ifdef FILTER_IPV6_SADDR
    struct in6_addr saddr6 = {};
    bpf_probe_read_kernel(&saddr6, sizeof(struct in6_addr),
        &sk->sk_v6_rcv_saddr);
    if (ipv6cmp((struct in6_addr*)(FILTER_IPV6_SADDR), &saddr6))
        return true;

#endif
#ifdef FILTER_IPV6_DADDR
    struct in6_addr daddr6 = {};
    bpf_probe_read_kernel(&daddr6, sizeof(struct in6_addr),
        &sk->sk_v6_daddr);
    if (ipv6cmp((struct in6_addr*)(FILTER_IPV6_DADDR), &daddr6))
        return true;
#endif
    return false;
}


int kprobe__tcp_send_delayed_ack(struct pt_regs *ctx, struct sock *sk)
{
    unsigned short family = sk->sk_family;
    if (
        true
#ifdef FILTER_ALLOW_IPV4
        && family != AF_INET
#endif 
#ifdef FILTER_ALLOW_IPV6
        && family != AF_INET6
#endif
    ) {
        return 0;
    }

    if (filter_sport(sk)) return 0;
    if (filter_dport(sk)) return 0;

    u64 now = bpf_ktime_get_ns();
    struct data_t data = {};
    if (family == AF_INET) {
        if (filter_ipv4(sk)) return 0;
        data.saddr = sk->sk_rcv_saddr;
        data.daddr = sk->sk_daddr;
    } else {
        if (filter_ipv6(sk)) return 0;
        bpf_probe_read_kernel(&data.saddr6, sizeof(struct in6_addr),
            &sk->sk_v6_rcv_saddr);
        bpf_probe_read_kernel(&data.daddr6, sizeof(struct in6_addr),
            &sk->sk_v6_daddr);
    }

    data.timestamp_ns = now;
    data.family = family;
    data.sport = sk->sk_num;
    u32 be_dport = sk->sk_dport;
    data.dport = ntohs(be_dport);
    data.quick = inet_csk(sk)->icsk_ack.quick;
    data.pingpong = inet_csk(sk)->icsk_ack.pingpong;
    data.snd_nxt = tcp_sk(sk)->snd_nxt;
    data.rcv_nxt = tcp_sk(sk)->rcv_nxt;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
};
"""

parser = argparse.ArgumentParser(
    description=__doc__,
    formatter_class=argparse.RawDescriptionHelpFormatter)

parser.add_argument('--sport', type=int, help='filter source port')
parser.add_argument('--dport', type=int, help='filter destination port')
parser.add_argument('--saddr', type=ip_address, help='filter source address')
parser.add_argument('--daddr', type=ip_address, help='filter dest address')
parser.add_argument('--no-ipv4', help='disable capturing ipv4')
parser.add_argument('--no-ipv6', help='disable capturing ipv6')
parser.add_argument('--ebpf', action='store_true',
                    help='prints ebpf code and exit')
parser.add_argument('duration', type=int, nargs='?',
                     help='capture duration in seconds, use keyboard '
                          'interrput when not specified')
args = parser.parse_args()

allow_ipv4 = True
allow_ipv6 = True
extra_defs = {}
if args.sport:
    extra_defs['FILTER_SPORT'] = str(args.sport)

if args.dport:
    extra_defs['FILTER_DPORT'] = str(args.dport)

def v6literal(addr):
    return '"' + ''.join(r'\x%02x' % c for c in v6_int_to_packed(int(addr))) + '"'

if args.saddr:
    if args.saddr.version == 4:
        allow_ipv6 = False
        extra_defs['FILTER_IPV4_SADDR'] = socket.htonl(int(args.saddr))
    else:
        allow_ipv4 = False
        extra_defs['FILTER_IPV6_SADDR'] = v6literal(args.saddr)

if args.daddr:
    if args.daddr.version == 4:
        allow_ipv6 = False
        extra_defs['FILTER_IPV4_DADDR'] = socket.htonl(int(args.daddr))
    else:
        allow_ipv4 = False
        extra_defs['FILTER_IPV6_DADDR'] = v6literal(args.daddr)

if args.no_ipv4:
    allow_ipv4 = False

if args.no_ipv6:
    allow_ipv6 = False

if not (allow_ipv4 or allow_ipv6):
    raise ValueError('both ipv4 and ipv6 are filtered, please refine filters')

if allow_ipv4:
    extra_defs['FILTER_ALLOW_IPV4'] = 1

if allow_ipv6:
    extra_defs['FILTER_ALLOW_IPV6'] = 1


bpf_text_rendered = '\n'.join('#define %s %s' % pair
                              for pair in extra_defs.items()) + bpf_text
if args.ebpf:
    print(bpf_text_rendered)
    exit()

b = BPF(text=bpf_text_rendered)
first_ts = BPF.monotonic_time()
first_ts_real = time.time()

def reltime(ts_ns):
    return 1e-9 * (ts_ns - first_ts)


def clocktime(ts_ns):
    return reltime(ts_ns) + first_ts_real


print('HH:MM:SS.000000 %21s - %21s  Q P %11s %11s' % ('SRC', 'DEST', 'SND_NXT', 'RCV_NXT'))
def callback(cpu, data, size, timefmt="%H:%M:%S.%f"):
    event = b["events"].event(data)
    if event.family == socket.AF_INET:
        saddr = str(ip_address(socket.ntohl(event.saddr)))
        daddr = str(ip_address(socket.ntohl(event.daddr)))
    else:
        saddr = ip_address(bytes(event.saddr6))
        daddr = ip_address(bytes(event.daddr6))

    print('%s %15s:%-5d - %15s:%-5d %2d %1d %11d %11d' % (
        datetime.datetime.fromtimestamp(clocktime(event.timestamp_ns)).strftime(timefmt),
        saddr,
        event.sport,
        daddr,
        event.dport,
        event.quick,
        event.pingpong,
        event.snd_nxt,
        event.rcv_nxt,
    ))


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
