#!/usr/bin/env python
"""A basic sample that uses TPACKET_V2 to take packet capture

This example only works on Linux

see https://docs.kernel.org/networking/packet_mmap.html
also thanks Suraj Signh for the nice pcap file tutorial: https://www.bitforestinfo.com/blog/01/13/save-python-raw-tcpip-packet-into-pcap-files.html
https://www.kernel.org/doc/html/latest/networking/filter.html

See netsniff-ng (http://netsniff-ng.org/) and libpcap for in prduction
TPACKET_V3 ring based capture.

Using Python to capture packets is great for ad-hoc capturing, bind
with tools such as bcc, also no need for compiling.

Copyright (c) 2023, Ping He.
License: MIT
"""

import struct
import socket
import ctypes as ct
import mmap
from itertools import cycle
import time

# uapi/linux/if_ether.h
ETH_P_IP = 0x0800

# linux/socket.h
SOL_PACKET = 263

# uapi/linux/if_packet.h
PACKET_RX_RING = 5
PACKET_VERSION = 10
TPACKET_V2 = 1

# uapi/asm-generic/mman.h
MAP_LOCKED = 0x2000


# uapi/linux/if_packet.h
class tpacket2_hdr(ct.Structure):
    _fields_ = [
        ("tp_status",    ct.c_uint32),
        ("tp_len",       ct.c_uint32),
        ("tp_snaplen",   ct.c_uint32),
        ("tp_mac",       ct.c_uint16),
        ("tp_net",       ct.c_uint16),
        ("tp_sec",       ct.c_uint32),
        ("tp_nsec",      ct.c_uint32),
        ("tp_vlan_tci",  ct.c_uint32),
        ("tp_vlan_tpid", ct.c_uint32),
        ("tp_padding",   ct.c_uint8 * 4),
    ]


# uapi/linux/if_packet.h
def tpacket_align(x, alignment=16):
    return (x + alignment - 1) & ~alignment


# uapi/linux/if_packet.h
# class sockaddr_ll(ct.Structure):
#     _fields_ = [
#         ("sll_family",   ct.c_uint16),
#         ("sll_protocol", ct.c_uint16),
#         ("sll_ifindex",  ct.c_int32),
#         ("sll_hatype",   ct.c_uint16),
#         ("sll_pkttype",  ct.c_uint8),
#         ("sll_halen",    ct.c_uint8),
#         ("sll_addr",     ct.c_uint8 * 8),
#     ]


def pcap_write_header(
    f,
    magic_number=0xa1b2c3d4,
    version_major=2,
    version_minor=4,
    thiszone=0,
    sigfigs=0,
    snaplen=65535,
    network=1,  # LINKTYPE_ETHERNET
):
    header = struct.pack("@IHHiIII", magic_number, version_major, version_minor,
                                     thiszone, sigfigs, snaplen, network)
    f.write(header)


def pcap_write_record(
    f, ts_sec, ts_usec, incl_len, orig_len, data
):
    f.write(struct.pack("@IIII", ts_sec, ts_usec, incl_len, orig_len))
    f.write(data)


def iter_frame(mm, tp_frame_size, tp_frame_nr):
    for offset in cycle(range(0, tp_frame_size * tp_frame_nr, tp_frame_size)):
        # yield mm[i:i+tp_frame_size]
        yield tpacket2_hdr.from_buffer(mm, offset)


def consume_pkt(hdr):
    for k, _ in hdr._fields_:
        print("%s: %s" % (k, getattr(hdr, k)))

    data = ct.cast(ct.byref(hdr, hdr.tp_mac), ct.POINTER(ct.c_char))[:hdr.tp_snaplen]
    return hdr.tp_sec, hdr.tp_nsec // 1000, hdr.tp_snaplen, hdr.tp_len, data


def main():
    tp_block_size = 4096
    tp_block_nr = 16
    tp_frame_size = 256
    tp_frame_nr = tp_block_size // tp_frame_size * tp_block_nr
    tpreq = struct.pack('IIII',
                        tp_block_size, tp_block_nr, tp_frame_size, tp_frame_nr)
    
    # ETH_P_IP instead of ETH_P_ALL as we are not interested in non-ip packets
    s = socket.socket(socket.PF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_IP))
    s.setsockopt(SOL_PACKET, PACKET_VERSION, struct.pack('@I', TPACKET_V2))
    s.setsockopt(SOL_PACKET, PACKET_RX_RING, tpreq)

    mm = mmap.mmap(s.fileno(), tp_block_size * tp_block_nr,
                   flags=mmap.MAP_SHARED | MAP_LOCKED)

    with open('mymmap.pcap', 'wb') as f:
        pcap_write_header(f)
        for hdr in iter_frame(mm, tp_frame_size, tp_frame_nr):
            while hdr.tp_status == 0:
                # consider to use poll
                time.sleep(0.1)

            rec = consume_pkt(hdr)
            pcap_write_record(f, *rec)
            # return the block to kernel
            hdr.tp_status = 0


if __name__=='__main__':
    main()
