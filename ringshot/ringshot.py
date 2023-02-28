#!/usr/bin/env python
"""ringshot

Taking packet snapshots as needed, one shot at a time, using TPACKET_V3. Only
works on Linux.

packet capture will only be taken when stdin of this script is available.

Copyright (c) 2023, Ping He.
License: MIT
"""

import struct
import socket
import ctypes as ct
import mmap
from itertools import chain
import argparse
import time
import datetime
import select
import sys
import os
import re
from contextlib import closing, ExitStack
import logging
import subprocess


logger = logging.getLogger(__name__)

# uapi/linux/if_ether.h
ETH_P_IP = 0x0800   # should work for our scenario 
ETH_P_ALL = 0x0003  # but who knows? maybe someone need to catch'em all

# linux/socket.h
SOL_PACKET = 263

# uapi/linux/if_packet.h
PACKET_RX_RING = 5
PACKET_VERSION = 10
TPACKET_V3 = 2
TP_STATUS_KERNEL = 0

# uapi/asm-generic/mman.h
MAP_LOCKED = 0x2000

# https://www.tcpdump.org/linktypes.html
LINKTYPE_ETHERNET = 1
LINKTYPE_LINUX_SLL2 = 276


class tpacket_bd_ts(ct.Structure):
    _fields_ = [
        ("ts_sec",          ct.c_uint32),
        ("ts_usec_or_nsec", ct.c_uint32),
    ]


class tpacket_hdr_v1(ct.Structure):
    _fields_ = [
        ("block_status",        ct.c_uint32),
        ("num_pkts",            ct.c_uint32),
        ("offset_to_first_pkt", ct.c_uint32),
        ("blk_len",             ct.c_uint32),
        ("seq_num",             ct.c_uint64),
        ("ts_first_pkt",        tpacket_bd_ts),
        ("ts_last_pkt",         tpacket_bd_ts),
    ]


class tpacket_block_desc(ct.Structure):
    _fields_ = [
        ("version",         ct.c_uint32),
        ("offset_to_priv",  ct.c_uint32),
        ("bh1",             tpacket_hdr_v1),
    ]


class tpacket_hdr_variant1(ct.Structure):
    _fields_ = [
        ("tp_rxhash",       ct.c_uint32),
        ("tp_vlan_tci",     ct.c_uint32),
        ("tp_vlan_tpid",    ct.c_uint16),
        ("tp_padding",      ct.c_uint16),
    ]


class tpacket3_hdr(ct.Structure):
    _fields_ = [
        ("tp_next_offset",  ct.c_uint32),
        ("tp_sec",          ct.c_uint32),
        ("tp_nsec",         ct.c_uint32),
        ("tp_snaplen",      ct.c_uint32),
        ("tp_len",          ct.c_uint32),
        ("tp_status",       ct.c_uint32),
        ("tp_mac",          ct.c_uint16),
        ("tp_net",          ct.c_uint16),
        ("hv1",             tpacket_hdr_variant1),
        ("tp_padding",      ct.c_uint8 * 8),
    ]


# This one is only used to fill SLL2 fields, not used for bind
class sockaddr_ll(ct.Structure):
    _fields_ = [
        ("sll_family",   ct.c_uint16),
        ("sll_protocol", ct.c_uint16),
        ("sll_ifindex",  ct.c_int32),
        ("sll_hatype",   ct.c_uint16),
        ("sll_pkttype",  ct.c_uint8),
        ("sll_halen",    ct.c_uint8),
        ("sll_addr",     ct.c_uint8 * 8),
    ]


def ctstr(structure):
    """debug function that converts ct structure to string"""
    if logger.level <= logging.DEBUG:
        args = []
        for k, _ in structure._fields_:
            v = getattr(structure, k)
            if isinstance(v, ct.Structure):
                v = ctstr(v)
            args.append('%s=%s' % (k, v))
        
        components = [str(structure), '(', ','.join(args)  , ')']

        return ''.join(components)
    return ""

def pcap_write_file_header(
    f,
    magic_number=0xa1b2c3d4,
    version_major=2,
    version_minor=4,
    thiszone=0,
    sigfigs=0,
    snaplen=65535,
    network=LINKTYPE_ETHERNET,
):
    header = struct.pack("IHHiIII", magic_number, version_major, version_minor,
                                     thiszone, sigfigs, snaplen, network)
    f.write(header)


def pcap_write_rec_header(
    f, ts_sec, ts_usec, incl_len, orig_len
):
    f.write(struct.pack("IIII", ts_sec, ts_usec, incl_len, orig_len))


def set_sock_tpacket_v3(
    s,
    tp_block_size,
    tp_block_nr,
    tp_frame_size,
    tp_frame_nr,
    tp_retire_blk_tov=0,
    tp_sizeof_priv=0,
    tp_feature_req_word=0,  # only for TP_FT_REQ_FILL_RXHASH which we don't need
):
    """ Set a pcap socket to tpacket_v3
    """
    s.setsockopt(SOL_PACKET, PACKET_VERSION, struct.pack('I', TPACKET_V3))
    tpreq = struct.pack('IIIIIII',
                        tp_block_size, tp_block_nr, tp_frame_size, tp_frame_nr,
                        tp_retire_blk_tov, tp_sizeof_priv, tp_feature_req_word)
    s.setsockopt(SOL_PACKET, PACKET_RX_RING, tpreq)


class Loop():
    def __init__(self, subproc, outf, ring,
                 shot_sink, keep_blocks, cadance=0.1):
        logger.debug('initiating Loop(%s, %s, %s, %s, %s, %s)', 
                     subproc, outf, ring, shot_sink, keep_blocks, cadance)
        self.subproc = subproc
        self.outf = outf
        self.ring = ring
        self.shot_sink = shot_sink
        self.keep_blocks = keep_blocks
        self.cadance = cadance
        # self.ep = select.epoll()
        self.ep = select.poll()
        self.inputs = []

    @property
    def inf(self):
        return self.subproc.stdout

    def on_painf(self):
        logger.debug('maintaining ring')
        self.ring.keep(self.keep_blocks)

    def on_inf(self):
        logger.debug('dealing with input')
        self.shot_sink.consume_shot(self.ring)
        infno = self.inf.fileno()
        outfno = self.outf.fileno()
        # logger.debug('inf: %s outf: %s', infno, outfno)
        # we try to use sendfile for efficiency
        # if not self.inputs:  # makes sure our inputs are not already backed up
        #     while True:
        #         try:
        #             os.sendfile(infno, outfno, None, 4096)
        #         except BlockingIOError:
        #             break

        # excess input are read into memory, then will be written when outf
        # available
        while True:
            try:
                assert not os.get_blocking(infno)
                self.inputs.append(os.read(infno, 4096))
            except BlockingIOError:  # there, no more input
                break

        self.ep.register(outfno, select.POLLOUT)

    def on_outf(self):
        # we play nicly on outf, as timing of it is low priority, don't want it
        # to block
        logger.debug('writing output')
        outfno = self.outf.fileno()
        while self.inputs:
            data = self.inputs.pop(0)
            try:
                # self.outf.write(data)
                os.write(outfno, data)
            except BlockingIOError:
                # we put it back :(
                self.inputs.insert(0, data)

        if not self.inputs:
            self.ep.unregister(outfno)

    def run(self):
        infno = self.inf.fileno()
        outfno = self.outf.fileno()
        painfno = self.ring.s.fileno()
        os.set_blocking(infno, False)
        os.set_blocking(outfno, False)
        ep = self.ep
        ep.register(infno, select.POLLIN)
        ep.register(painfno, select.POLLIN)
        filenos = set()
        while self.subproc.poll() == None:
            logger.debug('polling')
            before_timer = time.monotonic()
            filenos |= set(fileno for fileno, _ in ep.poll(self.cadance))
            logger.debug('filenos polled: %s', filenos)
            if infno in filenos:
                filenos.remove(infno)
                self.on_inf()
                # ep.modify(infno, inf_events)
                continue
            elif outfno in filenos:
                filenos.remove(outfno)
                self.on_outf()
                continue
            elif painfno in filenos:
                filenos.remove(painfno)
                self.on_painf()
                # we ration rapid painf maintenance

            dt = before_timer - time.monotonic()
            if dt < self.cadance:
                time.sleep(self.cadance - dt)

        logger.info('subproc exited with %d', self.subproc.returncode)
        while(self.inputs):
            self.on_outf()
            time.sleep(self.cadance)
        return self.subproc.returncode

    def close(self):
        # self.ep.close()
        pass


class ShotSink(object):
    # TODO: detect device type instead of assuming ethernet
    def __init__(self, cooked=False):
        
        self.current_file = None
        self.cooked = cooked

    def filename(self):
        """generate a filename"""
        return 'mycap.%s.pcap' % datetime.datetime.utcnow().strftime('%Y%m%d%H%M%S.%f')

    def newfile(self):
        f = open(self.filename(), 'wb', buffering=0)

        return f

    def cook(self, pd):
        # https://github.com/the-tcpdump-group/libpcap/blob/master/pcap/sll.h
        ll = ct.cast(ct.byref(pd, ct.sizeof(tpacket3_hdr)), ct.POINTER(sockaddr_ll)).contents
        logger.debug('cooking %s', ctstr(ll))
        # ll = sockaddr_ll.from_buffer(pd, ct.sizeof(tpacket3_hdr))
        return struct.pack('HxxIHBB8s',
                           ll.sll_protocol, ll.sll_ifindex, ll.sll_hatype,
                           ll.sll_pkttype, ll.sll_halen, bytes(ll.sll_addr))

    def consume_pd(self, pd):
        logger.debug('consuming pd %s', ctstr(pd))
        data = ct.cast(ct.byref(pd, pd.tp_mac),
                       ct.POINTER(ct.c_uint8 * pd.tp_snaplen)
                      ).contents
        plen = pd.tp_len
        psnaplen = pd.tp_snaplen
        logger.debug('original plen: %s, psnaplen: %s', plen, psnaplen)
        cooked = None
        if self.cooked:
            cooked = self.cook(pd)
            plen += len(cooked)
            psnaplen += len(cooked)
            logger.debug('cooked plen: %s, psnaplen: %s', plen, psnaplen)

        pcap_write_rec_header(
            self.current_file,
            pd.tp_sec, pd.tp_nsec // 1000, plen, psnaplen)

        if cooked:
            self.current_file.write(cooked)

        self.current_file.write(data)
        logger.debug('written')

    def consume_shot(self, ring):
        shotfile = self.current_file
        if ring.gapped:
            shotfile = None

        if not shotfile:
            shotfile = self.newfile()
            network = LINKTYPE_LINUX_SLL2 if self.cooked else LINKTYPE_ETHERNET
            pcap_write_file_header(shotfile, thiszone=time.timezone, network=network)
            self.current_file = shotfile

        for pd in ring.shot():
            self.consume_pd(pd)

    def close(self):
        if self.current_file:
            self.current_file.close()


class Ring(object):
    def __init__(self,
        block_size, block_nr, frame_size, retire_blk_tov,
        ifname, socktype, sockproto=ETH_P_ALL,
    ):
        logger.debug('starting Ring(%s, %s, %s, %s, %s, %s, %s)',
                     block_size, block_nr, frame_size, retire_blk_tov,
                     ifname, socktype, sockproto)
        stack = ExitStack()
        frame_nr = block_size // frame_size * block_nr
        s = socket.socket(socket.AF_PACKET, socktype, socket.htons(sockproto))
        stack.enter_context(s)
        try:
            if ifname:
                af_addr = (ifname, sockproto)
                s.bind(af_addr)

            set_sock_tpacket_v3(s,
                                block_size, block_nr, frame_size, frame_nr,
                                retire_blk_tov)
            mm = mmap.mmap(s.fileno(), block_size * block_nr,
                        flags=mmap.MAP_SHARED | MAP_LOCKED)
            stack.enter_context(mm)
        except Exception as e:
            stack.__exit__(type(e), e, e.__traceback__)

        self.exit_stack = stack
        self.s = s
        self.mm = mm
        self.block_size = block_size
        self.blocks = block_nr
        self.first_hold = 0
        self.cur_blkid = 0
        self._gapped = False

    def __enter__(self):
        return self

    def __exit__(self , *args):
        self.exit_stack.__exit__(*args)

    @property
    def gapped(self):
        return self._gapped

    def get_bd(self, blkid):
        assert 0 <= blkid < self.blocks, 'got blkid %d' % blkid
        return tpacket_block_desc.from_buffer(self.mm, self.block_size * blkid)

    def shot(self):
        """yields all frames and advance"""
        blkid = self.first_hold
        # blk = self.get_block(blkid)
        # bd = tpacket_block_desc.from_buffer(blk)
        bd = self.get_bd(blkid)
        blkids = chain(range(self.first_hold, self.blocks),
                       range(0, self.first_hold))
        # we will consume at most the entire ring in the shot, not more
        for blkid in blkids:
            bd = self.get_bd(blkid)
            logger.debug("bd: %s", ctstr(bd))
            if bd.bh1.block_status == TP_STATUS_KERNEL:
                break

            copytype = ct.c_uint8 * bd.bh1.blk_len
            copy = copytype.from_buffer_copy(ct.cast(ct.byref(bd), ct.POINTER(copytype)).contents)

            pd = tpacket3_hdr.from_buffer(copy, bd.bh1.offset_to_first_pkt)
            bd.bh1.block_status = TP_STATUS_KERNEL
            logger.debug('got pd: %s', ctstr(pd))
            yield pd
            while pd.tp_next_offset:
                pd = ct.cast(ct.byref(pd, pd.tp_next_offset), ct.POINTER(tpacket3_hdr)).contents
                logger.debug('got pd: %s', ctstr(pd))
                yield pd

        self.first_hold = blkid
        self.cur_blkid = blkid
        self._gapped = False

    def keep(self, keep_blocks):
        """advance cur_blk, and clear excessive blocks"""
        assert 0 <= keep_blocks < self.blocks
        removed = 0
        advanced = 0

        keeping = self.cur_blkid - self.first_hold
        if keeping < 0:
            keeping += self.blocks

        assert 0 <= keeping < self.blocks

        pbd = self.get_bd(self.cur_blkid)
        while pbd.bh1.block_status != TP_STATUS_KERNEL and keeping < self.blocks:
            keeping += 1
            self.cur_blkid += 1
            self.cur_blkid %= self.blocks
            advanced += 1
            pbd = self.get_bd(self.cur_blkid)

        
        pbd = self.get_bd(self.first_hold)
        while keeping > keep_blocks:
            # TODO: warning if there's packet loss
            pbd.bh1.block_status = TP_STATUS_KERNEL
            keeping -= 1
            self.first_hold += 1
            self.first_hold %= self.blocks
            self._gapped = True
            removed += 1
            pbd = self.get_bd(self.first_hold)

        logger.debug('keep removed %d blocks, advanced %d blocks', removed, advanced)

def po2int(txt):
    """allow K, M, G suffixed sizes"""
    m = re.match(r'^(0|[1-9]\d*)([KMG]?)$', txt)
    if not m:
        raise ValueError('invalid po2 size %s' % txt)

    SCALEMAP = {'K': 1024, 'M': 1024 * 1024, 'G': 1024 * 1024 * 1024, '': 1}
    base, scale = m.groups()
    return int(base) * SCALEMAP[scale]


def main():
    parser = argparse.ArgumentParser('ringshot')
    parser.add_argument('--block-size', type=po2int, default='64K',
                        help='block size of ringbuf, default is 64K')
    parser.add_argument('--blocks', type=po2int, default='8K',
                        help='number of blocks in ringbuf, default is 8k')
    parser.add_argument('--frame-size', type=po2int, default='256',
                        help='frame size of ringbuf, default is 256 bytes')
    parser.add_argument('--block-timeout-ms', type=int, default=0,
                        help='retire block timeout in msecs, default to 0 '
                             '(calculated by kernel)')
    parser.add_argument('-i', '--interface',
                        help='interface name, '
                             'default to capture all')
    parser.add_argument('--hold-ratio', type=int, default=50,
                        help='always hold ratio*blocks until shot, '
                             'in percentage, default to 50')
    parser.add_argument('-v', '--verbose', action='count', default=0,
                        help='increase verbosity')
    parser.add_argument('command', nargs='+',
                        help='command to run that informs ringshot of shots')
    args = parser.parse_args()
    verbosity_arr = [logging.WARNING, logging.INFO]
    verbosity = logging.DEBUG
    if args.verbose < len(verbosity_arr):
        verbosity = verbosity_arr[args.verbose]

    logging.basicConfig(level=verbosity, format="%(asctime)s %(levelname)s %(message)s")
    logger.info('starting ringshot')
    socktype = socket.SOCK_DGRAM
    cooked = True
    if args.interface:
        socktype = socket.SOCK_RAW
        cooked = False

    ring = Ring(args.block_size, args.blocks, args.frame_size,
                args.block_timeout_ms, args.interface, socktype)

    hold_ratio = args.hold_ratio
    if not (1 < hold_ratio < 100):
        raise ValueError('hold-ratio must be between 1 and 99')

    keep_blocks = hold_ratio * args.blocks // 100
    if not keep_blocks > 0:
        raise ValueError('no blocks are kept with the blocks and hold_ratio')

    shot_sink = ShotSink(cooked=cooked)

    with subprocess.Popen(args.command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT) as proc:
        loop = Loop(proc, sys.stdout, ring, shot_sink, keep_blocks)
        with ring, closing(loop), closing(shot_sink):
            retcode = loop.run()
            logger.info('subprocess exited with %d', retcode)


if __name__=='__main__':
    main()
