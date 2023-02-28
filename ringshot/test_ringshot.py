from ringshot import *
from ipaddress import ip_address, ip_network, ip_interface
import unittest
import sys
from subprocess import run
import shutil
import tempfile
import pprint
import logging
import ctypes as ct
import time
import socket
import io
import dpkt  # we use dpkt for checking our pcap

REQUIRED_EXE = ['ip', 'tcpdump']
DUMMYIF_IF = ip_interface('10.83.84.1/24')
DUMMYIP_NAME = 'dummy8384'
DEST_ADDR = ip_address('10.83.84.82')


def setUpModule():
    for exe in REQUIRED_EXE:
        if not shutil.which(exe):
            raise RuntimeError('this test suite requires %s' % exe)

    try:
        run("ip link add %s type dummy" % DUMMYIP_NAME, shell=True, check=True)
    except Exception as e:
        raise RuntimeError('cannot create dummy interface, this requeres CAP_NET_ADMIN') from e

    try:
        run("ip addr add %s dev %s" % (DUMMYIF_IF, DUMMYIP_NAME),
            shell=True, check=True)
        run("ip link set %s up" % DUMMYIP_NAME, shell=True, check=True)
    except Exception as e:
        run("ip link delete %s" % DUMMYIP_NAME, shell=True, check=True)
        raise


def tearDownModule():
    run("ip link delete %s" % DUMMYIP_NAME, shell=True, check=True)


class DummySink(ShotSink):
    def __init__(self, *args, **kw):
        super().__init__(*args, **kw)
        self.myfile = io.BytesIO()

    def newfile(self):
        return self.myfile


class TestRingshot(unittest.TestCase):
    testdata = [
                dict(port=1111, data=b'foobar1111'),
                dict(port=1111, data=b'foobar2222'),
                dict(port=1111, data=b'foobar3333'),
            ]
    def _assert_packets(self, dpkg_packets):
        self.assertEqual(len(dpkg_packets), len(self.testdata))
        for p, d in zip(dpkg_packets, self.testdata):
            ipp = p.data
            self.assertIsInstance(p.data, dpkt.ip.IP)
            self.assertEqual(ipp.udp.dport, d['port'])
            pprint.pprint(ipp)
            self.assertEqual(ip_address(ipp.dst), DEST_ADDR)
            self.assertEqual(ipp.data.data, d['data'])

    def _fire_data(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        dest_ip = str(DEST_ADDR)
        for d in self.testdata:
            sock.sendto(d['data'], (dest_ip, d['port']))

    def test_shot_raw_direct(self):
        ring = Ring(4096, 16, 256, 100, DUMMYIP_NAME,
                    socket.SOCK_RAW)
        
        with ring:
            self._fire_data()
            time.sleep(.3)  # 100ms should help
            pds = list(ring.shot())
            self.assertEqual(len(pds), len(self.testdata))
            dpkt_packets = [
                dpkt.ethernet.Ethernet(bytes(
                    ct.cast(ct.byref(pd, pd.tp_mac),
                            ct.POINTER(ct.c_uint8 * pd.tp_snaplen)).contents
                ))
                for pd in pds]
            self._assert_packets(dpkt_packets)

    def test_shot_raw_consumed(self):
        ring = Ring(4096, 16, 256, 100, DUMMYIP_NAME,
                    socket.SOCK_RAW)
        with ring:
            sink = DummySink(cooked=False)
            self._fire_data()
            time.sleep(.3)  # 100ms should help
            sink.consume_shot(ring)
            f = sink.myfile
            f.seek(0)
            reader = dpkt.pcap.Reader(f)
            dpkt_packets = list(dpkt.ethernet.Ethernet(buf) for ts, buf in reader)
            self._assert_packets(dpkt_packets)

    def test_shot_cooked_consumed(self):
        ring = Ring(4096, 16, 256, 100, DUMMYIP_NAME,
                    socket.SOCK_DGRAM)
        with ring:
            sink = DummySink(cooked=True)
            self._fire_data()
            time.sleep(.3)  # 100ms should help
            sink.consume_shot(ring)
            f = sink.myfile
            f.seek(0)
            reader = dpkt.pcap.Reader(f)
            # dpkt_packets = []
            # for ts, buf in reader:
            #     dpkt.sll2.SLL2(buf)
            dpkt_packets = list(dpkt.sll2.SLL2(buf) for ts, buf in reader)
            print(dpkt_packets)
            self._assert_packets(dpkt_packets)



if __name__ == '__main__':
    logging.basicConfig(level=logging.DEBUG)
    unittest.main()
