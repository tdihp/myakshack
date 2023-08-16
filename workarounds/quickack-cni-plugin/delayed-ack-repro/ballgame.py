import os
import socket
import select
import logging
from contextlib import ExitStack, closing
from collections import namedtuple
from functools import total_ordering
from time import sleep, monotonic
import struct
import heapq


logger = logging


class ProtocolError(Exception):
    pass


class Data(namedtuple('Data',
                      'session_id,latms,loops,pings,pongs,thisloop,thisball')):
    @staticmethod
    def decode(data):
        if not data.endswith(b'\r\n'):
            raise ProtocolError('invalid Data format, no trailing newline')
        try:
            return Data._make(map(int, data[:-2].split(b',')))
        except Exception as e:
            raise ProtocolError('invalid Data format') from e

    def encode(self):
        return ','.join(map(str, self)).encode('ascii') + b'\r\n'


def _server_flow(req, now):
    """takes in data, yields (response, ts) or None,
    exits when entire flow ends, raises ProtocolError on accidents
    ts is the write time scheduled, response is the data, alternatively None
    means now pending remote update
    """
    if req.session_id <= 0:
        raise ProtocolError('must use positive session_id: %s' % str(req))
    
    if req.latms < 0:
        raise ProtocolError('latms must be positive or zero: %s' % str(req))

    if req.pings < 1:
        raise ProtocolError('pings must >= 1: %s' % str(req))

    if req.pongs < 0:
        raise ProtocolError('pings must >= 0: %s' % str(req))

    if req.thisloop != 0:
        raise ProtocolError('thisloop != 0, potential leak: %s' % str(req))
    
    if req.thisball != 0:
        raise ProtocolError('thisball != 0, potential leak: %s' % str(req))

    start_ping = 1
    for loop in range(req.loops):
        for ping in range(start_ping, req.pings):
            now, update = yield None
            if update != req._replace(thisloop=loop, thisball=ping):
                raise ProtocolError('invalid ping: %s, session %s'
                                    % (str(update), str(req)))

        for pong in range(req.pongs):
            now = yield (now + req.latms / 1000,
                         req._replace(thisloop=loop, thisball=pong))

        start_ping = 0


def server_flow():
    now, req = yield None
    yield from _server_flow(req, now)


def client_flow(session_id, latms, loops, pings, pongs):
    req = Data(session_id, latms, loops, pings, pongs, 0, 0)
    now = yield req
    start_ping = 1
    for loop in range(loops):
        for ping in range(start_ping, pings):
            now = yield (now + latms/1000,
                         req._replace(thisloop=loop, thisball=ping))

        for pong in range(pongs):
            now, update = yield None
            if update != req._replace(thisloop=loop, thisball=pong):
                raise ProtocolError('invalid pong: %s, session %s'
                                    % (str(update), str(req)))

        start_ping = 0


@total_ordering
class Session(object):
    def __init__(self, sk, it, now):
        self.sk = sk
        self._it = it
        self.write = None
        self.write_time = float('inf')
        self.session_id = '?'
        self.start_time = now
        result = it.send(None)
        if result is not None:
            # write-start sessions
            self.write = result
            self.write_time = now
            self.session_id = self.write.session_id

    @property
    def fd(self):
        return self.sk.fileno()

    def on_read(self, now):
        buffers = []
        # assert self.sk.getblocking() == False
        logger.debug('session reading %r', self)
        while True:
            try:
                data = self.sk.recv(256)
                if not data:
                    break
                buffers.append(data)
            except BlockingIOError:
                break

        updates = b''.join(buffers).splitlines(keepends=True)
        logger.debug('got incoming %s from session %r', updates, self)
        for update in updates:
            data = Data.decode(update)
            if self.session_id == '?':
                self.session_id = data.session_id
            self._on_read(now, data)

    def _on_read(self, now, update):
        if self.write:
            raise ProtocolError('expecting writing, instead got input')

        result = self._it.send((now, update))
        if result is not None:
            self.write_time, self.write = result

    def on_write(self, now):
        if not self.write:
            raise ProtocolError('hit on_write when not in writing mode')

        while self.write_time <= now:
            try:
                payload = self.write.encode()
                logger.debug('writing payload %r', payload)
                self.sk.send(payload)
            except BlockingIOError:
                return

            result = self._it.send(now)
            if result is None:
                self.write_time = float('inf')
                self.write = None
                break
            else:
                self.write_time, self.write = result

    def __lt__(self, other):
        if not isinstance(other, Session):
            raise TypeError('Session object is only comparible with Session')

        return self.write_time < other.write_time

    def __repr__(self):

        return 'Session(id=%s, %r)' % (self.session_id, self.sk)


class Nudge(object):
    """data structure to quickly do complicated timeout logic"""
    def __init__(self, now):
        self.cycle = 0
        self.timeline = [[now, self.cycle, set()]]
        self.key2cycle = {}

    def advance(self, now, lookback):
        """returns a list of all keys in retired cycles"""
        self.cycle += 1
        key2cycle = self.key2cycle
        timeline = self.timeline
        timeline.append((now, self.cycle, set()))
        to_check = set()
        purge_cycle = -1
        while timeline[0][0] < (now - lookback):
            _, purge_cycle, keys = timeline.pop(0)
            to_check |= keys
            # logger.debug('purge cycle: %d', purge_cycle)

        # if to_check:
        #     logger.debug('timeout fds: %s', to_check)

        return [key for key in to_check 
                if key in key2cycle and key2cycle[key] <= purge_cycle]

    def nudge(self, key):
        _, cycle, bunch = self.timeline[-1]
        bunch.add(key)
        self.key2cycle[key] = cycle

    def remove(self, key):
        if key in self.key2cycle:
            del self.key2cycle[key]


DEFAULT_EVS = select.EPOLLIN|select.EPOLLRDHUP

class Loop(object):
    def __init__(self, max_wait=0.1, timeout=10, tcp_nodelay=False):
        self.ep = select.epoll()
        self.wq = []
        self.max_wait=max_wait
        self.listen_sk = None
        self.sessdict = {}
        self.timeout=10
        self.nudge = Nudge(0)
        self.tcp_nodelay = tcp_nodelay

    def init_socket(self, s):
        s.setblocking(False)
        if self.tcp_nodelay:
            s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)

    @property
    def listen_fd(self):
        return self.listen_sk.fileno() if self.listen_sk else None

    def accept(self):
        assert self.listen_sk
        s = self.listen_sk
        now = monotonic()
        while True:
            try:
                conn, addr = s.accept()
            except BlockingIOError:
                break

            self.init_socket(conn)
            logging.info('new connection established: %s', addr)
            newsess = Session(conn, server_flow(), now)
            self.add_session(newsess)

    def connect(self, ipaddr, port, *args, **kwargs):
        now = monotonic()
        sk = socket.socket(socket.AF_INET,
                           socket.SOCK_STREAM | socket.SOCK_NONBLOCK)
        self.init_socket(sk)
        newsess = Session(sk, client_flow(*args, **kwargs), now)
        try:
            logger.info('opening connection for %r', newsess)
            sk.connect((ipaddr, port))
        except BlockingIOError:
            pass

        self.add_session(newsess)

    def close(self):
        if self.listen_sk:
            self.listen_sk.close()

        for sess in list(self.sessdict.values()):
            self.remove_session(sess, destroy=True)

        self.ep.close()

    def start_server(self, ipaddr, port):
        sk = socket.socket(socket.AF_INET,
                           socket.SOCK_STREAM | socket.SOCK_NONBLOCK)
        # sk.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        sk.bind((ipaddr, port))
        # sk.setblocking(False)
        sk.listen()
        newfd = sk.fileno()
        self.listen_sk = sk
        self.ep.register(newfd, DEFAULT_EVS)
        logger.info('server hosting: %s', sk.getsockname())

    def add_session(self, session):
        logger.info('new session: %r', session)
        self.sessdict[session.fd] = session
        if session.write:
            logger.debug('write session with data: %r, time: %s', session.write, session.write_time)
            heapq.heappush(self.wq, (session.write_time, session.fd))

        self.ep.register(session.fd, DEFAULT_EVS)

    def remove_session(self, session, destroy=False):
        logger.debug('remove session %r', session)
        del self.sessdict[session.fd]
        self.ep.unregister(session.fd)
        self.nudge.remove(session.fd)
        s = socket.socket(fileno=session.fd)
        if destroy:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack('ii', 1, 0))

        s.close()

    def resolve_session_event(self, session, event, now):
        fd = session.fd
        ep = self.ep

        if event & (select.EPOLLHUP | select.EPOLLERR):
            if event & select.EPOLLHUP:
                logger.warning('session closed, %r', session)
            else:
                assert event & select.EPOLLERR
                logger.warning('connection error, %r', session)
            self.remove_session(session, destroy=True)
            return

        elif event & select.EPOLLRDHUP:
            logger.info('remote closed connection, %r', session)
            self.remove_session(session)
            return

        elif event & select.EPOLLIN:
            session.on_read(now)

        elif event & select.EPOLLOUT:
            session.on_write(now)
            ep.modify(fd, DEFAULT_EVS)

        if session.write:
            heapq.heappush(self.wq, (session.write_time, fd))
        
        self.nudge.nudge(fd)

    def handle_wq(self, now):
        wq = self.wq
        ep = self.ep
        sessdict = self.sessdict
        # logger.debug('wq: %s', wq)
        while wq and wq[0][0] <= now:
            _, fd = heapq.heappop(wq)
            if fd not in sessdict:
                continue

            ep.modify(fd, DEFAULT_EVS|select.EPOLLOUT)

    def handle_timeout(self, now):
        timeout_fds = self.nudge.advance(now, self.timeout)
        if timeout_fds:
            logger.debug('timeout fds: %s', timeout_fds)
        for fd in timeout_fds:
            session = self.sessdict[fd]
            logger.warning('session timeout %r', session)
            self.remove_session(session, destroy=True)

    def cycle(self):
        # logger.debug('cycle start')
        # we mark possible writes as writeble first
        now = monotonic()
        sessdict = self.sessdict
        wq = self.wq
        ep = self.ep
        self.handle_timeout(now)
        self.handle_wq(now)
        to_wait = self.max_wait
        if wq:
            dt = wq[0][0] - now
            if dt < to_wait:
                to_wait = dt

        evlist = ep.poll(to_wait)
        if evlist:
            logger.debug('evlist: %s', evlist)

        now = monotonic()
        for fd, event in evlist:
            if fd == self.listen_fd:
                assert event == select.EPOLLIN
                logger.debug('listen_fd fired')
                self.accept()
                continue

            session = sessdict[fd]
            try:
                self.resolve_session_event(session, event, now)
            except StopIteration:
                logger.info('session finished, took %fs closing %r',
                            now - session.start_time, session)
                self.remove_session(session)
            except Exception:
                logger.exception('failed due to exception, closing session %r',
                                 session)
                self.remove_session(session, destroy=True)
            # else:
                # logger.debug('nudging session %r', session)
                # self.nudge.nudge(fd)

    def loop(self):
        while self.sessdict or self.listen_fd:
            self.cycle()

        logger.info('emptied, quitting')


class Server(Loop):
    def __init__(self, host, port, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.start_server(host, port)

    def run(self):
        self.loop()        


class Client(Loop):
    def __init__(self, remote, port, concurrency=1, total=None, flow_args=None,
                 *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._remote = remote
        self._port = port
        self._concurrency = concurrency
        self._total = total
        self._started = 0
        self._flow_args = flow_args or {}

    def add_new_conn(self):
        diff = self._concurrency - len(self.sessdict)
        for i in range(diff):
            if not self._total or self._started < self._total:
                self._started += 1
                self.connect(self._remote, self._port, self._started,
                             **self._flow_args)

    def cycle(self):
        super().cycle()
        self.add_new_conn()

    def run(self):
        self.add_new_conn()
        self.loop()


def main():
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument('--port', type=int, default='7777',
                        help='protocol port, defaults to 7777')
    parser.add_argument('--nagle', action='store_false', dest='tcp_nodelay',
                        help="sockets to enable Nagle's algorithm, "
                             "i.e., disable TCP_NODELAY")
    parser.add_argument('-v', '--verbose', action='count', default=0,
                        help='increase verbosity, default to WARNING')
    subparsers = parser.add_subparsers(dest='subcommand', required=True)
    server_parser = subparsers.add_parser('server',
                                          help='start server')
    server_parser.add_argument('--host', default='0.0.0.0',
                               help='listening IP, default to 0.0.0.0')
    client_parser = subparsers.add_parser('client', help='start client')
    client_parser.add_argument('remote', help='server IP address')
    client_parser.add_argument('-c', '--concurrency', type=int, default='1',
                               help='concurrent connections')
    client_parser.add_argument('--loops', type=int, default='10',
                               help='total loops, defaults to 10')
    client_parser.add_argument('--latms', type=int, default='0',
                               help='latency introduced in ms, default to 0')
    client_parser.add_argument('--pings', type=int, default='1',
                               help='pings in a loop')
    client_parser.add_argument('--pongs', type=int, default='1',
                               help='pongs in a loop')
    client_parser.add_argument('--total', type=int, default='1',
                               help='total requests, default to 1, set 0 for infinite')

    args = parser.parse_args()
    logging_levels= [logging.WARNING, logging.INFO, logging.DEBUG]
    logging_level = logging_levels[min(args.verbose, len(logging_levels) - 1)]
    logging.basicConfig(level=logging_level, format='%(asctime)s %(levelname)s:%(message)s')
    loop_args = {
        'tcp_nodelay': args.tcp_nodelay
    }
    if args.subcommand == 'server':
        server = Server(args.host, args.port, **loop_args)
        with closing(server):
            server.run()

    elif args.subcommand == 'client':
        flow_args = {
            'latms': args.latms,
            'loops': args.loops,
            'pings': args.pings, 
            'pongs': args.pongs
        }
        client = Client(args.remote, args.port, concurrency=args.concurrency,
                        total=args.total, flow_args=flow_args, **loop_args)
        with closing(client):
            client.run()


if __name__ == '__main__':
    main()
