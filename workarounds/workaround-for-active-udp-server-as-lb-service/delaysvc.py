"""
A very simple ping-pong testing with a delay.

How it works:

bootstrapping:
client sends 0 to server
server sends 1 to client
client sends 2 to server

each time server receives a 2:
after delay, server sends 1 to client
client sends 2 to server
"""

import asyncio
import logging
logger = logging.getLogger(__name__)


class CounterProtocol:
    def __init__(self, max_i, init_c):
        self.max_i = max_i
        self.init_c = init_c

    def connection_made(self, transport):
        self.transport = transport

    def datagram_received(self, data, addr):
        logger.info('got %s from %s', data, addr)
        c = int(data)
        if c >= self.max_i:
            logger.info('received packet reached max')
            self.on_max(addr)
        else:
            new_c = c + 1
            logger.info('reply with %s', new_c)
            self.transport.sendto(str(new_c).encode(), addr)

    def kickstart(self, addr=None):
        # this one assumes we already have the sock (connection_made)
        logger.info('kickstarting message %s to %s', self.init_c, addr)
        self.transport.sendto(str(self.init_c).encode(), addr)

    def on_max(self, addr):
        pass


class CounterServerProtocol(CounterProtocol):
    def __init__(self, max_i, init_c, delay):
        super().__init__(max_i, init_c)
        # self.init_c = init_c
        self.delay = delay

    def on_max(self, addr):
        loop = asyncio.get_running_loop()
        loop.call_later(self.delay, self.kickstart, addr)


class CounterClientProtocol(CounterProtocol):
    def connection_made(self, transport):
        super().connection_made(transport)
        self.kickstart()


async def server(addr, port, delay):
    logger.info("Starting UDP Counter Server")
    loop = asyncio.get_running_loop()
    transport, protocol = await loop.create_datagram_endpoint(
        lambda: CounterServerProtocol(2, 1, delay),
        local_addr=(addr, port))

    while True:
        await asyncio.sleep(3600)
 

async def client(addr, port):
    logger.info("Starting UDP Counter Client")
    loop = asyncio.get_running_loop()
    transport, protocol = await loop.create_datagram_endpoint(
        lambda: CounterClientProtocol(2, 0),
        remote_addr=(addr, port))

    while True:
        await asyncio.sleep(3600)


if __name__ == '__main__':
    import argparse
    logging.basicConfig(level=logging.DEBUG, format='%(asctime)s %(name)s %(message)s')
    parser = argparse.ArgumentParser(description='udp counter server/client')
    parser.add_argument('-s', '--server', action='store_true',
                        help='run server instead of client')
    parser.add_argument('-d', '--delay', type=int, default=150,
                        help='server delay (default 150 seconds) of secondary visits')
    parser.add_argument('addr', help='address')
    parser.add_argument('port', type=int, help='port number')

    args = parser.parse_args()
    if args.server:
        asyncio.run(server(args.addr, args.port, args.delay))
    else:
        asyncio.run(client(args.addr, args.port))
