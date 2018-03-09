import asyncio
import json
import logging
import optparse
import socket

import sys
from chap import CHAP

local_storage = {
    'test1': '123456',
    'test2': '654321'
}


# python async_lcx.py -m slave -l 127.0.0.1 -p 3000 -r 127.0.0.1 -P 3500
class Forwarder(object):
    def __init__(self, ip, port, r_ip, r_port):
        self.s_ip = ip
        self.s_port = port
        self.d_ip = r_ip
        self.d_port = r_port

    def run(self):
        d_sk = socket.socket()
        d_sk.connect((self.d_ip, self.d_port))
        # s_sk = socket.socket()
        # s_sk.connect((self.s_ip, self.s_port))
        while True:
            data = d_sk.recv(1024)
            msg = data.decode()
            print(msg)
            # s_sk.send(data)


# python async_lcx.py -m listen -p 4500 -P 3500
# python async_lcx.py -m listen -p 4500 -P 3500 -E -C 5500
class Listener(object):

    def __init__(self, s_port, d_port, chap=False, chap_port=0):
        self.s_port = s_port
        self.d_port = d_port
        self.slave_sk = None
        self.enable_chap = chap
        if self.enable_chap:
            self.authenticated_set = set()
            self.chap_port = chap_port
            self.chap = CHAP(local_storage)

    def run(self):
        self.slave_conn()

        loop = asyncio.get_event_loop()
        servers = []

        trans_task = asyncio.start_server(
            self.master_listen,
            '127.0.0.1', self.s_port,
            loop=loop
        )
        servers.append(loop.run_until_complete(trans_task))
        if self.enable_chap:
            logging.info('enable chap')
            auth_task = asyncio.start_server(
                self.auth_listen,
                '127.0.0.1', self.chap_port,
                loop=loop
            )
            servers.append(loop.run_until_complete(auth_task))

        try:
            logging.info('start listening connection')
            loop.run_forever()
        except KeyboardInterrupt:
            for server in servers:
                server.close()
                loop.run_until_complete(server.wait_closed())
            loop.close()

    def slave_conn(self):
        slave = socket.socket()
        slave.bind(('127.0.0.1', self.d_port))
        slave.listen()
        print(f'waiting for connection at port{self.d_port}')
        conn, address = slave.accept()
        print(f'connection at {address[0]}:{address[1]}')
        self.slave_sk = conn

    async def master_listen(self, reader, writer):
        address = writer.get_extra_info('peername')
        logging.info(f'new connect at {address[0]}:{address[1]}')

        while not self.enable_chap or address[0] in self.authenticated_set:
            raw = await reader.read(1024)
            data = json.loads(raw.decode())
            msg = data['msg']
            logging.info(f'server received {msg} from {address[0]}')
            if msg == 'exit':
                break
            self.slave_sk.send(raw)
            logging.info(f'send msg {raw} to slave')
        data = {
            'username': 'server',
            'msg': 'Close connection from server'
        }
        writer.write(json.dumps(data).encode())
        await writer.drain()
        logging.info(f'Close connection with {address[0]}')
        writer.close()

    async def auth_listen(self, reader, writer):
        address = writer.get_extra_info('peername')
        logging.info(f'new auth connection at {address[0]}')
        while True:
            msg = self.chap.get_challenge('server')
            writer.write(msg.encode())
            await writer.drain()
            logging.info(f'send CHAP challenge to {address[0]}')
            raw = await reader.read(1024)
            reply = raw.decode()
            data = json.loads(reply)
            reply, auth = self.chap.get_auth_result(data)
            if auth:
                self.authenticated_set.add(address[0])
                logging.info(f'{address[0]} has been authenticated')
                writer.write(reply.encode())
                await writer.drain()
            else:
                writer.write(reply.encode())
                await writer.drain()
                break
            await asyncio.sleep(10)
        self.authenticated_set.remove(address[0])
        writer.close()


if __name__ == '__main__':
    parser = optparse.OptionParser()

    parser.add_option(
        '-l', '--local-ip', dest='local_ip',
        help='Local IP address to bind to')
    parser.add_option(
        '-p', '--local-port',
        type='int', dest='local_port',
        help='Local port to bind to')
    parser.add_option(
        '-r', '--remote-ip', dest='remote_ip',
        help='Local IP address to bind to')
    parser.add_option(
        '-P', '--remote-port',
        type='int', dest='remote_port',
        help='Remote port to bind to')
    parser.add_option(
        '-m', '--mode', dest='mode',
        help='Set mode'
    )
    parser.add_option(
        '-C', '--chap-port',
        type='int', dest='chap_port',
        help='Specify the CHAP port'
    )
    parser.add_option(
        '-E', '--enable-chap',
        action='store_true', dest='chap',
        help='enable CHAP'
    )
    opts, args = parser.parse_args()

    if len(sys.argv) == 1 or len(args) > 0:
        parser.print_help()
        exit()

    logging.basicConfig(level=logging.INFO, format='%(name)-11s: %(message)s')

    if opts.mode == 'listen':
        if opts.chap:
            Listener(
                opts.local_port,
                opts.remote_port,
                chap=True,
                chap_port=opts.chap_port
            ).run()
        else:
            Listener(
                opts.local_port,
                opts.remote_port,
            ).run()

    elif opts.mode == 'slave':
        Forwarder(
            opts.local_ip, opts.local_port,
            opts.remote_ip, opts.remote_port
        ).run()
    else:
        print('Please specify which mode you want to use!')
