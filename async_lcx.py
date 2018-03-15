import asyncio
import json
import logging
import optparse

import sys

from chap import CHAP

local_storage = {
    'test1': '123456',
    'test2': '654321'
}

MAX_CHAR = 1024


# python async_lcx.py -m slave -l 127.0.0.1 -p 3000 -r 127.0.0.1 -P 3500
# python async_lcx.py -m slave -l 10.3.8.211 -p 80 -r 127.0.0.1 -P 3500
class Forwarder(object):
    def __init__(self, ip, port, r_ip, r_port):
        self.s_ip = ip
        self.s_port = port
        self.p_ip = r_ip
        self.p_port = r_port
        self.writer_dict = dict()
        self.main_loop = asyncio.get_event_loop()

    def run(self):
        self.main_loop.run_until_complete(
            self.start(self.main_loop)
        )

    async def start(self, loop):
        p_reader, p_writer = await asyncio.open_connection(
            self.p_ip, self.p_port, loop=loop
        )

        while True:
            print('39 loop')
            raw = b''
            while True:
                print('42 loop')
                temp = await p_reader.read(MAX_CHAR)
                if not temp:
                    logging.info(f'connection with server closed')
                    return
                raw += temp
                if len(temp) < MAX_CHAR:
                    break
            logging.info(f'receive message {raw} from server')
            data = json.loads(raw.decode(errors='ignore'))
            ip = data['ip']
            port = data['port']
            address = (ip, port)
            writer = self.writer_dict.get(address)
            if not writer:
                s_reader, s_writer = await asyncio.open_connection(
                    self.s_ip, self.s_port, loop=loop
                )
                logging.info(f'create new reader and writer for {address[0]}:{address[1]}')
                self.writer_dict[address] = s_writer
                writer = s_writer

                asyncio.run_coroutine_threadsafe(
                    self.read(s_reader, p_writer, address),
                    loop
                )
            writer.write(data['msg'].encode(errors='ignore'))
            await writer.drain()
            logging.info('send message to control port')

    async def read(self, reader, writer, address):
        logging.info(f'start new reader task for {address[0]}:{address[1]}')
        while True:
            print('72 loop')
            raw = b''
            while True:
                print('75 loop')
                temp = await reader.read(MAX_CHAR)
                if not temp:
                    self.writer_dict.pop(address)
                    logging.info(f'connection with {address[0]}:{address[1]} closed')
                    return
                raw += temp
                if len(temp) < MAX_CHAR:
                    break
            data = {
                'ip': address[0],
                'port': address[1],
                'msg': raw.decode(errors='ignore')
            }
            raw = json.dumps(data).encode(errors='ignore')
            logging.info(f'send {raw} to {address[0]}:{address[1]}')
            writer.write(raw)
            await writer.drain()


# python async_lcx.py -m listen -p 4500 -P 3500
# python async_lcx.py -m listen -p 4500 -P 3500 -E -C 5500
class Listener(object):

    def __init__(self, s_port, d_port, chap=False, chap_port=0):
        self.s_port = s_port
        self.d_port = d_port
        self.slave_writer = None
        self.enable_chap = chap
        self.writer_dict = dict()
        if self.enable_chap:
            self.authenticated_set = set()
            self.chap_port = chap_port
            self.chap = CHAP(local_storage)

    def run(self):
        loop = asyncio.get_event_loop()
        servers = []

        slave_task = asyncio.start_server(
            self.slave_listen,
            '0.0.0.0', self.d_port,
            loop=loop
        )
        servers.append(loop.run_until_complete(slave_task))

        trans_task = asyncio.start_server(
            self.master_listen,
            '0.0.0.0', self.s_port,
            loop=loop
        )
        servers.append(loop.run_until_complete(trans_task))

        if self.enable_chap:
            logging.info('enable chap')
            auth_task = asyncio.start_server(
                self.auth_listen,
                '0.0.0.0', self.chap_port,
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

    async def slave_listen(self, reader, writer):
        address = writer.get_extra_info('peername')
        logging.info(f'slave connected at port{address[1]}')
        self.slave_writer = writer

        while True:
            print('153 loop')
            raw = b''
            while True:
                print('156 loop')
                temp = await reader.read(MAX_CHAR)
                if not temp:
                    logging.info(f'connection with slave closed')
                    return
                raw += temp
                if len(temp) < MAX_CHAR:
                    break
            logging.info(f'receive {raw} from salve')
            data = json.loads(raw.decode(errors='ignore'))
            address = (data['ip'], data['port'])
            writer = self.writer_dict.get(address)
            logging.info(f'send message to {address[0]}:{address[1]}')
            writer.write(data['msg'].encode(errors='ignore'))
            await writer.drain()

    async def master_listen(self, reader, writer):
        address = writer.get_extra_info('peername')
        logging.info(f'new connect at {address[0]}:{address[1]}')
        self.writer_dict[address] = writer

        while not self.enable_chap or address[0] in self.authenticated_set:
            raw = b''
            while True:
                print('177 loop')
                temp = await reader.read(MAX_CHAR)
                if not temp:
                    logging.info(f'connection with{address[0]}:{address[1]} closed')
                    return
                raw += temp
                if len(temp) < MAX_CHAR:
                    break
            logging.info(f'server received {raw} from {address[0]}:{address[1]}')
            msg = raw.decode(errors='ignore')
            if msg == 'exit':
                break
            data = {
                'ip': address[0],
                'port': address[1],
                'msg': msg
            }

            raw = json.dumps(data).encode(errors='ignore')
            self.slave_writer.write(raw)
            await self.slave_writer.drain()
            logging.info(f'send msg {raw} to slave')

        raw = 'Close connection from server'.encode(errors='ignore')
        writer.write(raw)
        await writer.drain()
        logging.info(f'Close connection with {address[0]}:{address[1]}')
        writer.close()
        self.writer_dict.pop(address)

    async def auth_listen(self, reader, writer):
        address = writer.get_extra_info('peername')
        logging.info(f'new auth connection at {address[0]}')
        while True:
            print('208 loop')
            msg = self.chap.get_challenge('server')
            writer.write(msg.encode(errors='ignore'))
            await writer.drain()
            logging.info(f'send CHAP challenge to {address[0]}')

            try:
                raw = await asyncio.wait_for(reader.read(MAX_CHAR), 5)
            except asyncio.futures.TimeoutError:
                logging.info(f'auth timeout with {address[0]}, auth FAILED')
                break

            reply = raw.decode(errors='ignore')
            data = json.loads(reply)
            reply, auth = self.chap.get_auth_result(data)

            if auth:
                self.authenticated_set.add(address[0])
                logging.info(f'{address[0]} has been authenticated')
                writer.write(reply.encode(errors='ignore'))
                await writer.drain()
            else:
                writer.write(reply.encode(errors='ignore'))
                await writer.drain()
                break

            await asyncio.sleep(10)

        if address[0] in self.authenticated_set:
            self.authenticated_set.remove(address[0])
            logging.info(f'remove {address[0]} from authentication list')
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
