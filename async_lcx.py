import asyncio
import hashlib
import json
import logging
import optparse
import random
import struct
import sys

MAX_CHAR = 1024 * 8
MAX_PAC = MAX_CHAR + 512
HEAD_SIZE = 4


def add_header(raw):
    header = [raw.__len__()]
    pack = struct.pack('!1I', *header)
    return pack + raw


def create_nonce(msg):
    return hashlib.sha224(msg.encode()).hexdigest()


class CHAP(object):
    def __init__(self, obj):
        self.id = 0
        self.local_storage = obj
        self.rand_dict = dict()

    def get_challenge(self, username):
        rand = str(random.randint(0, 9999)) + 'salt'
        self.id += 1
        data = {
            'code': 1,
            'id': self.id,
            'random': rand,
            'username': username
        }
        self.rand_dict[self.id] = rand
        string = json.dumps(data)
        return string

    def get_response(self, username, data):
        msg_id = data['id']
        rand = data['random']
        password = self.local_storage.get(data['username'])
        string = str(msg_id) + rand + password
        md5 = create_nonce(string)
        reply = {
            'code': 2,
            'id': msg_id,
            'hash': md5,
            'username': username
        }
        string = json.dumps(reply)
        return string

    def get_auth_result(self, data):
        msg_id = data['id']
        username = data['username']
        rand = self.rand_dict.get(msg_id)
        password = self.local_storage.get(username)
        print(username, password)
        string = str(msg_id) + rand + password
        md5 = create_nonce(string)

        hash_value = data['hash']
        reply = {'id': msg_id}
        if md5 == hash_value:
            reply['code'] = 3
            reply['message'] = 'authentication ok'
        else:
            reply['code'] = 4
            reply['message'] = 'authentication failed'
        string = json.dumps(reply)
        return string, md5 == hash_value


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
        try:
            from slave_config import config
            self.chap = CHAP(config['database'])
            self.name = config['username']
        except ImportError:
            print('you should has a slave_config first!')
            exit()

    def run(self):
        self.main_loop.run_until_complete(
            self.start(self.main_loop)
        )

    async def start(self, loop):
        p_reader, p_writer = await asyncio.open_connection(
            self.p_ip, self.p_port, loop=loop
        )

        data = await p_reader.read(MAX_CHAR)
        msg = json.loads(data.decode())
        logging.info(f'receive {data.decode()} from server')

        string = self.chap.get_response(self.name, msg)
        logging.info(f'send {string} to  server')
        p_writer.write(string.encode())
        await p_writer.drain()

        data = await p_reader.read(MAX_CHAR)
        msg = json.loads(data.decode())
        logging.info(msg['message'])
        if msg['code'] == 4:
            logging.info('closed connection')
            p_writer.close()

        while True:
            raw = await p_reader.read(MAX_PAC)  # read from server
            print(raw)
            if not raw:
                logging.info(f'connection with server closed')
                return
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
            raw = await reader.read(MAX_CHAR)  # read from client
            if not raw:
                self.writer_dict.pop(address)
                logging.info(f'connection with {address[0]}:{address[1]} closed')
                return
            data = {
                'ip': address[0],
                'port': address[1],
                'msg': raw.decode(errors='ignore')
            }
            raw = json.dumps(data).encode(errors='ignore')
            logging.info(f'send {raw} to {address[0]}:{address[1]}')

            writer.write(add_header(raw))
            await writer.drain()


# python async_lcx.py -m listen -p 4500 -P 3500
class Listener(object):

    def __init__(self, s_port, d_port):
        self.s_port = s_port
        self.d_port = d_port
        self.slave_writer = None
        self.writer_dict = dict()
        try:
            from server_config import config
            self.chap = CHAP(config['database'])
            self.name = config['username']
        except ImportError:
            print('you should has a server_config first!')
            exit()

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

        msg = self.chap.get_challenge(self.name)
        writer.write(msg.encode(errors='ignore'))
        await writer.drain()
        logging.info(f'send CHAP challenge to {address[0]}')

        try:
            raw = await asyncio.wait_for(reader.read(MAX_CHAR), 5)
        except asyncio.futures.TimeoutError:
            logging.info(f'auth timeout with slave, auth FAILED')
            writer.close()
            return

        reply = raw.decode(errors='ignore')
        data = json.loads(reply)
        reply, auth = self.chap.get_auth_result(data)

        if auth:
            logging.info(f'slave has been authenticated')
            writer.write(reply.encode(errors='ignore'))
            await writer.drain()
        else:
            writer.write(reply.encode(errors='ignore'))
            await writer.drain()
            writer.close()
            logging.info('close connection with slave')
            return

        self.slave_writer = writer
        buffer = b''
        while True:
            data = await reader.read(1024)
            if data:
                buffer += data
                while True:
                    if len(buffer) < HEAD_SIZE:
                        break

                    pack = struct.unpack('!1I', buffer[:HEAD_SIZE])
                    body_size = pack[0]

                    if len(buffer) < HEAD_SIZE + body_size:
                        break

                    raw = buffer[HEAD_SIZE:HEAD_SIZE + body_size]

                    logging.info(f'receive {raw} from slave')
                    data = json.loads(raw.decode(errors='ignore'))
                    address = (data['ip'], data['port'])
                    writer = self.writer_dict.get(address)
                    logging.info(f'send message to {address[0]}:{address[1]}')
                    writer.write(data['msg'].encode(errors='ignore'))
                    await writer.drain()
                    buffer = buffer[HEAD_SIZE + body_size:]

    async def master_listen(self, reader, writer):
        address = writer.get_extra_info('peername')
        logging.info(f'new connect at {address[0]}:{address[1]}')
        self.writer_dict[address] = writer

        while True:
            raw = await reader.read(MAX_PAC)  # read from control port
            if not raw:
                logging.info(f'connection with{address[0]}:{address[1]} closed')
                return

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
    opts, args = parser.parse_args()

    if len(sys.argv) == 1 or len(args) > 0:
        parser.print_help()
        exit()

    logging.basicConfig(level=logging.INFO, format='%(name)-11s: %(message)s')

    if opts.mode == 'listen':
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
