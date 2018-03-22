import asyncio
import hashlib
import logging
import optparse
import random
import struct
import sys

MAX_CHAR = 1024 * 8
HEAD_SIZE = 3

CHAP_SALT = b'A'
CHAP_HASH = b'B'
CHAP_RESULT = b'C'
BIND_REQ = b'D'
BIND_RES = b'E'
CONN_REQ = b'F'
CONN_RES = b'G'
DATA = b'H'
DIS_CONN = b'I'


def add_header(raw, type):
    header = [raw.__len__(), type]
    pack = struct.pack('!Hc', *header)
    return pack + raw


def create_nonce(msg):
    return hashlib.sha224(msg.encode()).hexdigest()


def get_chap_response(username, password, raw):
    username = username.encode()
    name_len = len(username)
    salt = raw[1:].decode()

    hash_val = create_nonce(password + salt).encode()
    hash_len = len(hash_val)

    name_len = struct.pack('!B', *[name_len])
    hash_len = struct.pack('!B', *[hash_len])
    return name_len + username + hash_len + hash_val


def get_chap_result(raw, storage, salt):
    name_len = raw[0]
    username = raw[:name_len + 1]
    hash_val = raw[name_len + 1:]
    password = storage.get(username)
    md5 = create_nonce(password + salt)

    res = 0
    if md5 == hash_val:
        res = 1
    return struct.pack('!B', res), res


def get_chap_salt():
    salt = str(random.randint(0, 9999)) + 'salt'
    raw = salt.encode()
    length = len(raw)
    pack = struct.pack('!B', length)
    return pack + raw, salt


# python async_lcx.py -m slave -l 127.0.0.1 -p 8000 -r 127.0.0.1 -P 3500
class Forwarder(object):
    def __init__(self, l_ip, l_port, r_ip, r_port):
        self.l_ip = l_ip
        self.l_port = l_port
        self.r_ip = r_ip
        self.r_port = r_port
        self.writer_dict = dict()
        self.loop = asyncio.get_event_loop()
        self.name = username
        self.pwd = password

    def run(self):
        self.loop.run_until_complete(
            self.start(self.loop)
        )

    async def start(self, loop):
        reader, writer = await asyncio.open_connection(
            self.r_ip, self.r_port, loop=loop
        )
        buffer = b''
        while True:
            raw = await reader.read(MAX_CHAR)  # read from server
            if not raw:
                logging.info(f'connection with server closed')
                return
            buffer += raw
            while True:
                if len(buffer) < HEAD_SIZE:
                    break
                pack = struct.unpack('!Hc', buffer[:HEAD_SIZE])
                body_size = pack[0]
                if len(buffer) < HEAD_SIZE + body_size:
                    break
                raw = buffer[HEAD_SIZE:HEAD_SIZE + body_size]
                logging.info(f'receive message {len(raw)} bytes from server')

                await self.dispatch(loop, writer, pack, raw, pack[1])

                buffer = buffer[HEAD_SIZE + body_size:]

    async def dispatch(self, loop, r_writer, pack, raw, type):
        if type == CHAP_SALT:
            raw = get_chap_response(self.name, self.pwd, raw)
            logging.info(f'send {raw} to  server')
            r_writer.write(add_header(raw, CHAP_HASH))
            await r_writer.drain()

        elif type == CHAP_RESULT:
            result = raw[0]
            if not result:
                logging.info('closed connection')
                r_writer.close()

        elif type == BIND_RES:
            pass

        elif type == CONN_RES:
            l_reader, l_writer = await asyncio.open_connection(
                self.l_ip, self.l_port, loop=loop
            )
            self.writer_dict[index] = l_writer
            asyncio.run_coroutine_threadsafe(
                self.reader(l_reader, r_writer, index),
                loop
            )

        elif type == DATA:
            index = pack[1]
            writer = self.writer_dict.get(index)
            writer.write(raw)
            await writer.drain()
            logging.info(f'send message to control port')

        elif type == DIS_CONN:
            pass
        else:
            pass

    # TODO index to conn id
    async def reader(self, reader, writer, index):
        logging.info(f'create new reader and writer for {index}')
        while True:
            raw = await reader.read(MAX_CHAR)  # read from client
            if not raw:
                self.writer_dict.pop(index)
                logging.info(f'connection with {index} closed')
                writer.write(add_header(struct.pack('!H', index), DIS_CONN))
                await writer.drain()

            logging.info(f'send {len(raw)} bytes to {index}')

            writer.write(add_header(raw, DATA))
            await writer.drain()


# python async_lcx.py -m listen -p 4500 -P 3500
class Listener(object):

    def __init__(self, port, user_dict):
        self.s_port = port
        self.slave_writer_dict = dict()  # {port: writer}
        self.master_writer_dict = dict()
        self.user_dict = user_dict  # {name: pwd}
        self.loop = asyncio.get_event_loop()
        self.index = 0

    def run(self):
        servers = []

        slave_task = asyncio.start_server(
            self.slave_listen,
            '0.0.0.0', self.s_port,
            loop=self.loop
        )

        servers.append(self.loop.run_until_complete(slave_task))

        try:
            logging.info('start listening connection')
            self.loop.run_forever()
        except KeyboardInterrupt:
            for server in servers:
                server.close()
                self.loop.run_until_complete(server.wait_closed())
            self.loop.close()

    async def slave_listen(self, reader, writer):
        address = writer.get_extra_info('peername')

        raw, salt = get_chap_salt()
        writer.write(add_header(raw, CHAP_SALT))
        await writer.drain()
        logging.info(f'send CHAP challenge to {address[0]}')

        try:
            raw = await asyncio.wait_for(reader.read(MAX_CHAR), 5)
        except asyncio.futures.TimeoutError:
            logging.info(f'auth timeout with slave, auth FAILED')
            writer.close()
            return

        buffer = b''
        while True:
            data = await reader.read(MAX_CHAR)
            if not data:
                logging.info(f'close connection with slave')
                writer.close()
                return

            buffer += data
            while True:
                if len(buffer) < HEAD_SIZE:
                    break

                pack = struct.unpack('!Hc', buffer[:HEAD_SIZE])
                body_size = pack[0]

                if len(buffer) < HEAD_SIZE + body_size:
                    break

                raw = buffer[HEAD_SIZE:HEAD_SIZE + body_size]
                type = pack[1]
                if type == CHAP_HASH:
                    reply, auth = get_chap_result(raw, self.user_dict, salt)
                    if auth:
                        logging.info(f'slave has been authenticated')
                        writer.write(reply)
                        await writer.drain()
                    else:
                        writer.write(reply)
                        await writer.drain()
                        writer.close()
                        logging.info('close connection with slave')
                        return

                elif type == BIND_REQ:
                    req_id, port = struct.unpack('!2H', raw)
                    master_task = asyncio.start_server(
                        self.master_listen,
                        '0.0.0.0', port,
                        loop=self.loop
                    )
                    asyncio.run_coroutine_threadsafe(master_task, self.loop)
                    server.sockets[0].getsockname()

                elif type == CONN_RES:
                    pass
                elif type == DATA:
                    if writer not in self.slave_writer_dict:
                        writer.close()
                        return
                    logging.info(f'receive {len(raw)} bytes from slave')
                    master_writer = self.master_writer_dict.get(index)
                    logging.info(f'send message to {index}')
                    master_writer.write(raw)
                    await master_writer.drain()

                elif type == DIS_CONN:
                    self.master_writer_dict.pop(index)
                    master_writer.close()
                    logging.info(f'close connection with {index}')
                else:
                    pass

                buffer = buffer[HEAD_SIZE + body_size:]

    async def master_listen(self, reader, writer):
        index = self.index
        self.index += 1
        self.master_writer_dict[index] = writer
        logging.info(f'new connect at {index}')

        self.slave_writer_dict.write(add_header(raw, CONN_REQ))
        await self.slave_writer_dict.drain()
        logging.info(f'send connection request')

        while True:
            raw = await reader.read(MAX_CHAR)  # read from control port
            if not raw:
                logging.info(f'connection with{index} closed')
                return
            logging.info(f'server received {len(raw)} bytes from {index}')
            # TODO 封装raw
            self.slave_writer_dict.write(add_header(raw, DATA))
            await self.slave_writer_dict.drain()
            logging.info(f'send msg {len(raw)} bytes to slave')


def parse_user(s_users):
    user_list = s_users.split(',')
    if len(user_list) == 1:
        return s_users.split(':')
    user_dict = dict()
    for user in user_list:
        username, password = user.split(':')
        user_dict[username] = password
    return user_dict


if __name__ == '__main__':
    parser = optparse.OptionParser()

    parser.add_option(
        '-l', '--local', dest='local',
        help='Local IP address and port (eg> 127.0.0.1:3000)')
    parser.add_option(
        '-r', '--remote', dest='remote',
        help='Remote IP address and port (eg> 127.0.0.1:4000)')
    parser.add_option(
        '-p', '--port',
        type='int', dest='port',
        help="Listen> port to listen slaves connection\n Slave> port that listener to open"
    )
    parser.add_option(
        '-u', '--users',
        dest='users', help='approved user')
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
        users = parse_user(opts.users)
        Listener(
            opts.port,
            users
        ).run()

    elif opts.mode == 'slave':
        username, password = parse_user(opts.users)
        Forwarder(
            opts.local_ip, opts.local_port,
            opts.remote_ip, opts.remote_port,
            username, password
        ).run()
    else:
        print('Please specify which mode you want to use!')
