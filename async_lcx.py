import asyncio
import hashlib
import logging
import optparse
import random
import struct
import sys


MAX_CHAR = 1024 * 8
# 消息格式 --> |message length: 2B | type: 1B| body |
HEAD_SIZE = 3

# | salt length: 1B | slat |
CHAP_SALT = b'A'
# | name length: 1B | name | hash length: 1B | hash |
CHAP_HASH = b'B'
# | result: 1B |
CHAP_RESULT = b'C'
# | port: 2B |
BIND_REQ = b'D'
# | result: 1B | port: 2B |
BIND_RES = b'E'
# | conn_id: 2B |
CONN_REQ = b'F'
# | result: 1B | conn_id: 2B |
CONN_RES = b'G'
# | conn_id: 2B | data |
DATA = b'H'
# | conn_id: 2B |
DIS_CONN = b'I'
# None
HEARTBEATS = b'J'


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
    username = raw[1:name_len + 1].decode()
    hash_val = raw[name_len + 2:].decode()
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


async def send_beats(writer):
    while True:
        await asyncio.sleep(3)
        writer.write(add_header(b'', HEARTBEATS))
        await writer.drain()
        logging.info('send HEARTBEATS')


class Forwarder(object):
    def __init__(self, local, remote, port, username, password):
        self.local = local
        self.remote = remote
        self.port = port
        self.writer_dict = dict()  # {conn_id: writer}
        self.loop = asyncio.get_event_loop()
        self.name = username
        self.pwd = password

    def run(self):
        self.loop.run_until_complete(
            self.start()
        )

    async def start(self):
        loop = self.loop

        count = 0
        while True:
            try:
                reader, writer = await asyncio.open_connection(
                    self.remote[0], self.remote[1], loop=loop
                )
                break
            except OSError:
                count += 1
                if count < 5:
                    logging.info('CONNECT to remote FAILED, try again')
                    await asyncio.sleep(1)
                    continue
                else:
                    logging.info('CANNOT CONNECT to remote, exiting...')
                    exit()

        beats = asyncio.run_coroutine_threadsafe(send_beats(writer), loop=loop)

        buffer = b''
        while True:
            raw = await reader.read(MAX_CHAR)  # read from server
            if not raw:
                logging.info(f'connection with server closed')
                for l_writer in self.writer_dict.values():
                    l_writer.close()
                    beats.cancel()
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

                await self.dispatch(writer, raw, pack[1])

                buffer = buffer[HEAD_SIZE + body_size:]

    async def dispatch(self, r_writer, raw, type):
        if type == CHAP_SALT:
            logging.info('recv CHAP_SALT')
            raw = get_chap_response(self.name, self.pwd, raw)
            # await asyncio.sleep(10)
            logging.info(f'send CHAP_HASH')
            r_writer.write(add_header(raw, CHAP_HASH))
            await r_writer.drain()

        elif type == CHAP_RESULT:
            (result,) = struct.unpack('!B', raw)
            logging.info(f'recv CHAP_RESULT --> result:{result}')
            if not result:
                r_writer.close()
                exit()
            raw = struct.pack('!H', self.port)
            r_writer.write(add_header(raw, BIND_REQ))
            await r_writer.drain()
            logging.info(f'send BIND_REQ --> port:{self.port}')

        elif type == BIND_RES:
            result, port = struct.unpack('!BH', raw)
            logging.info(f'recv BIND_RES --> result:{result} port:{port}')
            if not result:
                logging.info('bind FAILED, please try another port')
                r_writer.close()
                exit()
            else:
                self.port = port

        elif type == CONN_REQ:
            (conn_id,) = struct.unpack('!H', raw)
            logging.info(f'recv CONN_REQ --> conn_id:{conn_id}')
            result = 1
            try:
                l_reader, l_writer = await asyncio.open_connection(
                    self.local[0], self.local[1], loop=self.loop
                )
                self.writer_dict[conn_id] = l_writer
                asyncio.run_coroutine_threadsafe(
                    self.reader(l_reader, r_writer, conn_id),
                    self.loop
                )
            except OSError:
                result = 0
            raw = struct.pack('!BH', result, conn_id)
            r_writer.write(add_header(raw, CONN_RES))
            await r_writer.drain()
            logging.info(f'send CONN_RES --> result:{result} conn_id:{conn_id}')

        elif type == DATA:
            (conn_id,) = struct.unpack('!H', raw[:2])
            writer = self.writer_dict.get(conn_id)
            raw = raw[2:]
            logging.info(f'recv DATA --> conn_id:{conn_id} data:{len(raw)} bytes')
            writer.write(raw)
            await writer.drain()

        elif type == DIS_CONN:
            (conn_id,) = struct.unpack('!H', raw)
            if conn_id in self.writer_dict:
                writer = self.writer_dict.pop(conn_id)
                writer.close()
            logging.info(f'recv DIS_CONN: conn_id:{conn_id}')

        else:
            logging.info('RECV UNKNOWN message, CLOSE connection')
            for conn_id in self.writer_dict.keys():
                raw = struct.pack('!H', conn_id)
                r_writer.write(add_header(raw, DIS_CONN))
                await r_writer.drain()
            for writer in self.writer_dict.values():
                writer.close()
            r_writer.close()
            exit()

    async def reader(self, reader, writer, conn_id):
        logging.info(f'CREATE new reader and writer for {conn_id}')
        while True:
            raw = await reader.read(MAX_CHAR)  # read from client
            if not raw:
                self.writer_dict.pop(conn_id).close()
                logging.info(f'send DIS_CONN: conn_id:{conn_id}')
                writer.write(add_header(struct.pack('!H', conn_id), DIS_CONN))
                await writer.drain()
                return

            logging.info(f'send DATA: {len(raw)} TO {conn_id}')
            raw = struct.pack('!H', conn_id) + raw
            writer.write(add_header(raw, DATA))
            await writer.drain()


async def kill_conn(writer, msg):
    await asyncio.sleep(5)
    writer.close()
    logging.info(msg)


class Listener(object):

    def __init__(self, port, user_dict):
        self.s_port = port
        self.slave_writer_dict = dict()  # {port: nwriter}
        self.master_writer_dict = dict()  # {port: {conn_id: writer}} port --> req bind
        self.user_dict = user_dict  # {name: pwd}
        self.loop = asyncio.get_event_loop()
        self.conn_id = 0
        self.conn_future = dict()  # {conn_id: future} 超时断开

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
        raw, salt = get_chap_salt()
        writer.write(add_header(raw, CHAP_SALT))
        await writer.drain()
        logging.info(f'send CHAP_SALT')
        chap_future = asyncio.run_coroutine_threadsafe(kill_conn(
            writer, 'CHAP timeout, close connection'
        ), loop=self.loop)

        beats_future = asyncio.run_coroutine_threadsafe(kill_conn(
            writer, 'HEARTBEATS TIMEOUT, close connection'
        ), loop=self.loop)

        bind_port = 0
        buffer = b''
        while True:
            data = await reader.read(MAX_CHAR)
            if not data:
                logging.info(f'close connection with slave')
                writer.close()
                beats_future.cancel()
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
                    logging.info(f'recv CHAP_HASH')
                    reply, auth = get_chap_result(raw, self.user_dict, salt)

                    writer.write(add_header(reply, CHAP_RESULT))
                    await writer.drain()
                    logging.info(f'send CHAP_RESULT --> result:{auth}')
                    chap_future.cancel()
                    if not auth:
                        writer.close()
                        return

                elif type == BIND_REQ:
                    (port,) = struct.unpack('!H', raw)
                    logging.info(f'recv BIND_REQ --> port:{port}')
                    result = 1
                    try:
                        server = await asyncio.start_server(
                            self.master_listen,
                            '0.0.0.0', port,
                            loop=self.loop
                        )
                        bind_port = server.sockets[0].getsockname()[1]
                        self.slave_writer_dict[bind_port] = writer
                    except OSError:
                        result = 0
                    raw = struct.pack('!BH', result, bind_port)
                    writer.write(add_header(raw, BIND_RES))
                    logging.info(f'send BIND_RES --> result:{result} port:{port}')
                    await writer.drain()

                elif type == CONN_RES:
                    result, conn_id = struct.unpack('!BH', raw)
                    logging.info(f'recv CONN_RES --> result:{result} conn_id:{conn_id}')
                    if not result:
                        writer = self.master_writer_dict[bind_port].pop(conn_id)
                        writer.close()
                    self.conn_future.pop(conn_id).cancel()

                elif type == DATA:
                    if bind_port not in self.slave_writer_dict:
                        writer.close()
                        return
                    (conn_id,) = struct.unpack('!H', raw[: 2])
                    master_writer = self.master_writer_dict[bind_port][conn_id]
                    raw = raw[2:]
                    logging.info(f'recv DATA --> conn_id:{conn_id} data:{len(raw)} bytes')
                    master_writer.write(raw)
                    await master_writer.drain()

                elif type == DIS_CONN:
                    (conn_id,) = struct.unpack('!H', raw)
                    logging.info(f'recv DIS_CONN --> conn_id:{conn_id}')
                    master_writer = self.master_writer_dict[bind_port].pop(conn_id)
                    master_writer.close()

                elif type == HEARTBEATS:
                    logging.info('recv HEARTBEATS')
                    beats_future.cancel()
                    beats_future = asyncio.run_coroutine_threadsafe(kill_conn(
                        writer, 'HEARTBEATS TIMEOUT, close connection'
                    ), loop=self.loop)
                else:
                    logging.info('recv UNKNOWN --> CLOSE connection')
                    ids = self.master_writer_dict[bind_port].keys()
                    for conn_id in ids:
                        raw = struct.pack('!H', conn_id)
                        writer.write(add_header(raw, DIS_CONN))
                        await writer.drain()
                    writer.close()
                    writers = self.master_writer_dict[bind_port].values()
                    for writer in writers:
                        writer.close()
                    return

                buffer = buffer[HEAD_SIZE + body_size:]

    async def master_listen(self, reader, writer):
        ip, port = writer.get_extra_info('sockname')
        logging.info(f'new connect at {port}')

        slave_writer = self.slave_writer_dict.get(port)
        conn_id = self.conn_id
        raw = struct.pack('!H', conn_id)
        self.conn_id += 1
        if port not in self.master_writer_dict:
            self.master_writer_dict[port] = dict()
        self.master_writer_dict[port][conn_id] = writer
        slave_writer.write(add_header(raw, CONN_REQ))
        await slave_writer.drain()
        logging.info(f'send CONN_REQ --> conn_id:{conn_id}')
        self.conn_future[conn_id] = asyncio.run_coroutine_threadsafe(kill_conn(
            writer, f'CONN_RES TIMEOUT, close connection --> conn_id:{conn_id}'
        ), loop=self.loop)

        while True:
            raw = await reader.read(MAX_CHAR)  # read from remote client
            if not raw:
                raw = struct.pack('!H', conn_id)
                slave_writer.write(add_header(raw, DIS_CONN))
                await slave_writer.drain()
                logging.info(f'send DIS_CONN --> conn_id:{conn_id}')
                return
            logging.info(f'send DATA --> conn_id:{conn_id} data:{len(raw)} bytes')
            raw = struct.pack('!H', conn_id) + raw
            slave_writer.write(add_header(raw, DATA))
            await slave_writer.drain()


def parse_user(s_users, listen):
    if listen:
        user_list = s_users.split(',')
        user_dict = dict()
        for user in user_list:
            username, password = user.split(':')
            user_dict[username] = password
        return user_dict
    else:
        return s_users.split(':')


def parse_address(local, remote):
    l_ip, l_port = local.split(':')
    r_ip, r_port = remote.split(':')
    return (l_ip, l_port), (r_ip, r_port)


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
        users = parse_user(opts.users, True)
        Listener(
            opts.port,
            users
        ).run()

    elif opts.mode == 'slave':
        username, password = parse_user(opts.users, False)
        local, remote = parse_address(opts.local, opts.remote)
        Forwarder(
            local, remote,
            opts.port, username, password
        ).run()
    else:
        print('Please specify which mode you want to use!')
