import asyncio
import hashlib
import logging
import optparse
import random
import struct
import sys
import threading

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


class Forwarder(object):
    def __init__(self, local, remote, port, username, password):
        self.local = local
        self.remote = remote
        self.port = port
        self.writer_dict = dict() # {conn_id: writer}
        self.loop = asyncio.get_event_loop()
        self.name = username
        self.pwd = password

    def run(self):
        self.loop.run_until_complete(
            self.start()
        )

    async def start(self):
        loop = self.loop
        reader, writer = await asyncio.open_connection(
            self.remote[0], self.remote[1], loop=loop
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

                await self.dispatch(writer, raw, pack[1])

                buffer = buffer[HEAD_SIZE + body_size:]

    async def dispatch(self, r_writer, raw, type):
        if type == CHAP_SALT:
            raw = get_chap_response(self.name, self.pwd, raw)
            logging.info(f'send {len(raw)} to  server')
            r_writer.write(add_header(raw, CHAP_HASH))
            await r_writer.drain()

        elif type == CHAP_RESULT:
            result = raw[0]
            if not result:
                logging.info('closed connection')
                r_writer.close()
                exit()
            logging.info('CHAP passed')
            raw = struct.pack('!H', self.port)
            r_writer.write(add_header(raw, BIND_REQ))
            logging.info('send BIND_REQ')

        elif type == BIND_RES:
            logging.info('recv BIND_RES')
            result, port = struct.unpack('!BH', raw)
            if not result:
                pass
            else:
                self.port = port

        elif type == CONN_REQ:
            (conn_id, ) = struct.unpack('!H', raw)
            result = 1
            try:
                l_reader, l_writer = await asyncio.open_connection(
                    self.local[0], self.local[1], loop=self.loop
                )
                self.writer_dict[conn_id] = l_writer
                print(141, self.writer_dict.keys())
                asyncio.run_coroutine_threadsafe(
                    self.reader(l_reader, r_writer, conn_id),
                    self.loop
                )
            except OSError:
                result = 0
            raw = struct.pack('!BH', result, conn_id)
            r_writer.write(add_header(raw, CONN_RES))
            await r_writer.drain()
            logging.info('send CONN_RES')

        elif type == DATA:
            (conn_id, ) = struct.unpack('!H', raw[:2])
            print(155, self.writer_dict.keys())
            writer = self.writer_dict.get(conn_id)
            raw = raw[2:]
            writer.write(raw)
            await writer.drain()
            logging.info(f'send {raw} to local server')

        elif type == DIS_CONN:
            (conn_id, ) = struct.unpack('!H', raw)
            if conn_id in self.writer_dict:
                writer = self.writer_dict.pop(conn_id)
                writer.close()
            logging.info(f'recv DIS_CONN: conn_id:{conn_id}')
        else:
            pass

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


def kill_conn(writer):
    writer.close()
    logging.info('CHAP timeout, close connection')


class Listener(object):

    def __init__(self, port, user_dict):
        self.s_port = port
        self.slave_writer_dict = dict()  # {port: nwriter}
        self.master_writer_dict = dict()  # {port: {conn_id: writer}} port --> req bind
        self.user_dict = user_dict  # {name: pwd}
        self.loop = asyncio.get_event_loop()
        self.conn_id = 0

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
        s_addr = writer.get_extra_info('peername')
        raw, salt = get_chap_salt()
        writer.write(add_header(raw, CHAP_SALT))
        await writer.drain()
        logging.info(f'send CHAP challenge to {s_addr[0]}:{s_addr[1]}')
        timer = threading.Timer(10, kill_conn, args=[writer])

        bind_port = 0
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
                    writer.write(add_header(raw, CHAP_RESULT))
                    await writer.drain()
                    if auth:
                        logging.info(f'slave has been authenticated')
                        timer.cancel()
                    else:
                        writer.close()
                        logging.info('close connection with slave')
                        return

                elif type == BIND_REQ:
                    logging.info('recv BIND_REQ')
                    (port, ) = struct.unpack('!H', raw)
                    server = await asyncio.start_server(
                        self.master_listen,
                        '0.0.0.0', port,
                        loop=self.loop
                    )
                    result = 1
                    try:
                        bind_port = server.sockets[0].getsockname()[1]
                        # bind_port = port
                        self.slave_writer_dict[bind_port] = writer
                    except OSError:
                        result = 0
                    raw = struct.pack('!BH', result, bind_port)
                    writer.write(add_header(raw, BIND_RES))
                    logging.info(f'send BIND_RES -->result:{result}')
                    await writer.drain()

                elif type == CONN_RES:
                    logging.info('recv CONN_RES')
                    result, conn_id = struct.unpack('!BH', raw)
                    if not result:
                        self.master_writer_dict[bind_port].pop(conn_id)

                elif type == DATA:
                    if bind_port not in self.slave_writer_dict:
                        print(self.slave_writer_dict)
                        writer.close()
                        return
                    (conn_id, ) = struct.unpack('!H', raw[: 2])
                    master_writer = self.master_writer_dict[bind_port][conn_id]
                    logging.info(f'send message to {conn_id}')
                    raw = raw[2:]
                    logging.info(f'receive {len(raw)} from slave')
                    master_writer.write(raw)
                    await master_writer.drain()

                elif type == DIS_CONN:
                    logging.info('recv DIS_CONN')
                    (conn_id, ) = struct.unpack('!H', raw)
                    master_writer = self.master_writer_dict[bind_port].pop(conn_id)
                    master_writer.close()
                    logging.info(f'close connection with {conn_id}')
                else:
                    pass

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
        logging.info(f'send CONN_REQ')

        while True:
            raw = await reader.read(MAX_CHAR)  # read from remote client
            print(raw)
            if not raw:
                logging.info(f'connection with{conn_id} closed')
                raw = struct.pack('!H', conn_id)
                slave_writer.write(add_header(raw, DIS_CONN))
                await slave_writer.drain()
                return
            logging.info(f'server received {len(raw)} from {conn_id}')
            raw = struct.pack('!H', conn_id) + raw
            slave_writer.write(add_header(raw, DATA))
            await slave_writer.drain()
            logging.info(f'send msg {len(raw)} to slave')


# TODO slave master diff
def parse_user(s_users):
    user_list = s_users.split(',')
    if len(user_list) == 1:
        return s_users.split(':')
    user_dict = dict()
    for user in user_list:
        username, password = user.split(':')
        user_dict[username] = password
    return user_dict


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
        users = parse_user(opts.users)
        Listener(
            opts.port,
            users
        ).run()

    elif opts.mode == 'slave':
        username, password = parse_user(opts.users)
        local, remote = parse_address(opts.local, opts.remote)
        Forwarder(
            local, remote,
            opts.port, username, password
        ).run()
    else:
        print('Please specify which mode you want to use!')
