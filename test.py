import asyncio
import json
import logging

from chap import CHAP

MASTER_PORT = 4500
CHAP_PORT = 5500
USERNAME = 'test1'


local_storage = {
    'server': '123456'
}


async def chap_auth(lo):
    chap = CHAP(local_storage)
    reader, writer = await asyncio \
        .open_connection('127.0.0.1', CHAP_PORT, loop=lo)
    logging.info('start CHAP connection')
    while True:
        data = await reader.read(1024)
        msg = json.loads(data.decode())
        logging.info(f'receive {data.decode()} from server')
        type_code = msg['code']
        if type_code == 1:
            string = chap.get_response(USERNAME, msg)
            writer.write(string.encode())
        elif type_code == 2:
            pass
        else:
            logging.info(msg['message'])


if __name__ == '__main__':
    log_level = logging.INFO
    logging.basicConfig(level=log_level, format='%(name)-11s: %(message)s')
    loop = asyncio.get_event_loop()
    loop.run_until_complete(chap_auth(loop))
    loop.close()


# async def read(reader):
#     while True:
#         raw = await reader.read()
#         data = json.loads(raw.decode())
#         logging.info('receive message from server')
#         print(data['msg'])
#
#
# async def write(writer):
#     # msg = input('please input something: ')
#     data = {
#         'username': str(USERNAME),
#         'msg': 'you have been hacked'
#     }
#     while True:
#         raw = json.dumps(data).encode()
#         writer.write(raw)
#         await writer.drain()
#         logging.info(f'send message: {msg}')
#         await asyncio.sleep(1)
#
#
# async def tcp_client(lo):
#     await asyncio.sleep(1)
#     reader, writer = await asyncio. \
#         open_connection('127.0.0.1', MASTER_PORT, loop=lo)
#     logging.info('Connect to server')
#     while True:
#         await asyncio.wait([
#             read(reader),
#             write(writer)
#         ])
