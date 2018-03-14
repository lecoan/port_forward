import asyncio
import json
import logging

from chap import CHAP

CHAP_PORT = 5500
HOST_NAME = 'lecoan.me'
USERNAME = 'test1'

MAX_CHAR = 1024

local_storage = {
    'server': '123456'
}


async def chap_auth(lo):
    chap = CHAP(local_storage)
    reader, writer = await asyncio \
        .open_connection(HOST_NAME, CHAP_PORT, loop=lo)
    logging.info('start CHAP connection')
    while True:
        data = await reader.read(MAX_CHAR)
        msg = json.loads(data.decode())
        logging.info(f'receive {data.decode()} from server')
        type_code = msg['code']
        # await asyncio.sleep(10)
        if type_code == 1:
            string = chap.get_response(USERNAME, msg)
            writer.write(string.encode())
            await writer.drain()
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
