import asyncio


async def simple_server(reader, writer):
    while True:
        raw = await reader.read(1024)
        print(f'received {raw}')
        writer.write(raw)
        await writer.drain()
        print(f'send {raw}')


if __name__ == '__main__':
    loop = asyncio.get_event_loop()
    task = asyncio.start_server(
        simple_server,
        '127.0.0.1', 3000,
        loop=loop
    )
    server = loop.run_until_complete(task)
    loop.run_forever()
