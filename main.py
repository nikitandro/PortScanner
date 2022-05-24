import aiohttp.abc
import art
from aiohttp import web
import asyncio
import json
import syslog
import ipaddress
import datetime


async def check_input(ip, begin_port, end_port):
    try:
        ipaddress.ip_address(ip)
    except ValueError:
        return {'ERROR 400': 'Invalid IP address'}

    if begin_port > end_port:
        return {'ERROR 400': 'Invalid port value: begin port value cannot be higher than end port value.'}
    elif begin_port < 0 or end_port < 0:
        return {'ERROR 400': 'Invalid port value: port value cannot be less than 0.'}
    elif begin_port > 65535 or end_port > 65535:
        return {'ERROR 400': 'Invalid port value: port value cannot be higher than 65535'}

    return 1


async def check_port(ip, port):
    try:
        conn = asyncio.open_connection(ip, port)
        await asyncio.wait_for(conn, timeout=3)
        return {'port': port, 'state': 'open'}
    except asyncio.TimeoutError:
        return {'port': port, 'state': 'close'}


async def run_scanner(ip, begin_port, end_port):
    tasks = [asyncio.ensure_future(check_port(ip, port)) for port in range(begin_port, end_port + 1)]
    responses = await asyncio.gather(*tasks)
    return responses


async def handle(request: aiohttp.web.Request):
    ip = request.match_info.get('ip')
    begin_port = int(request.match_info.get('begin_port'))
    end_port = int(request.match_info.get('end_port'))

    checked_input = await check_input(ip, begin_port, end_port)

    if checked_input == 1:
        results = await asyncio.ensure_future(run_scanner(ip, begin_port, end_port))
        syslog.syslog(f'[{datetime.datetime.now()}] '
                      f'\"GET /scan/{ip}/{begin_port}/{end_port}\" 200')
        print(f'[{datetime.datetime.now()}] '
              f'\"GET /scan/{ip}/{begin_port}/{end_port}\" 200')
    else:
        results = checked_input
        syslog.syslog(f'[{datetime.datetime.now()}] '
                      f'\"GET /scan/{ip}/{begin_port}/{end_port}\" 400')
        print(f'[{datetime.datetime.now()}] '
              f'\"GET /scan/{ip}/{begin_port}/{end_port}\" 400')

    response = {'response': results}
    return web.Response(text=json.dumps(response), status=200)


if __name__ == '__main__':
    app = web.Application()
    app.router.add_get('/scan/{ip}/{begin_port}/{end_port}', handle)
    print(art.text2art('PORT SCANNER'))
    web.run_app(app)
