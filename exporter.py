#! /usr/bin/python3

import argparse
import asyncio
import json
import os
import sys
from asyncio.subprocess import PIPE

import aiorun
from aiohttp import web
from prometheus_client import REGISTRY, Counter, generate_latest


MATCH_COUNT = Counter(
    'tshark_exporter_match_count',
    'Number of packets observed by tshark matching filters',
    ['mac_src', 'mac_dst', 'ip_src', 'ip_dst', 'asn_src', 'asn_dst'],
)

MATCH_BYTES = Counter(
    'tshark_exporter_match_bytes',
    'Number of bytes of TCP payload observed by tshark matching filters',
    ['mac_src', 'mac_dst', 'ip_src', 'ip_dst', 'asn_src', 'asn_dst'],
)


async def tshark_watcher(args):
    print('Spawning tshark')

    cmd = [b'tshark', b'-T', b'ek'] + [arg.encode() for arg in args]

    process = await asyncio.create_subprocess_exec(*cmd, stdout=PIPE)

    while True:
        line = await process.stdout.readline()
        event = json.loads(line)

        # We are only interested in valid data
        if not 'timestamp' in event:
            continue
            
        if 'layers' not in event or 'ip' not in event['layers']:
            continue

        labels = (
            event['layers']['eth']['eth_eth_src'],
            event['layers']['eth']['eth_eth_dst'],
            event['layers']['ip']['ip_ip_src'],
            event['layers']['ip']['ip_ip_dst'],
            event['layers']['ip'].get('text_ip_geoip_dst_asnum', 'Unknown'),
            event['layers']['ip'].get('text_ip_geoip_src_asnum', 'Unknown'),
        )

        MATCH_COUNT.labels(*labels).inc()
        MATCH_BYTES.labels(*labels).inc(int(event['layers']['tcp']['tcp_tcp_len']))


async def tshark_watcher_watcher(args):
    ''' Restart tshark watcher if it dies '''

    while True:
        try:
            await tshark_watcher(args)
        except KeyboardInterrupt:
            return
        except Exception as e:
            print(e)
        await asyncio.sleep(1)


async def metrics(request):
    data = generate_latest(REGISTRY)
    return web.Response(text=data.decode('utf-8'), content_type='text/plain', charset='utf-8')


async def start_metrics_server(host, port):
    app = web.Application()
    app.router.add_get('/metrics', metrics)

    runner = web.AppRunner(app, access_log=None)
    await runner.setup()

    site = web.TCPSite(runner, host, port)

    await site.start()

    return runner


async def main():
    parser = argparse.ArgumentParser(prog='tshark-exporter')
    parser.add_argument('--export', default='0.0.0.0:9431')
    args, unknown = parser.parse_known_args()

    metrics = await start_metrics_server(*args.export.split(':'))
    
    await tshark_watcher_watcher(unknown)
    
    metrics.cancel()    
    await metrics.cleanup()


if __name__ == '__main__':
    aiorun.run(main())
