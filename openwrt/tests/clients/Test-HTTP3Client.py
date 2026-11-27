"""Full non-DNS UDP/443 request on one Windows physical interface.

Local-only aioquic dependency; no TCP fallback, insecure TLS, router changes,
or automatic claims about proxy routing. Confirm conntrack separately.
"""
import argparse
import hashlib
import importlib.util
import ipaddress
import json
import pathlib
import socket
import ssl
import sys
import time

HERE = pathlib.Path(__file__).resolve().parent
OPENWRT_ROOT = HERE.parents[1]


def load_client():
    spec = importlib.util.spec_from_file_location('physical_client', HERE / 'Test-NumericClient.py')
    client = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(client)
    return client


def request(client, address, domain, path, hold):
    sys.path.insert(0, str(OPENWRT_ROOT / 'build-stage/http3-test-deps'))
    import certifi
    from aioquic.quic.configuration import QuicConfiguration
    from aioquic.quic.connection import QuicConnection
    from aioquic.quic.events import HandshakeCompleted, ConnectionTerminated
    from aioquic.h3.connection import H3Connection, H3_ALPN
    from aioquic.h3.events import HeadersReceived, DataReceived

    config = QuicConfiguration(is_client=True, alpn_protocols=H3_ALPN, server_name=domain,
                               verify_mode=ssl.CERT_REQUIRED, cafile=certifi.where(), idle_timeout=15)
    connection = QuicConnection(configuration=config)
    http = H3Connection(connection)
    stream_id = None; handshake = False; complete = False; result = None
    status = None; body = bytearray(); sent = received = 0
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as stream:
        client.bind_client(stream)
        source_port = stream.getsockname()[1]
        if source_port == 41641:
            raise ValueError('Chosen source port is a direct rule, not a proxy candidate')
        client.emit({'test': 'http3-start', 'address': address, 'destination_port': 443,
                     'source_port': source_port, 'client': client.CLIENT, 'interface_index': client.INTERFACE_INDEX})
        connection.connect((address, 443), now=time.monotonic())
        deadline = time.monotonic() + 20
        finish_at = None
        try:
            while True:
                now = time.monotonic()
                if not complete and now >= deadline:
                    raise TimeoutError(f'HTTP/3 response deadline: sent={sent}, received={received}')
                if complete and now >= finish_at:
                    return result
                event = connection.next_event()
                while event is not None:
                    if isinstance(event, ConnectionTerminated):
                        raise ValueError(f'QUIC terminated: code={event.error_code}, reason={event.reason_phrase}')
                    if isinstance(event, HandshakeCompleted):
                        if event.alpn_protocol != 'h3':
                            raise ValueError('Expected HTTP/3 ALPN')
                        handshake = True
                        stream_id = connection.get_next_available_stream_id()
                        http.send_headers(stream_id, [(b':method', b'GET'), (b':scheme', b'https'),
                            (b':authority', domain.encode('ascii')), (b':path', path.encode('ascii')),
                            (b'user-agent', b'sb-router-acceptance/1')], end_stream=True)
                    for item in http.handle_event(event):
                        if getattr(item, 'stream_id', None) != stream_id:
                            continue
                        if isinstance(item, HeadersReceived):
                            for key, value in item.headers:
                                if key == b':status': status = int(value)
                        elif isinstance(item, DataReceived):
                            body.extend(item.data)
                            if len(body) > 65536: raise ValueError('HTTP/3 body exceeds diagnostic bound')
                        if isinstance(item, (HeadersReceived, DataReceived)) and item.stream_ended:
                            if not handshake or status != 200 or not body:
                                raise ValueError(f'Incomplete/unexpected HTTP/3 result: status={status}, bytes={len(body)}')
                            text = body.decode('ascii', errors='strict')
                            fields = dict(line.split('=', 1) for line in text.splitlines() if '=' in line)
                            if fields.get('http') != 'http/3' or not fields.get('ip'):
                                raise ValueError('Response is not the expected complete HTTP/3 trace')
                            complete = True; finish_at = time.monotonic() + hold
                            result = {'test': 'http3-complete', 'ok': True, 'address': address,
                                'source_port': source_port, 'destination_port': 443, 'http_status': status,
                                'bytes_read': len(body), 'body_sha256': hashlib.sha256(body).hexdigest(),
                                'tls_certificate_verified': True, 'alpn': 'h3', 'transport': 'udp',
                                'tcp_fallback': False, 'reported_egress_ipv4': fields['ip'],
                                'routing_verification': 'requires router conntrack evidence'}
                            client.emit(result)
                    event = connection.next_event()
                for packet, peer in connection.datagrams_to_send(now=time.monotonic()):
                    if peer != (address, 443): raise ValueError('Unexpected QUIC destination')
                    stream.sendto(packet, peer); sent += 1
                timer = connection.get_timer()
                timeout = min(0.2, max(0.001, timer - time.monotonic())) if timer is not None else 0.2
                stream.settimeout(timeout)
                try:
                    data, peer = stream.recvfrom(65535)
                    if peer != (address, 443): raise ValueError('Unexpected UDP response peer')
                    received += 1
                    connection.receive_datagram(data, peer, now=time.monotonic())
                except socket.timeout:
                    if timer is not None and time.monotonic() >= timer:
                        connection.handle_timer(now=time.monotonic())
        finally:
            connection.close()
            for packet, peer in connection.datagrams_to_send(now=time.monotonic()):
                stream.sendto(packet, peer)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--client-address', required=True, type=ipaddress.IPv4Address)
    parser.add_argument('--interface-index', required=True, type=int)
    parser.add_argument('--hold-seconds', type=int, default=10)
    args = parser.parse_args()
    if args.interface_index <= 0 or not 0 <= args.hold_seconds <= 10:
        parser.error('Positive interface required; hold bounded to ten seconds')
    client = load_client(); client.CLIENT = str(args.client_address); client.INTERFACE_INDEX = args.interface_index
    client.physical_path()
    domain = 'www.cloudflare.com'
    answer = client.dns(domain)
    if answer['rcode'] or not answer['addresses']:
        raise ValueError('No successful IPv4 answer for HTTP/3 test')
    request(client, answer['addresses'][0], domain, '/cdn-cgi/trace', args.hold_seconds)


if __name__ == '__main__':
    main()
