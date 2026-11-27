"""Real LAN client sockets: no system proxy, local service or adapter changes."""
import argparse
import http.client
import ipaddress
import json
import os
import secrets
import socket
import ssl
import struct
import subprocess
import time

CLIENT = None
INTERFACE_INDEX = None
ROUTER = '192.168.1.1'


def emit(value):
    print(json.dumps(value, ensure_ascii=False), flush=True)


def validate_path(snapshot, client_address, router_dns_only=False):
    if client_address not in snapshot['addresses']:
        raise ValueError('Test source address is absent from the selected interface')
    if snapshot['adapter_status'] != 'Up':
        raise ValueError('Selected physical interface is not up')
    if snapshot['local_core_count']:
        raise ValueError('Local sing-box is running; this tool never stops it')
    if not router_dns_only and ROUTER not in snapshot['gateways']:
        raise ValueError('Selected interface has no default gateway through the router; external tests refused')


def physical_path(router_dns_only=False):
    if os.name != 'nt':
        raise ValueError('This diagnostic requires the Windows physical-interface check')
    command = (
        "$ErrorActionPreference='Stop'; $idx=" + str(INTERFACE_INDEX) + "; "
        "$adapter=Get-NetAdapter -InterfaceIndex $idx; "
        "$ips=@(Get-NetIPAddress -InterfaceIndex $idx -AddressFamily IPv4 | ForEach-Object { $_.IPAddress }); "
        "$gateways=@(Get-NetRoute -InterfaceIndex $idx -AddressFamily IPv4 -DestinationPrefix '0.0.0.0/0' "
        "-ErrorAction SilentlyContinue | ForEach-Object { $_.NextHop }); "
        "$cores=@(Get-CimInstance Win32_Process -Filter \"Name='sing-box.exe'\"); "
        "@{addresses=$ips;gateways=$gateways;adapter_status=[string]$adapter.Status;"
        "local_core_count=$cores.Count} | ConvertTo-Json -Compress")
    shell = os.path.join(os.environ['SystemRoot'], 'System32', 'WindowsPowerShell', 'v1.0', 'powershell.exe')
    result = subprocess.run([shell, '-NoProfile', '-NonInteractive', '-Command', command],
                            capture_output=True, timeout=20, check=True)
    snapshot = json.loads(result.stdout.decode('utf-8-sig'))
    validate_path(snapshot, CLIENT, router_dns_only)
    emit({'test': 'physical-path-preflight', 'ok': True, 'client': CLIENT,
          'interface_index': INTERFACE_INDEX, 'router_dns_only': router_dns_only})


def bind_client(stream):
    # Windows IP_UNICAST_IF uses the interface index in network byte order.
    stream.setsockopt(socket.IPPROTO_IP, 31, struct.pack('!I', INTERFACE_INDEX))
    stream.bind((CLIENT, 0))


def assert_aaaa_rejected(answer):
    if answer['rcode'] != 5 or answer['answer_count'] != 0:
        raise ValueError('Expected AAAA REFUSED (rcode 5) with an empty answer section')


def read_exact(stream, count):
    data = b''
    while len(data) < count:
        block = stream.recv(count - len(data))
        if not block:
            raise ValueError('Truncated TCP DNS response')
        data += block
    return data


def read_dns_name(data, offset):
    labels = []
    wire_length = 1
    next_offset = None
    pointers = set()
    while True:
        if offset >= len(data):
            raise ValueError('Truncated DNS name')
        size = data[offset]
        if size & 0xc0 == 0xc0:
            if offset + 2 > len(data):
                raise ValueError('Truncated DNS pointer')
            target = ((size & 0x3f) << 8) | data[offset + 1]
            if not 12 <= target < offset or offset in pointers:
                raise ValueError('Invalid DNS compression pointer')
            pointers.add(offset)
            if next_offset is None:
                next_offset = offset + 2
            offset = target
            continue
        if size & 0xc0:
            raise ValueError('Invalid DNS label')
        offset += 1
        if size == 0:
            return tuple(labels), next_offset if next_offset is not None else offset
        end = offset + size
        wire_length += 1 + size
        if end > len(data) or wire_length > 255:
            raise ValueError('Invalid DNS name length')
        labels.append(data[offset:end].lower())
        offset = end


def dns(domain, transport='udp', target=ROUTER, qtype=1):
    tx = secrets.randbelow(65536)
    query_name = domain[:-1] if domain.endswith('.') else domain
    labels = tuple(label.lower() for label in query_name.encode('ascii').split(b'.')) if query_name else ()
    if any(not 1 <= len(label) <= 63 for label in labels) or sum(1 + len(label) for label in labels) > 254:
        raise ValueError('Invalid DNS query name')
    query_type_class = struct.pack('!HH', qtype, 1)
    query = struct.pack('!HHHHHH', tx, 0x100, 1, 0, 0, 0)
    query += b''.join(bytes([len(label)]) + label for label in labels) + b'\0' + query_type_class
    kind = socket.SOCK_DGRAM if transport == 'udp' else socket.SOCK_STREAM
    with socket.socket(socket.AF_INET, kind) as stream:
        stream.settimeout(8)
        bind_client(stream)
        if transport == 'udp':
            stream.sendto(query, (target, 53)); data, peer = stream.recvfrom(65535)
        else:
            stream.connect((target, 53)); stream.sendall(struct.pack('!H', len(query)) + query)
            data = read_exact(stream, struct.unpack('!H', read_exact(stream, 2))[0]); peer = stream.getpeername()
    if len(data) < 12 or peer[0] != target or peer[1] != 53:
        raise ValueError('Invalid DNS response header or peer')
    rid, flags, questions, answers, authority, additional = struct.unpack('!HHHHHH', data[:12])
    if rid != tx or not flags & 0x8000 or flags & 0x7800:
        raise ValueError('DNS transaction mismatch')
    if questions != 1:
        raise ValueError('DNS response must echo one question')
    response_name, offset = read_dns_name(data, 12)
    if response_name != labels or data[offset:offset+4] != query_type_class:
        raise ValueError('DNS response question mismatch')
    if flags & 0x200:
        if transport != 'udp':
            raise ValueError('Truncated TCP DNS response')
        # RFC 7766: TC is a request to retry TCP, not a failed resolution.
        result = dns(domain, 'tcp', target, qtype)
        result.update(transport='udp', udp_truncated=True, tcp_fallback=True,
                      final_transport='tcp', initial_udp_bytes=len(data))
        return result
    offset += 4
    address_records = []
    aliases = {}
    rcode = flags & 15
    for index in range(answers + authority + additional):
        owner, offset = read_dns_name(data, offset)
        if offset + 10 > len(data):
            raise ValueError('Truncated DNS record header')
        record_type, record_class, ttl, length = struct.unpack_from('!HHIH', data, offset)
        offset += 10
        if offset + length > len(data):
            raise ValueError('Truncated DNS record data')
        start = offset
        offset += length
        if index < answers and record_class == 1:
            if record_type == 5:
                alias, end = read_dns_name(data, start)
                if end != offset or (owner in aliases and aliases[owner] != alias):
                    raise ValueError('Invalid DNS CNAME record')
                aliases[owner] = alias
            if record_type in (1, 28):
                if length != (4 if record_type == 1 else 16):
                    raise ValueError('Invalid DNS address record length')
                if record_type == qtype:
                    address_records.append((owner, str(ipaddress.ip_address(data[start:offset]))))
        if index >= answers + authority and record_type == 41:
            rcode |= (ttl >> 24) << 4
    if offset != len(data):
        raise ValueError('Unexpected trailing DNS response data')
    terminal = labels
    visited = set()
    while terminal in aliases:
        if terminal in visited:
            raise ValueError('DNS CNAME loop')
        visited.add(terminal)
        terminal = aliases[terminal]
    addresses = [address for owner, address in address_records if owner == terminal]
    return {'domain': domain, 'transport': transport, 'target': target, 'qtype': qtype,
            'rcode': rcode, 'answer_count': answers, 'addresses': addresses, 'response_peer': peer,
            'udp_truncated': False, 'tcp_fallback': False, 'wire_bytes': len(data)}


def tcp(domain, path, address, tls=True, max_bytes=65536, hold=0, observe=None):
    stream = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    stream.settimeout(12); bind_client(stream)
    port = 443 if tls else 80
    stream.connect((address, port))
    local_port = stream.getsockname()[1]
    if tls:
        stream = ssl.create_default_context().wrap_socket(stream, server_hostname=domain)
    request = f'GET {path} HTTP/1.1\r\nHost: {domain}\r\nUser-Agent: sb-numeric-verification/1\r\nConnection: keep-alive\r\n\r\n'
    stream.sendall(request.encode('ascii'))
    response = http.client.HTTPResponse(stream); response.begin()
    data = response.read(max_bytes)
    result = {'domain': domain, 'address': address, 'destination_port': port, 'source_port': local_port,
              'http_status': response.status, 'bytes_read': len(data), 'tls_certificate_verified': tls}
    emit({'test': 'tcp-proxy' if domain == 'www.google.com' else 'tcp-direct-ip-candidate', 'result': result, 'socket_held_seconds': hold})
    if observe is not None:
        observe(result)
    if hold:
        time.sleep(hold)
    stream.close()
    if not 200 <= response.status < 400:
        raise ValueError('Unexpected HTTP status')
    return result


def stun(address):
    transaction = secrets.token_bytes(12)
    packet = struct.pack('!HHI', 1, 0, 0x2112a442) + transaction
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as stream:
        stream.settimeout(8); bind_client(stream); local_port = stream.getsockname()[1]
        stream.sendto(packet, (address, 19302))
        data, peer = stream.recvfrom(8192)
    if peer != (address, 19302):
        raise ValueError('Unexpected STUN response peer')
    if len(data) < 20:
        raise ValueError('Truncated STUN response header')
    kind, size, cookie = struct.unpack('!HHI', data[:8])
    if kind != 0x0101 or cookie != 0x2112a442 or data[8:20] != transaction or size % 4 or len(data) != size + 20:
        raise ValueError('Not a matching STUN Binding Success response')
    mapped = None
    offset = 20
    while offset < size + 20:
        if offset + 4 > size + 20:
            raise ValueError('Truncated STUN attribute header')
        attr, length = struct.unpack('!HH', data[offset:offset+4]); offset += 4
        padded_length = (length + 3) & ~3
        if offset + padded_length > size + 20:
            raise ValueError('STUN attribute exceeds response boundary')
        value = data[offset:offset+length]; offset += padded_length
        if attr == 0x0020 and length == 8 and value[1] == 1:
            mapped = [str(ipaddress.IPv4Address(struct.unpack('!I', value[4:])[0] ^ cookie)), struct.unpack('!H', value[2:4])[0] ^ 0x2112]
    if mapped is None:
        raise ValueError('No IPv4 XOR-MAPPED-ADDRESS in STUN response')
    return {'address': address, 'destination_port': 19302, 'source_port': local_port,
            'response_peer': peer, 'valid_stun_reply': True, 'mapped_address': mapped, 'bytes': len(data)}


def ntp(address):
    packet = bytearray(48); packet[0] = 0x23
    now = time.time() + 2208988800
    packet[40:48] = struct.pack('!II', int(now), int((now % 1) * 2**32))
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as stream:
        stream.settimeout(8); bind_client(stream); source_port = stream.getsockname()[1]
        stream.sendto(packet, (address, 123)); data, peer = stream.recvfrom(8192)
    if peer != (address, 123):
        raise ValueError('Unexpected NTP response peer')
    if len(data) < 48 or data[0] & 7 != 4 or data[24:32] != packet[40:48]:
        raise ValueError('Not a matching NTP server response')
    return {'address': address, 'destination_port': 123, 'source_port': source_port,
            'response_peer': peer, 'stratum': data[1], 'valid_ntp_reply': True}


def main():
    global CLIENT, INTERFACE_INDEX
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=['dns', 'tcp', 'udp', 'direct-hold'])
    parser.add_argument('--hold-seconds', type=int, default=45)
    parser.add_argument('--client-address', required=True, type=ipaddress.IPv4Address)
    parser.add_argument('--interface-index', required=True, type=int)
    parser.add_argument('--router-dns-only', action='store_true')
    args = parser.parse_args()
    CLIENT, INTERFACE_INDEX = str(args.client_address), args.interface_index
    if INTERFACE_INDEX <= 0 or (args.router_dns_only and args.action != 'dns'):
        parser.error('Positive physical interface index required; router-dns-only is for DNS only')
    try:
        physical_path(args.router_dns_only)
    except Exception as error:
        emit({'test': 'physical-path-preflight', 'ok': False, 'error': str(error)})
        raise SystemExit(1)
    failures = 0
    if args.action == 'dns':
        for domain in ('kookapp.cn', 'www.google.com'):
            for transport in ('udp', 'tcp'):
                for target in ((ROUTER,) if args.router_dns_only else (ROUTER, '8.8.8.8')):
                    try:
                        result = dns(domain, transport, target)
                        if result['rcode'] or not result['addresses']:
                            raise ValueError('DNS not successful with IPv4 answers')
                        emit({'test': 'dns', 'ok': True, 'result': result})
                    except Exception as error:
                        failures += 1; emit({'test': 'dns', 'ok': False, 'domain': domain, 'transport': transport, 'target': target, 'error': str(error)})
        for transport in ('udp', 'tcp'):
            try:
                result = dns('www.google.com', transport=transport, qtype=28)
                assert_aaaa_rejected(result)
                emit({'test': 'dns-aaaa', 'ok': True, 'result': result})
            except Exception as error:
                failures += 1
                emit({'test': 'dns-aaaa', 'ok': False, 'transport': transport, 'error': str(error)})
    elif args.action in ('tcp', 'direct-hold'):
        targets = [('mirrors.tuna.tsinghua.edu.cn', '/debian/dists/stable/Release', False)]
        if args.action == 'tcp':
            targets.append(('www.google.com', '/generate_204', True))
        for domain, path, tls in targets:
            try:
                answer = dns(domain); address = answer['addresses'][0]
                tcp(domain, path, address, tls, hold=args.hold_seconds if args.action == 'direct-hold' else 0)
            except Exception as error:
                failures += 1; emit({'test': 'tcp', 'domain': domain, 'ok': False, 'error': str(error)})
    else:
        for domain, function in [('stun.l.google.com', stun), ('ntp.tencent.com', ntp)]:
            try:
                answer = dns(domain); result = function(answer['addresses'][0])
                # Port exceptions do not exclude independently direct IP/source ports.
                # Only exact conntrack/set evidence can attest to the selected path.
                emit({'test': 'udp-stun-path-candidate' if function == stun else 'udp-ntp-direct-candidate',
                      'udp_proxy_verified': False, 'ok': True, 'result': result})
            except Exception as error:
                failures += 1; emit({'test': 'udp', 'domain': domain, 'ok': False, 'error': str(error)})
    if failures:
        raise SystemExit(1)


if __name__ == '__main__':
    main()
