"""Offline path-admission tests; no router or Windows settings changed."""
import importlib.util
import pathlib
import struct
import unittest
from unittest import mock

spec = importlib.util.spec_from_file_location('numeric_client', pathlib.Path(__file__).with_name('Test-NumericClient.py'))
client = importlib.util.module_from_spec(spec)
spec.loader.exec_module(client)


class PhysicalPathTests(unittest.TestCase):
    def snapshot(self):
        return {'addresses': ['192.168.1.2'], 'gateways': ['192.168.1.1'],
                'adapter_status': 'Up', 'local_core_count': 0}

    def test_valid_physical_path(self):
        client.validate_path(self.snapshot(), '192.168.1.2')

    def test_stale_source_rejected(self):
        with self.assertRaisesRegex(ValueError, 'absent'):
            client.validate_path(self.snapshot(), '192.168.1.9')

    def test_local_tun_rejected_even_for_local_dns(self):
        value = self.snapshot(); value['local_core_count'] = 1
        with self.assertRaisesRegex(ValueError, 'Local sing-box'):
            client.validate_path(value, '192.168.1.2', True)

    def test_gateway_required_for_external_tests(self):
        for gateways in ([], ['10.156.165.83']):
            value = self.snapshot(); value['gateways'] = gateways
            with self.assertRaisesRegex(ValueError, 'gateway'):
                client.validate_path(value, '192.168.1.2')
            client.validate_path(value, '192.168.1.2', True)

    def test_down_interface_rejected(self):
        value = self.snapshot(); value['adapter_status'] = 'Disconnected'
        with self.assertRaisesRegex(ValueError, 'not up'):
            client.validate_path(value, '192.168.1.2')

    def test_per_socket_index_network_byte_order(self):
        client.CLIENT, client.INTERFACE_INDEX = '192.168.1.2', 12
        stream = mock.Mock()
        client.bind_client(stream)
        stream.setsockopt.assert_called_once_with(client.socket.IPPROTO_IP, 31, b'\x00\x00\x00\x0c')
        stream.bind.assert_called_once_with(('192.168.1.2', 0))


class DNSFallbackTests(unittest.TestCase):
    def test_current_mosdns_aaaa_refused(self):
        client.assert_aaaa_rejected({'rcode': 5, 'answer_count': 0})
        for answer in ({'rcode': 0, 'answer_count': 0},
                       {'rcode': 5, 'answer_count': 1},
                       {'rcode': 2, 'answer_count': 0}):
            with self.subTest(answer=answer), self.assertRaisesRegex(ValueError, 'REFUSED'):
                client.assert_aaaa_rejected(answer)

    def packet(self, flags, answers=0, name=b'\x07example\x03com\0', qtype=1, qclass=1):
        data = struct.pack('!HHHHHH', 123, flags, 1, answers, 0, 0) + name + struct.pack('!HH', qtype, qclass)
        if answers:
            data += b'\xc0\x0c' + struct.pack('!HHIH', 1, 1, 60, 4) + bytes([1, 2, 3, 4])
        return data

    def run_query(self, udp, tcp=None, peer=('192.168.1.1', 53), transport='udp', qtype=1):
        first = mock.MagicMock(); second = mock.MagicMock()
        first.__enter__.return_value = first; second.__enter__.return_value = second
        first.recvfrom.return_value = (udp, peer)
        response = tcp if tcp is not None else udp
        tcp_socket = first if transport == 'tcp' else second
        tcp_socket.recv.side_effect = [struct.pack('!H', len(response)), response]
        tcp_socket.getpeername.return_value = peer
        with mock.patch.object(client.socket, 'socket', side_effect=[first, second]), mock.patch.object(client, 'bind_client'), mock.patch.object(client.secrets, 'randbelow', return_value=123):
            return client.dns('example.com', transport, qtype=qtype)

    def test_udp_tc_uses_tcp(self):
        value = self.run_query(self.packet(0x8380), self.packet(0x8180, 1))
        self.assertEqual(value['addresses'], ['1.2.3.4'])
        self.assertTrue(value['udp_truncated']); self.assertTrue(value['tcp_fallback'])
        self.assertEqual(value['final_transport'], 'tcp')

    def test_untruncated_udp(self):
        value = self.run_query(self.packet(0x8180, 1))
        self.assertEqual(value['addresses'], ['1.2.3.4'])
        self.assertFalse(value['tcp_fallback'])

    def test_a_query_ignores_aaaa_and_unrelated_ipv4(self):
        query = self.packet(0x8180)
        for owner, record_type, payload in (
            (b'\xc0\x0c', 28, bytes.fromhex('20010db8000000000000000000000001')),
            (b'\x05other\x03com\0', 1, bytes([1, 2, 3, 4])),
        ):
            record = owner + struct.pack('!HHIH', record_type, 1, 60, len(payload)) + payload
            packet = query[:6] + struct.pack('!H', 1) + query[8:] + record
            with self.subTest(record_type=record_type):
                self.assertEqual(self.run_query(packet)['addresses'], [])

    def test_a_query_follows_cname_in_any_answer_order(self):
        query = self.packet(0x8180)
        alias = b'\x05alias\xc0\x0c'
        ipv4 = alias + struct.pack('!HHIH', 1, 1, 60, 4) + bytes([1, 2, 3, 4])
        cname = b'\xc0\x0c' + struct.pack('!HHIH', 5, 1, 60, len(alias)) + alias
        packet = query[:6] + struct.pack('!H', 2) + query[8:] + ipv4 + cname
        self.assertEqual(self.run_query(packet)['addresses'], ['1.2.3.4'])

    def test_cname_loop_cannot_pass(self):
        query = self.packet(0x8180)
        cname = b'\xc0\x0c' + struct.pack('!HHIH', 5, 1, 60, 2) + b'\xc0\x0c'
        packet = query[:6] + struct.pack('!H', 1) + query[8:] + cname
        with self.assertRaisesRegex(ValueError, 'CNAME loop'):
            self.run_query(packet)

    def test_wrong_peer_refused(self):
        with self.assertRaisesRegex(ValueError, 'peer'):
            self.run_query(self.packet(0x8180, 1), peer=('192.168.1.9', 53))

    def test_short_packet_refused(self):
        with self.assertRaisesRegex(ValueError, 'header'):
            self.run_query(b'\0')

    def test_truncated_tcp_refused(self):
        with self.assertRaisesRegex(ValueError, 'Truncated TCP'):
            self.run_query(self.packet(0x8380), transport='tcp')

    def test_aaaa_refused_requires_matching_question(self):
        malformed = {'missing question': struct.pack('!6H', 123, 0x8185, 0, 0, 0, 0),
                     'wrong name': self.packet(0x8185, name=b'\x05other\x03com\0', qtype=28),
                     'wrong type': self.packet(0x8185),
                     'wrong class': self.packet(0x8185, qtype=28, qclass=3),
                     'truncated type or class': self.packet(0x8185, qtype=28)[:-1]}
        for transport in ('udp', 'tcp'):
            valid = self.packet(0x8185, name=b'\x07ExAmPlE\x03COM\0', qtype=28)
            client.assert_aaaa_rejected(self.run_query(valid, transport=transport, qtype=28))
            for label, packet in malformed.items():
                with self.subTest(transport=transport, case=label), self.assertRaisesRegex(ValueError, 'question'):
                    self.run_query(packet, transport=transport, qtype=28)

    def test_compression_loop_and_truncated_records_rejected(self):
        loop = self.packet(0x8180, name=b'\x01a\xc0\x0c')
        with self.assertRaisesRegex(ValueError, 'compression pointer'):
            self.run_query(loop)
        with self.assertRaisesRegex(ValueError, 'Truncated DNS record data'):
            self.run_query(self.packet(0x8180, 1)[:-1])

    def test_refused_checks_extended_rcode(self):
        response = bytearray(self.packet(0x8185, qtype=28))
        struct.pack_into('!H', response, 10, 1)
        response += b'\0' + struct.pack('!HHIH', 41, 1232, 1 << 24, 0)
        result = self.run_query(bytes(response), qtype=28)
        self.assertEqual(result['rcode'], 21)
        with self.assertRaisesRegex(ValueError, 'REFUSED'):
            client.assert_aaaa_rejected(result)


class UDPResponseValidationTests(unittest.TestCase):
    address = '192.0.2.10'
    transaction = b'fixture-id12'

    def run_stun(self, peer=None, declared_size=12, body=None):
        if body is None:
            mapped = struct.pack('!BBHI', 0, 1, 40000 ^ 0x2112, 0xcb007109 ^ 0x2112a442)
            body = struct.pack('!HH', 0x0020, 8) + mapped
        data = struct.pack('!HHI', 0x0101, declared_size, 0x2112a442) + self.transaction + body
        stream = mock.MagicMock()
        stream.__enter__.return_value = stream
        stream.getsockname.return_value = ('192.168.1.2', 50000)
        stream.recvfrom.return_value = (data, peer or (self.address, 19302))
        with mock.patch.object(client.socket, 'socket', return_value=stream), mock.patch.object(client, 'bind_client'), mock.patch.object(client.secrets, 'token_bytes', return_value=self.transaction):
            return client.stun(self.address)

    def run_ntp(self, peer=None):
        stream = mock.MagicMock()
        stream.__enter__.return_value = stream
        stream.getsockname.return_value = ('192.168.1.2', 50000)
        def reply(_):
            query = stream.sendto.call_args.args[0]
            data = bytearray(48)
            data[0] = 0x24
            data[1] = 2
            data[24:32] = query[40:48]
            return bytes(data), peer or (self.address, 123)
        stream.recvfrom.side_effect = reply
        with mock.patch.object(client.socket, 'socket', return_value=stream), mock.patch.object(client, 'bind_client'):
            return client.ntp(self.address)

    def test_valid_stun_response(self):
        self.assertEqual(self.run_stun()['mapped_address'], ['203.0.113.9', 40000])

    def test_stun_wrong_peer_rejected(self):
        for peer in (('192.0.2.11', 19302), (self.address, 19303)):
            with self.subTest(peer=peer), self.assertRaisesRegex(ValueError, 'peer'):
                self.run_stun(peer=peer)

    def test_stun_declared_size_must_match_datagram(self):
        for size in (8, 16, 11):
            with self.subTest(size=size), self.assertRaisesRegex(ValueError, 'STUN'):
                self.run_stun(declared_size=size)

    def test_stun_attribute_cannot_exceed_message(self):
        mapped = struct.pack('!BBHI', 0, 1, 40000 ^ 0x2112, 0xcb007109 ^ 0x2112a442)
        body = struct.pack('!HH', 0x0020, 8) + mapped + struct.pack('!HH', 0x8022, 8)
        with self.assertRaisesRegex(ValueError, 'STUN attribute'):
            self.run_stun(declared_size=len(body), body=body)

    def test_valid_ntp_response(self):
        self.assertTrue(self.run_ntp()['valid_ntp_reply'])

    def test_ntp_wrong_peer_rejected(self):
        for peer in (('192.0.2.11', 123), (self.address, 124)):
            with self.subTest(peer=peer), self.assertRaisesRegex(ValueError, 'peer'):
                self.run_ntp(peer=peer)


if __name__ == '__main__':
    unittest.main()
