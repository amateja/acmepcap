import ipaddress
from unittest import TestCase

from acmepcap import IPv4, IPv6, UDP, TTL


class IPv4Test(TestCase):
    def test_compose(self):
        source_port = 1001
        destination_port = 1002
        udp = UDP(source_port, destination_port, b'')
        source_ip = int(ipaddress.IPv4Address('192.168.1.1'))
        destination_ip = int(ipaddress.IPv4Address('192.168.1.2'))
        ip = IPv4(source_ip, destination_ip, udp)
        ip_checksum = 0xf77d
        length = 28
        int_ = int.from_bytes
        self.assertEqual(ip.checksum, ip_checksum)
        raw = bytes(ip)
        # Version|IHL
        self.assertEqual(raw[0], 0x45)
        # Type of Service
        self.assertEqual(raw[1], 0)
        # Total Length
        self.assertEqual(int_(raw[2:4]), length)
        # Identification
        self.assertEqual(int_(raw[4:6]), 0)
        # Flags|Fragment Offset
        self.assertEqual(int_(raw[6:8]), 0)
        # Time to Live
        self.assertEqual(raw[8], TTL)
        # Protocol
        self.assertEqual(raw[9], UDP.number)
        # Header Checksum
        self.assertEqual(int_(raw[10:12]), ip_checksum)
        # Source Address
        self.assertEqual(int_(raw[12:16]), ip.source)
        # Destination Address
        self.assertEqual(int_(raw[16:20]), ip.destination)
        # UDP part
        # Source Port
        self.assertEqual(int_(raw[20:22]), udp.source)
        # Destination Port
        self.assertEqual(int_(raw[22:24]), udp.destination)
        # Length
        self.assertEqual(int_(raw[24:26]), 8)
        # Checksum
        self.assertEqual(int_(raw[26:28]), 0x74b7)


class IPv6Test(TestCase):
    def test_compose(self):
        source_port = 1001
        destination_port = 1002
        udp = UDP(source_port, destination_port, b'')
        source_ip = int(ipaddress.IPv6Address('2001:db8::1'))
        destination_ip = int(ipaddress.IPv6Address('2001:db8::2'))
        ip = IPv6(source_ip, destination_ip, udp)
        length = 8
        raw = bytes(ip)
        # Version|Traffic Class|Flow Label
        self.assertEqual(int.from_bytes(raw[0:4]), 6 << 28)
        # Payload Length
        self.assertEqual(int.from_bytes(raw[4:6]), length)
        # Next Header
        self.assertEqual(raw[6], UDP.number)
        # Hop Limit
        self.assertEqual(raw[7], TTL)
        # Source Address
        self.assertEqual(int.from_bytes(raw[8:24]), source_ip)
        # Destination Address
        self.assertEqual(int.from_bytes(raw[24:40]), destination_ip)
        # UDP part
        # Source Port
        self.assertEqual(int.from_bytes(raw[40:42]), udp.source)
        # Destination Port
        self.assertEqual(int.from_bytes(raw[42:44]), udp.destination)
        # Length
        self.assertEqual(int.from_bytes(raw[44:46]), 8)
        # Checksum
        self.assertEqual(int.from_bytes(raw[46:48]), 0x9c96)
