"""Test UDP serialization and checksum behavior."""

import ipaddress
import unittest

import acmepcap


class TestUdpChecksum(unittest.TestCase):
    """Test UDP checksum behavior."""

    def test_udp_checksum(self) -> None:
        """Validate a published UDP checksum example.

        The scenario is taken from:
        http://profesores.elo.utfsm.cl/~agv/elo322/UDP_Checksum_HowTo.html
        """
        src_ip = int(ipaddress.IPv4Address('152.1.51.27'))
        dst_ip = int(ipaddress.IPv4Address('152.14.94.75'))
        src_port = 41103
        dst_port = 9876
        payload = b'\x62\x62'
        udp = acmepcap.UDP(src_port, dst_port, payload)
        acmepcap.IPv4(src_ip, dst_ip, udp)
        self.assertEqual(udp.checksum, 0x14de)

    def test_udp_checksum_with_no_network(self) -> None:
        """Unlikely scenario only to make sure that script will not fail."""
        src_port = 1001
        dst_port = 1002
        payload = b''
        udp = acmepcap.UDP(src_port, dst_port, payload)
        self.assertEqual(udp.checksum, 0xf80b)

    def test_udp_checksum_all_zeros(self) -> None:
        """Transmit a computed zero checksum as 0xFFFF.

        A UDP checksum field of zero means the checksum is not used. When the
        computed one's-complement checksum is zero, it must be transmitted as
        0xFFFF.
        """
        src_ip = int(ipaddress.IPv4Address('192.0.2.1'))
        dst_ip = int(ipaddress.IPv4Address('192.0.2.2'))
        src_port = 1
        dst_port = 31703
        payload = b'\x00'
        udp = acmepcap.UDP(src_port, dst_port, payload)
        acmepcap.IPv4(src_ip, dst_ip, udp)
        self.assertEqual(udp.checksum, 0xffff)

    def test_rejects_length_overflow(self) -> None:
        """Reject payloads that cannot fit into the UDP Length field."""
        payload = b'x' * (acmepcap.MAX_UINT16 - acmepcap.UDP.offset + 1)

        with self.assertRaises(ValueError):
            acmepcap.UDP(1001, 1002, payload)
