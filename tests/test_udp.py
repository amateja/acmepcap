import ipaddress
import unittest

from acmepcap import IPv4, UDP


class TestUdpChecksum(unittest.TestCase):
    def test_udp_checksum(self):
        """
        UDP checksum calculation test scenario taken from
        http://profesores.elo.utfsm.cl/~agv/elo322/UDP_Checksum_HowTo.html
        """
        src_ip = int(ipaddress.IPv4Address('152.1.51.27'))
        dst_ip = int(ipaddress.IPv4Address('152.14.94.75'))
        src_port = 41103
        dst_port = 9876
        payload = b'\x62\x62'
        udp = UDP(src_port, dst_port, payload)
        IPv4(src_ip, dst_ip, udp)
        self.assertEqual(udp.checksum, 0x14de)

    def test_udp_checksum_with_no_network(self):
        """
        Unlikely scenario only to make sure that script will not fail.
        """
        src_port = 1001
        dst_port = 1002
        payload = b''
        udp = UDP(src_port, dst_port, payload)
        self.assertEqual(udp.checksum, 0xf80b)

    def test_udp_checksum_all_zeros(self):
        """
        In case the checksum is not calculated the value should be set to 0.
        If the checksum calculation results in the value zero it should be
        set to 0xffff. This tests the latter.
        """
        src_ip = int(ipaddress.IPv4Address('192.168.0.1'))
        dst_ip = int(ipaddress.IPv4Address('192.168.0.2'))
        src_port = 1
        dst_port = 32391
        payload = b'\x00'
        udp = UDP(src_port, dst_port, payload)
        IPv4(src_ip, dst_ip, udp)
        self.assertEqual(udp.checksum, 0xffff)
