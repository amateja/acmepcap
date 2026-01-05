import io
import ipaddress
import sys
import time
import typing
import unittest

from acmepcap import ENDIANNESS, Frame, IPv4, LINKTYPE_RAW, PacketCapture, UDP


def get_byteorder() -> typing.Literal['little', 'big']:
    """
    Packet Capture may use in header part either big or little endian
    convention. This script by default uses native endianness, but to be a bit
    dynamic this is not taken for granted. Therefore, some verification
    mechanisms is required. This function returns 'little' or 'big' basing on
    acmepcap.ENDIANNESS constant and running CPU and OS architecture.

    :return: endianness string
    """
    if ENDIANNESS == '<':
        return 'little'
    elif ENDIANNESS in ('>', '!'):
        return 'big'
    return sys.byteorder


class TestPacketCapture(unittest.TestCase):
    def test_file_header(self):
        """
        Verify Packet Capture file header fields.
        """
        stream = io.BytesIO()
        p = PacketCapture()
        p.write(stream)
        stream.seek(0)
        raw = stream.read()
        byteorder = get_byteorder()
        # magic number
        self.assertEqual(int.from_bytes(raw[0:4], byteorder), 0xa1b2c3d4)
        # major version number
        self.assertEqual(int.from_bytes(raw[4:6], byteorder), 0x02)
        # minor version number
        self.assertEqual(int.from_bytes(raw[6:8], byteorder), 0x04)
        # Reserved1
        self.assertEqual(int.from_bytes(raw[8:12], byteorder), 0)
        # Reserved2
        self.assertEqual(int.from_bytes(raw[12:16], byteorder), 0)
        # max length of captured packets, in octets
        self.assertEqual(int.from_bytes(raw[16:20], byteorder), 0)
        # data link type and additional information
        self.assertEqual(int.from_bytes(raw[20:24], byteorder), LINKTYPE_RAW)
        self.assertEqual(len(raw), 24)

    def test_add_simple_frame(self):
        """
        Verify Packet Capture frame fields.
        """
        stream = io.BytesIO()
        p = PacketCapture()
        timestamp = time.time()
        seconds = int(timestamp)
        microseconds = int((timestamp - seconds) * 1000)
        source_port = 5060
        destination_port = 5060
        udp = UDP(source_port, destination_port, b'')
        source_ip = int(ipaddress.IPv4Address('192.168.0.1'))
        destination_ip = int(ipaddress.IPv4Address('192.168.0.2'))
        ip = IPv4(source_ip, destination_ip, udp)
        frame = Frame(seconds, microseconds, ip)
        p.add_frame(frame)
        p.write(stream)
        stream.seek(0)
        raw = stream.read()
        byteorder = get_byteorder()
        self.assertEqual(int.from_bytes(raw[24:28], byteorder), seconds)
        self.assertEqual(int.from_bytes(raw[28:32], byteorder), microseconds)
        self.assertEqual(int.from_bytes(raw[32:36], byteorder), ip.length)
        self.assertEqual(int.from_bytes(raw[36:40], byteorder), ip.length)
        self.assertEqual(len(raw), 68)
