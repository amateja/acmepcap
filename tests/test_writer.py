import ipaddress
import pathlib
import sys
import tempfile
import time
import typing
import unittest

from acmepcap import ENDIANNESS, Frame, IPv4, LINKTYPE_RAW, PacketCapture, \
    SNAP_LEN, UDP


def get_byteorder() -> typing.Literal['little', 'big']:
    """
    Packet Capture files may use either big-endian or little-endian headers.
    The implementation uses native endianness by default, so tests need to
    derive the expected byte order from `acmepcap.ENDIANNESS` and the current
    platform.

    :return: endianness string
    """
    if ENDIANNESS == '<':
        return 'little'
    elif ENDIANNESS in ('>', '!'):
        return 'big'
    return sys.byteorder


class TestPacketCapture(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory()
        self.output_path = pathlib.Path(self.tmpdir.name) / 'output.pcap'

    def tearDown(self):
        self.tmpdir.cleanup()

    def test_file_header(self):
        """
        Verify Packet Capture file header fields.
        """
        with PacketCapture(self.output_path, False):
            pass
        raw = self.output_path.read_bytes()
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
        # maximum length of captured packets, in octets
        self.assertEqual(int.from_bytes(raw[16:20], byteorder), SNAP_LEN)
        # data link type and additional information
        self.assertEqual(int.from_bytes(raw[20:24], byteorder), LINKTYPE_RAW)
        self.assertEqual(len(raw), 24)

    def test_exit_without_enter(self):
        """
        Ignore context exit when no output file was opened.
        """
        PacketCapture(self.output_path, False).__exit__(None, None, None)
        self.assertFalse(self.output_path.exists())

    def test_add_simple_frame(self):
        """
        Verify Packet Capture frame fields.
        """
        timestamp = time.time()
        seconds = int(timestamp)
        microseconds = int((timestamp - seconds) * 1000000)
        source_port = 5060
        destination_port = 5060
        udp = UDP(source_port, destination_port, b'')
        source_ip = int(ipaddress.IPv4Address('192.168.0.1'))
        destination_ip = int(ipaddress.IPv4Address('192.168.0.2'))
        ip = IPv4(source_ip, destination_ip, udp)
        frame = Frame(seconds, microseconds, ip)
        with PacketCapture(self.output_path, False) as pcap:
            pcap.write(frame)
        raw = self.output_path.read_bytes()
        byteorder = get_byteorder()
        self.assertEqual(int.from_bytes(raw[24:28], byteorder), seconds)
        self.assertEqual(int.from_bytes(raw[28:32], byteorder), microseconds)
        self.assertEqual(int.from_bytes(raw[32:36], byteorder), ip.length)
        self.assertEqual(int.from_bytes(raw[36:40], byteorder), ip.length)
        self.assertEqual(len(raw), 68)
