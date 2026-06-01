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
    if ENDIANNESS in ('>', '!'):
        return 'big'
    return sys.byteorder


class TestPacketCapture(unittest.TestCase):
    def setUp(self) -> None:
        self.tmpdir = tempfile.TemporaryDirectory()
        self.output_path = pathlib.Path(self.tmpdir.name) / 'output.pcap'

    def tearDown(self) -> None:
        self.tmpdir.cleanup()

    def test_file_header(self) -> None:
        """
        Verify Packet Capture file header fields.
        """
        with PacketCapture(self.output_path, compressed=False):
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

    def test_exit_without_enter(self) -> None:
        """
        Raise when context exit is called before context entry.
        """
        pcap = PacketCapture(self.output_path, compressed=False)
        with self.assertRaises(RuntimeError):
            pcap.__exit__(None, None, None)
        self.assertFalse(self.output_path.exists())

    def test_add_simple_frame(self) -> None:
        """
        Verify Packet Capture frame fields.
        """
        timestamp = time.time()
        seconds = int(timestamp)
        microseconds = int((timestamp - seconds) * 1000000)
        source_port = 5060
        destination_port = 5060
        udp = UDP(source_port, destination_port, b'')
        source_ip = int(ipaddress.IPv4Address('192.0.2.1'))
        destination_ip = int(ipaddress.IPv4Address('192.0.2.2'))
        ip = IPv4(source_ip, destination_ip, udp)
        frame = Frame(seconds, microseconds, ip)
        with PacketCapture(self.output_path, compressed=False) as pcap:
            pcap.write(frame)
        raw = self.output_path.read_bytes()
        byteorder = get_byteorder()
        self.assertEqual(int.from_bytes(raw[24:28], byteorder), seconds)
        self.assertEqual(int.from_bytes(raw[28:32], byteorder), microseconds)
        self.assertEqual(int.from_bytes(raw[32:36], byteorder), ip.length)
        self.assertEqual(int.from_bytes(raw[36:40], byteorder), ip.length)
        self.assertEqual(len(raw), 68)

    def test_rejects_packet_longer_than_snap_len(self) -> None:
        """
        Reject frames that cannot fit into the configured PCAP SnapLen.
        """
        udp = UDP(1001, 1002, b'')
        too_long_packet = IPv4(0, 0, udp)
        too_long_packet.length = SNAP_LEN + 1

        with self.assertRaises(ValueError):
            Frame(0, 0, too_long_packet)
