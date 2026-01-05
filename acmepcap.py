import argparse
import datetime
import gzip
import ipaddress
import os.path
import re
import struct
import typing
import zoneinfo

__version__ = '0.1.0'

# constants
ENDIANNESS = '='  # native
TTL = 64
# https://datatracker.ietf.org/doc/draft-ietf-opsawg-pcaplinktype/
LINKTYPE_RAW = 101
UTC = datetime.timezone.utc
MONTHS = {
    'Jan': 1,
    'Feb': 2,
    'Mar': 3,
    'Apr': 4,
    'May': 5,
    'Jun': 6,
    'Jul': 7,
    'Aug': 8,
    'Sep': 9,
    'Oct': 10,
    'Nov': 11,
    'Dec': 12
}
# types
IP_type = typing.Union['IPv4', 'IPv6']


def configure() -> argparse.Namespace:
    """
    Handle Command Line Interface parameters parsing.

    :return: settings
    """
    parser = argparse.ArgumentParser(
        description='Acme Packet sipmsg.log to packet capture converter.',
    )
    parser.add_argument(
        '-f', '--file',
        type=argparse.FileType('r'),
        required=True,
        help='sipmsg.log file',
    )
    parser.add_argument(
        '-c', '--compress',
        action='store_true',
        help='compress output packet capture file',
    )
    parser.add_argument(
        '-o', '--output',
        type=argparse.FileType('wb'),
        required=True,
        help='output packet capture file',
    )
    parser.add_argument(
        '-t', '--timezone',
        default='UTC',
        choices=zoneinfo.available_timezones(),
        help='SBC timezone as tz database identifier defaults to UTC',
        metavar='TIMEZONE'
    )
    return parser.parse_args()


class PacketCapture:
    """
    Packet Capture file writer based on
    https://datatracker.ietf.org/doc/draft-ietf-opsawg-pcap/
    """
    def __init__(self) -> None:
        self.packets = []
        self.max_snap_len = 0  # maximum length of captured packets in octets

    def add_frame(self, frame: 'Frame') -> None:
        """
        Adds a Frame object to the packet capture and calculates the length
        of the largest packet.

        :param frame: a Packet Capture Frame object
        """
        self.packets.append(bytes(frame))
        self.max_snap_len = max(self.max_snap_len, frame.packet.length)

    def write(self, fd) -> None:
        """
        Write the Packet Capture header to a fd followed by all packet frames.

        :param fd: writable binary file-like object
        """
        # Lower part of Magic Number (0xc3d4) denotes timestamps in
        # microseconds. Value 0x3c4d would denote timestamps in nanoseconds.
        data = struct.pack(
            f'{ENDIANNESS}IHHIIII',
            0xa1b2c3d4,         # Magic Number
            2,                  # Major Version
            4,                  # Minor Version
            0,                  # Reserved1
            0,                  # Reserved2
            self.max_snap_len,  # SnapLen
            LINKTYPE_RAW        # LinkType and additional information
        )
        fd.write(data)
        for packet in self.packets:
            fd.write(packet)


class Frame:
    """
    Packet Capture Frame bytes representation based on
    https://datatracker.ietf.org/doc/draft-ietf-opsawg-pcap/
    """
    def __init__(self, seconds: int, microseconds: int,
                 packet: IP_type) -> None:
        self.seconds = seconds
        self.microseconds = microseconds
        self.packet = packet

    def __bytes__(self) -> bytes:
        return struct.pack(
            f'{ENDIANNESS}IIII',
            self.seconds,        # Timestamp (Seconds)
            self.microseconds,   # Timestamp (Microseconds)
            self.packet.length,  # Captured Packet Length
            self.packet.length   # Original Packet Length
        ) + bytes(self.packet)   # Packet Data


class UDP:
    """
    User Datagram Protocol bytes representation based on RFC 768.
    """
    number = 17  # RFC 1700

    def __init__(self, source: int, destination: int, data: bytes) -> None:
        self.source = source
        self.destination = destination
        self.data = data
        self._ip = None
        self.length = len(data) + 8

    @property
    def checksum(self) -> int:
        """
        Compute a checksum for the UDP packet.

        :return: checksum
        """
        if self._ip is None:
            ip_source = 0
            ip_destination = 0
        else:
            ip_source = self._ip.source
            ip_destination = self._ip.destination

        vector = (
            # pseudo header part
            ip_source,
            ip_destination,
            self.number,
            self.length,
            # udp header part
            self.source,
            self.destination,
            self.length,
        )
        header = sum(vector)
        high = sum(i << 8 for i in self.data[::2])
        low = sum(i for i in self.data[1::2])

        total = header + high + low

        while total > 0xffff:
            total = (total & 0xffff) + (total >> 16)

        checksum_ = ~total & 0xffff
        if checksum_ == 0:
            checksum_ = 0xffff
        return checksum_

    def __bytes__(self) -> bytes:
        return struct.pack(
            '>HHHH',
            self.source,       # Source Port
            self.destination,  # Destination Port
            self.length,       # Length
            self.checksum      # Checksum
        ) + self.data          # data octets


class IP:
    """
    An abstract class for commons of Internet Protocol version 4 and version 6.
    """
    offset = 0

    def __init__(self, source: int, destination: int, transport: UDP) -> None:
        self.source = source
        self.destination = destination
        self.transport = transport
        self.length = self.offset + transport.length
        transport._ip = self

    def __bytes__(self) -> bytes:
        raise NotImplementedError


class IPv4(IP):
    """
    Internet Protocol version 6 bytes representation based on RFC 760.
    """
    offset = 20

    @property
    def checksum(self) -> int:
        """
        Compute a checksum for the IPv4 packet.

        :return: checksum
        """
        # The Header Checksum field is 16 bits unsigned integer. It is
        # computed as complement of complement sum of all 16 bit words in the
        # header. Both Source Address and Destination Address are 32 bits
        # long. It is possible that the sum crosses 16 bits of the Header
        # Checksum so a wrapping is required. This wrapping adds higher bits
        # than 16 to the lower part so it deals with carry bits and with
        # 32 bits sum components as well.
        total = sum(
            [
                # put together only non-zero headers as 16 or 32 bits integers
                (4 << 4 | 5) << 8,      # Version|IHL
                self.length,            # Total Length
                TTL << 8 | UDP.number,  # Time to Live|Protocol
                self.source,            # Source Address
                self.destination,       # Destination Address
            ]
        )
        # the wrapping
        while total > 0xffff:
            total = (total & 0xffff) + (total >> 16)

        return ~total & 0xffff

    def __bytes__(self) -> bytes:
        return struct.pack(
            '>BBHHHBBHII',
            4 << 4 | 5,       # Version|IHL
            0,                # Type of Service
            self.length,      # Total Length
            0,                # Identification
            0,                # Flags|Fragment Offset
            TTL,              # Time to Live
            UDP.number,       # Protocol
            self.checksum,    # Header Checksum
            self.source,      # Source Address
            self.destination  # Destination Address
        ) + bytes(self.transport)


class IPv6(IP):
    """
    Internet Protocol version 6 bytes representation based on RFC 2460.
    """
    offset = 40

    def __bytes__(self) -> bytes:
        # Assume Traffic Class = 0 (bits 4-11), Flow Label = 0 (12-31),
        packet = (
            struct.pack(
                '>IHBB',
                6 << 28,                    # Version|Traffic Class|Flow Label
                self.transport.length,      # Payload Length
                UDP.number,                 # Next Header
                TTL,                        # Hop Limit
            ),
            self.source.to_bytes(16),       # Source Address
            self.destination.to_bytes(16),  # Destination Address
            bytes(self.transport)
        )
        return b''.join(packet)


class SipMsgLogFile:
    """
    An iterable sipmsg.log reader and parser class.
    """
    def __init__(self, fd: typing.IO[str], timezone: str) -> None:
        self.fd = fd
        # Dates in sipmsg.log are written in local timezone but there is no
        # information what timezone it is. To be accurate some external hint
        # is required.
        self.timezone = zoneinfo.ZoneInfo(timezone)

    def __iter__(self) -> typing.Iterator[Frame]:
        m_timestamp = os.path.getmtime(self.fd.name)
        # When sipmsg.log is retrieved from package-logfiles tarball it has
        # mtimes resolution in seconds rounded down and time entries in
        # sipmsg.log are in milliseconds.
        if int(m_timestamp) == m_timestamp:
            m_timestamp += 60
        m_datetime = datetime.datetime.fromtimestamp(m_timestamp, UTC)
        m_year = m_datetime.year
        pattern = r'^(\w{3}) (\d+) (\d+):(\d+):(\d+)\.(\d+) On ' \
            r'(?:\[\d+:\d+\])?(\d+\.\d+\.\d+\.\d+):(\d+) ' \
            r'(sent to|received from) (\d+\.\d+\.\d+\.\d+):(\d+)\n' \
            r'(\w+.*?)(?:--+)'
        needles = re.findall(pattern, self.fd.read(), re.MULTILINE | re.DOTALL)
        if not needles:
            return
        month, day, hour, minute, second, millisecond, *_ = needles[-1]
        last_timestamp = datetime.datetime(
            year=m_year, month=MONTHS[month], day=int(day),
            hour=int(hour), minute=int(minute), second=int(second),
            microsecond=int(millisecond) * 1000, tzinfo=self.timezone
        )
        if last_timestamp > m_datetime:
            last_timestamp = last_timestamp.replace(year=m_year - 1)

        for i in needles:
            month, day, hour, minute, second, millisecond, local_ip, \
                local_port, direction, remote_ip, remote_port, message = i
            microsecond = int(millisecond) * 1000
            local_ip = int(ipaddress.ip_address(local_ip))
            remote_ip = int(ipaddress.ip_address(remote_ip))
            local_port = int(local_port)
            remote_port = int(remote_port)
            message = message.encode()
            if direction == 'sent to':
                source_ip = local_ip
                source_port = local_port
                destination_ip = remote_ip
                destination_port = remote_port
            else:
                source_ip = remote_ip
                source_port = remote_port
                destination_ip = local_ip
                destination_port = local_port

            udp = UDP(source_port, destination_port, message)
            ip = IPv4(source_ip, destination_ip, udp)
            timestamp = datetime.datetime(
                year=m_year, month=MONTHS[month], day=int(day),
                hour=int(hour), minute=int(minute), second=int(second),
                microsecond=microsecond, tzinfo=self.timezone
            )
            if timestamp > last_timestamp:
                timestamp = timestamp.replace(year=m_year - 1)
            yield Frame(int(timestamp.timestamp()), microsecond, ip)


def main() -> None:
    """
    Main function of the application. Retrieves user input, manages reading
    sipmsg.log and writing Packet Capture file.
    """
    settings = configure()
    pcap = PacketCapture()

    for frame in SipMsgLogFile(settings.file, settings.timezone):
        pcap.add_frame(frame)
    settings.file.close()

    if settings.compress:
        output = gzip.open(settings.output, 'wb')
    else:
        output = settings.output

    pcap.write(output)
    output.close()
    if settings.compress:
        settings.output.close()


if __name__ == '__main__':
    main()
