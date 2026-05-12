import argparse
import dataclasses
import datetime
import gzip
import ipaddress
import os.path
import re
import struct
import typing
import zoneinfo

__version__ = '0.1.0'
__all__ = [
    'ENDIANNESS',
    'Frame',
    'IPv4',
    'IPv6',
    'LINKTYPE_RAW',
    'PacketCapture',
    'SNAP_LEN',
    'SipMsgLogFile',
    'TTL',
    'UDP',
]

# constants
ENDIANNESS = '='  # native
TTL = 64
# https://datatracker.ietf.org/doc/draft-ietf-opsawg-pcaplinktype/
LINKTYPE_RAW = 101
SNAP_LEN = 65535
UTC = datetime.timezone.utc
# Month abbreviation to number mapping. Used instead of datetime.strptime
# for performance in tight parsing loops and because of sensitivity to locale
# differences.
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
SIPMSG_DELIMITER = b'-' * 40 + b'\n'
SIPMSG_HEADER = re.compile(
    rb'^(?P<month>Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec) {1,2}'
    rb'(?P<day>\d{1,2}) '
    rb'(?P<hour>\d{1,2}):(?P<minute>\d{2}):(?P<second>\d{2})\.'
    rb'(?P<millisecond>\d{3}) On '
    rb'(?:\[\d+:\d+])?'
    rb'(?P<local_ip>\d{1,3}(?:\.\d{1,3}){3}):'
    rb'(?P<local_port>\d{1,5}) '
    rb'(?P<direction>sent to|received from) '
    rb'(?P<remote_ip>\d{1,3}(?:\.\d{1,3}){3}):'
    rb'(?P<remote_port>\d{1,5})$'
)
SIPMSG_WORD_PAYLOAD = re.compile(rb'^\w')
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
        type=argparse.FileType('rb'),
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
    Streaming Packet Capture file writer based on
    https://datatracker.ietf.org/doc/draft-ietf-opsawg-pcap/
    """
    __slots__ = ['fd', 'compressed', 'output']

    def __init__(self, fd: typing.BinaryIO, compressed: bool) -> None:
        self.fd = fd
        self.compressed = compressed
        self.output = None

    def __enter__(self) -> 'PacketCapture':
        if self.compressed:
            self.output = gzip.open(self.fd, 'wb')
        else:
            self.output = self.fd
        self._write_file_header()
        return self

    def __exit__(self, *args: typing.Any) -> None:
        if self.compressed and self.output is not None:
            self.output.close()

    def _write_file_header(self) -> None:
        """
        Write the Packet Capture file header.
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
            SNAP_LEN,           # SnapLen
            LINKTYPE_RAW        # LinkType and additional information
        )
        self.output.write(data)

    def write(self, frame: 'Frame') -> None:
        """
        Write one Packet Capture frame.

        :param frame: Packet Capture frame object
        """
        self.output.write(bytes(frame))


class Frame:
    """
    Packet Capture Frame bytes representation based on
    https://datatracker.ietf.org/doc/draft-ietf-opsawg-pcap/
    """
    __slots__ = ['seconds', 'microseconds', 'packet']

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
    __slots__ = ['source', 'destination', 'data',
                 'ip_source', 'ip_destination', 'length']
    number = 17  # RFC 1700

    def __init__(self, source: int, destination: int, data: bytes) -> None:
        self.source = source & 65535
        self.destination = destination & 65535
        self.data = data
        self.ip_source = 0
        self.ip_destination = 0
        self.length = len(data) + 8

    @property
    def checksum(self) -> int:
        """
        Compute a checksum for the UDP packet.

        :return: checksum
        """
        vector = (
            # pseudo header part
            self.ip_source,
            self.ip_destination,
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
    __slots__ = ['source', 'destination', 'transport', 'length']
    offset = 0

    def __init__(self, source: int, destination: int, transport: UDP) -> None:
        self.source = transport.ip_source = source
        self.destination = transport.ip_destination = destination
        self.transport = transport
        self.length = self.offset + transport.length

    def __bytes__(self) -> bytes:
        raise NotImplementedError


class IPv4(IP):
    """
    Internet Protocol version 4 bytes representation based on RFC 760.
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


# TODO: So far no sipmsg.log with SIP over IPv6 was parsed. The IPv6 class
#  is just for future use.
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


@dataclasses.dataclass(frozen=True)
class SipMsgRecordHeader:
    """
    Parsed sipmsg.log header fields needed to build one packet frame.

    The log header itself has no year. The year is resolved later from file
    metadata and the position of the last valid message in the file.
    """
    month: int
    day: int
    hour: int
    minute: int
    second: int
    microsecond: int
    source_ip: int
    source_port: int
    destination_ip: int
    destination_port: int


@dataclasses.dataclass
class SipTimestampResolver:
    """
    Resolve missing sipmsg.log years while preserving log order.

    sipmsg.log timestamps are local wall-clock values without a year, UTC
    offset, or DST fold marker. The resolver assumes records are emitted in
    chronological order. It tries the earliest local timestamp that does not
    move backward in UTC; DST fold=1 is used only when it prevents a false
    fall-back rollover.
    """
    timezone: datetime.tzinfo
    start_year: int
    current_year: int = dataclasses.field(init=False)
    previous_utc: typing.Optional[datetime.datetime] = None

    def __post_init__(self) -> None:
        self.current_year = self.start_year

    def _fold_candidates(
            self, header: SipMsgRecordHeader
    ) -> typing.Iterator[datetime.datetime]:
        """
        Yield fold=0, and fold=1 only when timezone rules make it distinct.
        """
        kwargs = {
            'year': self.current_year,
            'month': header.month,
            'day': header.day,
            'hour': header.hour,
            'minute': header.minute,
            'second': header.second,
            'microsecond': header.microsecond,
            'tzinfo': self.timezone
        }
        timestamp = datetime.datetime(fold=0, **kwargs)
        yield timestamp

        folded = datetime.datetime(fold=1, **kwargs)
        if folded.utcoffset() != timestamp.utcoffset():
            yield folded

    def resolve(self, header: SipMsgRecordHeader) -> datetime.datetime:
        """
        Return the next chronological timestamp for a parsed log header.

        Equal millisecond timestamps are accepted as the same instant. If both
        DST folds move backward, the record is treated as a year rollover.
        """
        while True:
            for timestamp in self._fold_candidates(header):
                # Compare in UTC so DST folds are ordered by real time,
                # not wall time.
                timestamp_utc = timestamp.astimezone(UTC)
                if self.previous_utc is None or \
                        timestamp_utc >= self.previous_utc:
                    self.previous_utc = timestamp_utc
                    return timestamp
            self.current_year += 1


@dataclasses.dataclass
class SipMsgRecordState:
    """
    Mutable state for one sipmsg.log record while it is being parsed.
    """
    header: typing.Optional[SipMsgRecordHeader] = None
    timestamp: typing.Optional[datetime.datetime] = None
    payload: typing.Optional[typing.List[bytes]] = None
    is_skipped: bool = False

    @property
    def is_active(self) -> bool:
        return self.header is not None

    def start(self, header: SipMsgRecordHeader,
              timestamp: typing.Optional[datetime.datetime]) -> None:
        self.header = header
        self.timestamp = timestamp
        self.payload = None
        self.is_skipped = timestamp is None

    def reset(self) -> None:
        self.header = None
        self.timestamp = None
        self.payload = None
        self.is_skipped = False

    def add_payload_line(self, line: bytes) -> None:
        if self.payload is None:
            if SIPMSG_WORD_PAYLOAD.match(line):
                self.payload = [line]
            else:
                self.is_skipped = True
            return

        self.payload.append(line)

    def payload_bytes(self) -> bytes:
        return b''.join(self.payload or [])

    def to_record(self) -> typing.Optional['SipMsgRecord']:
        if self.header is None:
            return None
        if self.timestamp is None:
            return None
        if self.payload is None:
            return None

        return SipMsgRecord(
            timestamp=self.timestamp,
            header=self.header,
            payload=self.payload_bytes(),
        )


@dataclasses.dataclass(frozen=True)
class SipMsgRecord:
    """
    Complete sipmsg.log record ready for packet conversion.
    """
    timestamp: datetime.datetime
    header: SipMsgRecordHeader
    payload: bytes


class SipMsgLogFile:
    """
    An iterable sipmsg.log reader and parser class.

    The reader intentionally uses two passes over a seekable binary stream:

    1. Find the last valid message timestamp so year rollover can be inferred
       without reading the whole file into memory.
    2. Parse complete message records one by one and yield PCAP frames.

    Records whose first payload line does not start with a word character are
    treated as non-SIP and skipped. Their headers still contribute to timestamp
    chronology.
    """
    def __init__(self, fd: typing.BinaryIO, timezone: str) -> None:
        self.fd = fd
        # Dates in sipmsg.log are written in local timezone but there is no
        # information what timezone it is. To be accurate some external hint
        # is required.
        self.timezone = zoneinfo.ZoneInfo(timezone)

    @staticmethod
    def _parse_port(port: bytes) -> int:
        """
        Convert and validate a UDP port from a sipmsg.log header.

        UDP itself masks ports to 16 bits, but parser input should be checked
        at the boundary so malformed records can be skipped intentionally.
        """
        value = int(port)
        if not 0 <= value <= 0xffff:
            raise ValueError('UDP port out of range')
        return value

    def _parse_header(
            self, line: bytes) -> typing.Optional[SipMsgRecordHeader]:
        """
        Parse one sipmsg.log header line.

        Malformed headers return None so callers can continue scanning later
        records. This keeps conversion best-effort for machine-generated logs.
        """
        match = SIPMSG_HEADER.match(line)
        if match is None:
            return None

        try:
            header = match.groupdict()
            local_ip = int(ipaddress.ip_address(header['local_ip'].decode()))
            remote_ip = int(ipaddress.ip_address(header['remote_ip'].decode()))
            local_port = self._parse_port(header['local_port'])
            remote_port = self._parse_port(header['remote_port'])
        except (KeyError, ValueError):
            return None

        if header['direction'] == b'sent to':
            source_ip = local_ip
            source_port = local_port
            destination_ip = remote_ip
            destination_port = remote_port
        else:
            source_ip = remote_ip
            source_port = remote_port
            destination_ip = local_ip
            destination_port = local_port

        return SipMsgRecordHeader(
            month=MONTHS[header['month'].decode()],
            day=int(header['day']),
            hour=int(header['hour']),
            minute=int(header['minute']),
            second=int(header['second']),
            microsecond=int(header['millisecond']) * 1000,
            source_ip=source_ip,
            source_port=source_port,
            destination_ip=destination_ip,
            destination_port=destination_port,
        )

    def _mtime_reference(self) -> datetime.datetime:
        """
        Return file mtime in the log timezone, including tarball tolerance.

        Files copied directly from devices may have sub-second mtime precision.
        Archived files may store mtime with whole-second precision while
        sipmsg.log entries use milliseconds, so one second is enough tolerance.
        """
        m_timestamp = os.path.getmtime(self.fd.name)
        if int(m_timestamp) == m_timestamp:
            m_timestamp += 1
        return datetime.datetime.fromtimestamp(m_timestamp, self.timezone)

    def _resolve_start_year(self) -> typing.Optional[int]:
        """
        Scan valid headers and resolve the start year for the parsing pass.

        All valid headers, including non-SIP records, contribute to chronology.
        The first pass builds a virtual timeline from the mtime year, then
        shifts that timeline back until the last timestamp is not after file
        mtime. If a shifted date is invalid, such as Feb 29 in a non-leap year,
        the resolver keeps stepping back until the date can be represented.
        """
        reference = self._mtime_reference()
        resolver = SipTimestampResolver(self.timezone, reference.year)
        last_timestamp = None
        start_position = self.fd.tell()
        for line in self.fd:
            header = self._parse_header(line)
            if header is None:
                continue
            try:
                last_timestamp = resolver.resolve(header)
            except ValueError:
                continue
        self.fd.seek(start_position)
        if last_timestamp is None:
            return None

        years = 0
        timestamp_year = last_timestamp.year
        while last_timestamp > reference:
            years += 1
            try:
                last_timestamp = last_timestamp.replace(
                    year=timestamp_year - years)
            except ValueError:
                pass
        return reference.year - years

    def _iter_records(
            self, resolver: SipTimestampResolver
    ) -> typing.Iterator[SipMsgRecord]:
        """
        Yield valid SIP-text records from the current file position.

        Non-SIP records are skipped by checking only the first payload
        line. Once that line starts with a word character, the rest of the
        payload is kept unchanged until the exact 40-dash delimiter. Every
        valid header advances the timestamp resolver, even when its payload is
        skipped, because skipped records still preserve log chronology.
        """
        record = SipMsgRecordState()

        for line in self.fd:
            header = self._parse_header(line)
            if header is not None:
                timestamp = None
                try:
                    # Advance timestamp state...
                    timestamp = resolver.resolve(header)
                except ValueError:
                    # ... skipping headers with impossible dates.
                    pass
                record.start(header, timestamp)
                continue

            if line == SIPMSG_DELIMITER:
                completed = record.to_record()
                if completed is not None:
                    yield completed
                record.reset()
                continue

            if not record.is_active or record.is_skipped:
                # Ignore unrelated lines and skipped record bodies until
                # delimiter.
                continue

            record.add_payload_line(line)

        completed = record.to_record()
        if completed is not None:
            yield completed

    def __iter__(self) -> typing.Iterator[Frame]:
        start_year = self._resolve_start_year()
        if start_year is None:
            return

        timestamp_resolver = SipTimestampResolver(self.timezone, start_year)

        for record in self._iter_records(timestamp_resolver):
            header = record.header
            seconds = int(record.timestamp.timestamp())
            udp = UDP(
                header.source_port,
                header.destination_port,
                record.payload,
            )
            ip = IPv4(header.source_ip, header.destination_ip, udp)
            yield Frame(seconds, header.microsecond, ip)


def main() -> None:
    """
    Main function of the application. Retrieves user input, manages reading
    sipmsg.log and writing Packet Capture file.
    """
    settings = configure()
    with PacketCapture(settings.output, settings.compress) as pcap:
        for frame in SipMsgLogFile(settings.file, settings.timezone):
            pcap.write(frame)
    settings.file.close()
    settings.output.close()


if __name__ == '__main__':
    main()
