import argparse
import dataclasses
import datetime
import gzip
import ipaddress
import os.path
import re
import struct
import sys
import typing
import zoneinfo

__version__ = '0.2.0'
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
    b'Jan': 1,
    b'Feb': 2,
    b'Mar': 3,
    b'Apr': 4,
    b'May': 5,
    b'Jun': 6,
    b'Jul': 7,
    b'Aug': 8,
    b'Sep': 9,
    b'Oct': 10,
    b'Nov': 11,
    b'Dec': 12
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
SIPMSG_HEADER_CANDIDATE = re.compile(
    rb'^(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec) {1,2}\d{1,2} '
)
SIPMSG_WORD_PAYLOAD = re.compile(rb'^\w')


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
    parser.add_argument(
        '--summary',
        action='store_true',
        help='print conversion summary to stderr',
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
                 packet: typing.Union['IPv4', 'IPv6']) -> None:
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
    mtime and chronological order of valid log headers.
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
    Mutable state for the record currently being read.

    The parser receives sipmsg.log one line at a time. This object keeps the
    current header, resolved timestamp, payload lines, and skip state until a
    delimiter confirms that the record is complete.
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

    def add_payload_line(self, line: bytes) -> bool:
        """
        Add a payload line and return whether the record remains convertible.

        The first payload line decides if the record looks like SIP. Lines
        starting with whitespace are treated as non-SIP records and skipped.
        """
        if self.payload is None:
            if SIPMSG_WORD_PAYLOAD.match(line):
                self.payload = [line]
                return True
            else:
                self.is_skipped = True
                return False

        self.payload.append(line)
        return True

    def payload_bytes(self) -> bytes:
        return b''.join(self.payload or [])

    def to_record(self) -> typing.Optional['SipMsgRecord']:
        if self.header is None or self.timestamp is None or \
                self.payload is None:
            return None

        return SipMsgRecord(
            timestamp=self.timestamp,
            header=self.header,
            payload=self.payload_bytes(),
        )


@dataclasses.dataclass(frozen=True)
class SipMsgRecord:
    """
    Complete SIP record that can be converted into a PCAP frame.
    """
    timestamp: datetime.datetime
    header: SipMsgRecordHeader
    payload: bytes


class SipMsgLogFile:
    """
    Iterable reader for Acme Packet sipmsg.log files.

    The reader is designed for support workflows where large SBC logs need to
    be converted into PCAP without loading the whole file into memory. It uses
    two passes over a seekable binary stream:

    1. Find the last valid message timestamp so year rollover can be inferred
       without reading the whole file into memory.
    2. Parse complete message records one by one and yield PCAP frames.

    Records whose first payload line does not start with a word character are
    treated as non-SIP and skipped. Their headers still contribute to timestamp
    chronology. Records not closed by the exact 40-dash delimiter are treated
    as incomplete and skipped.
    """
    def __init__(self, fd: typing.BinaryIO, timezone: str) -> None:
        self.fd = fd
        self.converted = 0
        self.skipped_non_sip = 0
        self.skipped_malformed = 0
        self.skipped_timestamp = 0
        self.skipped_empty = 0
        self.skipped_incomplete = 0
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
            month=MONTHS[header['month']],
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

    def summary(self) -> str:
        """
        Return a human-readable conversion summary for optional CLI output.
        """
        skipped = self.skipped_non_sip + self.skipped_malformed + \
            self.skipped_timestamp + self.skipped_empty + \
            self.skipped_incomplete
        return 'Summary:\n' \
            f'  converted records: {self.converted}\n' \
            f'  skipped records: {skipped}\n' \
            f'  skipped non-SIP records: {self.skipped_non_sip}\n' \
            f'  skipped malformed records: {self.skipped_malformed}\n' \
            f'  skipped timestamp records: {self.skipped_timestamp}\n' \
            f'  skipped empty records: {self.skipped_empty}\n' \
            f'  skipped incomplete records: {self.skipped_incomplete}\n'

    def _start_record(self, record: SipMsgRecordState,
                      header: SipMsgRecordHeader,
                      resolver: SipTimestampResolver) -> None:
        """
        Start tracking a new log record and resolve its timestamp.

        Timestamp resolution happens before payload classification so skipped
        non-SIP records still preserve chronological context for later records.
        """
        timestamp = None
        try:
            timestamp = resolver.resolve(header)
        except ValueError:
            self.skipped_timestamp += 1
        record.start(header, timestamp)

    def _flush_record(
            self, record: SipMsgRecordState) -> typing.Optional[Frame]:
        """
        Convert a delimiter-closed record into a frame when it is complete.

        Empty records are counted as skipped. Incomplete records are handled at
        EOF, where a missing delimiter means the record may have been truncated
        by log rotation.
        """
        completed = record.to_record()
        if completed is not None:
            header = completed.header
            seconds = int(completed.timestamp.timestamp())
            udp = UDP(
                header.source_port,
                header.destination_port,
                completed.payload,
            )
            ip = IPv4(header.source_ip, header.destination_ip, udp)
            self.converted += 1
            record.reset()
            return Frame(seconds, header.microsecond, ip)
        if record.header is not None and record.timestamp is not None \
                and record.payload is None and not record.is_skipped:
            self.skipped_empty += 1
        record.reset()
        return None

    def __iter__(self) -> typing.Iterator[Frame]:
        """
        Yield frames for complete SIP records.

        The state machine reacts to valid headers, malformed header candidates,
        exact delimiters, and payload lines. EOF without a delimiter marks the
        active record as incomplete instead of yielding it.
        """
        start_year = self._resolve_start_year()
        if start_year is None:
            return

        timestamp_resolver = SipTimestampResolver(self.timezone, start_year)
        record = SipMsgRecordState()

        for line in self.fd:
            header = self._parse_header(line)
            if header is not None:
                # A valid header starts a new sipmsg.log record. Resolve the
                # timestamp before reading the payload so skipped records still
                # preserve chronology.
                self._start_record(record, header, timestamp_resolver)
                continue

            if SIPMSG_HEADER_CANDIDATE.match(line):
                # The line looks like a sipmsg.log header but failed strict
                # parsing, for example because of an invalid IP address or
                # port.
                self.skipped_malformed += 1
                record.reset()
                continue

            if line == SIPMSG_DELIMITER:
                # The exact 40-dash delimiter is the only trusted end-of-record
                # marker. A complete SIP record is converted; an empty record
                # is counted as skipped.
                frame = self._flush_record(record)
                if frame is not None:
                    yield frame
                continue

            if not record.is_active or record.is_skipped:
                # We are either outside a record or ignoring the body of a
                # record already classified as skipped. Wait for a header or
                # delimiter to change parser state.
                continue

            # We are inside an active record. The first payload line decides
            # whether this is SIP-like enough to convert; later payload lines
            # are preserved.
            if not record.add_payload_line(line):
                self.skipped_non_sip += 1

        # EOF before a delimiter means the active record may be truncated by
        # log rotation, so it is counted but not converted.
        if record.is_active and not record.is_skipped:
            self.skipped_incomplete += 1


def main() -> None:
    """
    Main function of the application. Retrieves user input, manages reading
    sipmsg.log and writing Packet Capture file.
    """
    settings = configure()
    reader = SipMsgLogFile(settings.file, settings.timezone)
    with PacketCapture(settings.output, settings.compress) as pcap:
        for frame in reader:
            pcap.write(frame)
    if settings.summary:
        sys.stderr.write(reader.summary())
    settings.file.close()
    settings.output.close()


if __name__ == '__main__':
    main()
