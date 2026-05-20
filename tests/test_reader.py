import datetime
import ipaddress
import pathlib
import tempfile
import time
import unittest
from unittest.mock import patch

from acmepcap import SipMsgLogFile

UTC = datetime.timezone.utc


class ReaderTest(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory()
        self.sipmsg_path = pathlib.Path(self.tmpdir.name) / 'sipmsg.log'

    def tearDown(self):
        self.tmpdir.cleanup()

    def test_read_empty(self):
        """
        Simulate an input file with no content.
        """
        buffer = b''
        self.sipmsg_path.write_bytes(buffer)
        sip_msg = SipMsgLogFile(self.sipmsg_path, 'UTC')

        with patch('acmepcap.os.path.getmtime', return_value=time.time()):
            self.assertEqual(list(sip_msg), [])

    def test_read_outgoing(self):
        """
        Simulate a native input file with a sent message.
        """
        now = datetime.datetime.now(tz=UTC)
        date = f'{now:%b %d %H:%M:%S.%f}'[:-3].encode()
        buffer = date + b' On [0:0]10.0.0.1:5060 sent to 10.0.0.2:5060\n' \
            b'spam\n' \
            b'----------------------------------------\n'
        self.sipmsg_path.write_bytes(buffer)
        sip_msg = SipMsgLogFile(self.sipmsg_path, 'UTC')

        with patch('acmepcap.os.path.getmtime', return_value=time.time()):
            frames = list(sip_msg)

        self.assertEqual(len(frames), 1)
        self.assertEqual(frames[0].seconds, int(now.timestamp()))
        self.assertEqual(sip_msg.converted, 1)
        self.assertEqual(sip_msg.skipped_non_sip, 0)
        self.assertEqual(sip_msg.skipped_malformed, 0)
        self.assertEqual(sip_msg.skipped_timestamp, 0)
        self.assertEqual(sip_msg.skipped_empty, 0)
        self.assertEqual(sip_msg.skipped_incomplete, 0)

    def test_read_incoming(self):
        """
        Simulate a native input file with a received message.
        """
        now = datetime.datetime.now(tz=UTC)
        date = f'{now:%b %d %H:%M:%S.%f}'[:-3].encode()
        buffer = \
            date + b' On [0:0]10.0.0.1:5060 received from 10.0.0.2:5060\n' \
            b'spam\n' \
            b'----------------------------------------\n'
        self.sipmsg_path.write_bytes(buffer)
        sip_msg = SipMsgLogFile(self.sipmsg_path, 'UTC')

        with patch('acmepcap.os.path.getmtime', return_value=time.time()):
            frames = list(sip_msg)

        self.assertEqual(len(frames), 1)
        self.assertEqual(frames[0].seconds, int(now.timestamp()))

    def test_outgoing_packet_direction_and_payload(self):
        """
        Use local address as packet source for outgoing SIP records.
        """
        now = datetime.datetime.now(tz=UTC)
        date = f'{now:%b %d %H:%M:%S.%f}'[:-3]
        source_ip = ipaddress.IPv4Address('10.0.0.1')
        source_port = 5060
        destination_ip = ipaddress.IPv4Address('10.0.0.2')
        destination_port = 5070
        payload = 'INVITE sip:user@example.com SIP/2.0\r\n'
        buffer = f'{date} On {source_ip}:{source_port} ' \
            f'sent to {destination_ip}:{destination_port}\n' \
            f'{payload}----------------------------------------\n'.encode()
        self.sipmsg_path.write_bytes(buffer)
        sip_msg = SipMsgLogFile(self.sipmsg_path, 'UTC')

        with patch('acmepcap.os.path.getmtime', return_value=time.time()):
            frame, = list(sip_msg)

        packet = frame.packet
        segment = packet.transport
        self.assertEqual(packet.source, int(source_ip))
        self.assertEqual(packet.destination, int(destination_ip))
        self.assertEqual(segment.source, source_port)
        self.assertEqual(segment.destination, destination_port)
        self.assertEqual(segment.data, payload.encode())

    def test_incoming_packet_direction_and_payload(self):
        """
        Use remote address as packet source for incoming SIP records.
        """
        now = datetime.datetime.now(tz=UTC)
        date = f'{now:%b %d %H:%M:%S.%f}'[:-3]
        source_ip = ipaddress.IPv4Address('10.0.0.2')
        source_port = 5070
        destination_ip = ipaddress.IPv4Address('10.0.0.1')
        destination_port = 5060
        payload = 'SIP/2.0 200 OK\r\n'
        buffer = f'{date} On {destination_ip}:{destination_port} ' \
            f'received from {source_ip}:{source_port}\n' \
            f'{payload}----------------------------------------\n'.encode()
        self.sipmsg_path.write_bytes(buffer)
        sip_msg = SipMsgLogFile(self.sipmsg_path, 'UTC')

        with patch('acmepcap.os.path.getmtime', return_value=time.time()):
            frame, = list(sip_msg)

        packet = frame.packet
        segment = packet.transport
        self.assertEqual(packet.source, int(source_ip))
        self.assertEqual(packet.destination, int(destination_ip))
        self.assertEqual(segment.source, source_port)
        self.assertEqual(segment.destination, destination_port)
        self.assertEqual(segment.data, payload.encode())

    def test_read_multiline_payload(self):
        """
        Preserve all lines of a multi-line SIP payload.
        """
        now = datetime.datetime.now(tz=UTC)
        date = f'{now:%b %d %H:%M:%S.%f}'[:-3]
        payload = 'INVITE sip:user@example.com SIP/2.0\r\n' \
            'Via: SIP/2.0/UDP 10.0.0.1:5060\r\n' \
            'Call-ID: abc\r\n'
        buffer = f'{date} On [0:0]10.0.0.1:5060 sent to 10.0.0.2:5060\n' \
            f'{payload}----------------------------------------\n'.encode()
        self.sipmsg_path.write_bytes(buffer)
        sip_msg = SipMsgLogFile(self.sipmsg_path, 'UTC')

        with patch('acmepcap.os.path.getmtime', return_value=time.time()):
            frames = list(sip_msg)

        self.assertEqual(len(frames), 1)
        self.assertEqual(frames[0].packet.transport.data, payload.encode())

    def test_read_flip_mtime(self):
        """
        Simulate an input file from a tar archive with mtime from the past.
        """
        now = datetime.datetime.now(tz=UTC)
        date = f'{now:%b %d %H:%M:%S.%f}'[:-3].encode()
        buffer = date + b' On [0:0]10.0.0.1:5060 sent to 10.0.0.2:5060\n' \
            b'spam\n----------------------------------------\n'
        self.sipmsg_path.write_bytes(buffer)
        sip_msg = SipMsgLogFile(self.sipmsg_path, 'UTC')

        with patch('acmepcap.os.path.getmtime',
                   return_value=int(time.time()) - 3600):
            frames = list(sip_msg)

        self.assertEqual(len(frames), 1)
        self.assertAlmostEqual(frames[0].seconds, int(now.timestamp()),
                               delta=366 * 24 * 60 * 60)

    def test_read_single_digit_day(self):
        """
        Parse syslog-style single digit days with two spaces after month.
        """
        expected = datetime.datetime(2022, 2, 3, 1, 17, 42, 267000, tzinfo=UTC)
        # Use an explicit date because datetime.strftime('%d') is zero-padded.
        buffer = b'Feb  3 01:17:42.267 On [0:2829]10.0.0.1:5060 ' \
            b'sent to 10.0.0.2:5060\n' \
            b'spam\n' \
            b'----------------------------------------\n'
        self.sipmsg_path.write_bytes(buffer)
        mtime = expected.replace(microsecond=0) + datetime.timedelta(seconds=1)
        sip_msg = SipMsgLogFile(self.sipmsg_path, 'UTC')

        with patch('acmepcap.os.path.getmtime',
                   return_value=mtime.timestamp()):
            frames = list(sip_msg)

        self.assertEqual(len(frames), 1)
        self.assertEqual(frames[0].seconds, int(expected.timestamp()))

    def test_read_without_bracketed_context(self):
        """
        Parse headers where the optional [network-interface:VLAN] context is
        absent.
        """
        now = datetime.datetime.now(tz=UTC)
        date = f'{now:%b %d %H:%M:%S.%f}'[:-3].encode()
        buffer = \
            date + b' On 192.168.19.74:8270 sent to 192.168.19.71:5061\n' \
            b'spam\n----------------------------------------\n'
        self.sipmsg_path.write_bytes(buffer)
        sip_msg = SipMsgLogFile(self.sipmsg_path, 'UTC')

        with patch('acmepcap.os.path.getmtime', return_value=time.time()):
            frames = list(sip_msg)

        self.assertEqual(len(frames), 1)

    def test_skip_non_sip_payload(self):
        """
        Skip records whose payload starts with whitespace.
        """
        now = datetime.datetime.now(tz=UTC)
        date = f'{now:%b %d %H:%M:%S.%f}'[:-3].encode()
        buffer = date + b' On 127.0.0.1:2945 sent to 127.0.0.1:2944\n' \
            b'  spam\n' \
            b'----------------------------------------\n'
        self.sipmsg_path.write_bytes(buffer)
        sip_msg = SipMsgLogFile(self.sipmsg_path, 'UTC')

        with patch('acmepcap.os.path.getmtime', return_value=time.time()):
            self.assertEqual(list(sip_msg), [])

        self.assertEqual(sip_msg.converted, 0)
        self.assertEqual(sip_msg.skipped_non_sip, 1)
        self.assertEqual(sip_msg.skipped_malformed, 0)
        self.assertEqual(sip_msg.skipped_timestamp, 0)
        self.assertEqual(sip_msg.skipped_empty, 0)
        self.assertEqual(sip_msg.skipped_incomplete, 0)

    def test_skip_malformed_record_and_yield_next_valid_record(self):
        """
        Continue after a malformed record and extract later valid records.
        """
        buffer = \
            b'Sep 10 15:40:33.054 On 999.0.0.1:2945 sent to 127.0.0.1:2944\n' \
            b'spam\n' \
            b'----------------------------------------\n' \
            b'Sep 10 15:40:34.054 On 127.0.0.1:2945 sent to 127.0.0.1:2944\n' \
            b'spam\n' \
            b'----------------------------------------\n'
        self.sipmsg_path.write_bytes(buffer)
        mtime = datetime.datetime(2025, 9, 10, 16, tzinfo=UTC)
        sip_msg = SipMsgLogFile(self.sipmsg_path, 'UTC')

        with patch('acmepcap.os.path.getmtime',
                   return_value=mtime.timestamp()):
            frames = list(sip_msg)

        self.assertEqual(len(frames), 1)
        self.assertEqual(sip_msg.skipped_malformed, 1)

    def test_skip_invalid_port_and_yield_next_valid_record(self):
        """
        Continue after a header containing an out-of-range UDP port.
        """
        buffer = b'Sep 10 15:40:33.054 On 127.0.0.1:70000 ' \
            b'sent to 127.0.0.1:2944\n' \
            b'spam\n' \
            b'----------------------------------------\n' \
            b'Sep 10 15:40:34.054 On 127.0.0.1:2945 sent to 127.0.0.1:2944\n' \
            b'spam\n' \
            b'----------------------------------------\n'
        self.sipmsg_path.write_bytes(buffer)
        mtime = datetime.datetime(2025, 9, 10, 16, tzinfo=UTC)
        sip_msg = SipMsgLogFile(self.sipmsg_path, 'UTC')

        with patch('acmepcap.os.path.getmtime',
                   return_value=mtime.timestamp()):
            frames = list(sip_msg)

        self.assertEqual(len(frames), 1)
        self.assertEqual(sip_msg.skipped_malformed, 1)

    def test_skip_impossible_date_and_yield_next_valid_record(self):
        """
        Continue after a valid-looking header with an impossible date.
        """
        buffer = \
            b'Feb 29 15:40:33.054 On 127.0.0.1:2945 sent to 127.0.0.1:2944\n' \
            b'spam\n' \
            b'----------------------------------------\n' \
            b'Mar  1 15:40:34.054 On 127.0.0.1:2945 sent to 127.0.0.1:2944\n' \
            b'spam\n' \
            b'----------------------------------------\n'
        self.sipmsg_path.write_bytes(buffer)
        mtime = datetime.datetime(2025, 3, 1, 16, tzinfo=UTC)
        sip_msg = SipMsgLogFile(self.sipmsg_path, 'UTC')

        with patch('acmepcap.os.path.getmtime',
                   return_value=mtime.timestamp()):
            frames = list(sip_msg)

        expected = datetime.datetime(2025, 3, 1, 15, 40, 34, 54000, tzinfo=UTC)
        self.assertEqual(len(frames), 1)
        self.assertEqual(frames[0].seconds, int(expected.timestamp()))
        self.assertEqual(sip_msg.skipped_timestamp, 1)

    def test_skip_empty_record_and_yield_next_valid_record(self):
        """
        Continue after a header without payload before delimiter.
        """
        buffer = \
            b'Sep 10 15:40:33.054 On 127.0.0.1:2945 sent to 127.0.0.1:2944\n' \
            b'----------------------------------------\n' \
            b'Sep 10 15:40:34.054 On 127.0.0.1:2945 sent to 127.0.0.1:2944\n' \
            b'spam\n' \
            b'----------------------------------------\n'
        self.sipmsg_path.write_bytes(buffer)
        mtime = datetime.datetime(2025, 9, 10, 16, tzinfo=UTC)
        sip_msg = SipMsgLogFile(self.sipmsg_path, 'UTC')

        with patch('acmepcap.os.path.getmtime',
                   return_value=mtime.timestamp()):
            frames = list(sip_msg)

        self.assertEqual(len(frames), 1)
        self.assertEqual(sip_msg.skipped_empty, 1)

    def test_leap_day_year_shift_skips_non_leap_years(self):
        """
        Continue shifting Feb 29 until the target year is valid.
        """
        buffer = \
            b'Feb 29 23:59:59.999 On 127.0.0.1:2945 sent to 127.0.0.1:2944\n' \
            b'spam\n' \
            b'----------------------------------------\n'
        self.sipmsg_path.write_bytes(buffer)
        mtime = datetime.datetime(2028, 2, 28, 0, tzinfo=UTC)
        sip_msg = SipMsgLogFile(self.sipmsg_path, 'UTC')

        with patch('acmepcap.os.path.getmtime',
                   return_value=mtime.timestamp()):
            frames = list(sip_msg)

        expected = datetime.datetime(2024, 2, 29, 23, 59, 59, 999000, UTC)
        self.assertEqual(len(frames), 1)
        self.assertEqual(frames[0].seconds, int(expected.timestamp()))

    def test_skip_final_message_without_delimiter(self):
        """
        Treat the final record as incomplete when the delimiter is missing.
        """
        now = datetime.datetime.now(UTC)
        date = f'{now:%b %d %H:%M:%S.%f}'[:-3].encode()
        buffer = date + b' On 127.0.0.1:2945 sent to 127.0.0.1:2944\n' \
            b'spam\n'
        self.sipmsg_path.write_bytes(buffer)
        sip_msg = SipMsgLogFile(self.sipmsg_path, 'UTC')

        with patch('acmepcap.os.path.getmtime', return_value=time.time()):
            frames = list(sip_msg)

        self.assertEqual(len(frames), 0)
        self.assertEqual(sip_msg.skipped_incomplete, 1)

    def test_two_pass_year_rollover(self):
        """
        Use the last header to resolve December/January rollover.
        """
        buffer = \
            b'Dec 31 23:59:59.000 On 10.0.0.1:5060 sent to 10.0.0.2:5060\n' \
            b'spam\n' \
            b'----------------------------------------\n' \
            b'Jan  1 00:00:01.000 On 10.0.0.1:5060 sent to 10.0.0.2:5060\n' \
            b'spam\n' \
            b'----------------------------------------\n'
        self.sipmsg_path.write_bytes(buffer)
        mtime = datetime.datetime(2025, 1, 1, 0, 1, tzinfo=UTC)
        sip_msg = SipMsgLogFile(self.sipmsg_path, 'UTC')

        with patch('acmepcap.os.path.getmtime',
                   return_value=mtime.timestamp()):
            frames = list(sip_msg)

        expected_first = datetime.datetime(2024, 12, 31, 23, 59, 59,
                                           tzinfo=UTC)
        expected_second = datetime.datetime(2025, 1, 1, 0, 0, 1, tzinfo=UTC)
        self.assertEqual(len(frames), 2)
        self.assertEqual(frames[0].seconds, int(expected_first.timestamp()))
        self.assertEqual(frames[1].seconds, int(expected_second.timestamp()))

    def test_three_pass_year_rollover(self):
        """
        Use the last header to resolve December/January rollover.
        """
        buffer = \
            b'Dec 31 23:59:59.000 On 10.0.0.1:5060 sent to 10.0.0.2:5060\n' \
            b'spam\n' \
            b'----------------------------------------\n' \
            b'Dec 30 23:59:59.000 On 10.0.0.1:5060 sent to 10.0.0.2:5060\n' \
            b'spam\n' \
            b'----------------------------------------\n' \
            b'Jan  1 00:00:01.000 On 10.0.0.1:5060 sent to 10.0.0.2:5060\n' \
            b'spam\n' \
            b'----------------------------------------\n'
        self.sipmsg_path.write_bytes(buffer)
        mtime = datetime.datetime(2025, 1, 1, 0, 1, tzinfo=UTC)
        sip_msg = SipMsgLogFile(self.sipmsg_path, 'UTC')

        with patch('acmepcap.os.path.getmtime',
                   return_value=mtime.timestamp()):
            frames = list(sip_msg)

        expected_first = datetime.datetime(
            2023, 12, 31, 23, 59, 59, tzinfo=UTC
        )
        expected_second = datetime.datetime(
            2024, 12, 30, 23, 59, 59, tzinfo=UTC
        )
        expected_third = datetime.datetime(
            2025, 1, 1, 0, 0, 1, tzinfo=UTC
        )
        self.assertEqual(len(frames), 3)
        self.assertEqual(frames[0].seconds, int(expected_first.timestamp()))
        self.assertEqual(frames[1].seconds, int(expected_second.timestamp()))
        self.assertEqual(frames[2].seconds, int(expected_third.timestamp()))

    def test_multiyear_forward_rollover(self):
        """
        Resolve multiple chronological rollovers without storing all records.
        """
        buffer = \
            b'Jul 31 12:01:02.003 On 10.0.0.1:5060 sent to 10.0.0.2:5060\n' \
            b'spam\n' \
            b'----------------------------------------\n' \
            b'Jul 31 12:01:02.003 On 10.0.0.1:5060 sent to 10.0.0.2:5060\n' \
            b'ham\n' \
            b'----------------------------------------\n' \
            b'Aug  1 10:11:02.003 On 10.0.0.1:5060 sent to 10.0.0.2:5060\n' \
            b'bacon\n' \
            b'----------------------------------------\n' \
            b'Jun 10 23:00:40.443 On 10.0.0.1:5060 sent to 10.0.0.2:5060\n' \
            b'and\n' \
            b'----------------------------------------\n' \
            b'Mar  8 17:18:19.202 On 10.0.0.1:5060 sent to 10.0.0.2:5060\n' \
            b'eggs\n' \
            b'----------------------------------------\n'
        self.sipmsg_path.write_bytes(buffer)
        mtime = datetime.datetime(2026, 3, 8, 17, 18, 20, tzinfo=UTC)
        sip_msg = SipMsgLogFile(self.sipmsg_path, 'UTC')

        with patch('acmepcap.os.path.getmtime',
                   return_value=mtime.timestamp()):
            frames = list(sip_msg)

        expected = [
            datetime.datetime(2024, 7, 31, 12, 1, 2, 3000, tzinfo=UTC),
            datetime.datetime(2024, 7, 31, 12, 1, 2, 3000, tzinfo=UTC),
            datetime.datetime(2024, 8, 1, 10, 11, 2, 3000, tzinfo=UTC),
            datetime.datetime(2025, 6, 10, 23, 0, 40, 443000, tzinfo=UTC),
            datetime.datetime(2026, 3, 8, 17, 18, 19, 202000, tzinfo=UTC),
        ]
        self.assertEqual(len(frames), len(expected))
        self.assertEqual([frame.seconds for frame in frames],
                         [int(item.timestamp()) for item in expected])

    def test_skipped_record_header_contributes_to_rollover(self):
        """
        Use skipped non-SIP record headers when calculating chronology.
        """
        buffer = \
            b'Jan  1 00:00:01.000 On 10.0.0.1:5060 sent to 10.0.0.2:5060\n' \
            b'spam\n' \
            b'----------------------------------------\n' \
            b'Dec 31 23:59:59.000 On 10.0.0.1:5060 sent to 10.0.0.2:5060\n' \
            b'  spam\n' \
            b'----------------------------------------\n'
        self.sipmsg_path.write_bytes(buffer)
        mtime = datetime.datetime(2025, 1, 1, 0, 1, tzinfo=UTC)
        sip_msg = SipMsgLogFile(self.sipmsg_path, 'UTC')

        with patch('acmepcap.os.path.getmtime',
                   return_value=mtime.timestamp()):
            frames = list(sip_msg)

        expected = datetime.datetime(2024, 1, 1, 0, 0, 1, tzinfo=UTC)
        self.assertEqual(len(frames), 1)
        self.assertEqual(frames[0].seconds, int(expected.timestamp()))

    def test_dst_fallback_uses_second_fold_when_time_moves_back(self):
        """
        Resolve repeated DST hour before treating the record as year rollover.
        """
        buffer = \
            b'Oct 25 02:59:59.000 On 10.0.0.1:5060 sent to 10.0.0.2:5060\n' \
            b'spam\n' \
            b'----------------------------------------\n' \
            b'Oct 25 02:00:00.000 On 10.0.0.1:5060 sent to 10.0.0.2:5060\n' \
            b'spam\n' \
            b'----------------------------------------\n'
        self.sipmsg_path.write_bytes(buffer)
        mtime = datetime.datetime(2026, 10, 25, 3, 5, tzinfo=UTC)
        sip_msg = SipMsgLogFile(self.sipmsg_path, 'Europe/Warsaw')

        with patch('acmepcap.os.path.getmtime',
                   return_value=mtime.timestamp()):
            frames = list(sip_msg)

        expected_first = datetime.datetime(
            2026, 10, 25, 2, 59, 59,
            tzinfo=datetime.timezone(datetime.timedelta(hours=2))
        )
        expected_second = datetime.datetime(
            2026, 10, 25, 2, 0, 0,
            tzinfo=datetime.timezone(datetime.timedelta(hours=1))
        )
        self.assertEqual(len(frames), 2)
        self.assertEqual(frames[0].seconds, int(expected_first.timestamp()))
        self.assertEqual(frames[1].seconds, int(expected_second.timestamp()))
