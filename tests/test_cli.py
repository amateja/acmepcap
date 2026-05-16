import argparse
import gzip
import io
import sys
import time
import unittest
from unittest.mock import mock_open, patch

import acmepcap


class TestArgs(unittest.TestCase):
    def test_parse_args_minimal(self):
        """
        Give only the minimal arguments in and verify if all configuration
        parameters are returned.
        """
        args = f'prog -f {__file__} -o {__file__}.pcap.gz'.split()
        with patch.object(sys, 'argv', args), \
                patch('argparse.open', mock_open()):
            settings = acmepcap.configure()
        self.assertTrue(hasattr(settings, 'file'))
        self.assertTrue(hasattr(settings, 'output'))
        self.assertTrue(hasattr(settings, 'compress'))
        self.assertTrue(hasattr(settings, 'timezone'))
        self.assertTrue(hasattr(settings, 'summary'))
        self.assertFalse(settings.summary)

    def test_parse_args_summary(self):
        """
        Enable conversion summary output.
        """
        args = f'prog -f {__file__} -o {__file__}.pcap --summary'.split()
        with patch.object(sys, 'argv', args), \
                patch('argparse.open', mock_open()):
            settings = acmepcap.configure()
        self.assertTrue(settings.summary)


class AlwaysOpenBytes(io.BytesIO):
    """
    For testing purpose keep the stream inspectable after close().
    """

    def __init__(self):
        super().__init__()
        self.close_count = 0

    def close(self):
        """
        Count close requests without closing the in-memory buffer.
        """
        self.close_count += 1


def configure(compress: bool, payload=b'') -> argparse.Namespace:
    """
    Mock of acmepcap.configure function.

    :param compress: is gzip compression required
    :param payload: sipmsg.log payload
    :return: argparse.Namespace with all configuration parameters.
    """
    sip_msg = io.BytesIO(payload)
    sip_msg.name = 'spam'
    return argparse.Namespace(
        file=sip_msg,
        compress=compress,
        output=AlwaysOpenBytes(),
        timezone='UTC',
        summary=False,
    )


class TestMain(unittest.TestCase):
    def test_with_compression(self):
        settings = configure(True)
        with patch('acmepcap.configure', return_value=settings), \
                patch('acmepcap.os.path.getmtime', return_value=time.time()):
            acmepcap.main()
        self.assertEqual(settings.output.tell(), 37)
        self.assertEqual(settings.output.close_count, 1)
        settings.output.seek(0)
        with gzip.GzipFile(fileobj=settings.output, mode='rb') as gzip_file:
            self.assertEqual(len(gzip_file.read()), 24)

    def test_without_compression(self):
        settings = configure(False)
        with patch('acmepcap.configure', return_value=settings), \
                patch('acmepcap.os.path.getmtime', return_value=time.time()):
            acmepcap.main()
        self.assertEqual(settings.output.tell(), 24)
        self.assertEqual(settings.output.close_count, 1)

    def test_with_payload(self):
        settings = configure(
            False,
            b'Jun 21 12:13:14.567 On [0:0]1.1.1.1:5060 sent to 2.2.2.2:5060\n'
            b'spam\n'
            b'----------------------------------------\n'
        )
        with patch('acmepcap.configure', return_value=settings), \
                patch('acmepcap.os.path.getmtime', return_value=time.time()):
            acmepcap.main()
        self.assertEqual(settings.output.tell(), 73)
        self.assertEqual(settings.output.close_count, 1)

    def test_summary_is_not_written_by_default(self):
        settings = configure(False)
        stderr = io.StringIO()

        with patch('acmepcap.configure', return_value=settings), \
                patch('acmepcap.os.path.getmtime', return_value=time.time()), \
                patch('sys.stderr', stderr):
            acmepcap.main()

        self.assertEqual(stderr.getvalue(), '')

    def test_summary_is_written_when_enabled(self):
        settings = configure(
            False,
            b'Jun 21 12:13:14.567 On [0:0]1.1.1.1:5060 '
            b'sent to 2.2.2.2:5060\n'
            b' spam\n'
            b'----------------------------------------\n'
        )
        settings.summary = True
        stderr = io.StringIO()

        with patch('acmepcap.configure', return_value=settings), \
                patch('acmepcap.os.path.getmtime', return_value=time.time()), \
                patch('sys.stderr', stderr):
            acmepcap.main()

        self.assertEqual(
            stderr.getvalue(),
            'Summary:\n'
            '  converted records: 0\n'
            '  skipped records: 1\n'
            '  skipped non-SIP records: 1\n'
            '  skipped malformed records: 0\n'
            '  skipped timestamp records: 0\n'
            '  skipped empty records: 0\n'
            '  skipped incomplete records: 0\n'
        )
