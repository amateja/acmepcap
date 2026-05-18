import argparse
import gzip
import io
import pathlib
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

import acmepcap


class TestArgs(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory()
        self.input_path = pathlib.Path(self.tmpdir.name) / 'sipmsg.log'
        self.output_path = pathlib.Path(self.tmpdir.name) / 'output.pcap'
        self.input_path.write_bytes(b'')

    def tearDown(self):
        self.tmpdir.cleanup()

    def test_parse_args_minimal(self):
        """
        Give only the minimal arguments in and verify if all configuration
        parameters are returned.
        """
        args = [
            'prog', '-f', str(self.input_path), '-o', str(self.output_path)
        ]
        with patch.object(sys, 'argv', args):
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
        args = [
            'prog', '-f', str(self.input_path), '-o', str(self.output_path),
            '--summary'
        ]
        with patch.object(sys, 'argv', args):
            settings = acmepcap.configure()
        self.assertTrue(settings.summary)


class TestFileArguments(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory()
        self.root = pathlib.Path(self.tmpdir.name)

    def tearDown(self):
        self.tmpdir.cleanup()

    def test_input_path_accepts_readable_file(self):
        path = self.root / 'sipmsg.log'
        path.write_bytes(b'')

        self.assertEqual(acmepcap.input_path(str(path)), path.absolute())

    def test_input_path_rejects_missing_file(self):
        path = self.root / 'missing.log'

        with self.assertRaises(argparse.ArgumentTypeError):
            acmepcap.input_path(str(path))

    def test_input_path_rejects_directory(self):
        with self.assertRaises(argparse.ArgumentTypeError):
            acmepcap.input_path(str(self.root))

    def test_input_path_rejects_unreadable_file(self):
        path = self.root / 'sipmsg.log'
        path.write_bytes(b'')

        with patch('acmepcap.os.access', return_value=False):
            with self.assertRaises(argparse.ArgumentTypeError):
                acmepcap.input_path(str(path))

    def test_output_path_accepts_new_file(self):
        path = self.root / 'output.pcap'

        self.assertEqual(acmepcap.output_path(str(path)), path.absolute())

    def test_output_path_accepts_existing_file(self):
        path = self.root / 'output.pcap'
        path.write_bytes(b'')

        self.assertEqual(acmepcap.output_path(str(path)), path.absolute())

    def test_output_path_rejects_directory(self):
        with self.assertRaises(argparse.ArgumentTypeError):
            acmepcap.output_path(str(self.root))

    def test_output_path_rejects_unwritable_file(self):
        path = self.root / 'output.pcap'
        path.write_bytes(b'')

        with patch('acmepcap.os.access', return_value=False):
            with self.assertRaises(argparse.ArgumentTypeError):
                acmepcap.output_path(str(path))

    def test_output_path_rejects_missing_parent(self):
        path = self.root / 'missing' / 'output.pcap'

        with self.assertRaises(argparse.ArgumentTypeError):
            acmepcap.output_path(str(path))

    def test_output_path_rejects_parent_that_is_not_directory(self):
        parent = self.root / 'not-a-directory'
        parent.write_bytes(b'')
        path = parent / 'output.pcap'

        with self.assertRaises(argparse.ArgumentTypeError):
            acmepcap.output_path(str(path))

    def test_output_path_rejects_unwritable_parent(self):
        path = self.root / 'output.pcap'

        with patch('acmepcap.os.access', return_value=False):
            with self.assertRaises(argparse.ArgumentTypeError):
                acmepcap.output_path(str(path))


class TestMain(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory()
        self.input_path = pathlib.Path(self.tmpdir.name) / 'sipmsg.log'
        self.output_path = pathlib.Path(self.tmpdir.name) / 'output.pcap'

    def tearDown(self):
        self.tmpdir.cleanup()

    def configure(self, compress: bool, payload=b'') -> argparse.Namespace:
        """
        Mock acmepcap.configure with temporary input/output paths.
        """
        self.input_path.write_bytes(payload)
        return argparse.Namespace(
            file=self.input_path,
            compress=compress,
            output=self.output_path,
            timezone='UTC',
            summary=False,
        )

    def test_with_compression(self):
        settings = self.configure(True)
        with patch('acmepcap.configure', return_value=settings), \
                patch('acmepcap.os.path.getmtime', return_value=time.time()):
            acmepcap.main()
        self.assertGreater(settings.output.stat().st_size, 0)
        with gzip.open(settings.output, mode='rb') as gzip_file:
            self.assertEqual(len(gzip_file.read()), 24)

    def test_without_compression(self):
        settings = self.configure(False)
        with patch('acmepcap.configure', return_value=settings), \
                patch('acmepcap.os.path.getmtime', return_value=time.time()):
            acmepcap.main()
        self.assertEqual(settings.output.stat().st_size, 24)

    def test_with_payload(self):
        settings = self.configure(
            False,
            b'Jun 21 12:13:14.567 On [0:0]1.1.1.1:5060 sent to 2.2.2.2:5060\n'
            b'spam\n'
            b'----------------------------------------\n'
        )
        with patch('acmepcap.configure', return_value=settings), \
                patch('acmepcap.os.path.getmtime', return_value=time.time()):
            acmepcap.main()
        self.assertEqual(settings.output.stat().st_size, 73)

    def test_summary_is_not_written_by_default(self):
        settings = self.configure(False)
        stderr = io.StringIO()

        with patch('acmepcap.configure', return_value=settings), \
                patch('acmepcap.os.path.getmtime', return_value=time.time()), \
                patch('sys.stderr', stderr):
            acmepcap.main()

        self.assertEqual(stderr.getvalue(), '')

    def test_summary_is_written_when_enabled(self):
        settings = self.configure(
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
