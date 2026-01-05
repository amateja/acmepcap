import argparse
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


class AlwaysOpenBytes(io.BytesIO):
    """
    For testing purpose keep the stream always open by overriding its close()
    method.
    """
    def close(self):
        """
        Override parent's class method to do nothing.
        """
        pass


def configure(compress: bool, payload='') -> argparse.Namespace:
    """
    Mock of acmepcap.configure function.

    :param compress: is gzip compression required
    :param payload: sipmsg.log payload
    :return: argparse.Namespace with all configuration parameters.
    """
    sip_msg = io.StringIO(payload)
    sip_msg.name = 'spam'
    return argparse.Namespace(
        file=sip_msg,
        compress=compress,
        output=AlwaysOpenBytes(),
        timezone='UTC',
    )


class TestMain(unittest.TestCase):
    def test_with_compression(self):
        settings = configure(True)
        with patch('acmepcap.configure', return_value=settings), \
                patch('acmepcap.os.path.getmtime', return_value=time.time()):
            acmepcap.main()
        self.assertEqual(settings.output.tell(), 32)

    def test_without_compression(self):
        settings = configure(False)
        with patch('acmepcap.configure', return_value=settings), \
                patch('acmepcap.os.path.getmtime', return_value=time.time()):
            acmepcap.main()
        self.assertEqual(settings.output.tell(), 24)

    def test_with_payload(self):
        settings = configure(
            False,
            'Jun 21 12:13:14.567 On [0:0]1.1.1.1:5060 sent to 2.2.2.2:5060\n'
            'spam\n--'
        )
        with patch('acmepcap.configure', return_value=settings), \
                patch('acmepcap.os.path.getmtime', return_value=time.time()):
            acmepcap.main()
        self.assertEqual(settings.output.tell(), 73)
