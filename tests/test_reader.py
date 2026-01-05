import io
import time
import unittest
import datetime
from unittest.mock import patch

from acmepcap import SipMsgLogFile


class ReaderTest(unittest.TestCase):
    def test_read_empty(self):
        """
        Simulate an input file with no content.
        """
        stream = io.StringIO('')
        stream.name = 'spam'
        sip_msg = SipMsgLogFile(stream, 'UTC')
        with patch('acmepcap.os.path.getmtime', return_value=time.time()):
            self.assertEqual(list(sip_msg), [])

    def test_read_outgoing(self):
        """
        Simulate a native input file with a sent message.
        """
        now = datetime.datetime.now(tz=datetime.timezone.utc)
        date = f'{now:%b %d %H:%M:%S.%f}'[:-3]
        stream = io.StringIO(
            f'{date} On [0:0]10.0.0.1:5060 sent to 10.0.0.2:5060\n'
            f'spam\n--'
        )
        sip_msg = SipMsgLogFile(stream, 'UTC')
        stream.name = 'spam'
        with patch('acmepcap.os.path.getmtime', return_value=time.time()):
            frames = list(sip_msg)
            self.assertEqual(len(frames), 1)
            self.assertEqual(frames[0].seconds, int(now.timestamp()))

    def test_read_incoming(self):
        """
        Simulate a native input file with a received message.
        """
        now = datetime.datetime.now(tz=datetime.timezone.utc)
        date = f'{now:%b %d %H:%M:%S.%f}'[:-3]
        stream = io.StringIO(
            f'{date} On [0:0]10.0.0.1:5060 received from 10.0.0.2:5060\n'
            f'spam\n--'
        )
        sip_msg = SipMsgLogFile(stream, 'UTC')
        stream.name = 'spam'
        with patch('acmepcap.os.path.getmtime', return_value=time.time()):
            frames = list(sip_msg)
            self.assertEqual(len(frames), 1)
            self.assertEqual(frames[0].seconds, int(now.timestamp()))

    def test_read_flip_mtime(self):
        """
        Simulate an input file from a tar archive with mtime from future.
        """
        now = datetime.datetime.now(tz=datetime.timezone.utc)
        date = f'{now:%b %d %H:%M:%S.%f}'[:-3]
        stream = io.StringIO(
            f'{date} On [0:0]10.0.0.1:5060 sent to 10.0.0.2:5060\n'
            f'spam\n--'
        )
        sip_msg = SipMsgLogFile(stream, 'UTC')
        stream.name = 'spam'
        with patch('acmepcap.os.path.getmtime',
                   return_value=int(time.time()) - 3600):
            frames = list(sip_msg)
            self.assertEqual(len(frames), 1)
            self.assertAlmostEqual(frames[0].seconds, int(now.timestamp()),
                                   delta=366 * 24 * 60 * 60)
