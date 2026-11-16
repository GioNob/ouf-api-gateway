from contextlib import redirect_stderr, redirect_stdout
import errno
import io
import json
from pathlib import Path
import socket
import ssl
import tempfile
import unittest
from unittest.mock import Mock, patch

from tools import semantic_provider_adapter as adapter
from tests.test_semantic_provider_adapter import KEY, binding


LISTENING = 'SEMANTIC_PROVIDER_ADAPTER=LISTENING NO_SECRETS_PRINTED=true\n'


class FlushedOutput(io.StringIO):
    def __init__(self):
        super().__init__()
        self.flushes = 0

    def flush(self):
        self.flushes += 1
        super().flush()


class AdapterExitCodesTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.configuration = Path(self.temp.name)/'private-configuration.json'
        self.output = FlushedOutput()
        self.stderr = io.StringIO()
        self.addCleanup(patch.stopall)
        patch('sys.argv', ['adapter', '--configuration', str(self.configuration)]).start()
        patch.object(adapter.os, 'geteuid', return_value=10006).start()

    def blocked(self, stage, reason, *, listening=False):
        with redirect_stdout(self.output), redirect_stderr(self.stderr), self.assertRaises(SystemExit) as stopped:
            adapter.main()
        self.assertEqual(stopped.exception.code, 1)
        self.assertIsNone(stopped.exception.__cause__)
        self.assertTrue(stopped.exception.__suppress_context__)
        self.assertEqual(self.output.getvalue(), (LISTENING if listening else '')
            +'SEMANTIC_PROVIDER_ADAPTER=BLOCKED STAGE='+stage+' REASON='+reason+' NO_SECRETS_PRINTED=true\n')
        self.assertEqual(self.output.flushes, 2 if listening else 1)
        self.assertEqual(self.stderr.getvalue(), '')

    def loaded(self):
        return patch.object(adapter, 'load_configuration', return_value=(
            {'listenAddress': '127.0.0.1', 'listenPort': 12345, 'maxWorkers': 1}, binding(), Mock()))

    def test_root_is_denied_before_configuration(self):
        with patch.object(adapter.os, 'geteuid', return_value=0), patch.object(adapter, 'load_configuration') as load:
            self.blocked('NON_ROOT', 'NON_ROOT_REQUIRED')
        load.assert_not_called()

    def test_wrong_configuration_keys(self):
        self.configuration.write_text('{"wrong": true}')
        self.blocked('CONFIGURATION', 'CONFIGURATION_INVALID')

    def test_public_receipt_key_file(self):
        key = Path(self.temp.name)/'receipt-key'
        key.write_text(KEY)
        key.chmod(0o644)
        cfg = dict.fromkeys(('listenAddress', 'listenPort', 'maxWorkers', 'requestTimeoutSeconds',
            'searchPath', 'fetchPath', 'provider', 'admission', 'receiptKeyFile',
            'tlsCertificateFile', 'tlsPrivateKeyFile'))
        cfg.update(listenAddress='127.0.0.1', listenPort=12345, receiptKeyFile=str(key))
        self.configuration.write_text(json.dumps(cfg))
        # Keep the real file ownership check valid even when CI runs as root.
        with patch.object(adapter.os, 'geteuid', side_effect=[10006, key.stat().st_uid]):
            self.blocked('CONFIGURATION', 'PRIVATE_FILE_REQUIRED')

    def test_missing_configuration(self):
        self.blocked('CONFIGURATION', 'OSERROR_ENOENT')

    def test_invalid_json(self):
        self.configuration.write_text('{invalid-json')
        self.blocked('CONFIGURATION', 'EXCEPTION_JSONDecodeError')

    def test_real_listener_port_already_in_use(self):
        with socket.socket() as occupied:
            occupied.bind(('127.0.0.1', 0))
            occupied.listen(1)
            with patch.object(adapter, 'load_configuration', return_value=(
                    {'listenAddress': '127.0.0.1', 'listenPort': occupied.getsockname()[1], 'maxWorkers': 1},
                    binding(), Mock())):
                self.blocked('LISTENER', 'OSERROR_EADDRINUSE')

    def test_unexpected_serve_failure_has_no_secret_output(self):
        message = str(self.configuration)+' '+KEY+' sensitive exception message'
        server = Mock()
        server.serve_forever.side_effect = RuntimeError(message)
        with self.loaded(), patch.object(adapter, 'BoundedTLSServer') as listener:
            listener.return_value.__enter__.return_value = server
            self.blocked('SERVE', 'EXCEPTION_RuntimeError', listening=True)
        for secret in (str(self.configuration), KEY, message, 'sensitive exception message'):
            self.assertNotIn(secret, self.output.getvalue()+self.stderr.getvalue())

    def test_listening_is_printed_and_flushed_once_before_serve(self):
        server = Mock()
        def serve():
            self.assertEqual(self.output.getvalue(), LISTENING)
            self.assertEqual(self.output.flushes, 1)
        server.serve_forever.side_effect = serve
        with self.loaded(), patch.object(adapter, 'BoundedTLSServer') as listener, \
                redirect_stdout(self.output), redirect_stderr(self.stderr):
            listener.return_value.__enter__.return_value = server
            adapter.main()
        server.serve_forever.assert_called_once_with()
        self.assertEqual(self.output.getvalue(), LISTENING)
        self.assertEqual(self.output.flushes, 1)
        self.assertEqual(self.stderr.getvalue(), '')


class DenialReasonTest(unittest.TestCase):
    def test_all_denial_classes_accept_only_closed_first_argument(self):
        for cls in (adapter.AdapterDenied, adapter.AdmissionDenied, adapter.relay.RelayDenied,
                    adapter.ProviderRequestDenied, adapter.SouthboundDenied):
            for code in ('A', 'A'+'0_'*31+'Z', 'CONFIGURATION_INVALID'):
                with self.subTest(cls=cls, code=code):
                    self.assertEqual(adapter.denial_reason(cls(code, 'secret second argument')), code)
            for args in ((), (None,), (123,), (b'CODE',), ('',), ('lowercase',),
                         ('CODE\n',), ('A'*65,), ('/private/path',), ('A SECRET',)):
                with self.subTest(cls=cls, args=args):
                    self.assertEqual(adapter.denial_reason(cls(*args)), 'DENIED_'+cls.__name__)

    def test_oserror_subclasses_and_unknown_errno(self):
        for error, code in ((FileNotFoundError(errno.ENOENT, 'secret path'), 'ENOENT'),
                            (PermissionError(errno.EACCES, 'secret path'), 'EACCES'),
                            (OSError(errno.EIO, 'secret path'), 'EIO'),
                            (OSError('secret'), 'UNKNOWN'), (OSError(999999, 'secret'), 'UNKNOWN')):
            with self.subTest(code=code):
                self.assertEqual(adapter.denial_reason(error), 'OSERROR_'+code)

    def test_ssl_is_classified_before_oserror(self):
        error = ssl.SSLError(errno.EACCES, 'secret certificate path')
        self.assertIsInstance(error, OSError)
        for reason in ('CERTIFICATE_VERIFY_FAILED', 'A'*64, None, 123, '', 'private path', 'BAD\n', 'A'*65):
            error.reason = reason
            expected = reason if reason in ('CERTIFICATE_VERIFY_FAILED', 'A'*64) else 'UNKNOWN'
            with self.subTest(reason=reason):
                self.assertEqual(adapter.denial_reason(error), 'SSLERROR_'+expected)
        self.assertEqual(adapter.denial_reason(ssl.SSLError('secret')), 'SSLERROR_UNKNOWN')

    def test_generic_exception_class_names_are_bounded(self):
        for cls in (ValueError, KeyError, TypeError, RuntimeError, Exception):
            self.assertEqual(adapter.denial_reason(cls('secret')), 'EXCEPTION_'+cls.__name__)
        for name in ('A'*64, 'Custom_Error123', 'Bad Name', 'A'*65, '_Private', 'Bad\n', 'Érror'):
            cls = type(name, (Exception,), {})
            expected = name if name in ('A'*64, 'Custom_Error123') else 'UNKNOWN'
            self.assertEqual(adapter.denial_reason(cls('secret')), 'EXCEPTION_'+expected)

    def test_exception_messages_are_never_formatted(self):
        class Unprintable(Exception):
            def __str__(self):
                raise AssertionError('must not format exception')

            __repr__ = __str__

        self.assertEqual(adapter.denial_reason(Unprintable('secret')), 'EXCEPTION_Unprintable')
        self.assertEqual(adapter.denial_reason(adapter.AdapterDenied(Unprintable())), 'DENIED_AdapterDenied')


if __name__ == '__main__':
    unittest.main()
