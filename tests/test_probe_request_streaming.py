"""Keep the disposable request-stream probe from leaving an APISIX route."""
import importlib.util
import sys
import unittest
from pathlib import Path
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location(
    "probe_request_streaming", ROOT / "ops/apisix/probe_request_streaming.py"
)
probe = importlib.util.module_from_spec(spec)
spec.loader.exec_module(probe)


class ProbeTest(unittest.TestCase):
    def test_probe_removes_exact_temporary_route_even_on_failure(self):
        import tempfile

        for passes in (True, False):
            with self.subTest(passes=passes), tempfile.TemporaryDirectory() as directory:
                key_file = Path(directory) / "key"
                key_file.write_text("private-test-key")
                self.run_case(key_file, passes)

    def run_case(self, key_file, passes):
        calls = []
        installed = set()

        def fake_admin(method, route_id, key, body=None):
            self.assertEqual(key, "private-test-key")
            self.assertTrue(route_id.startswith("ouf-request-stream-probe-"))
            calls.append((method, route_id))
            if method == "GET":
                return 200 if route_id in installed else 404
            if method == "PUT":
                self.assertEqual(body["plugins"]["proxy-control"], {"request_buffering": False})
                self.assertEqual(body["plugins"]["ip-restriction"], {"whitelist": ["127.0.0.1"]})
                installed.add(route_id)
                return 200
            installed.remove(route_id)
            return 200

        with patch.object(probe, "admin", fake_admin), patch.object(probe, "probe", lambda uri: (passes, 204)), patch.object(probe.time, "sleep"), patch.object(sys, "argv", ["probe_request_streaming.py", "--admin-key", str(key_file)]):
            if passes:
                probe.main()
            else:
                with self.assertRaisesRegex(RuntimeError, "not demonstrated"):
                    probe.main()
        self.assertEqual([method for method, _ in calls], ["GET", "PUT", "GET", "DELETE", "GET"])
        self.assertEqual(len({route_id for _, route_id in calls}), 1)
        self.assertFalse(installed)
