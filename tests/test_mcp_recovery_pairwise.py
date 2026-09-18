import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from tools.compile_config import ROOT, compile_config
from tools.mcp_dispatch import TrustedIdentity
from tools.mcp_dispatch import DispatchError
from tools.mcp_recovery import MCPRecoveryMediator
from tools.pairwise_server import HTTPUpstream


def test_gateway_queries_real_owner_adapter_by_persisted_backend_request_id():
    seen = []

    class Owner(BaseHTTPRequestHandler):
        def do_GET(self):
            seen.append((self.path, dict(self.headers.items())))
            payload = json.dumps({"BackendRequestID": "udp-request-1", "Outcome": "NOT_DISPATCHED", "OutcomeCode": "OWNER_PROVES_NO_DISPATCH"}, separators=(",", ":")).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(payload)

        def log_message(self, *_):
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Owner)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        mediator = MCPRecoveryMediator(compile_config(ROOT / "ouf-config"), HTTPUpstream(f"http://127.0.0.1:{server.server_port}"), service_identity="ouf-mcp-server")
        body = (ROOT / "tests/fixtures/mcp-recovery-request.json").read_bytes()
        identity = TrustedIdentity("ouf-mcp-server", "agent-1", "tenant-1", "MCP_SERVER", "authn-1", "decision-1", frozenset({"mcp.attempt.recover"}))
        result = mediator.recover(body, {"X-Correlation-ID": "correlation-recovery-1"}, identity)
    finally:
        server.shutdown()
        thread.join()
        server.server_close()
    assert json.loads(result.body)["OutcomeCode"] == "OWNER_PROVES_NO_DISPATCH"
    assert len(seen) == 1 and seen[0][0] == "/internal/v1/attempt-outcomes/udp-request-1"
    received_headers = {name.lower(): value for name, value in seen[0][1].items()}
    assert received_headers["x-ouf-recovery-for"] == "udp-request-1"
    assert received_headers["x-correlation-id"] == "correlation-recovery-1"


def test_owner_network_unavailable_is_not_inferred_as_terminal():
    mediator = MCPRecoveryMediator(compile_config(ROOT / "ouf-config"), HTTPUpstream("http://127.0.0.1:1"), service_identity="ouf-mcp-server")
    body = (ROOT / "tests/fixtures/mcp-recovery-request.json").read_bytes()
    identity = TrustedIdentity("ouf-mcp-server", "agent-1", "tenant-1", "MCP_SERVER", "authn-1", "decision-1", frozenset({"mcp.attempt.recover"}))
    try:
        mediator.recover(body, {"X-Correlation-ID": "correlation-recovery-1"}, identity)
    except DispatchError as error:
        assert error.code == "OWNER_RECOVERY_UNAVAILABLE"
    else:
        raise AssertionError("owner network failure was treated as terminal evidence")
