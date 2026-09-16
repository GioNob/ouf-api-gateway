#!/usr/bin/env python3
import argparse
import json
import os
import sys
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from tools.compile_config import ROOT, compile_config
from tools.mcp_dispatch import BackendResponse, DispatchError, MCPDispatcher, TrustedIdentity
from tools.mcp_recovery import MCPRecoveryMediator


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class HTTPUpstream:
    def __init__(self, base_url: str):
        self.base_url = base_url.rstrip("/")
        self.opener = urllib.request.build_opener(NoRedirect)

    def execute(self, service, path, body, headers, timeout_seconds):
        if service != "ouf-udp-object-resolution" or not path.startswith("/internal/"):
            raise RuntimeError("pairwise upstream is not the governed UDP binding")
        request = urllib.request.Request(self.base_url + path, data=body, headers=headers, method="POST")
        try:
            response = self.opener.open(request, timeout=timeout_seconds)
        except urllib.error.HTTPError as error:
            response = error
        with response:
            return BackendResponse(response.status, response.read(), dict(response.headers.items()))

    def recover(self, service, path, headers, timeout_seconds):
        if service != "ouf-udp-object-resolution" or not path.startswith("/internal/v1/attempt-outcomes/"):
            raise RuntimeError("pairwise recovery upstream is not the governed UDP binding")
        request = urllib.request.Request(self.base_url + path, headers=headers, method="GET")
        try:
            response = self.opener.open(request, timeout=timeout_seconds)
        except urllib.error.HTTPError as error:
            response = error
        except urllib.error.URLError:
            return BackendResponse(503, b"", {})
        with response:
            return BackendResponse(response.status, response.read(65537), dict(response.headers.items()))


def handler(dispatcher, recovery, expected_token):
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            if self.path == "/health/ready":
                self.send_response(204); self.end_headers(); return
            self.send_error(404)

        def do_POST(self):
            if self.path not in ("/internal/capabilities/v1/execute/urban.object.related_search", "/internal/capabilities/v1/recovery"):
                self.send_error(404); return
            if self.headers.get("Authorization") != f"Bearer {expected_token}":
                self._problem(DispatchError(401, "INVALID_SERVICE_IDENTITY", "workload token rejected")); return
            length = int(self.headers.get("Content-Length", "0"))
            body = self.rfile.read(min(length, 1048577))
            identity = TrustedIdentity("ouf-mcp-server", "agent-1", "tenant-1", "AI_AGENT", "authn-1", "decision-1", frozenset({"urban.object.related_search", "mcp.attempt.recover"}))
            try:
                if self.path == "/internal/capabilities/v1/recovery":
                    response = recovery.recover(body, dict(self.headers.items()), identity)
                else:
                    response = dispatcher.dispatch(body, dict(self.headers.items()), identity)
            except DispatchError as error:
                self._problem(error); return
            self.send_response(response.status)
            for name, value in response.headers.items(): self.send_header(name, value)
            self.end_headers(); self.wfile.write(response.body)

        def _problem(self, error):
            payload = json.dumps(error.problem(), separators=(",", ":")).encode()
            self.send_response(error.status); self.send_header("Content-Type", "application/problem+json")
            self.end_headers(); self.wfile.write(payload)

        def log_message(self, *_): pass
    return Handler


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--listen", default="127.0.0.1:0")
    args = parser.parse_args()
    token = os.environ.get("PAIRWISE_WORKLOAD_TOKEN")
    udp_url = os.environ.get("PAIRWISE_UDP_URL")
    if not token or not udp_url: raise SystemExit("PAIRWISE_WORKLOAD_TOKEN and PAIRWISE_UDP_URL are required")
    compiled = compile_config(ROOT / "ouf-config")
    upstream = HTTPUpstream(udp_url)
    dispatcher = MCPDispatcher(compiled, upstream)
    recovery = MCPRecoveryMediator(compiled, upstream)
    host, port = args.listen.rsplit(":", 1)
    server = ThreadingHTTPServer((host, int(port)), handler(dispatcher, recovery, token))
    print(server.server_address[1], flush=True)
    server.serve_forever()


if __name__ == "__main__": main()
