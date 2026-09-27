#!/usr/bin/env python3
"""Measure request streaming through a disposable APISIX route.

Run from the host in the APISIX container network namespace with nsenter -n.
The probe uses only loopback and a random route ID/URI. It never reads or
prints an APISIX credential, application secret, or a customer file.
"""
import argparse
import http.client
import http.server
import json
import secrets
import threading
import time
import urllib.error
import urllib.request
from pathlib import Path


class Receiver(http.server.BaseHTTPRequestHandler):
    first_byte = threading.Event()

    def do_POST(self):
        remaining = int(self.headers["Content-Length"])
        first = self.rfile.read(1)
        if first:
            self.first_byte.set()
            remaining -= 1
        while remaining:
            chunk = self.rfile.read(min(remaining, 8192))
            if not chunk:
                break
            remaining -= len(chunk)
        self.send_response(204 if remaining == 0 else 400)
        self.end_headers()

    def log_message(self, *args):
        pass


def admin(method, route_id, key, body=None):
    data = None if body is None else json.dumps(body, separators=(",", ":")).encode()
    req = urllib.request.Request(
        "http://127.0.0.1:9180/apisix/admin/routes/" + route_id,
        data=data, method=method,
        headers={"X-API-KEY": key, "Content-Type": "application/json"},
    )
    try:
        with urllib.request.urlopen(req, timeout=5) as response:
            return response.status
    except urllib.error.HTTPError as exc:
        return exc.code


def probe(uri):
    connection = http.client.HTTPConnection("127.0.0.1", 9080, timeout=12)
    try:
        connection.putrequest("POST", uri)
        connection.putheader("Content-Type", "application/octet-stream")
        connection.putheader("Content-Length", "8192")
        connection.endheaders()
        connection.send(b"a" * 4096)
        # Check while the client still has half of the body to send.
        early = Receiver.first_byte.wait(3)
        connection.send(b"b" * 4096)
        response = connection.getresponse()
        response.read()
        return early, response.status
    finally:
        connection.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--admin-key", required=True, type=Path)
    args = parser.parse_args()
    key = args.admin_key.read_text().strip()
    if not key or "\n" in key or "\r" in key:
        raise ValueError("invalid Admin API key file")
    token = secrets.token_hex(16)
    route_id = "ouf-request-stream-probe-" + token
    uri = "/__ouf_request_stream_probe/" + token
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Receiver)
    listener = threading.Thread(target=server.serve_forever, daemon=True)
    listener.start()
    route = {
        "uri": uri,
        "methods": ["POST"],
        "plugins": {
            "proxy-control": {"request_buffering": False},
            "client-control": {"max_body_size": 262144},
            "ip-restriction": {"whitelist": ["127.0.0.1"]},
        },
        "upstream": {"type": "roundrobin", "nodes": {"127.0.0.1:" + str(server.server_port): 1}, "retries": 0},
    }
    created = False
    try:
        if admin("GET", route_id, key) != 404:
            raise RuntimeError("probe route ID is not available")
        created = True  # Even a failed PUT may leave a route to remove.
        if admin("PUT", route_id, key, route) not in (200, 201):
            raise RuntimeError("APISIX refused the probe route")
        if admin("GET", route_id, key) != 200:
            raise RuntimeError("probe route readback failed")
        # Give APISIX workers a bounded interval to converge on the new route.
        time.sleep(2)
        early, status = probe(uri)
        print("FIRST_BYTE_BEFORE_CLIENT_FINISH=" + str(early).lower(), flush=True)
        print("PROBE_HTTP_STATUS=" + str(status), flush=True)
        if not early or status != 204:
            raise RuntimeError("request streaming not demonstrated")
    finally:
        if created:
            removed = admin("DELETE", route_id, key)
            verified = admin("GET", route_id, key)
            print("PROBE_ROUTE_REMOVED=" + str(removed in (200, 204) and verified == 404).lower(), flush=True)
        server.shutdown()
        server.server_close()


if __name__ == "__main__":
    main()
