#!/usr/bin/env python3
"""Persist normalized Gateway operational incidents from live APISIX and etcd observations.

This collector runs beside the Gateway. It stores only bounded semantic incident state
and collector freshness. Raw access logs, request bodies, bearer tokens and etcd output
are never persisted in the operational incident store.
"""
from __future__ import annotations

import argparse
import re
import subprocess
import threading
import time
from collections import defaultdict, deque
from pathlib import Path

from tools.operational_incidents import SQLiteOperationalIncidentStore

ACCESS = re.compile(
    r'"(?:POST|GET|PUT|DELETE) (?P<path>\S+) HTTP/[^" ]+" (?P<status>\d{3}) \d+ '
    r'(?P<total>\d+(?:\.\d+)?) "[^"]*" "[^"]*" (?P<upstream>.*?) "[^"\n]*" "[^"\n]*"$'
)

ROUTES = (
    ("/mcp", "gateway://northbound/mcp"),
    ("/internal/capabilities/v1/execute", "gateway://internal/execute"),
    ("/internal/capabilities/v1/authorization/policy-bundle/active", "gateway://internal/authorization-policy"),
    ("/internal/capabilities/v1/recovery", "gateway://internal/recovery"),
)
FAILURE_STATUS = {502, 503, 504}


def logical_endpoint(path: str) -> str | None:
    path = path.split("?", 1)[0]
    for prefix, endpoint in ROUTES:
        if path == prefix or path.startswith(prefix + "/"):
            return endpoint
    return None


class ApisixIncidentCollector:
    def __init__(self, store: SQLiteOperationalIncidentStore, failure_threshold: int, failure_window_seconds: int):
        if not 1 <= failure_threshold <= 20:
            raise ValueError("failure threshold outside governed bounds")
        if not 5 <= failure_window_seconds <= 600:
            raise ValueError("failure window outside governed bounds")
        self.store = store
        self.failure_threshold = failure_threshold
        self.failure_window_seconds = failure_window_seconds
        self.failures: dict[str, deque[float]] = defaultdict(deque)
        self.open_keys: set[str] = store.active_incident_keys("gateway:upstream:")
        self.last_heartbeat = 0.0

    def observe(self, line: str, now: float | None = None) -> None:
        heartbeat_now = time.monotonic() if now is None else now
        if heartbeat_now - self.last_heartbeat >= 5:
            self.store.mark_collector_observed("APISIX")
            self.last_heartbeat = heartbeat_now
        match = ACCESS.search(line.strip())
        if not match:
            return
        endpoint = logical_endpoint(match["path"])
        if endpoint is None:
            return
        status = int(match["status"])
        now = heartbeat_now
        key = "gateway:upstream:" + endpoint
        if status in FAILURE_STATUS:
            failures = self.failures[endpoint]
            failures.append(now)
            cutoff = now - self.failure_window_seconds
            while failures and failures[0] < cutoff:
                failures.popleft()
            if len(failures) >= self.failure_threshold:
                self.store.open_incident(
                    dedup_key=key,
                    event_type="GATEWAY_UPSTREAM_UNREACHABLE",
                    severity="ERROR",
                    error_code="UPSTREAM_HTTP_" + str(status),
                    impact_summary="A governed Gateway upstream is repeatedly unavailable.",
                    endpoint_ref=endpoint,
                    action_required=True,
                    visibility_class="TENANT_OPERATIONAL",
                )
                self.store.mark_collector_observed("APISIX", event=True)
                self.open_keys.add(key)
                failures.clear()
            return
        if 200 <= status < 500:
            self.failures.pop(endpoint, None)
            if key in self.open_keys:
                resolved = self.store.resolve_incident(
                    key, "The governed Gateway upstream is reachable again."
                )
                if resolved is not None:
                    self.store.mark_collector_observed("APISIX", event=True)
                self.open_keys.discard(key)


def apisix_loop(args) -> None:
    store = SQLiteOperationalIncidentStore(args.store)
    collector = ApisixIncidentCollector(store, args.failure_threshold, args.failure_window_seconds)
    stop = threading.Event()

    def heartbeat():
        heartbeat_store = SQLiteOperationalIncidentStore(args.store)
        try:
            while not stop.wait(args.heartbeat_seconds):
                heartbeat_store.mark_collector_observed("APISIX")
        finally:
            heartbeat_store.close()

    thread = threading.Thread(target=heartbeat, name="apisix-collector-heartbeat", daemon=True)
    thread.start()
    command = ["docker", "logs", "--follow", "--since", args.since, "--timestamps", args.container]
    try:
        with subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1) as proc:
            if proc.stdout is None:
                raise RuntimeError("APISIX log stream unavailable")
            store.mark_collector_observed("APISIX")
            for line in proc.stdout:
                collector.observe(line)
            code = proc.wait()
            if code != 0:
                raise RuntimeError("APISIX log stream exited with code " + str(code))
    finally:
        stop.set()
        thread.join(timeout=max(1, args.heartbeat_seconds))
        store.close()


def etcd_probe(args) -> int:
    store = SQLiteOperationalIncidentStore(args.store)
    key = "gateway:etcd:collector-health"
    try:
        command = ["docker", "exec", args.container, "etcdctl", "endpoint", "health"]
        completed = subprocess.run(command, capture_output=True, text=True, timeout=args.timeout_seconds)
        store.mark_collector_observed("ETCD")
        if completed.returncode == 0:
            resolved = store.resolve_incident(
                key, "The Gateway etcd control-plane endpoint is healthy again."
            )
            if resolved is not None:
                store.mark_collector_observed("ETCD", event=True)
            return 0
        store.open_incident(
            dedup_key=key,
            event_type="GATEWAY_ETCD_DEGRADED",
            severity="CRITICAL",
            error_code="ETCD_ENDPOINT_UNHEALTHY",
            impact_summary="Gateway control-plane persistence is unavailable; publication safety is degraded.",
            endpoint_ref="gateway://control-plane/etcd",
            action_required=True,
            visibility_class="TENANT_OPERATIONAL",
        )
        store.mark_collector_observed("ETCD", event=True)
        return 2
    except (subprocess.SubprocessError, OSError):
        store.mark_collector_observed("ETCD")
        store.open_incident(
            dedup_key=key,
            event_type="GATEWAY_ETCD_DEGRADED",
            severity="CRITICAL",
            error_code="ETCD_PROBE_FAILED",
            impact_summary="Gateway control-plane persistence could not be verified.",
            endpoint_ref="gateway://control-plane/etcd",
            action_required=True,
            visibility_class="TENANT_OPERATIONAL",
        )
        store.mark_collector_observed("ETCD", event=True)
        return 2
    finally:
        store.close()


def parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser()
    sub = p.add_subparsers(dest="mode", required=True)

    a = sub.add_parser("apisix")
    a.add_argument("--store", type=Path, required=True)
    a.add_argument("--container", default="ouf-apisix")
    a.add_argument("--since", default="0s")
    a.add_argument("--failure-threshold", type=int, default=3)
    a.add_argument("--failure-window-seconds", type=int, default=60)
    a.add_argument("--heartbeat-seconds", type=int, default=15)
    a.set_defaults(run=apisix_loop)

    e = sub.add_parser("etcd")
    e.add_argument("--store", type=Path, required=True)
    e.add_argument("--container", default="ouf-etcd")
    e.add_argument("--timeout-seconds", type=int, default=8)
    e.set_defaults(run=etcd_probe)
    return p


def main() -> int:
    args = parser().parse_args()
    result = args.run(args)
    return result if isinstance(result, int) else 0


if __name__ == "__main__":
    raise SystemExit(main())
