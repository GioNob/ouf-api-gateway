#!/usr/bin/env python3
"""Persist normalized Gateway operational incidents from live APISIX and etcd observations.

This collector runs beside the Gateway. It stores only bounded semantic incident state
and collector freshness. Raw access logs, request bodies, bearer tokens and etcd output
are never persisted in the operational incident store.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import stat
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


AUTHORITY_STATUS_SCHEMA = "ouf.semantic-mandate-renewal-status.v1"
AUTHORITY_STATUS_FIELDS = {"schema", "checkedAt", "outcome", "reasonCode", "ledgers", "versionedBase", "openIncident"}
AUTHORITY_PREFIX = "authority:mandates:"
AUTHORITY_ENDPOINT = "authority://mandates/renewal"
AUTHORITY_STATUS_LIMIT = 16384
AUTHORITY_SILENT_SECONDS = 172800
AUTHORITY_NEAR_EXPIRY_SECONDS = 1296000
AUTHORITY_CLOCK_SKEW_SECONDS = 300
PUBLIC_CODE = re.compile(r"[A-Z0-9_]{1,80}")
SHA256 = re.compile(r"[0-9a-f]{64}")
AUTHORITY_RULES = {
    "blocked": ("AUTHORITY_MANDATE_RENEWAL_BLOCKED", "CRITICAL",
                "Automatic authority mandate renewal is blocked; mandates will expire without intervention.",
                "Automatic authority mandate renewal is no longer blocked."),
    "silent": ("AUTHORITY_MANDATE_RENEWAL_SILENT", "CRITICAL",
               "The authority mandate renewal job has not reported recently.",
               "The authority mandate renewal job is reporting again."),
    "near-expiry": ("AUTHORITY_MANDATE_NEAR_EXPIRY", "CRITICAL",
                    "An authority mandate expires soon and has not been renewed.",
                    "Authority mandates are no longer close to expiry."),
    "status-unavailable": ("AUTHORITY_MANDATE_STATUS_UNAVAILABLE", "ERROR",
                           "The authority mandate renewal status cannot be verified.",
                           "The authority mandate renewal status is verifiable again."),
}


class AuthorityStatusUnavailable(Exception):
    """Carries only a public code; never status contents."""


def _epoch(value) -> bool:
    return type(value) is int and 0 <= value < 2 ** 62


def read_authority_status(path: Path, *, owner: tuple[int, int] = (0, 0)) -> dict:
    """Read the renewal job status with root custody and an exact closed schema."""
    unreadable = "AUTHORITY_MANDATE_STATUS_UNREADABLE"

    def require(condition):
        if not condition:
            raise AuthorityStatusUnavailable(unreadable)

    path = Path(path)
    require(path.is_absolute() and ".." not in path.parts)
    try:
        for parent in path.parents:
            info = parent.lstat()
            require(stat.S_ISDIR(info.st_mode) and (info.st_uid in (0, owner[0])) and not info.st_mode & 0o022)
        try:
            fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        except FileNotFoundError:
            raise AuthorityStatusUnavailable("AUTHORITY_MANDATE_STATUS_MISSING") from None
        try:
            info = os.fstat(fd)
            require(stat.S_ISREG(info.st_mode) and (info.st_uid, info.st_gid) == owner
                    and stat.S_IMODE(info.st_mode) == 0o600 and info.st_nlink == 1
                    and 0 < info.st_size <= AUTHORITY_STATUS_LIMIT)
            raw = os.read(fd, AUTHORITY_STATUS_LIMIT + 1)
            require(len(raw) == info.st_size)
        finally:
            os.close(fd)
    except OSError:
        raise AuthorityStatusUnavailable(unreadable) from None

    def unique(pairs):
        result = {}
        for key, value in pairs:
            require(key not in result)
            result[key] = value
        return result

    try:
        value = json.loads(raw.decode("ascii"), object_pairs_hook=unique,
                           parse_constant=lambda _: (_ for _ in ()).throw(ValueError()))
    except (ValueError, UnicodeError, RecursionError):
        raise AuthorityStatusUnavailable(unreadable) from None
    require(type(value) is dict and set(value) == AUTHORITY_STATUS_FIELDS
            and value["schema"] == AUTHORITY_STATUS_SCHEMA and _epoch(value["checkedAt"])
            and value["outcome"] in ("NOOP", "RENEWED", "BLOCKED")
            and (value["reasonCode"] is None or type(value["reasonCode"]) is str
                 and PUBLIC_CODE.fullmatch(value["reasonCode"]) is not None)
            and type(value["openIncident"]) is bool)
    ledgers = value["ledgers"]
    require(type(ledgers) is dict and set(ledgers) == {"b1b2", "base"})
    for ledger in ledgers.values():
        require(type(ledger) is dict and set(ledger) == {"generation", "headSha256", "earliestExpiresAt"}
                and type(ledger["generation"]) is int and 0 <= ledger["generation"] <= 512
                and (ledger["headSha256"] is None if ledger["generation"] == 0 else
                     type(ledger["headSha256"]) is str and SHA256.fullmatch(ledger["headSha256"]) is not None)
                and _epoch(ledger["earliestExpiresAt"]))
    versioned = value["versionedBase"]
    require(versioned is None or type(versioned) is dict and set(versioned) == {"generation", "sha256"}
            and type(versioned["generation"]) is int and 1 <= versioned["generation"] <= 512
            and type(versioned["sha256"]) is str and SHA256.fullmatch(versioned["sha256"]) is not None)
    require((value["outcome"] == "BLOCKED") == (value["reasonCode"] is not None))
    return value


def authority_mandates_probe(args, *, now: float | None = None, owner: tuple[int, int] = (0, 0)) -> int:
    """Mirror the renewal job status into Gateway incidents; 0 only when none is open."""
    store = SQLiteOperationalIncidentStore(args.store)
    now = time.time() if now is None else now

    def raise_rule(rule, code):
        event_type, severity, summary, _ = AUTHORITY_RULES[rule]
        store.open_incident(dedup_key=AUTHORITY_PREFIX + rule, event_type=event_type, severity=severity,
                            error_code=code, impact_summary=summary, endpoint_ref=AUTHORITY_ENDPOINT,
                            action_required=True, visibility_class="TENANT_OPERATIONAL")

    def clear_rule(rule):
        store.resolve_incident(AUTHORITY_PREFIX + rule, AUTHORITY_RULES[rule][3])

    try:
        try:
            status = read_authority_status(args.status, owner=owner)
            if status["checkedAt"] > now + AUTHORITY_CLOCK_SKEW_SECONDS:
                raise AuthorityStatusUnavailable("AUTHORITY_MANDATE_STATUS_UNREADABLE")
        except AuthorityStatusUnavailable as error:
            # Without a verifiable status the other rules are unknown: keep their state.
            raise_rule("status-unavailable", str(error))
        else:
            clear_rule("status-unavailable")
            if status["outcome"] == "BLOCKED":
                raise_rule("blocked", status["reasonCode"])
            else:
                clear_rule("blocked")
            if now - status["checkedAt"] > AUTHORITY_SILENT_SECONDS:
                raise_rule("silent", "STATUS_STALE")
            else:
                clear_rule("silent")
            earliest = min(ledger["earliestExpiresAt"] for ledger in status["ledgers"].values())
            if earliest - now < AUTHORITY_NEAR_EXPIRY_SECONDS:
                raise_rule("near-expiry", "MANDATE_NEAR_EXPIRY")
            else:
                clear_rule("near-expiry")
        return 2 if store.active_incident_keys(AUTHORITY_PREFIX) else 0
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

    m = sub.add_parser("authority-mandates")
    m.add_argument("--store", type=Path, required=True)
    m.add_argument("--status", type=Path, required=True)
    m.set_defaults(run=authority_mandates_probe)
    return p


def main() -> int:
    args = parser().parse_args()
    result = args.run(args)
    return result if isinstance(result, int) else 0


if __name__ == "__main__":
    raise SystemExit(main())
