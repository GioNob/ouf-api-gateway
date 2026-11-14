import json
import subprocess
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import pytest

from tools import gateway_operational_collector
from tools.gateway_operational_collector import ApisixIncidentCollector, etcd_probe
from tools.operational_incidents import SQLiteOperationalIncidentStore


class Clock:
    def __init__(self):
        self.now = datetime(2026, 9, 20, 20, 0, tzinfo=timezone.utc)

    def __call__(self):
        return self.now

    def advance(self, seconds):
        self.now += timedelta(seconds=seconds)


def access(path, status):
    return f'"GET {path} HTTP/1.1" {status} 0 0.010 "-" "-" 127.0.0.1:8080 0.006 {status} "-" "-"'


def test_collector_freshness_persists_and_expires(tmp_path):
    clock = Clock()
    path = tmp_path / "gateway.sqlite"
    store = SQLiteOperationalIncidentStore(path, clock=clock)
    assert store.collector_freshness(60) == {"APISIX": False, "ETCD": False}
    store.mark_collector_observed("APISIX")
    store.mark_collector_observed("ETCD")
    assert store.collector_freshness(60) == {"APISIX": True, "ETCD": True}
    clock.advance(61)
    assert store.collector_freshness(60) == {"APISIX": False, "ETCD": False}
    store.close()

    reopened = SQLiteOperationalIncidentStore(path, clock=clock)
    assert reopened.collector_freshness(60) == {"APISIX": False, "ETCD": False}
    reopened.close()


def test_apisix_failures_deduplicate_and_recovery_closes_same_incident(tmp_path):
    store = SQLiteOperationalIncidentStore(tmp_path / "gateway.sqlite")
    collector = ApisixIncidentCollector(store, failure_threshold=2, failure_window_seconds=30)
    collector.observe(access("/internal/capabilities/v1/execute/ouf.ingestion.operations.summary", 503), now=1)
    assert not store.active_incident_keys("gateway:upstream:")
    collector.observe(access("/internal/capabilities/v1/execute/ouf.ingestion.operations.summary", 503), now=2)

    active = store.active_incident_keys("gateway:upstream:")
    assert len(active) == 1
    incident_id = store.list_incidents()[0].incident_id
    collector.observe(access("/internal/capabilities/v1/execute/ouf.ingestion.operations.summary", 200), now=3)

    item = store.get(incident_id)
    assert item.lifecycle_state == "RESOLVED"
    assert item.occurrence_count == 1
    assert not store.active_incident_keys("gateway:upstream:")
    store.close()


def test_collector_restart_recovers_existing_open_incident(tmp_path):
    path = tmp_path / "gateway.sqlite"
    store = SQLiteOperationalIncidentStore(path)
    store.open_incident(
        dedup_key="gateway:upstream:gateway://northbound/mcp",
        event_type="GATEWAY_UPSTREAM_UNREACHABLE",
        severity="ERROR",
        error_code="UPSTREAM_HTTP_503",
        impact_summary="A governed Gateway upstream is repeatedly unavailable.",
        endpoint_ref="gateway://northbound/mcp",
        visibility_class="TENANT_OPERATIONAL",
    )
    store.close()

    reopened = SQLiteOperationalIncidentStore(path)
    collector = ApisixIncidentCollector(reopened, failure_threshold=2, failure_window_seconds=30)
    collector.observe(access("/mcp", 200), now=10)
    assert reopened.list_incidents()[0].lifecycle_state == "RESOLVED"
    reopened.close()


def test_apisix_reopens_as_new_episode_and_tracks_open_keys(tmp_path):
    clock = Clock()
    store = SQLiteOperationalIncidentStore(tmp_path / "gateway.sqlite", clock=clock)
    collector = ApisixIncidentCollector(store, failure_threshold=2, failure_window_seconds=30)
    for now in (1, 2):
        collector.observe(access("/mcp", 503), now=now)
    first = store.list_incidents()[0]
    assert collector.open_keys == {first.dedup_key}
    clock.advance(15)
    collector.observe(access("/mcp", 200), now=3)
    resolved = store.get(first.incident_id)
    assert collector.open_keys == set()

    clock.advance(15)
    for now in (4, 5):
        collector.observe(access("/mcp", 503), now=now)
    second = store.list_incidents()[0]
    assert second.incident_id != first.incident_id
    assert second.occurrence_count == 1
    assert collector.open_keys == store.active_incident_keys() == {first.dedup_key}
    clock.advance(15)
    collector.observe(access("/mcp", 200), now=6)
    assert store.get(second.incident_id).lifecycle_state == "RESOLVED"
    assert collector.open_keys == store.active_incident_keys() == set()
    projections = [json.loads(row[0]) for row in store.db.execute(
        "select projection from gateway_incident_transition where incident_id=? order by sequence_id", (first.incident_id,)
    )]
    assert len(projections) == 2
    assert projections[-1]["resolved_at"] == resolved.resolved_at
    assert projections[-1]["lifecycle_state"] == "RESOLVED"
    store.close()


@pytest.fixture
def probe(tmp_path, monkeypatch):
    clock = Clock()
    args = SimpleNamespace(store=tmp_path / "etcd.sqlite", container="ouf-etcd", timeout_seconds=8)
    real_store = SQLiteOperationalIncidentStore
    monkeypatch.setattr(gateway_operational_collector, "SQLiteOperationalIncidentStore",
                        lambda path: real_store(path, clock=clock))
    calls = []
    result = [1]

    def run(command, **kwargs):
        calls.append((command, kwargs))
        return subprocess.CompletedProcess(command, result[0])

    monkeypatch.setattr(gateway_operational_collector.subprocess, "run", run)

    def execute(returncode):
        result[0] = returncode
        return etcd_probe(args)

    return args, clock, execute, calls


def test_etcd_healthy_probes_preserve_closure_transitions_and_last_event(probe):
    args, clock, execute, calls = probe
    assert execute(1) == 2
    clock.advance(15)
    assert execute(0) == 0
    store = SQLiteOperationalIncidentStore(args.store, clock=clock)
    resolved = store.list_incidents()[0]
    before = [tuple(row) for row in store.db.execute("select * from gateway_incident_transition")]
    assert len(before) == 2
    last_event = store.db.execute("select last_event_at from gateway_operational_collector_state where source='ETCD'").fetchone()[0]
    assert last_event == resolved.resolved_at
    store.close()

    for _ in range(3):
        clock.advance(15)
        assert execute(0) == 0
        store = SQLiteOperationalIncidentStore(args.store, clock=clock)
        assert store.get(resolved.incident_id) == resolved
        assert [tuple(row) for row in store.db.execute("select * from gateway_incident_transition")] == before
        state = store.db.execute("select * from gateway_operational_collector_state where source='ETCD'").fetchone()
        assert state["last_event_at"] == last_event
        assert state["last_observed_at"] == clock().isoformat().replace("+00:00", "Z")
        store.close()
    assert len(calls) == 5
    assert all(command == ["docker", "exec", "ouf-etcd", "etcdctl", "endpoint", "health"]
               and kwargs == dict(capture_output=True, text=True, timeout=8) for command, kwargs in calls)


def test_etcd_failure_success_failure_produces_two_episodes(probe):
    args, clock, execute, _ = probe
    assert execute(1) == 2
    store = SQLiteOperationalIncidentStore(args.store, clock=clock)
    first = store.list_incidents()[0]
    store.close()
    clock.advance(15)
    assert execute(0) == 0
    store = SQLiteOperationalIncidentStore(args.store, clock=clock)
    resolved = store.get(first.incident_id)
    before = [tuple(row) for row in store.db.execute("select * from gateway_incident_transition")]
    store.close()
    clock.advance(15)
    assert execute(1) == 2

    store = SQLiteOperationalIncidentStore(args.store, clock=clock)
    second = store.list_incidents()[0]
    assert second.incident_id != first.incident_id
    assert second.dedup_key == first.dedup_key
    assert second.first_seen_at == second.last_seen_at == "2026-09-20T20:00:30Z"
    assert second.occurrence_count == 1
    assert second.lifecycle_state == "OPEN"
    after = [tuple(row) for row in store.db.execute("select * from gateway_incident_transition")]
    assert after[:-1] == before
    assert len(after) == 3
    assert json.loads(after[1][2])["resolved_at"] == resolved.resolved_at
    assert after[-1][1] == second.incident_id
    store.close()


# --- authority-mandates (sprint-01 task-31, D-030) ---------------------------

import os
import shutil
import sys
import uuid
from pathlib import Path

from tools.gateway_operational_collector import authority_mandates_probe, read_authority_status

NOW = 1795000000
DAY = 86400
LINUX = sys.platform.startswith("linux")
needs_posix = pytest.mark.skipif(not LINUX, reason="POSIX custody semantics")
SECRET = "SECRET-STATUS-CONTENT"


def mandate_status(**changes):
    value = {"schema": "ouf.semantic-mandate-renewal-status.v1", "checkedAt": NOW - 60, "outcome": "NOOP",
             "reasonCode": None, "openIncident": False, "versionedBase": {"generation": 1, "sha256": "a" * 64},
             "ledgers": {"b1b2": {"generation": 1, "headSha256": "b" * 64, "earliestExpiresAt": NOW + 60 * DAY},
                         "base": {"generation": 1, "headSha256": "c" * 64, "earliestExpiresAt": NOW + 60 * DAY}}}
    value.update(changes)
    return value


@pytest.fixture
def authority(tmp_path):
    # Not under /tmp: a world-writable ancestor is rightly refused.
    root = Path.home() / ("ouf-authority-status-" + uuid.uuid4().hex)
    root.mkdir(mode=0o700)
    status = root / "status.json"
    owner = (os.getuid(), os.getgid()) if LINUX else (0, 0)

    def write(value, mode=0o600):
        raw = value if isinstance(value, bytes) else json.dumps(value, sort_keys=True).encode()
        status.write_bytes(raw)
        status.chmod(mode)

    def run(now=NOW):
        args = SimpleNamespace(store=tmp_path / "gateway.sqlite", status=status)
        return authority_mandates_probe(args, now=now, owner=owner)

    def open_incidents():
        store = SQLiteOperationalIncidentStore(tmp_path / "gateway.sqlite")
        try:
            return {i.dedup_key: i for i in store.list_incidents(lifecycle_state="OPEN")}
        finally:
            store.close()

    yield SimpleNamespace(root=root, status=status, write=write, run=run, open=open_incidents, owner=owner)
    root.chmod(0o700)
    shutil.rmtree(root, ignore_errors=True)


@needs_posix
def test_authority_noop_and_renewed_open_nothing(authority):
    for outcome in ("NOOP", "RENEWED"):
        authority.write(mandate_status(outcome=outcome))
        assert authority.run() == 0
    assert authority.open() == {}


@needs_posix
def test_authority_blocked_opens_with_reason_and_noop_resolves(authority):
    authority.write(mandate_status(outcome="BLOCKED", reasonCode="MANDATE_TEMPORARY_ENTRY_PRESENT", openIncident=True))
    assert authority.run() == 2
    incident = authority.open()["authority:mandates:blocked"]
    assert (incident.event_type, incident.severity, incident.error_code) == (
        "AUTHORITY_MANDATE_RENEWAL_BLOCKED", "CRITICAL", "MANDATE_TEMPORARY_ENTRY_PRESENT")
    assert (incident.endpoint_ref, incident.visibility_class, incident.action_required) == (
        "authority://mandates/renewal", "TENANT_OPERATIONAL", True)
    assert authority.run() == 2
    assert authority.open()["authority:mandates:blocked"].occurrence_count == 2
    authority.write(mandate_status())
    assert authority.run() == 0
    assert authority.open() == {}


@needs_posix
def test_authority_stale_status_is_silent(authority):
    authority.write(mandate_status(checkedAt=NOW - 2 * DAY - 1))
    assert authority.run() == 2
    assert authority.open()["authority:mandates:silent"].error_code == "STATUS_STALE"
    authority.write(mandate_status(checkedAt=NOW - 2 * DAY))
    assert authority.run() == 0


@needs_posix
def test_authority_near_expiry(authority):
    ledgers = mandate_status()["ledgers"]
    ledgers["base"]["earliestExpiresAt"] = NOW + 15 * DAY - 1
    authority.write(mandate_status(ledgers=ledgers))
    assert authority.run() == 2
    assert authority.open()["authority:mandates:near-expiry"].error_code == "MANDATE_NEAR_EXPIRY"
    ledgers["base"]["earliestExpiresAt"] = NOW + 15 * DAY
    authority.write(mandate_status(ledgers=ledgers))
    assert authority.run() == 0


@needs_posix
def test_authority_missing_status(authority):
    assert authority.run() == 2
    incident = authority.open()["authority:mandates:status-unavailable"]
    assert (incident.severity, incident.error_code) == ("ERROR", "AUTHORITY_MANDATE_STATUS_MISSING")


@needs_posix
def test_authority_unavailable_keeps_other_rules_and_recovers(authority):
    authority.write(mandate_status(outcome="BLOCKED", reasonCode="PRECONDITION_CUSTODY_INTACT_UNMET"))
    assert authority.run() == 2
    authority.status.unlink()
    assert authority.run() == 2
    assert set(authority.open()) == {"authority:mandates:blocked", "authority:mandates:status-unavailable"}
    authority.write(mandate_status())
    assert authority.run() == 0
    assert authority.open() == {}


def malformed():
    good = mandate_status()
    ledgers = good["ledgers"]
    cases = [json.dumps(good).encode()[:-1], b'{"schema":"a","schema":"a"}', b"[]", b'{"a":NaN}',
             json.dumps(good | {"extra": 1}).encode(), json.dumps(good | {"schema": SECRET}).encode(),
             json.dumps(good | {"outcome": "UNKNOWN"}).encode(),
             json.dumps(good | {"outcome": "BLOCKED", "reasonCode": SECRET.lower()}).encode(),
             json.dumps(good | {"outcome": "BLOCKED"}).encode(),
             json.dumps(good | {"reasonCode": "X"}).encode(),
             json.dumps(good | {"checkedAt": True}).encode(),
             json.dumps(good | {"checkedAt": NOW + 301}).encode(),
             json.dumps(good | {"openIncident": 0}).encode(),
             json.dumps(good | {"versionedBase": {"generation": 0, "sha256": "a" * 64}}).encode(),
             json.dumps(good | {"ledgers": {"b1b2": ledgers["b1b2"]}}).encode(),
             json.dumps(good | {"ledgers": {**ledgers, "b1b2": {**ledgers["b1b2"], "headSha256": None}}}).encode(),
             b"x" * 16385]
    for key in good:
        value = dict(good)
        del value[key]
        cases.append(json.dumps(value).encode())
    return cases


@needs_posix
@pytest.mark.parametrize("raw", malformed())
def test_authority_malformed_status_is_unreadable_and_never_echoed(authority, raw, capsys):
    authority.write(raw)
    assert authority.run() == 2
    incident = authority.open()["authority:mandates:status-unavailable"]
    assert incident.error_code == "AUTHORITY_MANDATE_STATUS_UNREADABLE"
    for text in (incident.impact_summary, incident.error_code, *capsys.readouterr()):
        assert SECRET not in text and SECRET.lower() not in text


@needs_posix
@pytest.mark.parametrize("defect", ["mode", "symlink", "hardlink", "directory", "owner", "ancestor"])
def test_authority_status_custody_defects(authority, defect):
    authority.write(mandate_status())
    owner = authority.owner
    if defect == "mode":
        authority.status.chmod(0o644)
    elif defect == "symlink":
        target = authority.root / "real.json"
        authority.status.rename(target)
        authority.status.symlink_to(target)
    elif defect == "hardlink":
        os.link(authority.status, authority.root / "second.json")
    elif defect == "directory":
        authority.status.unlink()
        authority.status.mkdir(mode=0o700)
    elif defect == "owner":
        owner = (owner[0] + 1, owner[1])
    else:
        authority.root.chmod(0o777)
    with pytest.raises(gateway_operational_collector.AuthorityStatusUnavailable) as caught:
        read_authority_status(authority.status, owner=owner)
    assert str(caught.value) == "AUTHORITY_MANDATE_STATUS_UNREADABLE"


@needs_posix
def test_authority_default_owner_is_root(authority):
    authority.write(mandate_status())
    if os.getuid() != 0:
        with pytest.raises(gateway_operational_collector.AuthorityStatusUnavailable):
            read_authority_status(authority.status)
    else:
        assert read_authority_status(authority.status)["outcome"] == "NOOP"


def test_authority_cli_mode_is_registered():
    args = gateway_operational_collector.parser().parse_args(
        ["authority-mandates", "--store", "/var/lib/x.sqlite", "--status", "/var/lib/y/status.json"])
    assert args.run is authority_mandates_probe
    assert args.status == Path("/var/lib/y/status.json")
