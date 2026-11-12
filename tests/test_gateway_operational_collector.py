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
