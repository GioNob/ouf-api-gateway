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
def authority(snapshots):
    return SimpleNamespace(root=snapshots.root, status=snapshots.status, write=snapshots.write,
                           run=lambda now=NOW: snapshots.run("authority", now),
                           open=snapshots.items, owner=snapshots.owner)


def test_authority_noop_and_renewed_open_nothing(authority):
    for outcome in ("NOOP", "RENEWED"):
        authority.write(mandate_status(outcome=outcome))
        assert authority.run() == 0
    assert authority.open() == {}


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


def test_authority_stale_status_is_silent(authority):
    authority.write(mandate_status(checkedAt=NOW - 2 * DAY - 1))
    assert authority.run() == 2
    assert authority.open()["authority:mandates:silent"].error_code == "STATUS_STALE"
    authority.write(mandate_status(checkedAt=NOW - 2 * DAY))
    assert authority.run() == 0


def test_authority_near_expiry(authority):
    ledgers = mandate_status()["ledgers"]
    ledgers["base"]["earliestExpiresAt"] = NOW + 15 * DAY - 1
    authority.write(mandate_status(ledgers=ledgers))
    assert authority.run() == 2
    assert authority.open()["authority:mandates:near-expiry"].error_code == "MANDATE_NEAR_EXPIRY"
    ledgers["base"]["earliestExpiresAt"] = NOW + 15 * DAY
    authority.write(mandate_status(ledgers=ledgers))
    assert authority.run() == 2
    assert set(authority.open()) == {"authority:mandates:overdue"}


def test_authority_missing_status(authority):
    assert authority.run() == 2
    incident = authority.open()["authority:mandates:status-unavailable"]
    assert (incident.severity, incident.error_code) == ("ERROR", "AUTHORITY_MANDATE_STATUS_MISSING")


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


# --- semantic-provider / trust-windows (sprint-01 task-47, D-039) -----------

import stat


def semantic_status():
    def role():
        return dict(epoch=3, state="READY", failure=None, live=True, previousState="CREATED",
                    dockerRunning=True, denials=[])

    return {"schema": "ouf.semantic-provider-r3-health.v1", "checkedAt": NOW,
            "head": {"decision": "OPERATE", "sequence": 5},
            "supervisor": {"unitActive": True, "state": "ACTIVE", "reason": None,
                           "updatedAt": NOW, "activationsLastHour": 1},
            "lease": {"state": "LEASE_READY", "leaseAuthorized": True},
            "roles": {"adapter": role(), "southbound": role()}, "readError": None}


def trust_status():
    return {"schema": "ouf.trust-window-status.v1", "checkedAt": NOW,
            "windows": [{"ref": "policy-a", "policySha256": "a" * 64,
                         "expiresAt": NOW + 60 * DAY, "liveConsumers": ["consumer-a"]}]}


def denial(reason="COHORT_NOT_READY", mode="prepare", at=NOW):
    return {"mode": mode, "reason": reason, "at": at}


@pytest.fixture
def snapshots(tmp_path, monkeypatch):
    """Real files/SQLite; Windows emulates only metadata/flags missing from POSIX.

    On Linux the same cases exercise the complete native custody reader.
    Separate needs_posix cases below verify real filesystem custody defects.
    """
    root = Path.cwd() / (".ouf-status-" + uuid.uuid4().hex)
    root.mkdir(mode=0o700)
    status = root / "status.json"
    owner = (os.getuid(), os.getgid()) if LINUX else (0, 0)
    args = SimpleNamespace(store=tmp_path / "gateway.sqlite", status=status)
    clock = Clock()
    clock.now = datetime.fromtimestamp(NOW, timezone.utc)
    monkeypatch.setattr(gateway_operational_collector, "SQLiteOperationalIncidentStore",
                        lambda path: SQLiteOperationalIncidentStore(path, clock=clock))
    if not LINUX:
        # Do not replace JSON parsing, reads, SQLite or any rule evaluation.
        original_lstat = Path.lstat
        parents = set(status.parents)

        def lstat(path, *a, **kw):
            if path in parents:
                return SimpleNamespace(st_mode=stat.S_IFDIR | 0o700, st_uid=0)
            return original_lstat(path, *a, **kw)

        def fstat(fd):
            info = os.fstat(fd)
            return SimpleNamespace(st_mode=stat.S_IFREG | 0o600, st_uid=0, st_gid=0,
                                   st_nlink=1, st_size=info.st_size)

        monkeypatch.setattr(Path, "lstat", lstat)
        monkeypatch.setattr(gateway_operational_collector, "os", SimpleNamespace(
            O_RDONLY=os.O_RDONLY | os.O_BINARY, O_NOFOLLOW=0, O_NONBLOCK=0,
            open=os.open, fstat=fstat, read=os.read, close=os.close))

    def write(value):
        status.write_bytes(value if isinstance(value, bytes) else json.dumps(value).encode("ascii"))
        status.chmod(0o600)

    def run(mode="semantic", now=NOW):
        clock.now = datetime.fromtimestamp(now, timezone.utc)
        probe = {"semantic": gateway_operational_collector.semantic_provider_probe,
                 "trust": gateway_operational_collector.trust_windows_probe,
                 "authority": authority_mandates_probe}[mode]
        return probe(args, now=now, owner=owner)

    def items(active=True):
        store = SQLiteOperationalIncidentStore(args.store)
        try:
            return {item.dedup_key: item for item in store.list_incidents(
                lifecycle_state="OPEN" if active else None, limit=200)}
        finally:
            store.close()

    yield SimpleNamespace(root=root, status=status, owner=owner, write=write, run=run, items=items, args=args)
    root.chmod(0o700)
    shutil.rmtree(root)


def test_semantic_healthy_and_nullable_schema(snapshots):
    value = semantic_status()
    snapshots.write(value)
    assert snapshots.run() == 0
    value["head"]["sequence"] = None
    value["lease"]["leaseAuthorized"] = None
    for field in ("reason", "updatedAt", "activationsLastHour"):
        value["supervisor"][field] = None
    for role in value["roles"].values():
        for field in ("epoch", "state", "failure", "previousState", "dockerRunning"):
            role[field] = None
    snapshots.write(value)
    assert snapshots.run() == 0


@pytest.mark.parametrize("cause", ["lease", "supervisor", "adapter", "southbound"])
def test_semantic_down_each_cause_and_recovery(snapshots, cause):
    value = semantic_status()
    if cause == "lease":
        value["lease"]["state"] = None
    elif cause == "supervisor":
        value["supervisor"]["state"] = None
    else:
        value["roles"][cause]["live"] = False
    snapshots.write(value)
    assert snapshots.run() == 2
    item = snapshots.items()["semantic:r3:down"]
    assert (item.event_type, item.severity, item.error_code) == ("SEMANTIC_PROVIDER_R3_DOWN", "WARNING", "R3_NOT_READY")
    assert (item.endpoint_ref, item.visibility_class, item.action_required) == (
        "semantic://provider/r3", "TENANT_OPERATIONAL", True)
    snapshots.write(semantic_status())
    assert snapshots.run() == 0
    assert snapshots.items(False)[item.dedup_key].lifecycle_state == "RESOLVED"


def test_semantic_down_escalation_uses_persisted_episode_and_resets(snapshots):
    value = semantic_status()
    value["roles"]["adapter"]["live"] = False
    snapshots.write(value)
    assert snapshots.run() == 2
    first = snapshots.items()["semantic:r3:down"]
    for elapsed, severity in ((900, "WARNING"), (901, "CRITICAL"), (902, "CRITICAL")):
        value["checkedAt"] = value["supervisor"]["updatedAt"] = NOW + elapsed
        snapshots.write(value)
        assert snapshots.run(now=NOW + elapsed) == 2
        item = snapshots.items()[first.dedup_key]
        assert (item.incident_id, item.first_seen_at, item.severity) == (first.incident_id, first.first_seen_at, severity)
    snapshots.write(semantic_status())
    assert snapshots.run(now=NOW + 903) == 2  # supervisor timestamp is now stale
    value = semantic_status()
    value["checkedAt"] = value["supervisor"]["updatedAt"] = NOW + 904
    snapshots.write(value)
    assert snapshots.run(now=NOW + 904) == 0
    value["roles"]["adapter"]["live"] = False
    snapshots.write(value)
    assert snapshots.run(now=NOW + 905) == 2
    second = snapshots.items()[first.dedup_key]
    assert second.incident_id != first.incident_id
    assert second.first_seen_at != first.first_seen_at
    assert second.severity == "WARNING"


def test_semantic_down_error_code_priority_and_current_epoch(snapshots):
    value = semantic_status()
    value["roles"]["adapter"].update(live=False, failure="ADAPTER_FAILURE", denials=[denial(), denial("SECOND_DENIAL")])
    value["roles"]["southbound"].update(failure="SOUTHBOUND_FAILURE", denials=[denial("SOUTHBOUND_DENIAL")])
    value["supervisor"]["reason"] = "SUPERVISOR_REASON"
    for expected in ("COHORT_NOT_READY", "SOUTHBOUND_DENIAL", "ADAPTER_FAILURE", "SOUTHBOUND_FAILURE",
                     "SUPERVISOR_REASON", "R3_NOT_READY"):
        snapshots.write(value)
        assert snapshots.run() == 2
        assert snapshots.items()["semantic:r3:down"].error_code == expected
        if expected == "COHORT_NOT_READY":
            value["roles"]["adapter"]["epoch"] = None
        elif expected == "SOUTHBOUND_DENIAL":
            value["roles"]["southbound"]["denials"] = []
        elif expected == "ADAPTER_FAILURE":
            value["roles"]["adapter"]["failure"] = None
        elif expected == "SOUTHBOUND_FAILURE":
            value["roles"]["southbound"]["failure"] = None
        else:
            value["supervisor"]["reason"] = None


def test_semantic_stopped_fixed_warning_and_denial_prevents_it(snapshots):
    value = semantic_status()
    for role in value["roles"].values():
        role.update(state="DELETED", dockerRunning=False, live=False)
    snapshots.write(value)
    assert snapshots.run() == 2
    assert set(snapshots.items()) == {"semantic:r3:stopped"}
    value["checkedAt"] = value["supervisor"]["updatedAt"] = NOW + 901
    snapshots.write(value)
    assert snapshots.run(now=NOW + 901) == 2
    assert snapshots.items()["semantic:r3:stopped"].severity == "WARNING"
    value["roles"]["southbound"]["denials"] = [denial()]
    snapshots.write(value)
    assert snapshots.run(now=NOW + 901) == 2
    assert set(snapshots.items()) == {"semantic:r3:down", "semantic:r3:denial"}
    snapshots.write(semantic_status())
    assert snapshots.run() == 0


@pytest.mark.parametrize("defect", ["epoch", "state", "dockerRunning"])
def test_semantic_stopped_requires_terminal_epoch_and_absent_container(snapshots, defect):
    value = semantic_status()
    for role in value["roles"].values():
        role.update(state="DELETED", dockerRunning=False, live=False)
    value["roles"]["adapter"][defect] = None
    snapshots.write(value)
    assert snapshots.run() == 2
    assert set(snapshots.items()) == {"semantic:r3:down"}


@pytest.mark.parametrize("cause", ["adapter", "southbound", "rate-limit"])
def test_semantic_denial_and_recovery(snapshots, cause):
    value = semantic_status()
    if cause == "rate-limit":
        value["supervisor"]["state"] = "PARKED_RATE_LIMITED"
    else:
        value["roles"][cause]["denials"] = [denial()]
    snapshots.write(value)
    assert snapshots.run() == 2
    item = snapshots.items()["semantic:r3:denial"]
    assert (item.event_type, item.severity) == ("SEMANTIC_PROVIDER_R3_DENIAL_PERSISTENT", "CRITICAL")
    snapshots.write(semantic_status())
    assert snapshots.run() == 0


@pytest.mark.parametrize("cause", ["unit", "FAILED", "STOPPED", "old"])
def test_semantic_supervisor_each_cause_and_recovery(snapshots, cause):
    value = semantic_status()
    if cause == "unit":
        value["supervisor"]["unitActive"] = False
    elif cause == "old":
        value["supervisor"]["updatedAt"] = NOW - 601
    else:
        value["supervisor"]["state"] = cause
    snapshots.write(value)
    assert snapshots.run() == 2
    item = snapshots.items()["semantic:r3:supervisor"]
    assert (item.event_type, item.severity) == ("SEMANTIC_PROVIDER_R3_SUPERVISOR_DOWN", "CRITICAL")
    value = semantic_status()
    value["supervisor"]["updatedAt"] = NOW - 600
    snapshots.write(value)
    assert snapshots.run() == 0


@pytest.mark.parametrize("head", ["OPERATE", "STOP", "UNPROVEN"])
@pytest.mark.parametrize("reason", ["AUTHORITY_REVOKED", "CONFIGURATION_DRIFT", "INTEGRITY_UNPROVEN", None])
def test_semantic_integrity_in_every_head_state(snapshots, head, reason):
    value = semantic_status()
    value["head"]["decision"] = head
    value["supervisor"]["reason"] = reason
    snapshots.write(value)
    active = head == "UNPROVEN" or reason is not None
    assert snapshots.run() == (2 if active else 0)
    if active:
        item = snapshots.items()["semantic:r3:integrity"]
        assert (item.event_type, item.severity) == ("SEMANTIC_PROVIDER_R3_INTEGRITY_UNPROVEN", "CRITICAL")
    snapshots.write(semantic_status())
    assert snapshots.run() == 0


def test_semantic_stop_closes_all_four_rules_and_unproven_preserves(snapshots):
    value = semantic_status()
    value["supervisor"].update(state="FAILED", unitActive=False)
    value["roles"]["adapter"]["denials"] = [denial()]
    snapshots.write(value)
    assert snapshots.run() == 2
    before = snapshots.items()
    assert set(before) == {"semantic:r3:down", "semantic:r3:denial", "semantic:r3:supervisor"}
    value["head"]["decision"] = "UNPROVEN"
    snapshots.write(value)
    assert snapshots.run() == 2
    for key, item in before.items():
        assert snapshots.items()[key] == item
    value["head"]["decision"] = "STOP"
    value["supervisor"]["reason"] = "AUTHORITY_REVOKED"
    snapshots.write(value)
    assert snapshots.run() == 2
    assert set(snapshots.items()) == {"semantic:r3:integrity"}
    value["supervisor"]["reason"] = None
    snapshots.write(value)
    assert snapshots.run() == 0
    value = semantic_status()
    for role in value["roles"].values():
        role.update(state="DELETED", dockerRunning=False, live=False)
    snapshots.write(value)
    assert snapshots.run() == 2
    value["head"]["decision"] = "STOP"
    snapshots.write(value)
    assert snapshots.run() == 0


@pytest.mark.parametrize("mode,factory,limit,prefix", [
    ("semantic", semantic_status, 1200, "semantic:r3:"),
    ("trust", trust_status, 172800, "trust:windows:")])
def test_new_status_silent_boundaries_and_recovery(snapshots, mode, factory, limit, prefix):
    value = factory()
    value["checkedAt"] = NOW - limit - 1
    snapshots.write(value)
    assert snapshots.run(mode) == 2
    assert snapshots.items()[prefix + "silent"].severity == "CRITICAL"
    value["checkedAt"] += 1
    snapshots.write(value)
    assert snapshots.run(mode) == 0


@pytest.mark.parametrize("mode,factory,prefix,cause", [
    (mode, factory, prefix, cause)
    for mode, factory, prefix in (("semantic", semantic_status, "semantic:r3:"),
                                 ("trust", trust_status, "trust:windows:"))
    for cause in ("missing", "malformed", "future", "readError")
    if mode == "semantic" or cause != "readError"])
def test_new_status_unavailable_preserves_all_other_incidents(snapshots, mode, factory, prefix, cause):
    value = factory()
    value["checkedAt"] = NOW - 3 * DAY
    if mode == "semantic":
        value["roles"]["adapter"].update(live=False, denials=[denial()])
        value["supervisor"].update(state="FAILED", reason="AUTHORITY_REVOKED")
    else:
        value["windows"][0]["expiresAt"] = NOW - 1
    snapshots.write(value)
    assert snapshots.run(mode) == 2
    before = snapshots.items()
    if cause == "missing":
        snapshots.status.unlink()
    elif cause == "malformed":
        snapshots.write(b"{")
    else:
        value["checkedAt"] = NOW + 301
        if cause == "readError":
            value.update(checkedAt=NOW, readError="READ_FAILED")
        snapshots.write(value)
    assert snapshots.run(mode) == 2
    after = snapshots.items()
    assert after[prefix + "status-unavailable"].severity == "ERROR"
    for key, item in before.items():
        assert after[key] == item
    value = factory()
    value["checkedAt"] = NOW + 300
    snapshots.write(value)
    assert snapshots.run(mode) == 0


@pytest.mark.parametrize("seconds,event,severity", [
    (45 * DAY, None, None), (45 * DAY - 1, "NEAR_EXPIRY", "WARNING"),
    (21 * DAY, "NEAR_EXPIRY", "WARNING"), (21 * DAY - 1, "NEAR_EXPIRY", "ERROR"),
    (7 * DAY, "NEAR_EXPIRY", "ERROR"), (7 * DAY - 1, "NEAR_EXPIRY", "CRITICAL"),
    (1, "NEAR_EXPIRY", "CRITICAL"), (0, "EXPIRED", "CRITICAL"), (-1, "EXPIRED", "CRITICAL")])
def test_trust_window_exact_thresholds(snapshots, seconds, event, severity):
    value = trust_status()
    value["windows"][0]["expiresAt"] = NOW + seconds
    snapshots.write(value)
    assert snapshots.run("trust") == (2 if event else 0)
    if event:
        item = snapshots.items()["trust:window:policy-a"]
        assert (item.event_type, item.severity) == ("TRUST_POLICY_" + event, severity)
        assert (item.endpoint_ref, item.visibility_class, item.action_required) == (
            "authority://trust-policy/policy-a", "TENANT_OPERATIONAL", True)


def test_trust_escalation_and_closure_for_inactive_removed_and_renewed_windows(snapshots):
    value = trust_status()
    first = None
    for remaining, severity in ((44 * DAY, "WARNING"), (20 * DAY, "ERROR"), (6 * DAY, "CRITICAL"), (-1, "CRITICAL")):
        value["windows"][0]["expiresAt"] = NOW + remaining
        snapshots.write(value)
        assert snapshots.run("trust") == 2
        item = snapshots.items()["trust:window:policy-a"]
        first = first or item
        assert (item.incident_id, item.first_seen_at, item.severity) == (first.incident_id, first.first_seen_at, severity)
    value["windows"][0]["liveConsumers"] = []
    snapshots.write(value)
    assert snapshots.run("trust") == 0
    value["windows"][0]["liveConsumers"] = ["consumer-a"]
    snapshots.write(value)
    assert snapshots.run("trust") == 2
    assert snapshots.items()[first.dedup_key].incident_id != first.incident_id
    value["windows"] = []
    snapshots.write(value)
    assert snapshots.run("trust") == 0
    value = trust_status()
    value["windows"][0]["expiresAt"] = NOW - 1
    snapshots.write(value)
    assert snapshots.run("trust") == 2
    snapshots.write(trust_status())
    assert snapshots.run("trust") == 0


def test_trust_windows_are_independent_and_accept_maximum_consumers(snapshots):
    value = trust_status()
    value["windows"] = [dict(value["windows"][0], ref="policy-" + str(i), expiresAt=NOW - 1,
                             liveConsumers=["consumer-" + str(j) for j in range(16)]) for i in range(16)]
    snapshots.write(value)
    assert snapshots.run("trust") == 2
    assert len(snapshots.items()) == 16
    value["windows"][0]["liveConsumers"] = []
    value["windows"].pop()
    snapshots.write(value)
    assert snapshots.run("trust") == 2
    assert len(snapshots.items()) == 14
    snapshots.write(trust_status())
    assert snapshots.run("trust") == 0


@pytest.mark.parametrize("outcome", ["NOOP", "RENEWED", "BLOCKED"])
def test_authority_overdue_threshold_and_blocked_exclusion(snapshots, outcome):
    value = mandate_status(outcome=outcome, reasonCode="RENEWAL_BLOCKED" if outcome == "BLOCKED" else None)
    value["ledgers"]["base"]["earliestExpiresAt"] = NOW + 28 * DAY - 1
    snapshots.write(value)
    assert snapshots.run("authority") == 2
    items = snapshots.items()
    if outcome == "BLOCKED":
        assert set(items) == {"authority:mandates:blocked"}
    else:
        item = items["authority:mandates:overdue"]
        assert (item.event_type, item.severity) == ("AUTHORITY_MANDATE_RENEWAL_OVERDUE", "ERROR")
    value["ledgers"]["base"]["earliestExpiresAt"] += 1
    snapshots.write(value)
    assert snapshots.run("authority") == (2 if outcome == "BLOCKED" else 0)


def test_authority_overdue_preserved_when_unavailable_and_closed_when_blocked(snapshots):
    value = mandate_status()
    value["ledgers"]["b1b2"]["earliestExpiresAt"] = NOW - 1
    snapshots.write(value)
    assert snapshots.run("authority") == 2
    item = snapshots.items()["authority:mandates:overdue"]
    snapshots.status.unlink()
    assert snapshots.run("authority") == 2
    assert snapshots.items()[item.dedup_key] == item
    value.update(outcome="BLOCKED", reasonCode="RENEWAL_BLOCKED")
    snapshots.write(value)
    assert snapshots.run("authority") == 2
    assert item.dedup_key not in snapshots.items()


@pytest.mark.parametrize("mode,probe", [("semantic-provider", gateway_operational_collector.semantic_provider_probe),
                                        ("trust-windows", gateway_operational_collector.trust_windows_probe)])
def test_new_cli_modes(mode, probe):
    args = gateway_operational_collector.parser().parse_args([mode, "--store", "x.sqlite", "--status", "status.json"])
    assert args.run is probe
    assert args.status == Path("status.json")


def status_schema_cases(factory):
    """Check exact fields at every object level, including denial/window objects."""
    import copy
    value = factory()
    if factory is semantic_status:
        value["roles"]["adapter"]["denials"] = [denial()]

    def objects(node, path=()):
        if type(node) is dict:
            yield path, node
            for key, child in node.items():
                yield from objects(child, (*path, key))
        elif type(node) is list:
            for i, child in enumerate(node):
                yield from objects(child, (*path, i))

    cases = []
    for path, node in objects(value):
        for key in (*node, "extra"):
            changed = copy.deepcopy(value)
            target = changed
            for part in path:
                target = target[part]
            if key == "extra":
                target[key] = SECRET
            else:
                del target[key]
            cases.append(json.dumps(changed).encode())
    bad_values = {
        ("schema",): [SECRET, None, []], ("checkedAt",): [True, 1.5, None, "1"],
    }
    if factory is semantic_status:
        bad_values.update({
            ("head", "decision"): ["RUN", None, {}], ("head", "sequence"): [True, 1.5, "1"],
            ("supervisor", "unitActive"): [0, None, "true"],
            ("supervisor", "state"): ["UNKNOWN", {}, "active"],
            ("supervisor", "reason"): [SECRET, "a" * 81, "PRIVATE.CODE", 1],
            ("supervisor", "updatedAt"): [True, "1"],
            ("supervisor", "activationsLastHour"): [True, "1"],
            ("lease", "state"): [SECRET, "", "A" * 81],
            ("lease", "leaseAuthorized"): [1, "false"],
            ("roles", "adapter", "epoch"): [True, "1"],
            ("roles", "adapter", "state"): [SECRET, "NON_ASCII_\u00e9", "A" * 81],
            ("roles", "adapter", "failure"): [SECRET, "PRIVATE.CODE", ""],
            ("roles", "adapter", "previousState"): [SECRET, 0],
            ("roles", "adapter", "live"): [1, None],
            ("roles", "adapter", "dockerRunning"): [0, "true"],
            ("roles", "adapter", "denials"): [None, {}, [denial()] * 5],
            ("roles", "adapter", "denials", 0, "mode"): ["authorize", "Prepare", SECRET, None],
            ("roles", "adapter", "denials", 0, "reason"): [SECRET, None, "A" * 81, ""],
            ("roles", "adapter", "denials", 0, "at"): [True, None, "1"],
            ("readError",): [SECRET, "private_code", 0, "A" * 81],
        })
    else:
        bad_values.update({
            ("windows",): [None, {}, value["windows"] * 17, value["windows"] * 2],
            ("windows", 0, "ref"): [SECRET, "", "a" * 65, "A", "with/slash", 1],
            ("windows", 0, "policySha256"): ["g" * 64, "a" * 63, None],
            ("windows", 0, "expiresAt"): [True, None, "1"],
            ("windows", 0, "liveConsumers"): [None, {}, ["consumer"] * 17, [SECRET], [1], ["a" * 65]],
        })
    for path, invalid_values in bad_values.items():
        for invalid in invalid_values:
            changed = copy.deepcopy(value)
            target = changed
            for part in path[:-1]:
                target = target[part]
            target[path[-1]] = invalid
            cases.append(json.dumps(changed).encode())
    raw = json.dumps(value).encode()
    cases.extend([b"[]", b"null", b"{", b"x" * 16385, raw.replace(b'"checkedAt":', b'"checkedAt":0,"checkedAt":', 1),
                  raw.replace(str(NOW).encode(), b"NaN", 1), raw.replace(str(NOW).encode(), b"Infinity", 1),
                  raw.replace(str(NOW).encode(), b"-Infinity", 1), b"[" * 1500 + b"]" * 1500,
                  raw.replace(b'"schema"', b'"\xffschema"', 1)])
    return cases


@pytest.mark.parametrize("mode,raw", [(mode, raw) for mode, factory in
                                     (("semantic", semantic_status), ("trust", trust_status))
                                     for raw in status_schema_cases(factory)])
def test_new_status_schema_rejection_and_no_content_disclosure(snapshots, mode, raw, capsys):
    snapshots.write(raw)
    assert snapshots.run(mode) == 2
    prefix = "semantic:r3:" if mode == "semantic" else "trust:windows:"
    item = snapshots.items()[prefix + "status-unavailable"]
    assert item.error_code == "STATUS_UNREADABLE"
    assert len(snapshots.items()) == 1
    assert SECRET not in item.impact_summary
    assert SECRET not in "".join(capsys.readouterr())


@pytest.mark.parametrize("mode,reader,factory", [
    ("semantic", gateway_operational_collector.read_semantic_status, semantic_status),
    ("trust", gateway_operational_collector.read_trust_status, trust_status)])
@needs_posix
@pytest.mark.parametrize("defect", ["mode", "symlink", "hardlink", "directory", "owner", "group", "ancestor"])
def test_new_status_real_posix_custody(snapshots, mode, reader, factory, defect):
    snapshots.write(factory())
    owner = snapshots.owner
    if defect == "mode":
        snapshots.status.chmod(0o640)
    elif defect == "symlink":
        target = snapshots.root / "target.json"
        snapshots.status.rename(target)
        snapshots.status.symlink_to(target)
    elif defect == "hardlink":
        os.link(snapshots.status, snapshots.root / "other.json")
    elif defect == "directory":
        snapshots.status.unlink()
        snapshots.status.mkdir()
    elif defect in ("owner", "group"):
        owner = (owner[0] + (defect == "owner"), owner[1] + (defect == "group"))
    else:
        snapshots.root.chmod(0o777)
    with pytest.raises(gateway_operational_collector.StatusUnavailable) as caught:
        reader(snapshots.status, owner=owner)
    assert str(caught.value) == "STATUS_UNREADABLE"


@needs_posix
def test_new_status_real_posix_default_owner_and_symlink_ancestor(snapshots):
    snapshots.write(semantic_status())
    reader = gateway_operational_collector.read_semantic_status
    if os.getuid() == os.getgid() == 0:
        assert reader(snapshots.status)["schema"] == "ouf.semantic-provider-r3-health.v1"
    else:
        with pytest.raises(gateway_operational_collector.StatusUnavailable):
            reader(snapshots.status)
    link = snapshots.root / "link"
    link.symlink_to(snapshots.root, target_is_directory=True)
    with pytest.raises(gateway_operational_collector.StatusUnavailable):
        reader(link / "status.json", owner=snapshots.owner)


def test_new_status_summaries_are_fixed_and_public_codes_are_bounded(snapshots):
    value = semantic_status()
    value["roles"]["adapter"].update(live=False, denials=[denial("PUBLIC_REASON_1")])
    snapshots.write(value)
    assert snapshots.run() == 2
    summaries = {key: item.impact_summary for key, item in snapshots.items().items()}
    value["roles"]["adapter"]["denials"] = [denial("PUBLIC_REASON_2")]
    snapshots.write(value)
    assert snapshots.run() == 2
    for key, item in snapshots.items().items():
        assert item.impact_summary == summaries[key]
        assert "PUBLIC_REASON" not in item.impact_summary
        assert gateway_operational_collector.PUBLIC_CODE.fullmatch(item.error_code)


def test_semantic_all_broker_modes_and_denial_limit_are_accepted(snapshots):
    for mode in gateway_operational_collector.BROKER_MODES:
        value = semantic_status()
        value["roles"]["adapter"]["denials"] = [denial(mode=mode)] * 4
        snapshots.write(value)
        assert snapshots.run() == 2
        assert "semantic:r3:status-unavailable" not in snapshots.items()


def test_systemd_probe_examples():
    for mode, period, directory in (("semantic-provider", "5min", "ouf-semantic-provider-health"),
                                     ("trust-windows", "1h", "ouf-trust-windows")):
        base = Path("ops/systemd") / ("ouf-gateway-" + mode + "-probe")
        service = base.with_suffix(".service").read_text()
        timer = base.with_suffix(".timer").read_text()
        for setting in ("Type=oneshot", "ProtectSystem=strict", "NoNewPrivileges=true",
                        "ReadOnlyPaths=/opt/ouf/gateway -/var/lib/" + directory,
                        "ReadWritePaths=/var/lib/ouf-gateway-operations", "SuccessExitStatus=2"):
            assert setting in service
        assert " " + mode + " --store " in service
        assert "--status /var/lib/" + directory + "/status.json" in service
        assert "OnUnitActiveSec=" + period in timer


@pytest.mark.parametrize("reader,factory", [
    (gateway_operational_collector.read_semantic_status, semantic_status),
    (gateway_operational_collector.read_trust_status, trust_status)])
@pytest.mark.parametrize("defect", ["uid", "gid", "permissions", "hardlink", "directory", "size", "empty",
                                   "read-error", "short-read", "ancestor-mode", "ancestor-owner", "ancestor-symlink"])
def test_new_status_custody_checks_with_syscall_faults(snapshots, monkeypatch, reader, factory, defect):
    """Exercise custody branches on Windows too; native POSIX tests remain separate."""
    snapshots.write(factory())
    original_os = gateway_operational_collector.os
    original_lstat = Path.lstat

    def fstat(fd):
        info = original_os.fstat(fd)
        changes = dict(st_mode=info.st_mode, st_uid=info.st_uid, st_gid=info.st_gid,
                       st_nlink=info.st_nlink, st_size=info.st_size)
        changes.update({
            "uid": {"st_uid": snapshots.owner[0] + 1},
            "gid": {"st_gid": snapshots.owner[1] + 1},
            "permissions": {"st_mode": stat.S_IFREG | 0o640},
            "hardlink": {"st_nlink": 2}, "directory": {"st_mode": stat.S_IFDIR | 0o600},
            "size": {"st_size": 16385}, "empty": {"st_size": 0},
        }.get(defect, {}))
        return SimpleNamespace(**changes)

    def read(fd, size):
        if defect == "read-error":
            raise OSError(SECRET)
        raw = original_os.read(fd, size)
        return raw[:-1] if defect == "short-read" else raw

    def lstat(path, *args, **kwargs):
        info = original_lstat(path, *args, **kwargs)
        if path == snapshots.root:
            if defect == "ancestor-mode":
                return SimpleNamespace(st_mode=stat.S_IFDIR | 0o777, st_uid=snapshots.owner[0])
            if defect == "ancestor-owner":
                return SimpleNamespace(st_mode=stat.S_IFDIR | 0o700, st_uid=snapshots.owner[0] + 1)
            if defect == "ancestor-symlink":
                return SimpleNamespace(st_mode=stat.S_IFLNK | 0o700, st_uid=snapshots.owner[0])
        return info

    monkeypatch.setattr(Path, "lstat", lstat)
    monkeypatch.setattr(gateway_operational_collector, "os", SimpleNamespace(
        O_RDONLY=original_os.O_RDONLY, O_NOFOLLOW=original_os.O_NOFOLLOW, O_NONBLOCK=original_os.O_NONBLOCK,
        open=original_os.open, fstat=fstat, read=read, close=original_os.close))
    with pytest.raises(gateway_operational_collector.StatusUnavailable) as caught:
        reader(snapshots.status, owner=snapshots.owner)
    assert str(caught.value) == "STATUS_UNREADABLE"


def test_new_status_schema_accepts_integers_without_adding_bounds(snapshots):
    value = semantic_status()
    value["head"]["sequence"] = -(2 ** 64)
    value["roles"]["adapter"]["epoch"] = 2 ** 64
    snapshots.write(value)
    assert gateway_operational_collector.read_semantic_status(snapshots.status, owner=snapshots.owner) == value
    value = trust_status()
    value["windows"][0].update(policySha256="A" * 64, expiresAt=-1)
    snapshots.write(value)
    assert snapshots.run("trust") == 2
    assert snapshots.items()["trust:window:policy-a"].event_type == "TRUST_POLICY_EXPIRED"


@pytest.mark.parametrize("mode,factory", [("semantic", semantic_status), ("trust", trust_status)])
def test_new_status_exact_size_limit_and_nested_duplicate_rejection(snapshots, mode, factory):
    raw = json.dumps(factory()).encode()
    snapshots.write(raw + b" " * (16384 - len(raw)))
    assert snapshots.run(mode) == 0
    if mode == "semantic":
        raw = raw.replace(b'"unitActive": true', b'"unitActive": true, "unitActive": true')
    else:
        raw = raw.replace(b'"ref": "policy-a"', b'"ref": "policy-a", "ref": "policy-a"')
    snapshots.write(raw)
    assert snapshots.run(mode) == 2
    assert next(iter(snapshots.items().values())).error_code == "STATUS_UNREADABLE"
