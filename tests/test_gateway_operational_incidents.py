import json
import sqlite3
from datetime import datetime, timedelta, timezone

import pytest

from tools.etcd_resilience import EtcdHealth, EtcdSafetyError, PublicationResilienceGate
from tools.operational_incidents import SQLiteOperationalIncidentStore


class Clock:
    def __init__(self):
        self.now = datetime(2026, 9, 16, 10, 0, tzinfo=timezone.utc)

    def __call__(self):
        return self.now

    def advance(self, seconds):
        self.now += timedelta(seconds=seconds)


def test_incident_dedup_recovery_and_reopen_persist(tmp_path):
    clock = Clock()
    path = tmp_path / "gateway-operations.sqlite"
    store = SQLiteOperationalIncidentStore(path, clock=clock)
    first = store.open_incident(
        dedup_key="gateway:upstream:ingestion",
        event_type="GATEWAY_UPSTREAM_UNREACHABLE",
        severity="ERROR",
        error_code="UPSTREAM_TIMEOUT",
        impact_summary="One governed producer is temporarily unavailable.",
        endpoint_ref="service://ouf-ingestion-runtime",
    )
    clock.advance(30)
    repeated = store.open_incident(
        dedup_key="gateway:upstream:ingestion",
        event_type="GATEWAY_UPSTREAM_UNREACHABLE",
        severity="ERROR",
        error_code="UPSTREAM_TIMEOUT",
        impact_summary="One governed producer is temporarily unavailable.",
        endpoint_ref="service://ouf-ingestion-runtime",
    )
    assert repeated.incident_id == first.incident_id
    assert repeated.occurrence_count == 2
    clock.advance(30)
    resolved = store.resolve_incident("gateway:upstream:ingestion", "Producer connectivity recovered.")
    assert resolved.lifecycle_state == "RESOLVED"
    assert resolved.action_required is False
    store.close()

    reopened = SQLiteOperationalIncidentStore(path, clock=clock)
    persisted = reopened.get(first.incident_id)
    assert persisted.lifecycle_state == "RESOLVED"
    assert persisted.occurrence_count == 2
    assert reopened.summary()["status"] == "HEALTHY"
    reopened.close()


def test_etcd_degradation_updates_one_incident_and_recovery_closes_it(tmp_path):
    store = SQLiteOperationalIncidentStore(tmp_path / "gateway-operations.sqlite")
    gate = PublicationResilienceGate({"https://owner.example"}, max_pending_proposals=8, incident_sink=store)

    with pytest.raises(EtcdSafetyError, match="ETCD_QUORUM_UNAVAILABLE"):
        gate.require_publication_allowed(EtcdHealth(False, False, 0, 1))
    with pytest.raises(EtcdSafetyError, match="ETCD_STORAGE_SLOW"):
        gate.require_publication_allowed(EtcdHealth(True, True, 0, 1))

    items = store.list_incidents()
    assert len(items) == 1
    assert items[0].occurrence_count == 2
    assert items[0].error_code == "ETCD_STORAGE_SLOW"
    assert items[0].endpoint_ref == "gateway://control-plane/etcd"
    assert items[0].lifecycle_state == "OPEN"

    gate.require_publication_allowed(EtcdHealth(True, False, 0, 1))
    assert store.list_incidents()[0].lifecycle_state == "RESOLVED"
    store.close()


def test_store_rejects_unbounded_or_invalid_query(tmp_path):
    store = SQLiteOperationalIncidentStore(tmp_path / "gateway-operations.sqlite")
    with pytest.raises(ValueError):
        store.list_incidents(limit=201)
    with pytest.raises(ValueError):
        store.list_incidents(lifecycle_state="ANY")
    store.close()


def open_fault(store, **overrides):
    fields = dict(
        dedup_key="gateway:upstream:ingestion",
        event_type="GATEWAY_UPSTREAM_UNREACHABLE",
        severity="ERROR",
        error_code="UPSTREAM_TIMEOUT",
        impact_summary="One governed producer is temporarily unavailable.",
        visibility_class="TENANT_OPERATIONAL",
    )
    fields.update(overrides)
    return store.open_incident(**fields)


def transitions(store):
    return [tuple(row) for row in store.db.execute(
        "select sequence_id,incident_id,projection from gateway_incident_transition order by sequence_id"
    )]


@pytest.mark.parametrize("recover_first", [False, True])
def test_resolve_is_idempotent_and_preserves_closure(tmp_path, recover_first):
    clock = Clock()
    store = SQLiteOperationalIncidentStore(tmp_path / "gateway.sqlite", clock=clock)
    first = open_fault(store)
    if recover_first:
        store.recovering(first.dedup_key, "Recovery started.")
    clock.advance(30)
    count = len(transitions(store))
    resolved = store.resolve_incident(first.dedup_key, "Recovered.")
    assert resolved.lifecycle_state == "RESOLVED"
    assert resolved.resolved_at == resolved.last_seen_at == "2026-09-16T10:00:30Z"
    assert len(transitions(store)) == count + 1
    before = transitions(store)
    changes = store.db.total_changes

    clock.advance(30)
    assert store.resolve_incident(first.dedup_key, "Still healthy.") is None
    assert store.get(first.incident_id) == resolved
    assert transitions(store) == before
    assert store.db.total_changes == changes
    store.close()


@pytest.mark.parametrize("state", ["RECOVERING", "RESOLVED"])
def test_recovering_is_idempotent_and_cannot_reopen_resolved(tmp_path, state):
    clock = Clock()
    store = SQLiteOperationalIncidentStore(tmp_path / "gateway.sqlite", clock=clock)
    first = open_fault(store)
    clock.advance(30)
    recovering = store.recovering(first.dedup_key, "Recovery started.")
    assert recovering.lifecycle_state == "RECOVERING"
    assert recovering.last_seen_at == "2026-09-16T10:00:30Z"
    assert recovering.action_required is False
    assert len(transitions(store)) == 2

    expected = recovering
    if state == "RESOLVED":
        clock.advance(30)
        expected = store.resolve_incident(first.dedup_key, "Recovered.")
    before = transitions(store)
    changes = store.db.total_changes
    clock.advance(30)
    assert store.recovering(first.dedup_key, "Still recovering.") is None
    assert store.get(first.incident_id) == expected
    assert transitions(store) == before
    assert store.db.total_changes == changes
    store.close()


def test_missing_incident_transitions_do_not_write(tmp_path):
    store = SQLiteOperationalIncidentStore(tmp_path / "gateway.sqlite")
    changes = store.db.total_changes
    assert store.resolve_incident("missing", "Recovered.") is None
    assert store.recovering("missing", "Recovery started.") is None
    assert store.db.total_changes == changes
    assert transitions(store) == []
    store.close()


@pytest.mark.parametrize("state", ["OPEN", "RECOVERING"])
def test_open_active_episode_preserves_identity_and_metadata(tmp_path, state):
    clock = Clock()
    store = SQLiteOperationalIncidentStore(tmp_path / "gateway.sqlite", clock=clock)
    first = open_fault(store, correlation_id="correlation-1", endpoint_ref="service://producer")
    if state == "RECOVERING":
        store.recovering(first.dedup_key, "Recovery started.")
    clock.advance(30)
    count = len(transitions(store))
    repeated = open_fault(store)
    assert repeated.incident_id == first.incident_id
    assert repeated.first_seen_at == first.first_seen_at
    assert repeated.last_seen_at == "2026-09-16T10:00:30Z"
    assert repeated.occurrence_count == 2
    assert repeated.lifecycle_state == "OPEN"
    assert repeated.resolved_at is None
    assert repeated.correlation_id == first.correlation_id
    assert repeated.endpoint_ref == first.endpoint_ref
    assert len(transitions(store)) == count + 1
    store.close()


@pytest.mark.parametrize("metadata", [{}, {"correlation_id": "new-correlation", "endpoint_ref": "service://new"}])
def test_closed_incident_starts_new_episode_and_preserves_history(tmp_path, metadata):
    clock = Clock()
    path = tmp_path / "gateway.sqlite"
    store = SQLiteOperationalIncidentStore(path, clock=clock)
    first = open_fault(store, correlation_id="old-correlation", endpoint_ref="service://old")
    open_fault(store)
    clock.advance(30)
    resolved = store.resolve_incident(first.dedup_key, "Recovered.")
    before = transitions(store)
    store.close()

    clock.advance(14 * 24 * 60 * 60)
    store = SQLiteOperationalIncidentStore(path, clock=clock)
    new = open_fault(store, event_type="GATEWAY_ETCD_DEGRADED", severity="CRITICAL",
                     error_code="ETCD_ENDPOINT_UNHEALTHY", impact_summary="Control plane unavailable.",
                     action_required=False, visibility_class="PUBLIC_OPERATIONAL", **metadata)
    assert new.incident_id != first.incident_id
    assert new.dedup_key == first.dedup_key
    assert new.occurrence_count == 1
    assert new.first_seen_at == new.last_seen_at == "2026-09-30T10:00:30Z"
    assert new.lifecycle_state == "OPEN"
    assert new.resolved_at is None
    assert new.correlation_id == metadata.get("correlation_id")
    assert new.endpoint_ref == metadata.get("endpoint_ref")
    assert new.event_type == "GATEWAY_ETCD_DEGRADED"
    assert new.severity == "CRITICAL"
    assert new.error_code == "ETCD_ENDPOINT_UNHEALTHY"
    assert new.impact_summary == "Control plane unavailable."
    assert new.action_required is False
    assert new.visibility_class == "PUBLIC_OPERATIONAL"
    assert store.list_incidents() == [new]
    after = transitions(store)
    assert after[:-1] == before
    assert len(after) == len(before) + 1
    assert after[-1][1] == new.incident_id
    old_projection = json.loads(before[-1][2])
    assert old_projection["incident_id"] == first.incident_id
    assert old_projection["lifecycle_state"] == "RESOLVED"
    assert old_projection["resolved_at"] == resolved.resolved_at
    assert json.loads(after[-1][2])["lifecycle_state"] == "OPEN"
    page = store.incident_page({"since": first.first_seen_at}, "tenant:reader")
    assert {item["incident_id"]: item["lifecycle_state"] for item in page["items"]} == {
        first.incident_id: "RESOLVED", new.incident_id: "OPEN",
    }
    store.close()


def test_existing_schema_and_history_reopen_without_rewriting(tmp_path):
    # Create the pre-change schema independently of the store initializer.
    path = tmp_path / "legacy.sqlite"
    legacy = sqlite3.connect(path)
    legacy.executescript("""
        create table gateway_operational_incident(
          incident_id text primary key, dedup_key text not null unique,
          module text not null, event_type text not null,
          lifecycle_state text not null check(lifecycle_state in('OPEN','RECOVERING','RESOLVED')),
          severity text not null check(severity in('INFO','WARNING','ERROR','CRITICAL')),
          first_seen_at text not null, last_seen_at text not null, resolved_at text,
          correlation_id text, endpoint_ref text, error_code text, impact_summary text not null,
          action_required integer not null check(action_required in(0,1)),
          occurrence_count integer not null check(occurrence_count>0), visibility_class text not null
        );
        create table gateway_operational_collector_state(
          source text primary key, last_observed_at text not null, last_event_at text
        );
        create table gateway_incident_transition(
          sequence_id integer primary key autoincrement, incident_id text not null, projection text not null
        );
        create index gateway_incident_current on gateway_incident_transition(incident_id,sequence_id desc);
    """)
    row = dict(
        incident_id="legacy-episode", module="GATEWAY", event_type="GATEWAY_ETCD_DEGRADED",
        lifecycle_state="OPEN", severity="CRITICAL", first_seen_at="2026-09-01T10:00:00Z",
        last_seen_at="2026-09-01T10:00:00Z", resolved_at=None, correlation_id=None,
        endpoint_ref="gateway://control-plane/etcd", error_code="ETCD_ENDPOINT_UNHEALTHY",
        impact_summary="Control plane unavailable.", action_required=1,
        dedup_key="gateway:etcd:collector-health", occurrence_count=2, visibility_class="TENANT_OPERATIONAL",
    )
    pairs = ",".join(f"'{key}',new.{key}" for key in row)
    for event in ("insert", "update"):
        legacy.execute(f"""create trigger gateway_incident_capture_{event}
            after {event} on gateway_operational_incident begin
            insert into gateway_incident_transition(incident_id,projection)
            values(new.incident_id,json_object({pairs})); end""")
    legacy.execute(f"insert into gateway_operational_incident({','.join(row)}) values({','.join('?' for _ in row)})", tuple(row.values()))
    legacy.execute("""update gateway_operational_incident set lifecycle_state='RESOLVED',
        last_seen_at='2026-09-01T10:01:00Z',resolved_at='2026-09-01T10:01:00Z',action_required=0""")
    # Preserve even redundant transitions produced by the old implementation.
    legacy.execute("update gateway_operational_incident set last_seen_at=last_seen_at")
    legacy.execute("insert into gateway_operational_collector_state values('ETCD','2026-09-01T10:01:00Z','2026-09-01T10:01:00Z')")
    legacy.commit()
    before = list(legacy.iterdump())
    legacy.close()

    store = SQLiteOperationalIncidentStore(path)
    assert store.db.total_changes == 0
    after = list(store.db.iterdump())
    new_index = "CREATE INDEX gateway_incident_transition_dedup on gateway_incident_transition(json_extract(projection,'$.dedup_key'), sequence_id desc);"
    assert new_index in after
    assert [line for line in after if line != new_index] == before
    assert store.get("legacy-episode").lifecycle_state == "RESOLVED"
    assert len(transitions(store)) == 3
    store.close()

    reopened = SQLiteOperationalIncidentStore(path)
    assert reopened.db.total_changes == 0
    assert list(reopened.db.iterdump()) == after
    reopened.close()


def test_episode_visibility_applies_by_dedup_key_to_existing_cursor(tmp_path):
    clock = Clock()
    store = SQLiteOperationalIncidentStore(tmp_path / "gateway.sqlite", clock=clock)
    first = open_fault(store)
    clock.advance(1)
    resolved = store.resolve_incident(first.dedup_key, "Recovered.")
    open_fault(store, dedup_key="other")
    page = store.incident_page({"limit": 1}, "tenant:reader")
    assert page["hasMore"] is True
    cursor_query = {"limit": 1, "cursor": page["nextCursor"]}
    historical_until = clock().isoformat()

    clock.advance(1)
    second = open_fault(store, visibility_class="RESTRICTED_OPERATIONAL")
    assert second.incident_id != first.incident_id
    hidden = store.incident_page(cursor_query, "tenant:reader")
    assert hidden["items"] == []
    assert hidden["partial"] is True
    assert hidden["authorization"] == "REDACTED"
    assert hidden["hasMore"] is False
    historical = store.incident_page({"until": historical_until}, "tenant:reader")
    assert [item["dedup_key"] for item in historical["items"]] == ["other"]
    assert historical["partial"] is True

    clock.advance(1)
    visible = open_fault(store)
    assert visible.incident_id == second.incident_id
    restored = store.incident_page(cursor_query, "tenant:reader")
    assert [item["incident_id"] for item in restored["items"]] == [first.incident_id]
    assert restored["items"][0]["resolved_at"] == resolved.resolved_at
    assert restored["partial"] is False
    current = store.incident_page({"limit": 100}, "tenant:reader")
    assert {item["incident_id"]: item["lifecycle_state"] for item in current["items"]} == {
        first.incident_id: "RESOLVED", second.incident_id: "OPEN",
        page["items"][0]["incident_id"]: "OPEN",
    }
    assert current["partial"] is False
    store.close()


def test_historical_projection_without_dedup_key_fails_closed(tmp_path):
    clock = Clock()
    store = SQLiteOperationalIncidentStore(tmp_path / "gateway.sqlite", clock=clock)
    incident = open_fault(store)
    legacy = json.loads(transitions(store)[0][2])
    del legacy["dedup_key"]
    store.db.execute("delete from gateway_incident_transition")
    store.db.execute("insert into gateway_incident_transition(incident_id,projection) values(?,?)",
                     (incident.incident_id, json.dumps(legacy)))
    store.db.commit()
    open_fault(store, dedup_key="other")
    page = store.incident_page({"limit": 1}, "tenant:reader")

    # Even a later visible projection of the same incident must not make a
    # historical projection without a dedup key visible through this cursor.
    clock.advance(1)
    open_fault(store)
    hidden = store.incident_page({"limit": 1, "cursor": page["nextCursor"]}, "tenant:reader")
    assert hidden["items"] == []
    assert hidden["partial"] is True
    assert hidden["authorization"] == "REDACTED"
    assert hidden["hasMore"] is False
    store.close()


def test_incident_page_uses_dedup_index_with_redundant_history(tmp_path):
    clock = Clock()
    store = SQLiteOperationalIncidentStore(tmp_path / "gateway.sqlite", clock=clock)
    first = open_fault(store)
    store.resolve_incident(first.dedup_key, "Recovered.")
    projection = transitions(store)[-1][2]
    store.db.executemany("insert into gateway_incident_transition(incident_id,projection) values(?,?)",
                         ((first.incident_id, projection) for _ in range(20_000)))
    store.db.commit()
    clock.advance(1)
    second = open_fault(store)
    others = [open_fault(store, dedup_key=f"other-{i}") for i in range(3)]
    assert len(transitions(store)) >= 20_000

    statements = []
    store.db.set_trace_callback(statements.append)
    page = store.incident_page({"limit": 100}, "tenant:reader")
    store.db.set_trace_callback(None)
    assert {item["incident_id"] for item in page["items"]} == {
        first.incident_id, second.incident_id, *(item.incident_id for item in others),
    }
    assert page["partial"] is False
    assert page["hasMore"] is False
    # Explain the actual page SQL, including its correlated visibility lookup,
    # so an accidental divergence from the indexed expression is detected.
    page_sql = next(sql for sql in statements if "current_visibility" in sql)
    plan = [row[3] for row in store.db.execute("explain query plan " + page_sql)]
    assert any("SEARCH current USING INDEX gateway_incident_transition_dedup" in detail for detail in plan), plan
    store.close()
