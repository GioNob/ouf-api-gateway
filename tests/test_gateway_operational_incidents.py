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
