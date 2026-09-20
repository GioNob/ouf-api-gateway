from datetime import datetime, timedelta, timezone

from tools.gateway_operational_collector import ApisixIncidentCollector
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
