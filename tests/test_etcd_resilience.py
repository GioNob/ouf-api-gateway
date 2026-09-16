import pytest

from tools.etcd_resilience import (
    DesiredState,
    EtcdHealth,
    EtcdSafetyError,
    PublicationResilienceGate,
    RestoredState,
)


def gate():
    return PublicationResilienceGate(
        allowed_upstreams=("udp-object-resolution:8443", "mcp-server:8443"),
        max_pending_proposals=64,
    )


def test_healthy_quorum_allows_publication():
    assert gate().publication_allowed(EtcdHealth(True, False, 2, 0))


@pytest.mark.parametrize(
    "health,code",
    [
        (EtcdHealth(False, False, 0, 0), "ETCD_QUORUM_UNAVAILABLE"),
        (EtcdHealth(True, True, 0, 0), "ETCD_STORAGE_SLOW"),
        (EtcdHealth(True, False, 65, 0), "ETCD_BACKPRESSURE_REQUIRED"),
    ],
)
def test_degraded_etcd_blocks_new_publication(health, code):
    with pytest.raises(EtcdSafetyError, match=code):
        gate().require_publication_allowed(health)


def test_restore_requires_exact_desired_state_and_allowlist():
    desired = DesiredState("rev-1", ("route-a", "route-b"), ("udp-object-resolution:8443",))
    restored = RestoredState("rev-1", ("route-b", "route-a"), ("udp-object-resolution:8443",))
    gate().verify_restore(desired, restored)


@pytest.mark.parametrize(
    "restored,code",
    [
        (RestoredState("rev-0", ("route-a",), ("udp-object-resolution:8443",)), "RESTORE_REVISION_MISMATCH"),
        (RestoredState("rev-1", ("route-a",), ("udp-object-resolution:8443",)), "RESTORE_PARTIAL_OR_EXTRA_ROUTES"),
        (RestoredState("rev-1", ("route-a", "route-b"), ("evil.example:443",)), "RESTORE_PARTIAL_OR_EXTRA_UPSTREAMS"),
        (RestoredState("rev-1", ("route-*", "route-b"), ("udp-object-resolution:8443",)), "RESTORE_PARTIAL_OR_EXTRA_ROUTES"),
    ],
)
def test_restore_fail_closed(restored, code):
    desired = DesiredState("rev-1", ("route-a", "route-b"), ("udp-object-resolution:8443",))
    with pytest.raises(EtcdSafetyError, match=code):
        gate().verify_restore(desired, restored)


def test_restore_rejects_wildcard_even_if_desired_is_corrupt():
    desired = DesiredState("rev-1", ("route-*",), ("udp-object-resolution:8443",))
    restored = RestoredState("rev-1", ("route-*",), ("udp-object-resolution:8443",))
    with pytest.raises(EtcdSafetyError, match="RESTORE_WILDCARD_ROUTE"):
        gate().verify_restore(desired, restored)
