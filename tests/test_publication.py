from datetime import datetime, timezone

import pytest

from tools.compile_config import ROOT
from tools.publication import Change, FilePublicationStore, PublicationError, Publisher, coalesce


CHECKS = {"health": True, "routeBinding": True, "authorizationNegativePath": True, "upstreamReachability": True, "convergence": True}


class FakeControlPlane:
    def __init__(self, healthy=True, checks=None, fail_at=None):
        self.is_healthy = healthy
        self.checks = checks or CHECKS
        self.calls = []
        self.fail_at = fail_at

    def healthy(self):
        self.calls.append("health")
        return self.is_healthy

    def stage(self, artifact):
        self.calls.append("stage")
        if self.fail_at == "stage":
            raise RuntimeError("stage failed")
        return "apisix-revision-42"

    def verify(self, revision, artifact):
        self.calls.append("verify")
        if self.fail_at == "verify":
            raise RuntimeError("verify failed")
        return self.checks

    def activate(self, revision):
        self.calls.append("activate")
        if self.fail_at == "activate":
            raise RuntimeError("activate failed")

    def rollback(self, revision):
        self.calls.append("rollback")


def publisher(tmp_path, plane):
    fixed = lambda: datetime(2026, 9, 15, 12, 0, tzinfo=timezone.utc)
    return Publisher(plane, FilePublicationStore(tmp_path), fixed)


def test_activation_requires_all_verification_and_records_manifest(tmp_path):
    plane = FakeControlPlane()
    result = publisher(tmp_path, plane).publish(ROOT / "ouf-config", "test", "git:abc123", "publication-1")
    assert result["status"] == "ACTIVE"
    assert result["controlPlaneRevision"] == "apisix-revision-42"
    assert result["artifactSetHash"]
    assert result["inputHashes"]
    assert (tmp_path / "artifacts" / f"{result['artifactSetHash']}.json").exists()
    assert plane.calls == ["health", "stage", "verify", "activate"]
    assert FilePublicationStore(tmp_path).active_manifest()["publicationId"] == "publication-1"


def test_degraded_control_plane_blocks_stage_and_preserves_last_known_good(tmp_path):
    first_plane = FakeControlPlane()
    first = publisher(tmp_path, first_plane).publish(ROOT / "ouf-config", "test", "git:one", "publication-good")
    degraded = FakeControlPlane(healthy=False)
    failed = publisher(tmp_path, degraded).publish(ROOT / "ouf-config", "test", "git:two", "publication-degraded")
    assert failed["status"] == "FAILED"
    assert degraded.calls == ["health"]
    assert FilePublicationStore(tmp_path).active_manifest()["publicationId"] == first["publicationId"]


def test_failed_verification_rolls_back_stage_and_does_not_activate(tmp_path):
    checks = dict(CHECKS)
    checks["authorizationNegativePath"] = False
    plane = FakeControlPlane(checks=checks)
    result = publisher(tmp_path, plane).publish(ROOT / "ouf-config", "test", "git:bad", "publication-bad")
    assert result["status"] == "ROLLED_BACK"
    assert plane.calls == ["health", "stage", "verify", "rollback"]
    assert FilePublicationStore(tmp_path).active_manifest() is None


@pytest.mark.parametrize("failure,expected", [("stage", ["health", "stage"]), ("verify", ["health", "stage", "verify", "rollback"]), ("activate", ["health", "stage", "verify", "activate", "rollback"])])
def test_control_plane_exceptions_never_activate_a_failed_publication(tmp_path, failure, expected):
    plane = FakeControlPlane(fail_at=failure)
    result = publisher(tmp_path, plane).publish(ROOT / "ouf-config", "test", "git:error", f"publication-{failure}")
    assert result["status"] in {"FAILED", "ROLLED_BACK"}
    assert plane.calls == expected
    assert FilePublicationStore(tmp_path).active_manifest() is None


def test_publication_manifest_is_immutable(tmp_path):
    service = publisher(tmp_path, FakeControlPlane())
    service.publish(ROOT / "ouf-config", "test", "git:one", "publication-same")
    with pytest.raises(PublicationError, match="immutable"):
        service.publish(ROOT / "ouf-config", "test", "git:one", "publication-same")


def test_invalid_publication_identity_fails_before_control_plane_io(tmp_path):
    plane = FakeControlPlane()
    with pytest.raises(PublicationError, match="invalid publication manifest"):
        publisher(tmp_path, plane).publish(ROOT / "ouf-config", "", "git:one", "publication-invalid")
    assert plane.calls == []
    with pytest.raises(PublicationError, match="invalid publication manifest"):
        publisher(tmp_path, plane).publish(ROOT / "ouf-config", "test", "git:one", "../escape")
    assert not (tmp_path.parent / "escape.json").exists()


def test_batch_coalesces_latest_change_per_object_and_applies_backpressure():
    changes = [Change("route:a", 1, {"v": 1}), Change("route:b", 1, {"v": 1}), Change("route:a", 2, {"v": 2})]
    result = coalesce(changes, maximum=2)
    assert [(item.object_ref, item.sequence) for item in result] == [("route:a", 2), ("route:b", 1)]
    with pytest.raises(PublicationError, match="bounded capacity"):
        coalesce(changes + [Change("route:c", 1, {})], maximum=2)
