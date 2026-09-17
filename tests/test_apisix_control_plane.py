import pytest

from tools.apisix_control_plane import APISIXControlPlane


class FakeAdmin:
    def __init__(self):
        self.revisions = {}
        self.active = None
        self.checks = {k: True for k in ("health", "routeBinding", "authorizationNegativePath", "upstreamReachability", "convergence")}
        self.corrupt_read = False
        self.activation_converges = True

    def health(self): return True
    def put_revision(self, revision, artifact): self.revisions[revision] = artifact
    def revision_matches(self, revision, artifact):
        if self.corrupt_read: return False
        return self.revisions.get(revision) == artifact
    def probe_revision(self, revision): return self.checks
    def activate_revision(self, revision):
        if self.activation_converges: self.active = revision
    def active_revision(self): return self.active
    def delete_revision(self, revision): self.revisions.pop(revision, None)


def artifact(): return {"configurationSha256": "a" * 64, "routes": [{"id": "r1"}]}


def test_stage_is_content_addressed_and_read_after_write_verified():
    admin = FakeAdmin(); plane = APISIXControlPlane(admin); value = artifact()
    revision = plane.stage(value)
    assert revision.startswith("sha256:") and admin.revisions[revision] == value


def test_stage_fails_closed_on_etcd_readback_mismatch():
    admin = FakeAdmin(); admin.corrupt_read = True
    with pytest.raises(RuntimeError): APISIXControlPlane(admin).stage(artifact())


def test_verification_requires_every_governance_probe():
    admin = FakeAdmin(); plane = APISIXControlPlane(admin); value = artifact(); revision = plane.stage(value)
    admin.checks["authorizationNegativePath"] = False
    checks = plane.verify(revision, value)
    assert checks["authorizationNegativePath"] is False and checks["artifactIntegrity"] is True


def test_activation_requires_read_after_write_convergence():
    admin = FakeAdmin(); admin.activation_converges = False; plane = APISIXControlPlane(admin); revision = plane.stage(artifact())
    with pytest.raises(RuntimeError): plane.activate(revision)


def test_rollback_never_deletes_active_revision():
    admin = FakeAdmin(); plane = APISIXControlPlane(admin); revision = plane.stage(artifact()); admin.active = revision
    with pytest.raises(RuntimeError): plane.rollback(revision)
    assert revision in admin.revisions


def test_rollback_discards_only_non_active_staged_revision():
    admin = FakeAdmin(); plane = APISIXControlPlane(admin); revision = plane.stage(artifact())
    plane.rollback(revision)
    assert revision not in admin.revisions
