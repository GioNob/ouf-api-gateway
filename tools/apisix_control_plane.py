import hashlib
import json
from dataclasses import dataclass
from typing import Protocol


class APISIXAdminPort(Protocol):
    def health(self) -> bool: ...
    def put_revision(self, revision: str, artifact: dict) -> None: ...
    def read_revision(self, revision: str) -> dict: ...
    def probe_revision(self, revision: str) -> dict[str, bool]: ...
    def activate_revision(self, revision: str) -> None: ...
    def active_revision(self) -> str | None: ...
    def delete_revision(self, revision: str) -> None: ...


@dataclass
class APISIXControlPlane:
    """Publication adapter with immutable content-addressed revisions.

    This adapter deliberately treats APISIX/etcd as an external port. It never
    infers success from a write acknowledgement: stage is read-after-write
    verified and activation is read-after-write verified. The real Admin API
    transport and deployed etcd evidence remain environment concerns.
    """

    admin: APISIXAdminPort

    @staticmethod
    def revision_for(artifact: dict) -> str:
        canonical = json.dumps(artifact, separators=(",", ":"), sort_keys=True).encode()
        return "sha256:" + hashlib.sha256(canonical).hexdigest()

    def healthy(self) -> bool:
        try:
            return self.admin.health() is True
        except Exception:
            return False

    def stage(self, artifact: dict) -> str:
        revision = self.revision_for(artifact)
        self.admin.put_revision(revision, artifact)
        if self.admin.read_revision(revision) != artifact:
            raise RuntimeError("APISIX staged revision failed read-after-write verification")
        return revision

    def verify(self, revision: str, artifact: dict) -> dict[str, bool]:
        if revision != self.revision_for(artifact):
            return {"artifactIntegrity": False}
        if self.admin.read_revision(revision) != artifact:
            return {"artifactIntegrity": False}
        checks = self.admin.probe_revision(revision)
        return {
            "health": checks.get("health") is True,
            "routeBinding": checks.get("routeBinding") is True,
            "authorizationNegativePath": checks.get("authorizationNegativePath") is True,
            "upstreamReachability": checks.get("upstreamReachability") is True,
            "convergence": checks.get("convergence") is True,
            "artifactIntegrity": True,
        }

    def activate(self, revision: str) -> None:
        self.admin.activate_revision(revision)
        if self.admin.active_revision() != revision:
            raise RuntimeError("APISIX activation did not converge to staged revision")

    def rollback(self, revision: str) -> None:
        # A staged, non-active revision is disposable. The publisher's ACTIVE
        # manifest remains last-known-good and is never advanced on failure.
        if self.admin.active_revision() == revision:
            raise RuntimeError("refusing to delete active APISIX revision")
        self.admin.delete_revision(revision)
