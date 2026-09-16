from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable


class EtcdSafetyError(RuntimeError):
    pass


@dataclass(frozen=True)
class EtcdHealth:
    quorum: bool
    storage_slow: bool
    pending_proposals: int
    leader_changes: int


@dataclass(frozen=True)
class DesiredState:
    revision: str
    routes: tuple[str, ...]
    upstreams: tuple[str, ...]


@dataclass(frozen=True)
class RestoredState:
    active_revision: str | None
    routes: tuple[str, ...]
    upstreams: tuple[str, ...]


class PublicationResilienceGate:
    """Fail-closed publication/restore safety gate for the adopted etcd boundary."""

    def __init__(self, allowed_upstreams: Iterable[str], max_pending_proposals: int = 64):
        allowed = frozenset(allowed_upstreams)
        if not allowed:
            raise ValueError("allowed_upstreams must be non-empty")
        if max_pending_proposals < 1:
            raise ValueError("max_pending_proposals must be positive")
        self.allowed_upstreams = allowed
        self.max_pending_proposals = max_pending_proposals

    def publication_allowed(self, health: EtcdHealth) -> bool:
        return (
            health.quorum
            and not health.storage_slow
            and health.pending_proposals <= self.max_pending_proposals
        )

    def require_publication_allowed(self, health: EtcdHealth) -> None:
        if not health.quorum:
            raise EtcdSafetyError("ETCD_QUORUM_UNAVAILABLE")
        if health.storage_slow:
            raise EtcdSafetyError("ETCD_STORAGE_SLOW")
        if health.pending_proposals > self.max_pending_proposals:
            raise EtcdSafetyError("ETCD_BACKPRESSURE_REQUIRED")

    def verify_restore(self, desired: DesiredState, restored: RestoredState) -> None:
        if restored.active_revision != desired.revision:
            raise EtcdSafetyError("RESTORE_REVISION_MISMATCH")
        if tuple(sorted(restored.routes)) != tuple(sorted(desired.routes)):
            raise EtcdSafetyError("RESTORE_PARTIAL_OR_EXTRA_ROUTES")
        if tuple(sorted(restored.upstreams)) != tuple(sorted(desired.upstreams)):
            raise EtcdSafetyError("RESTORE_PARTIAL_OR_EXTRA_UPSTREAMS")
        if any(u not in self.allowed_upstreams for u in restored.upstreams):
            raise EtcdSafetyError("RESTORE_UNALLOWLISTED_UPSTREAM")
        if any("*" in r or "*" in u for r in restored.routes for u in ("",)):
            raise EtcdSafetyError("RESTORE_WILDCARD_ROUTE")
        if any("*" in u for u in restored.upstreams):
            raise EtcdSafetyError("RESTORE_WILDCARD_UPSTREAM")
