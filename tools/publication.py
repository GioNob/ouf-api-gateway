import fcntl
import hashlib
import json
import os
import re
import tempfile
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Protocol

from jsonschema import Draft202012Validator, FormatChecker

from tools.compile_config import ROOT, compile_config


class PublicationError(RuntimeError):
    pass


class ControlPlane(Protocol):
    def healthy(self) -> bool: ...
    def stage(self, artifact: dict) -> str: ...
    def verify(self, revision: str, artifact: dict) -> dict[str, bool]: ...
    def activate(self, revision: str) -> None: ...
    def rollback(self, revision: str) -> None: ...


@dataclass(frozen=True)
class Change:
    object_ref: str
    sequence: int
    payload: dict


def coalesce(changes: list[Change], maximum: int) -> list[Change]:
    if maximum < 1:
        raise PublicationError("maximum batch size must be positive")
    latest: dict[str, Change] = {}
    for change in changes:
        current = latest.get(change.object_ref)
        if current is None or change.sequence > current.sequence:
            latest[change.object_ref] = change
    if len(latest) > maximum:
        raise PublicationError("publication batch exceeds bounded capacity")
    return sorted(latest.values(), key=lambda item: item.object_ref)


class FilePublicationStore:
    def __init__(self, root: Path):
        self.root = root
        self.manifests = root / "manifests"
        self.artifacts = root / "artifacts"
        self.active = root / "active.json"

    def active_manifest(self) -> dict | None:
        return json.loads(self.active.read_text()) if self.active.exists() else None

    @contextmanager
    def exclusive(self):
        self.root.mkdir(parents=True, exist_ok=True)
        with (self.root / ".publication.lock").open("w") as lock:
            fcntl.flock(lock, fcntl.LOCK_EX)
            try:
                yield
            finally:
                fcntl.flock(lock, fcntl.LOCK_UN)

    def contains(self, publication_id: str) -> bool:
        return (self.manifests / f"{publication_id}.json").exists()

    def record(self, manifest: dict, artifact: dict, activate: bool = False) -> None:
        self.manifests.mkdir(parents=True, exist_ok=True)
        target = self.manifests / f"{manifest['publicationId']}.json"
        if target.exists():
            raise PublicationError("publication manifest is immutable")
        artifact_target = self.artifacts / f"{manifest['artifactSetHash']}.json"
        if artifact_target.exists() and json.loads(artifact_target.read_text()) != artifact:
            raise PublicationError("artifact hash collision")
        if not artifact_target.exists():
            self._atomic_write(artifact_target, artifact)
        self._atomic_write(target, manifest)
        if activate:
            self._atomic_write(self.active, manifest)

    @staticmethod
    def _atomic_write(target: Path, value: dict) -> None:
        target.parent.mkdir(parents=True, exist_ok=True)
        descriptor, temporary = tempfile.mkstemp(dir=target.parent, prefix=f".{target.name}.")
        try:
            with os.fdopen(descriptor, "w") as stream:
                stream.write(json.dumps(value, indent=2, sort_keys=True) + "\n")
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary, target)
        finally:
            if os.path.exists(temporary):
                os.unlink(temporary)


class Publisher:
    REQUIRED_CHECKS = ("health", "routeBinding", "authorizationNegativePath", "upstreamReachability", "convergence")

    def __init__(self, plane: ControlPlane, store: FilePublicationStore, clock=None):
        self.plane = plane
        self.store = store
        self.clock = clock or (lambda: datetime.now(timezone.utc))
        self.schema = json.loads((ROOT / "schemas" / "gateway-publication-manifest-v1.json").read_text())

    def publish(self, config_root: Path, environment: str, source_revision: str, publication_id: str) -> dict:
        with self.store.exclusive():
            return self._publish(config_root, environment, source_revision, publication_id)

    def _publish(self, config_root: Path, environment: str, source_revision: str, publication_id: str) -> dict:
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}", publication_id):
            raise PublicationError("invalid publication manifest: unsafe publicationId")
        if self.store.contains(publication_id):
            raise PublicationError("publication manifest is immutable")
        previous = self.store.active_manifest()
        created = self.clock().isoformat().replace("+00:00", "Z")
        try:
            artifact = compile_config(config_root)
        except Exception as exc:
            raise PublicationError(f"validation/compile failed: {exc}") from exc
        manifest = {
            "publicationId": publication_id,
            "environment": environment,
            "sourceRevisionRef": source_revision,
            "artifactSetHash": artifact["configurationSha256"],
            "status": "COMPILED",
            "createdAt": created,
            "activatedAt": None,
            "verification": None,
            "previousActivePublicationId": previous["publicationId"] if previous else None,
            "controlPlaneRevision": None,
            "inputHashes": self._input_hashes(config_root),
        }
        self._validate(manifest)
        try:
            healthy = self.plane.healthy()
        except Exception:
            healthy = False
        if not healthy:
            manifest["status"] = "FAILED"
            manifest["verification"] = {"health": False}
            self._record(manifest, artifact)
            return manifest
        try:
            revision = self.plane.stage(artifact)
        except Exception:
            manifest["status"] = "FAILED"
            manifest["verification"] = {"stage": False}
            self._record(manifest, artifact)
            return manifest
        manifest["status"] = "APPLYING"
        manifest["controlPlaneRevision"] = revision
        try:
            verification = self.plane.verify(revision, artifact)
        except Exception:
            verification = {"verification": False}
        manifest["verification"] = verification
        if not all(verification.get(check) is True for check in self.REQUIRED_CHECKS):
            self.plane.rollback(revision)
            manifest["status"] = "ROLLED_BACK"
            self._record(manifest, artifact)
            return manifest
        manifest["status"] = "VERIFIED"
        try:
            self.plane.activate(revision)
        except Exception:
            self.plane.rollback(revision)
            manifest["status"] = "ROLLED_BACK"
            manifest["verification"]["activation"] = False
            self._record(manifest, artifact)
            return manifest
        manifest["status"] = "ACTIVE"
        manifest["activatedAt"] = self.clock().isoformat().replace("+00:00", "Z")
        self._record(manifest, artifact, activate=True)
        return manifest

    def _record(self, manifest: dict, artifact: dict, activate: bool = False) -> None:
        self._validate(manifest)
        self.store.record(manifest, artifact, activate)

    def _validate(self, manifest: dict) -> None:
        errors = sorted(Draft202012Validator(self.schema, format_checker=FormatChecker()).iter_errors(manifest), key=lambda e: list(e.path))
        if errors:
            raise PublicationError(f"invalid publication manifest: {errors[0].message}")

    @staticmethod
    def _input_hashes(config_root: Path) -> dict[str, str]:
        return {str(path.relative_to(config_root)): hashlib.sha256(path.read_bytes()).hexdigest() for path in sorted(config_root.rglob("*.yaml"))}
