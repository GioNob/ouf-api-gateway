import hashlib
import json
from dataclasses import dataclass
from pathlib import Path


class AuthorizationBundleError(RuntimeError):
    pass


@dataclass(frozen=True)
class FileAuthorizationGate:
    bundle_file: Path
    expected_sha256: str
    expected_bundle_id: str
    expected_version: int

    def __post_init__(self):
        if len(self.expected_sha256) != 64 or any(c not in "0123456789abcdef" for c in self.expected_sha256):
            raise ValueError("expected authorization bundle sha256 must be lowercase hex")
        raw = self.bundle_file.read_bytes()
        actual = hashlib.sha256(raw).hexdigest()
        if actual != self.expected_sha256:
            raise AuthorizationBundleError("authorization bundle sha256 mismatch")
        try:
            bundle = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise AuthorizationBundleError("authorization bundle is not valid JSON") from exc
        if not isinstance(bundle, dict):
            raise AuthorizationBundleError("authorization bundle must be an object")
        if bundle.get("bundleId") != self.expected_bundle_id:
            raise AuthorizationBundleError("authorization bundle id mismatch")
        if bundle.get("version") != self.expected_version:
            raise AuthorizationBundleError("authorization bundle version mismatch")
        capabilities = bundle.get("capabilities")
        if not isinstance(capabilities, list):
            raise AuthorizationBundleError("authorization bundle capabilities missing")
        normalized = {}
        for item in capabilities:
            if not isinstance(item, dict):
                raise AuthorizationBundleError("authorization capability descriptor must be an object")
            capability_id = item.get("capabilityId")
            required_scope = item.get("requiredScope")
            if not isinstance(capability_id, str) or not capability_id or not isinstance(required_scope, str) or not required_scope:
                raise AuthorizationBundleError("authorization capability descriptor invalid")
            if capability_id in normalized:
                raise AuthorizationBundleError("duplicate authorization capability descriptor")
            normalized[capability_id] = required_scope
        object.__setattr__(self, "_capability_scopes", normalized)

    def binding_exists(self, capability_ref: str, required_scope: str) -> bool:
        if not isinstance(capability_ref, str) or not isinstance(required_scope, str):
            return False
        capability_id = capability_ref.rsplit("@", 1)[0]
        return self._capability_scopes.get(capability_id) == required_scope
