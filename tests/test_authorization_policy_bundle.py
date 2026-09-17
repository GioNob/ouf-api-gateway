import hashlib
import json

import pytest

from tools.authorization_policy_bundle import AuthorizationBundleError, FileAuthorizationGate


def write_bundle(tmp_path, *, scope="urban.object.related_search", bundle_id="lab", version=7):
    path=tmp_path/"bundle.json"
    value={
        "bundleId":bundle_id,
        "version":version,
        "publishedAt":"2026-09-17T00:00:00Z",
        "capabilities":[{"capabilityId":"urban.object.related_search","operation":"READ","requiredScope":scope,"allowedActors":["SERVICE"]}],
        "grants":[],
    }
    path.write_text(json.dumps(value,sort_keys=True,separators=(",",":")))
    digest=hashlib.sha256(path.read_bytes()).hexdigest()
    return path,digest


def test_exact_policy_bundle_binding_is_required(tmp_path):
    path,digest=write_bundle(tmp_path)
    gate=FileAuthorizationGate(path,digest,"lab",7)
    assert gate.binding_exists("urban.object.related_search@1.0.0","urban.object.related_search") is True
    assert gate.binding_exists("urban.object.related_search@1.0.0","wrong.scope") is False
    assert gate.binding_exists("missing@1.0.0","urban.object.related_search") is False


def test_policy_bundle_hash_id_and_version_fail_closed(tmp_path):
    path,digest=write_bundle(tmp_path)
    with pytest.raises(AuthorizationBundleError,match="sha256"):
        FileAuthorizationGate(path,"0"*64,"lab",7)
    with pytest.raises(AuthorizationBundleError,match="id mismatch"):
        FileAuthorizationGate(path,digest,"other",7)
    with pytest.raises(AuthorizationBundleError,match="version mismatch"):
        FileAuthorizationGate(path,digest,"lab",8)
