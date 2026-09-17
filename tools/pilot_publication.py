#!/usr/bin/env python3
import argparse
import json
import os
import shutil
import tempfile
from pathlib import Path

import yaml

from tools.apisix_admin_http import APISIXAdminHTTP
from tools.apisix_control_plane import APISIXControlPlane
from tools.apisix_runtime_probe import APISIXHTTPRuntimeProbe
from tools.authorization_policy_bundle import FileAuthorizationGate
from tools.compile_config import ROOT, compile_config
from tools.publication import FilePublicationStore, Publisher, PublicationError


def filtered_config(source_root: Path, route_id: str, target_root: Path) -> Path:
    if not route_id or any(ch.isspace() for ch in route_id):
        raise PublicationError("pilot route id is invalid")
    shutil.copytree(source_root, target_root)
    routes_root = target_root / "routes"
    matches = 0
    for path in sorted(routes_root.rglob("*.yaml")):
        doc = yaml.safe_load(path.read_text())
        current = ((doc or {}).get("metadata") or {}).get("id") if isinstance(doc, dict) else None
        if current == route_id:
            matches += 1
        else:
            path.unlink()
    if matches != 1:
        raise PublicationError("pilot route must resolve to exactly one governed RouteBinding")
    return target_root


def build_plane(admin_url: str, data_plane_url: str) -> APISIXControlPlane:
    admin_key = os.environ.get("APISIX_ADMIN_KEY", "")
    negative = os.environ.get("OUF_PROBE_NEGATIVE_TOKEN", "")
    positive = os.environ.get("OUF_PROBE_POSITIVE_TOKEN", "")
    runtime_probe = APISIXHTTPRuntimeProbe(data_plane_url, negative, positive)
    return APISIXControlPlane(APISIXAdminHTTP(admin_url, admin_key, runtime_probe=runtime_probe))


def build_authorization_gate(args) -> FileAuthorizationGate:
    return FileAuthorizationGate(
        Path(args.authorization_bundle),
        args.authorization_bundle_sha256,
        args.authorization_bundle_id,
        args.authorization_bundle_version,
    )


def preflight(config_root: Path, route_id: str, environment: str, plane, authorization_gate) -> dict:
    publisher = Publisher(plane, FilePublicationStore(Path(tempfile.mkdtemp(prefix="ouf-pilot-preflight-store-"))), authorization_gate=authorization_gate)
    with tempfile.TemporaryDirectory(prefix="ouf-pilot-config-") as temp:
        filtered = filtered_config(config_root, route_id, Path(temp) / "ouf-config")
        publisher._validate_repository_governance(filtered, environment)
        artifact = compile_config(filtered)
        if len(artifact.get("apisixRoutes", [])) != 1:
            raise PublicationError("pilot preflight must compile exactly one APISIX route")
        if not plane.healthy():
            raise PublicationError("pilot control plane is unhealthy")
        revision = plane.stage(artifact)
        try:
            checks = plane.verify(revision, artifact)
            required = Publisher.REQUIRED_CHECKS + ("artifactIntegrity",)
            verified = all(checks.get(name) is True for name in required)
            return {
                "routeId": route_id,
                "revision": revision,
                "verified": verified,
                "checks": checks,
            }
        finally:
            plane.rollback(revision)


def publish(config_root: Path, route_id: str, environment: str, source_revision: str, publication_id: str, store_root: Path, plane, authorization_gate) -> dict:
    with tempfile.TemporaryDirectory(prefix="ouf-pilot-config-") as temp:
        filtered = filtered_config(config_root, route_id, Path(temp) / "ouf-config")
        publisher = Publisher(plane, FilePublicationStore(store_root), authorization_gate=authorization_gate)
        return publisher.publish(filtered, environment, source_revision, publication_id)


def main():
    parser = argparse.ArgumentParser(description="Governed single-route APISIX pilot publication")
    parser.add_argument("mode", choices=("preflight", "publish"))
    parser.add_argument("--route-id", required=True)
    parser.add_argument("--environment", choices=("dev", "test", "prod"), default="test")
    parser.add_argument("--config", type=Path, default=ROOT / "ouf-config")
    parser.add_argument("--admin-url", default="http://127.0.0.1:9180")
    parser.add_argument("--data-plane-url", default="http://127.0.0.1:9080")
    parser.add_argument("--authorization-bundle", required=True)
    parser.add_argument("--authorization-bundle-sha256", required=True)
    parser.add_argument("--authorization-bundle-id", required=True)
    parser.add_argument("--authorization-bundle-version", required=True, type=int)
    parser.add_argument("--source-revision")
    parser.add_argument("--publication-id")
    parser.add_argument("--store", type=Path)
    args = parser.parse_args()

    plane = build_plane(args.admin_url, args.data_plane_url)
    gate = build_authorization_gate(args)
    if args.mode == "preflight":
        result = preflight(args.config, args.route_id, args.environment, plane, gate)
    else:
        if not args.source_revision or not args.publication_id or args.store is None:
            parser.error("publish requires --source-revision, --publication-id and --store")
        result = publish(args.config, args.route_id, args.environment, args.source_revision, args.publication_id, args.store, plane, gate)
    print(json.dumps(result, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
