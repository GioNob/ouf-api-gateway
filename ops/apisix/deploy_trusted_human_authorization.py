#!/usr/bin/env python3
"""Install the bounded trusted-HUMAN Authorization namespace in APISIX.

All managed route IDs, including the superseded capability-only routes, are
snapshotted before the first write. Deployment verifies readback and anonymous
401 protection. Any failure restores the entire managed set.
"""
import argparse
import json
import os
from pathlib import Path
import subprocess
import tempfile

NAMESPACE = "/api/trusted-human/v1/authorization/*"
METHODS = ("GET", "POST", "PUT", "DELETE")
CURRENT_IDS = {f"trusted-human-authorization-{m.lower()}" for m in METHODS}
LEGACY_IDS = {
    "trusted-human-authorization-capabilities-read",
    "trusted-human-authorization-capabilities-register",
}
MANAGED_IDS = CURRENT_IDS | LEGACY_IDS


def route_value(doc):
    value = doc.get("value", doc)
    if isinstance(value, dict) and isinstance(value.get("value"), dict):
        value = value["value"]
    return {k: v for k, v in value.items() if k not in ("create_time", "update_time")}


class Admin:
    def __init__(self, args):
        self.args = args
        args.backup_dir.mkdir(parents=True, exist_ok=True)
        self.work = Path(tempfile.mkdtemp(prefix="trusted-human-auth-", dir=args.backup_dir))
        key = args.admin_key.read_text().strip()
        if not key or "\n" in key or "\r" in key:
            raise ValueError("invalid APISIX admin key file")
        (self.work / "admin.header").write_text("X-API-KEY: " + key + "\n")
        os.chmod(self.work / "admin.header", 0o600)
        print("BACKUP=" + str(self.work / "previous.json"), flush=True)

    def curl(self, path, method="GET", data=None, admin=False):
        cmd = [
            "docker", "run", "--rm", "--user", "0:0",
            "--network", "container:" + self.args.container,
            "-v", str(self.work) + ":/work",
            self.args.curl_image, "--max-time", "15", "-sS",
            "-o", "/work/response.json", "-w", "%{http_code}", "-X", method,
        ]
        if admin:
            cmd += ["-H", "@/work/admin.header"]
        if data is not None:
            (self.work / "request.json").write_text(json.dumps(data))
            cmd += ["-H", "Content-Type: application/json", "--data-binary", "@/work/request.json"]
        cmd += ["http://127.0.0.1:" + ("9180" if admin else "9080") + path]
        result = subprocess.run(cmd, check=True, capture_output=True, text=True)
        raw = (self.work / "response.json").read_text()
        try:
            value = json.loads(raw)
        except json.JSONDecodeError:
            value = {}
        return int(result.stdout), value

    def route(self, method, route_id, data=None):
        return self.curl("/apisix/admin/routes/" + route_id, method, data, admin=True)

    def close(self):
        for name in ("admin.header", "request.json", "response.json"):
            (self.work / name).unlink(missing_ok=True)


def snapshot(admin):
    previous = {}
    for route_id in sorted(MANAGED_IDS):
        code, body = admin.route("GET", route_id)
        if code not in (200, 404):
            raise RuntimeError(f"snapshot HTTP {code} for {route_id}")
        previous[route_id] = route_value(body) if code == 200 else None
    (admin.work / "previous.json").write_text(json.dumps(previous, indent=2) + "\n")
    return previous


def restore(previous, admin):
    failures = []
    for route_id in sorted(MANAGED_IDS):
        old = previous.get(route_id)
        try:
            code, _ = admin.route("PUT" if old else "DELETE", route_id, old)
            if code not in (200, 201, 204, 404):
                failures.append(route_id)
        except Exception:
            failures.append(route_id)
    if failures:
        raise RuntimeError("rollback incomplete: " + ",".join(failures))


def apply(routes, admin):
    previous = snapshot(admin)
    try:
        for route in routes:
            code, _ = admin.route("PUT", route["id"], route)
            if code not in (200, 201):
                raise RuntimeError(f"write HTTP {code}")
            code, body = admin.route("GET", route["id"])
            actual = route_value(body) if code == 200 else {}
            if any(actual.get(k) != v for k, v in route.items()):
                raise RuntimeError("route readback differs")
        for route_id in LEGACY_IDS:
            code, _ = admin.route("DELETE", route_id)
            if code not in (200, 204, 404):
                raise RuntimeError(f"legacy delete HTTP {code}")
        for path in (
            "/api/trusted-human/v1/authorization/capabilities?limit=1&offset=0",
            "/api/trusted-human/v1/authorization/access?subjectId=probe",
            "/api/trusted-human/v1/authorization/policies",
        ):
            code, _ = admin.curl(path, "GET")
            if code != 401:
                raise RuntimeError(f"unauthenticated protected namespace HTTP {code} for {path}")
    except BaseException:
        restore(previous, admin)
        raise


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--materialization", type=Path)
    group.add_argument("--restore", type=Path)
    parser.add_argument("--admin-key", type=Path, required=True)
    parser.add_argument("--container", default="ouf-apisix")
    parser.add_argument("--curl-image", default="curlimages/curl:8.16.0")
    parser.add_argument("--backup-dir", type=Path, default=Path("/opt/ouf/backup"))
    args = parser.parse_args()
    os.umask(0o077)
    admin = Admin(args)
    try:
        if args.restore:
            previous = json.loads(args.restore.read_text())
            if set(previous) != MANAGED_IDS:
                raise ValueError("snapshot does not contain the full managed route set")
            restore(previous, admin)
            print("TRUSTED_HUMAN_AUTHORIZATION_ROUTES_RESTORED")
            return
        doc = json.loads(args.materialization.read_text())
        routes = doc.get("routes")
        if not isinstance(routes, list) or len(routes) != 4:
            raise ValueError("expected four trusted HUMAN namespace routes")
        if {r.get("id") for r in routes} != CURRENT_IDS:
            raise ValueError("unexpected trusted HUMAN route IDs")
        if {tuple(r.get("methods", [])) for r in routes} != {(m,) for m in METHODS}:
            raise ValueError("trusted HUMAN routes must cover GET/POST/PUT/DELETE")
        if any(r.get("uri") != NAMESPACE for r in routes):
            raise ValueError("unexpected trusted HUMAN namespace")
        apply(routes, admin)
        print("TRUSTED_HUMAN_AUTHORIZATION_NAMESPACE_INSTALLED")
    finally:
        admin.close()


if __name__ == "__main__":
    main()
