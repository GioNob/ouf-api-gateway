#!/usr/bin/env python3
"""Install the reviewed trusted-HUMAN Authorization catalogue routes in APISIX.

The script snapshots both route IDs before the first write, verifies readback,
checks that the public GET is protected, and restores the snapshot on failure.
It never prints the APISIX admin key or OIDC secret material.
"""
import argparse
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile

PATH = "/api/trusted-human/v1/authorization/capabilities"
EXPECTED_IDS = {
    "trusted-human-authorization-capabilities-read",
    "trusted-human-authorization-capabilities-register",
}


def route_value(doc):
    value = doc.get("value", doc)
    if isinstance(value, dict) and isinstance(value.get("value"), dict):
        value = value["value"]
    return {k: v for k, v in value.items() if k not in ("create_time", "update_time")}


class Admin:
    def __init__(self, args):
        self.args = args
        backup_dir = args.backup_dir
        backup_dir.mkdir(parents=True, exist_ok=True)
        self.work = Path(tempfile.mkdtemp(prefix="trusted-human-auth-", dir=backup_dir))
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
        (self.work / "admin.header").unlink(missing_ok=True)
        (self.work / "request.json").unlink(missing_ok=True)
        (self.work / "response.json").unlink(missing_ok=True)


def apply(routes, admin):
    previous = {}
    for route in routes:
        code, body = admin.route("GET", route["id"])
        if code not in (200, 404):
            raise RuntimeError(f"snapshot HTTP {code}")
        previous[route["id"]] = route_value(body) if code == 200 else None
    (admin.work / "previous.json").write_text(json.dumps(previous, indent=2) + "\n")

    attempted = []
    try:
        for route in routes:
            attempted.append(route["id"])
            code, _ = admin.route("PUT", route["id"], route)
            if code not in (200, 201):
                raise RuntimeError(f"write HTTP {code}")
            code, body = admin.route("GET", route["id"])
            actual = route_value(body) if code == 200 else {}
            if any(actual.get(k) != v for k, v in route.items()):
                raise RuntimeError("route readback differs")
        code, _ = admin.curl(PATH + "?limit=1&offset=0")
        if code != 401:
            raise RuntimeError(f"unauthenticated trusted HUMAN GET HTTP {code}")
    except BaseException:
        failures = []
        for route_id in reversed(attempted):
            old = previous[route_id]
            try:
                code, _ = admin.route("PUT" if old else "DELETE", route_id, old)
                if code not in (200, 201, 204, 404):
                    failures.append(route_id)
            except Exception:
                failures.append(route_id)
        if failures:
            raise RuntimeError("rollback incomplete: " + ",".join(failures))
        raise


def restore(snapshot, admin):
    previous = json.loads(snapshot.read_text())
    if set(previous) != EXPECTED_IDS:
        raise ValueError("snapshot does not contain the two reviewed route IDs")
    for route_id, old in previous.items():
        code, _ = admin.route("PUT" if old else "DELETE", route_id, old)
        if code not in (200, 201, 204, 404):
            raise RuntimeError("restore failed")
    print("TRUSTED_HUMAN_AUTHORIZATION_ROUTES_RESTORED")


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
            restore(args.restore, admin)
            return
        doc = json.loads(args.materialization.read_text())
        routes = doc.get("routes")
        if not isinstance(routes, list) or len(routes) != 2:
            raise ValueError("expected exactly two trusted HUMAN routes")
        if {r.get("id") for r in routes} != EXPECTED_IDS:
            raise ValueError("unexpected trusted HUMAN route IDs")
        if {tuple(r.get("methods", [])) for r in routes} != {("GET",), ("POST",)}:
            raise ValueError("trusted HUMAN routes must be GET and POST")
        if any(r.get("uri") != PATH for r in routes):
            raise ValueError("unexpected trusted HUMAN route path")
        for route in routes:
            oidc = (route.get("plugins") or {}).get("openid-connect") or {}
            ref = oidc.get("client_secret", "")
            if not ref.startswith("$ENV://"):
                raise ValueError("OIDC client secret must remain an environment reference")
        apply(routes, admin)
        print("TRUSTED_HUMAN_AUTHORIZATION_ROUTES_INSTALLED")
    finally:
        admin.close()


if __name__ == "__main__":
    main()
