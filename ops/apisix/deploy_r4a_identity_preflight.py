#!/usr/bin/env python3
"""Install only reviewed R4a identity routes with APISIX snapshot and rollback."""

import argparse
import json
import os
from pathlib import Path
import re
import subprocess

from ops.apisix.deploy_status_execute import Admin, apply_routes, inherits_env, route_value


EXPECTED = {
    "ths-identity-preflight-create": ("POST", "/api/udp/v1/governance/identity/preflight"),
    "ths-identity-preflight-read": ("GET", "/api/udp/v1/governance/identity/preflight"),
    "onboarding-identity-preflight-read": ("GET", "/api/udp/v1/governance/internal/identity/preflight"),
}


class IdentityAdmin(Admin):
    def save_snapshot(self, previous):
        super().save_snapshot(previous)
        target = self.args.backup_output
        if target is None or target.exists():
            raise RuntimeError("R4A_DURABLE_BACKUP_PATH_REQUIRED_AND_MUST_BE_NEW")
        with os.fdopen(os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "w") as output:
            json.dump(previous, output, indent=2)
            output.write("\n")
        print("R4A_DURABLE_BACKUP=" + str(target), flush=True)

    def check_public(self):
        for route_id, (method, path) in EXPECTED.items():
            body = {"sourceId": "probe", "configurationHash": "probe", "configuration": {}} if method == "POST" else None
            code, _ = self.curl(path, method, body)
            if code != 401:
                raise RuntimeError("unauthenticated identity route " + route_id + " HTTP " + str(code))


def inspect_environment(container, routes):
    inspected = json.loads(subprocess.run(["docker", "inspect", container], check=True,
                                  capture_output=True, text=True).stdout)[0]
    env = dict(item.split("=", 1) for item in inspected["Config"]["Env"] if "=" in item)
    nginx = subprocess.run(["docker", "exec", container, "cat", "/usr/local/apisix/conf/nginx.conf"],
                           check=True, capture_output=True, text=True).stdout
    for route in routes:
        oidc = route["plugins"]["openid-connect"]
        reference = oidc["client_secret"]
        name = reference[7:] if reference.startswith("$ENV://") else ""
        if not re.fullmatch(r"[A-Z][A-Z0-9_]{0,127}", name) or not env.get(name) or not inherits_env(nginx, name):
            raise RuntimeError("APISIX_OIDC_SECRET_UNAVAILABLE")


def validate(document):
    routes = document.get("routes")
    if not isinstance(routes, list) or len(routes) != 3 or {r.get("id") for r in routes} != set(EXPECTED):
        raise RuntimeError("R4A_ROUTE_SET_INVALID")
    for route in routes:
        method, path = EXPECTED[route["id"]]
        if route.get("methods") != [method] or route.get("uri") != path:
            raise RuntimeError("R4A_ROUTE_PATH_INVALID")
        if route.get("labels", {}).get("ouf-r4a") != "identity-preflight":
            raise RuntimeError("R4A_ROUTE_LABEL_INVALID")
    return routes


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    choice = parser.add_mutually_exclusive_group(required=True)
    choice.add_argument("--materialization", type=Path)
    choice.add_argument("--restore", type=Path)
    parser.add_argument("--admin-key", type=Path, required=True)
    parser.add_argument("--backup-output", type=Path,
                        help="new 0600 snapshot path, required when installing")
    parser.add_argument("--container", default="ouf-apisix")
    parser.add_argument("--curl-image", default="curlimages/curl:8.16.0")
    args = parser.parse_args()
    os.umask(0o077)
    if args.restore:
        previous = json.loads(args.restore.read_text())
        if not isinstance(previous, dict) or set(previous) != set(EXPECTED):
            raise RuntimeError("R4A_BACKUP_INVALID")
        admin = IdentityAdmin(args)
        try:
            for route_id, old in previous.items():
                code, _ = admin("PUT" if old else "DELETE", route_id, old)
                if code not in (200, 201, 204, 404):
                    raise RuntimeError("R4A_RESTORE_FAILED:" + route_id)
                code, actual = admin("GET", route_id)
                if (old is None and code != 404) or (old is not None and (code != 200 or route_value(actual) != old)):
                    raise RuntimeError("R4A_RESTORE_READBACK_FAILED:" + route_id)
            print("R4A_IDENTITY_ROUTES_RESTORED=true")
        finally:
            (admin.work / "admin.header").unlink(missing_ok=True)
        return
    routes = validate(json.loads(args.materialization.read_text()))
    if args.backup_output is None or args.backup_output.exists() or not args.backup_output.parent.is_dir():
        raise RuntimeError("R4A_DURABLE_BACKUP_PATH_REQUIRED_AND_MUST_BE_NEW")
    inspect_environment(args.container, routes)
    admin = IdentityAdmin(args)
    try:
        apply_routes(routes, admin)
        print("R4A_IDENTITY_ROUTES_INSTALLED=3 AUTHENTICATED_SMOKE_PENDING=true")
    finally:
        (admin.work / "admin.header").unlink(missing_ok=True)


if __name__ == "__main__":
    main()
