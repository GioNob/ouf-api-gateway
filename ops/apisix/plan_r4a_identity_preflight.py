#!/usr/bin/env python3
"""Compile the active projection and prepare three R4a routes without APISIX writes."""

import argparse
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile

from tools.compile_config import ROOT, compile_config
from tools.apply_installation_projection import apply_projection
from tools.materialize_r4a_identity_preflight import materialize
from ops.apisix.deploy_r4a_identity_preflight import validate


def upstream_check(host):
    result = subprocess.run([
        "docker", "run", "--rm", "--network", "container:ouf-apisix",
        "curlimages/curl:8.16.0", "--max-time", "5", "-sS", "-o", "/dev/null",
        "-w", "%{remote_ip}", "http://" + host + ":8080/actuator/health",
    ], capture_output=True, text=True, timeout=30)
    if result.returncode or not re.fullmatch(r"[0-9a-fA-F:.]+", result.stdout.strip()):
        raise RuntimeError("R4A_PRIVATE_UDP_UPSTREAM_UNREACHABLE")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--projection", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--upstream-host", default="ouf-udp")
    parser.add_argument("--oidc-client-secret-ref", default="$ENV://OUF_GATEWAY_OIDC_CLIENT_SECRET")
    args = parser.parse_args()
    if not args.output_dir.is_dir() or not re.fullmatch(r"[a-z0-9][a-z0-9-]*", args.upstream_host):
        raise RuntimeError("R4A_OUTPUT_OR_UPSTREAM_INVALID")
    projection = json.loads(args.projection.read_text())
    compiled = compile_config(ROOT / "ouf-config")
    resolved = apply_projection(compiled, projection)
    document = materialize(resolved, args.oidc_client_secret_ref, args.upstream_host)
    routes = validate(document)
    upstream_check(args.upstream_host)
    os.umask(0o077)
    fd, name = tempfile.mkstemp(prefix="r4a-identity-routes-", suffix=".json", dir=args.output_dir)
    with os.fdopen(fd, "w") as output:
        json.dump(document, output, indent=2)
        output.write("\n")
    print("R4A_ROUTE_PLAN=PASS APISIX_WRITES=0")
    print("R4A_INSTALLATION=" + resolved["x-ouf-installation"]["installationId"])
    print("R4A_AUDIENCE=" + resolved["x-ouf-installation"]["gatewayAudience"])
    print("R4A_UPSTREAM=" + args.upstream_host + ":8080 REACHABLE=true")
    print("R4A_ROUTE_IDS=" + ",".join(sorted(r["id"] for r in routes)))
    print("R4A_PLAN_FILE=" + name)


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as error:
        print("R4A_ROUTE_PLAN_BLOCKED=" + type(error).__name__ + ":" + str(error))
        raise SystemExit(1)
