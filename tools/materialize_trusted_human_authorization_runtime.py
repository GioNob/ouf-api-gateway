#!/usr/bin/env python3
"""Materialize the bounded trusted-HUMAN Authorization namespace.

The Gateway authenticates HUMAN OIDC callers and strips forged OUF trust
headers. It intentionally preserves the original Authorization bearer because
Onboarding is also a resource server and must revalidate that bearer to create
TrustedWriteProof for state-changing operations.
"""
import argparse
import copy
import json
from pathlib import Path

from tools.materialize_apisix_runtime import (
    MaterializationError,
    SECRET_REF_PREFIXES,
    require_https_url,
    require_text,
    trusted_pre_function,
)

NAMESPACE = "/api/trusted-human/v1/authorization/*"
CAPABILITY = "authorization.policy.admin"
METHODS = ("GET", "POST", "PUT", "DELETE")
MAX_BODY = 5 * 1024 * 1024
TRUSTED_HEADERS = [
    "X-OUF-Gateway-Verified",
    "X-OUF-Service-Principal",
    "X-OUF-Principal-ID",
    "X-OUF-Tenant-ID",
    "X-OUF-Actor-Type",
    "X-OUF-Authentication-Context-Ref",
    "X-OUF-Token-Issuer",
    "X-OUF-Token-Audience",
    "X-OUF-Granted-Scopes",
]


def _validate(route):
    if route.get("uri") != NAMESPACE:
        raise MaterializationError("unexpected trusted HUMAN Authorization namespace")
    method = tuple(route.get("methods") or [])
    if method not in {(m,) for m in METHODS}:
        raise MaterializationError("unexpected trusted HUMAN Authorization method")
    cap = route.get("x-ouf-capability") or {}
    policy = route.get("x-ouf-policy") or {}
    if cap.get("capabilityId") != CAPABILITY:
        raise MaterializationError("unexpected Authorization admin capability")
    if cap.get("owner") != "authorization" or cap.get("operationType") != "COMMAND":
        raise MaterializationError("Authorization admin capability semantics changed")
    if cap.get("toolEligible") or not cap.get("humanRequired"):
        raise MaterializationError("Authorization admin capability must remain HUMAN-only")
    if policy.get("identity") != "OIDC":
        raise MaterializationError("trusted HUMAN Authorization requires OIDC")
    if policy.get("requiredScope") != CAPABILITY:
        raise MaterializationError("Authorization admin scope changed")
    if policy.get("allowedActorTypes") != ["HUMAN"]:
        raise MaterializationError("trusted HUMAN Authorization must allow HUMAN only")
    if policy.get("maxRequestBytes") != MAX_BODY or policy.get("timeoutSeconds") != 10:
        raise MaterializationError("trusted HUMAN Authorization limits changed")
    if route.get("service_id") != "ouf-onboarding":
        raise MaterializationError("trusted HUMAN Authorization owner changed")
    if "proxy-rewrite" in (route.get("plugins") or {}):
        raise MaterializationError("wildcard namespace must preserve request path")


def materialize(runtime, oidc_secret_ref):
    installation = runtime.get("x-ouf-installation")
    if not isinstance(installation, dict):
        raise MaterializationError("resolved installation metadata is required")
    issuer = require_https_url(installation, "issuerUrl")
    audience = require_text(installation, "gatewayAudience")
    if not oidc_secret_ref.startswith(SECRET_REF_PREFIXES):
        raise MaterializationError("OIDC client secret must be an APISIX secret reference")

    bindings = [
        r for r in runtime.get("routes", [])
        if isinstance(r, dict)
        and r.get("uri") == NAMESPACE
        and (r.get("labels") or {}).get("exposure") == "public"
    ]
    if len(bindings) != 4:
        raise MaterializationError(f"expected four trusted HUMAN Authorization bindings, found {len(bindings)}")
    if {tuple(r.get("methods") or []) for r in bindings} != {(m,) for m in METHODS}:
        raise MaterializationError("trusted HUMAN Authorization requires GET/POST/PUT/DELETE")

    routes = []
    for route in sorted(bindings, key=lambda r: METHODS.index(r["methods"][0])):
        _validate(route)
        method = route["methods"][0]
        plugins = {
            "request-id": copy.deepcopy((route.get("plugins") or {}).get("request-id", {})),
            "limit-count": copy.deepcopy((route.get("plugins") or {}).get("limit-count", {})),
            "client-control": {"max_body_size": MAX_BODY},
            "serverless-pre-function": {
                "phase": "rewrite",
                "functions": [trusted_pre_function(TRUSTED_HEADERS)],
            },
            "openid-connect": {
                "client_id": audience,
                "client_secret": oidc_secret_ref,
                "discovery": issuer + "/.well-known/openid-configuration",
                "bearer_only": True,
                "unauth_action": "deny",
                "use_jwks": True,
                "ssl_verify": True,
                "required_scopes": [CAPABILITY],
                "claim_validator": {
                    "audience": {"required": True, "match_with_client_id": True}
                },
                "set_access_token_header": False,
                "set_id_token_header": False,
                "set_userinfo_header": False,
            },
        }
        routes.append({
            "id": require_text(route, "id"),
            "uri": NAMESPACE,
            "methods": [method],
            "labels": {
                "ouf-managed": "true",
                "ouf-installation": require_text(installation, "installationId"),
                "ouf-installation-revision": str(installation.get("revision")),
                "ouf-capability": CAPABILITY,
                "ouf-surface": "TRUSTED_HUMAN",
            },
            "plugins": plugins,
            "upstream": {
                "type": "roundrobin",
                "scheme": "http",
                "nodes": {"ouf-onboarding:8080": 1},
                "retries": 0,
                "timeout": {"connect": 10, "send": 10, "read": 10},
            },
        })

    return {
        "formatVersion": "1.0",
        "installationId": require_text(installation, "installationId"),
        "installationRevision": installation.get("revision"),
        "installationChecksum": require_text(installation, "checksum"),
        "routes": routes,
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--runtime", type=Path, required=True)
    parser.add_argument("--oidc-client-secret-ref", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    result = materialize(json.loads(args.runtime.read_text()), args.oidc_client_secret_ref)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")


if __name__ == "__main__":
    main()
