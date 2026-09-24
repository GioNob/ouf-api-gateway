#!/usr/bin/env python3
"""Materialize the direct trusted-HUMAN Authorization capability catalogue route.

This route is deliberately not MCP-mediated. The Gateway validates the HUMAN
bearer first and forwards that same bearer to Onboarding, whose resource-server
chain revalidates it and establishes TrustedWriteProof for state-changing calls.
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

PATH = "/api/trusted-human/v1/authorization/capabilities"
CAPABILITY = "authorization.policy.admin"
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


def _validate_binding(route):
    if route.get("uri") != PATH:
        raise MaterializationError("unexpected trusted HUMAN Authorization path")
    if route.get("methods") not in (["GET"], ["POST"]):
        raise MaterializationError("trusted HUMAN catalogue supports GET or POST only")
    cap = route.get("x-ouf-capability") or {}
    policy = route.get("x-ouf-policy") or {}
    if cap.get("capabilityId") != CAPABILITY:
        raise MaterializationError("unexpected Authorization admin capability")
    if cap.get("owner") != "authorization" or cap.get("operationType") != "COMMAND":
        raise MaterializationError("Authorization admin capability semantics changed")
    if cap.get("toolEligible") or not cap.get("humanRequired"):
        raise MaterializationError("Authorization admin capability must remain HUMAN-only")
    if policy.get("identity") != "OIDC":
        raise MaterializationError("trusted HUMAN catalogue requires OIDC")
    if policy.get("requiredScope") != CAPABILITY:
        raise MaterializationError("Authorization admin scope changed")
    if policy.get("allowedActorTypes") != ["HUMAN"]:
        raise MaterializationError("trusted HUMAN catalogue must allow HUMAN only")
    if policy.get("maxRequestBytes") != 65536 or policy.get("timeoutSeconds") != 5:
        raise MaterializationError("trusted HUMAN catalogue limits changed")
    if route.get("service_id") != "ouf-onboarding":
        raise MaterializationError("trusted HUMAN catalogue owner changed")
    if (route.get("plugins") or {}).get("proxy-rewrite", {}).get("uri") != PATH:
        raise MaterializationError("trusted HUMAN catalogue backend path changed")


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
        and r.get("uri") == PATH
        and (r.get("labels") or {}).get("exposure") == "public"
    ]
    if len(bindings) != 2:
        raise MaterializationError(f"expected GET and POST trusted HUMAN bindings, found {len(bindings)}")
    if {tuple(r.get("methods") or []) for r in bindings} != {("GET",), ("POST",)}:
        raise MaterializationError("trusted HUMAN catalogue requires exactly GET and POST bindings")

    routes = []
    for route in sorted(bindings, key=lambda r: r["methods"][0]):
        _validate_binding(route)
        method = route["methods"][0]
        plugins = {
            "request-id": copy.deepcopy((route.get("plugins") or {}).get("request-id", {})),
            "limit-count": copy.deepcopy((route.get("plugins") or {}).get("limit-count", {})),
            "proxy-rewrite": {"uri": PATH},
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
                # Onboarding is itself the trusted HUMAN resource server and
                # must see the original bearer to create TrustedWriteProof.
                "set_access_token_header": False,
                "set_id_token_header": False,
                "set_userinfo_header": False,
            },
        }
        if method == "POST":
            plugins["request-validation"] = {
                "max_req_body_size": 65536,
                "body_schema": {
                    "type": "object",
                    "additionalProperties": False,
                    "required": ["ownerRef", "descriptor"],
                    "properties": {
                        "ownerRef": {"type": "string", "minLength": 1},
                        "descriptor": {"type": "object"},
                    },
                },
            }
        routes.append({
            "id": require_text(route, "id"),
            "uri": PATH,
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
                "timeout": {"connect": 5, "send": 5, "read": 5},
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
