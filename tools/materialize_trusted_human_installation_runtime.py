#!/usr/bin/env python3
"""Materialize the Trusted Human Installation namespace.

Gateway authenticates OIDC and enforces HUMAN actor only. Exact installation
capabilities remain owner-authoritative in Source Onboarding, because different
paths in this namespace require read/write/activate/export respectively.
The original bearer is preserved so Onboarding can revalidate it and establish
TrustedWriteProof for mutation requests.
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

NAMESPACE = "/api/trusted-human/v1/installations/*"
METHODS = ("GET", "POST")
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


def human_guard():
    return (
        "return function(conf, ctx) "
        "local cjson=require('cjson.safe'); "
        "local auth=ngx.var.http_authorization; "
        "if not auth then return ngx.exit(401) end; "
        "local token=auth:match('^[Bb]earer%s+(.+)$'); "
        "if not token then return ngx.exit(401) end; "
        "local payload=token:match('^[^.]+%.([^.]+)%.[^.]+$'); "
        "if not payload then return ngx.exit(401) end; "
        "payload=payload:gsub('-','+'):gsub('_','/'); "
        "local rem=#payload%4; if rem>0 then payload=payload..string.rep('=',4-rem) end; "
        "local decoded=ngx.decode_base64(payload); "
        "local claims=decoded and cjson.decode(decoded) or nil; "
        "if type(claims)~='table' then return ngx.exit(401) end; "
        "if claims['ouf_actor_type']~='HUMAN' then return ngx.exit(403) end; "
        "end"
    )


def materialize(installation, oidc_secret_ref):
    if not isinstance(installation, dict):
        raise MaterializationError("resolved installation metadata is required")
    issuer = require_https_url(installation, "issuerUrl")
    audience = require_text(installation, "gatewayAudience")
    installation_id = require_text(installation, "installationId")
    checksum = require_text(installation, "checksum")
    if not oidc_secret_ref.startswith(SECRET_REF_PREFIXES):
        raise MaterializationError("OIDC client secret must be an APISIX secret reference")

    routes = []
    for method in METHODS:
        routes.append({
            "id": f"trusted-human-installation-{method.lower()}",
            "uri": NAMESPACE,
            "methods": [method],
            "labels": {
                "ouf-managed": "true",
                "ouf-installation": installation_id,
                "ouf-installation-revision": str(installation.get("revision")),
                "ouf-surface": "TRUSTED_HUMAN",
                "ouf-owner": "installation",
            },
            "plugins": {
                "request-id": {
                    "header_name": "X-Correlation-ID",
                    "include_in_response": True,
                    "algorithm": "uuid",
                },
                "limit-count": {
                    "count": 120,
                    "time_window": 60,
                    "rejected_code": 429,
                    "key_type": "var",
                    "key": "remote_addr",
                    "policy": "local",
                },
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
                    "claim_validator": {
                        "audience": {"required": True, "match_with_client_id": True}
                    },
                    "set_access_token_header": False,
                    "set_id_token_header": False,
                    "set_userinfo_header": False,
                },
                "serverless-post-function": {
                    "phase": "access",
                    "functions": [human_guard()],
                },
            },
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
        "installationId": installation_id,
        "installationRevision": installation.get("revision"),
        "installationChecksum": checksum,
        "routes": routes,
    }


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--projection", type=Path, required=True)
    p.add_argument("--oidc-client-secret-ref", required=True)
    p.add_argument("--output", type=Path, required=True)
    a = p.parse_args()
    projection = json.loads(a.projection.read_text())
    gateway = projection.get("gateway") or {}
    installation = {
        "installationId": projection.get("installationId"),
        "revision": projection.get("revision"),
        "checksum": projection.get("checksum"),
        "issuerUrl": gateway.get("issuerUrl"),
        "gatewayAudience": gateway.get("requiredAudience"),
    }
    result = materialize(installation, a.oidc_client_secret_ref)
    a.output.parent.mkdir(parents=True, exist_ok=True)
    a.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")


if __name__ == "__main__":
    main()
