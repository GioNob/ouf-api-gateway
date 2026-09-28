#!/usr/bin/env python3
"""Materialize the three R4a identity preflight routes for APISIX 3.18.

Input is the resolved Gateway runtime, not an unbound product catalogue.
The upstream host is an explicit installation binding on the private network.
"""

import argparse
import json
from pathlib import Path
import re


SPECS = {
    "ths-identity-preflight-create": ("POST", "/api/udp/v1/governance/identity/preflight", "urban.identity.preflight", "HUMAN", "OIDC", 2097152, 60),
    "ths-identity-preflight-read": ("GET", "/api/udp/v1/governance/identity/preflight", "urban.identity.preflight", "HUMAN", "OIDC", 65536, 10),
    "onboarding-identity-preflight-read": ("GET", "/api/udp/v1/governance/internal/identity/preflight", "ouf.udp.identity.attestation.read", "SERVICE", "M2M", 65536, 10),
}


def require(value, name):
    if not isinstance(value, str) or not value:
        raise ValueError("R4A_BINDING_MISSING:" + name)
    return value


def strip_headers():
    return "return function() for k,_ in pairs(ngx.req.get_headers(0)) do if k:lower():sub(1,6)=='x-ouf-' then ngx.req.clear_header(k) end end end"


def actor_guard(actor, service=None):
    identity = "if claims['client_id']~='ouf-source-onboarding' and claims['azp']~='ouf-source-onboarding' then return ngx.exit(403) end; " if service else ""
    return (
        "return function() local cjson=require('cjson.safe'); "
        "local bearer=ngx.var.http_authorization; "
        "if not bearer then return ngx.exit(401) end; "
        "local token=bearer:match('^[Bb]earer%s+(.+)$'); "
        "if not token then return ngx.exit(401) end; "
        "local payload=token:match('^[^.]+%.([^.]+)%.[^.]+$'); "
        "if not payload then return ngx.exit(401) end; "
        "payload=payload:gsub('-','+'):gsub('_','/'); "
        "local rem=#payload%4; if rem>0 then payload=payload..string.rep('=',4-rem) end; "
        "local decoded=ngx.decode_base64(payload); "
        "local claims=decoded and cjson.decode(decoded) or nil; "
        "if type(claims)~='table' then return ngx.exit(401) end; "
        f"if claims['ouf_actor_type']~={json.dumps(actor)} then return ngx.exit(403) end; "
        + identity + "end"
    )


def materialize(runtime, oidc_secret_ref, upstream_host):
    installation = runtime.get("x-ouf-installation")
    if not isinstance(installation, dict):
        raise ValueError("R4A_RESOLVED_INSTALLATION_REQUIRED")
    issuer = require(installation.get("issuerUrl"), "issuerUrl").rstrip("/")
    audience = require(installation.get("gatewayAudience"), "gatewayAudience")
    if not issuer.startswith("https://") or not oidc_secret_ref.startswith("$ENV://"):
        raise ValueError("R4A_OIDC_BINDING_INVALID")
    if not re.fullmatch(r"[a-z0-9][a-z0-9-]*", upstream_host):
        raise ValueError("R4A_UPSTREAM_HOST_INVALID")
    routes = []
    for route_id, (method, path, capability, actor, identity, size, timeout) in SPECS.items():
        matches = [r for r in runtime.get("routes", []) if r.get("id") == route_id]
        if len(matches) != 1:
            raise ValueError("R4A_ROUTE_BINDING_MISSING:" + route_id)
        binding = matches[0]
        p, c = binding.get("x-ouf-policy", {}), binding.get("x-ouf-capability", {})
        if (binding.get("uri") != path or binding.get("methods") != [method]
            or binding.get("service_id") != "ouf-udp-object-resolution"
            or binding.get("plugins", {}).get("proxy-rewrite", {}).get("uri") != path
            or c.get("capabilityId") != capability or c.get("owner") != "udp"
            or p.get("requiredScope") != capability or p.get("identity") != identity
            or p.get("allowedActorTypes") != [actor]
            or p.get("maxRequestBytes") != size or p.get("timeoutSeconds") != timeout):
            raise ValueError("R4A_ROUTE_BINDING_CHANGED:" + route_id)
        if identity == "M2M" and p.get("allowedServiceIdentities") != ["ouf-source-onboarding"]:
            raise ValueError("R4A_SERVICE_BINDING_CHANGED")
        if identity == "OIDC" and p.get("allowedServiceIdentities"):
            raise ValueError("R4A_HUMAN_BINDING_CHANGED")
        plugins = {
            "request-id": {"header_name": "X-Correlation-ID", "include_in_response": True, "algorithm": "uuid"},
            "limit-count": {"count": 60, "time_window": 60, "rejected_code": 429},
            "proxy-rewrite": {"uri": path},
            "openid-connect": {
                "client_id": audience, "client_secret": oidc_secret_ref,
                "discovery": issuer + "/.well-known/openid-configuration",
                "bearer_only": True, "unauth_action": "deny", "use_jwks": True,
                "ssl_verify": True, "required_scopes": [capability],
                "claim_validator": {"audience": {"required": True, "match_with_client_id": True}},
                "set_access_token_header": True, "set_id_token_header": False,
                "set_userinfo_header": False,
            },
            "serverless-pre-function": {"phase": "rewrite", "functions": [strip_headers()]},
            "serverless-post-function": {"phase": "access", "functions": [actor_guard(actor, identity == "M2M")]},
        }
        if method == "POST":
            plugins["request-validation"] = {
                "max_req_body_size": size,
                "body_schema": {"type": "object", "additionalProperties": False,
                                "required": ["sourceId", "configurationHash", "configuration"],
                                "properties": {"sourceId": {"type": "string"},
                                               "configurationHash": {"type": "string"},
                                               "configuration": {"type": "object"}}},
            }
        else:
            plugins["client-control"] = {"max_body_size": size}
        routes.append({
            "id": route_id, "uri": path, "methods": [method],
            "labels": {"ouf-managed": "true", "ouf-installation": require(installation.get("installationId"), "installationId"),
                       "ouf-capability": capability, "ouf-r4a": "identity-preflight"},
            "plugins": plugins,
            "upstream": {"type": "roundrobin", "scheme": "http", "nodes": {upstream_host + ":8080": 1},
                         "retries": 0, "timeout": {"connect": 3, "send": 3, "read": timeout}},
        })
    return {"formatVersion": "1.0", "routes": routes, "upstreamHost": upstream_host}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--runtime", type=Path, required=True)
    parser.add_argument("--oidc-client-secret-ref", required=True)
    parser.add_argument("--upstream-host", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    result = materialize(json.loads(args.runtime.read_text()), args.oidc_client_secret_ref, args.upstream_host)
    args.output.write_text(json.dumps(result, indent=2) + "\n")


if __name__ == "__main__":
    main()
