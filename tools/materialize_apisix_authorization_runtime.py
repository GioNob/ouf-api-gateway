#!/usr/bin/env python3
import argparse
import json
import re
from pathlib import Path

class MaterializationError(RuntimeError):
    pass

SECRET_REF_PREFIXES = ("$ENV://", "$secret://")
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

def require_text(obj, key):
    value = obj.get(key)
    if not isinstance(value, str) or not value.strip():
        raise MaterializationError(f"missing or invalid {key}")
    return value.strip()

def lua_quote(value):
    return json.dumps(value)

def strip_untrusted_headers():
    quoted = ",".join(lua_quote(h) for h in TRUSTED_HEADERS)
    return (
        "return function(conf, ctx) "
        f"local headers={{{quoted}}}; "
        "for _,name in ipairs(headers) do ngx.req.clear_header(name) end "
        "end"
    )

def workload_guard(allowed_services, allowed_actors):
    services = ",".join(f"[{lua_quote(v)}]=true" for v in allowed_services)
    actors = ",".join(f"[{lua_quote(v)}]=true" for v in allowed_actors)
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
        f"local allowed_services={{{services}}}; "
        f"local allowed_actors={{{actors}}}; "
        "local actor=claims['ouf_actor_type']; "
        "if type(actor)~='string' or not allowed_actors[actor] then return ngx.exit(403) end; "
        "local service=claims['client_id'] or claims['azp']; "
        "if type(service)~='string' or not allowed_services[service] then return ngx.exit(403) end; "
        "local required={'sub','tenant_id','acr','iss','scope'}; "
        "for _,k in ipairs(required) do if claims[k]==nil or tostring(claims[k])=='' then return ngx.exit(401) end end; "
        "local aud=claims['aud']; if type(aud)=='table' then aud=table.concat(aud,' ') end; "
        "if aud==nil or tostring(aud)=='' then return ngx.exit(401) end; "
        "end"
    )

def materialize_bundle_route(route, installation, oidc_secret_ref):
    if route.get("uri") != "/internal/capabilities/v1/authorization/policy-bundle/active":
        raise MaterializationError("unexpected Authorization bundle route path")
    if route.get("methods") != ["GET"]:
        raise MaterializationError("Authorization bundle route must be GET-only")
    policy = route.get("x-ouf-policy")
    capability = route.get("x-ouf-capability")
    if not isinstance(policy, dict) or not isinstance(capability, dict):
        raise MaterializationError("missing governed Authorization route metadata")
    if capability.get("capabilityId") != "authorization.bundle.read":
        raise MaterializationError("unexpected Authorization capability")
    if require_text(policy, "identity") != "M2M":
        raise MaterializationError("Authorization bundle route requires M2M identity")
    if require_text(policy, "requiredScope") != "authorization.bundle.read":
        raise MaterializationError("Authorization bundle scope changed")
    allowed_services = policy.get("allowedServiceIdentities")
    allowed_actors = policy.get("allowedActorTypes")
    if not isinstance(allowed_services, list) or not allowed_services or not all(isinstance(v, str) and v for v in allowed_services):
        raise MaterializationError("allowed service identities are required")
    if allowed_actors != ["SERVICE"]:
        raise MaterializationError("Authorization bundle route must allow only SERVICE actors")
    if not oidc_secret_ref.startswith(SECRET_REF_PREFIXES):
        raise MaterializationError("OIDC client secret must be an APISIX secret reference")
    issuer = require_text(installation, "issuerUrl").rstrip("/")
    audience = require_text(installation, "gatewayAudience")
    service = require_text(route, "service_id")
    backend = route.get("plugins", {}).get("proxy-rewrite", {}).get("uri")
    if backend != "/api/internal/v1/authorization/policy-bundle/active":
        raise MaterializationError("Authorization bundle backend path changed")
    if not re.fullmatch(r"[A-Za-z0-9._-]+", service):
        raise MaterializationError("invalid Authorization backend service")
    return {
        "id": require_text(route, "id"),
        "uri": route["uri"],
        "methods": ["GET"],
        "labels": {
            "ouf-managed": "true",
            "ouf-installation": require_text(installation, "installationId"),
            "ouf-installation-revision": str(installation.get("revision")),
            "ouf-capability": "authorization.bundle.read",
        },
        "plugins": {
            "request-id": route.get("plugins", {}).get("request-id", {}),
            "limit-count": route.get("plugins", {}).get("limit-count", {}),
            "proxy-rewrite": {"uri": backend},
            "serverless-pre-function": {
                "phase": "rewrite",
                "functions": [strip_untrusted_headers()],
            },
            "openid-connect": {
                "client_id": audience,
                "client_secret": oidc_secret_ref,
                "discovery": issuer + "/.well-known/openid-configuration",
                "bearer_only": True,
                "unauth_action": "deny",
                "use_jwks": True,
                "ssl_verify": True,
                "required_scopes": ["authorization.bundle.read"],
                "claim_validator": {
                    "audience": {"required": True, "match_with_client_id": True}
                },
            },
            "serverless-post-function": {
                "phase": "access",
                "functions": [workload_guard(allowed_services, allowed_actors)],
            },
        },
        "upstream": {
            "type": "roundrobin",
            "scheme": "http",
            "nodes": {f"{service}:8080": 1},
        },
    }

def materialize(runtime, oidc_secret_ref):
    installation = runtime.get("x-ouf-installation")
    if not isinstance(installation, dict):
        raise MaterializationError("resolved installation metadata is required")
    candidates = [
        r for r in runtime.get("routes", [])
        if isinstance(r, dict)
        and (r.get("x-ouf-capability") or {}).get("capabilityId") == "authorization.bundle.read"
        and (r.get("labels") or {}).get("exposure") == "internal"
    ]
    if len(candidates) != 1:
        raise MaterializationError(f"expected exactly one Authorization bundle route, found {len(candidates)}")
    route = materialize_bundle_route(candidates[0], installation, oidc_secret_ref)
    return {
        "formatVersion": "1.0",
        "installationId": require_text(installation, "installationId"),
        "installationRevision": installation.get("revision"),
        "installationChecksum": require_text(installation, "checksum"),
        "routes": [route],
    }

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--runtime", type=Path, required=True)
    parser.add_argument("--oidc-client-secret-ref", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    runtime = json.loads(args.runtime.read_text())
    result = materialize(runtime, args.oidc_client_secret_ref)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")

if __name__ == "__main__":
    main()
