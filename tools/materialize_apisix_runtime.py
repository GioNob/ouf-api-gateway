#!/usr/bin/env python3
import argparse
import json
import re
from pathlib import Path

class MaterializationError(RuntimeError):
    pass

SECRET_REF_PREFIXES = ("$ENV://", "$secret://")


def require_text(obj, key):
    value = obj.get(key)
    if not isinstance(value, str) or not value.strip():
        raise MaterializationError(f"missing or invalid {key}")
    return value.strip()


def lua_quote(value):
    return json.dumps(value)


def trusted_pre_function(headers):
    quoted = ",".join(lua_quote(h) for h in headers)
    return (
        "return function(conf, ctx) "
        f"local headers={{{quoted}}}; "
        "for _,name in ipairs(headers) do ngx.req.clear_header(name) end "
        "end"
    )


def trusted_post_function(allowed_actors):
    allowed = ",".join(f"[{lua_quote(a)}]=true" for a in allowed_actors)
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
        f"local allowed={{{allowed}}}; "
        "local actor=claims['ouf_actor_type']; "
        "if type(actor)~='string' or not allowed[actor] then return ngx.exit(403) end; "
        "local required={'sub','tenant_id','acr','iss','scope'}; "
        "for _,k in ipairs(required) do if claims[k]==nil or tostring(claims[k])=='' then return ngx.exit(401) end end; "
        "local aud=claims['aud']; if type(aud)=='table' then aud=table.concat(aud,' ') end; "
        "if aud==nil or tostring(aud)=='' then return ngx.exit(401) end; "
        "local sp=claims['azp'] or claims['client_id'] or ''; "
        "ngx.req.set_header('X-OUF-Gateway-Verified','true'); "
        "ngx.req.set_header('X-OUF-Service-Principal',tostring(sp)); "
        "ngx.req.set_header('X-OUF-Principal-ID',tostring(claims['sub'])); "
        "ngx.req.set_header('X-OUF-Tenant-ID',tostring(claims['tenant_id'])); "
        "ngx.req.set_header('X-OUF-Actor-Type',tostring(actor)); "
        "ngx.req.set_header('X-OUF-Authentication-Context-Ref',tostring(claims['acr'])); "
        "ngx.req.set_header('X-OUF-Token-Issuer',tostring(claims['iss'])); "
        "ngx.req.set_header('X-OUF-Token-Audience',tostring(aud)); "
        "ngx.req.set_header('X-OUF-Granted-Scopes',tostring(claims['scope'])); "
        "ngx.req.clear_header('Authorization'); "
        "end"
    )


def materialize_mcp_route(route, installation, oidc_secret_ref):
    if route.get("uri") != "/mcp":
        raise MaterializationError("MCP endpoint materializer only accepts /mcp")
    if route.get("methods") != ["POST"]:
        raise MaterializationError("/mcp must be POST-only")

    policy = route.get("x-ouf-policy")
    trusted = route.get("x-ouf-trusted-identity")
    backend = route.get("x-ouf-backend-binding")
    if not isinstance(policy, dict) or not isinstance(trusted, dict) or not isinstance(backend, dict):
        raise MaterializationError("missing governed MCP route metadata")

    identity = require_text(policy, "identity")
    if identity != "OIDC":
        raise MaterializationError("/mcp requires OIDC")
    audience = require_text(policy, "requiredAudience")
    required_scope = require_text(policy, "requiredScope")
    allowed_actors = policy.get("allowedActorTypes")
    if not isinstance(allowed_actors, list) or not allowed_actors or not all(
        isinstance(v, str) and v for v in allowed_actors
    ):
        raise MaterializationError("missing MCP allowedActorTypes")

    issuer = require_text(installation, "issuerUrl").rstrip("/")
    service = require_text(backend, "service")
    port = backend.get("port")
    path = require_text(backend, "path")
    if path != "/mcp":
        raise MaterializationError("MCP backend path must remain /mcp")
    if not isinstance(port, int) or port < 1 or port > 65535:
        raise MaterializationError("invalid MCP backend port")
    if not re.fullmatch(r"[A-Za-z0-9._-]+", service):
        raise MaterializationError("invalid MCP backend service")

    stripped = trusted.get("stripClientHeaders")
    if not isinstance(stripped, list) or not stripped:
        raise MaterializationError("trusted header strip list is required")
    expected_injected = trusted.get("injectAfterVerification")
    if expected_injected != {"X-OUF-Gateway-Verified": "true"}:
        raise MaterializationError("Gateway verified marker contract changed")

    if not oidc_secret_ref.startswith(SECRET_REF_PREFIXES):
        raise MaterializationError("OIDC client secret must be an APISIX secret reference")

    plugins = {
        "request-id": route.get("plugins", {}).get("request-id", {}),
        "limit-count": route.get("plugins", {}).get("limit-count", {}),
        "request-validation": {
            "max_req_body_size": int(policy.get("maxRequestBytes", 1048576))
        },
        "proxy-rewrite": {"uri": "/mcp"},
        "serverless-pre-function": {
            "phase": "rewrite",
            "functions": [trusted_pre_function(sorted(set(stripped)))],
        },
        "openid-connect": {
            "client_id": audience,
            "client_secret": oidc_secret_ref,
            "discovery": issuer + "/.well-known/openid-configuration",
            "bearer_only": True,
            "unauth_action": "deny",
            "use_jwks": True,
            "ssl_verify": True,
            "required_scopes": [required_scope],
            "claim_validator": {
                "audience": {
                    "required": True,
                    "match_with_client_id": True,
                }
            },
        },
        "serverless-post-function": {
            "phase": "access",
            "functions": [trusted_post_function(allowed_actors)],
        },
    }

    return {
        "id": require_text(route, "id"),
        "uri": "/mcp",
        "methods": ["POST"],
        "labels": {
            "ouf-managed": "true",
            "ouf-installation": require_text(installation, "installationId"),
            "ouf-installation-revision": str(installation.get("revision")),
            "ouf-protocol": "MCP",
        },
        "plugins": plugins,
        "upstream": {
            "type": "roundrobin",
            "scheme": "http",
            "nodes": {f"{service}:{port}": 1},
        },
    }


def materialize(runtime, oidc_secret_ref):
    installation = runtime.get("x-ouf-installation")
    if not isinstance(installation, dict):
        raise MaterializationError("resolved installation metadata is required")

    candidates = [
        r for r in runtime.get("routes", [])
        if isinstance(r, dict)
        and (r.get("x-ouf-protocol") or {}).get("name") == "MCP"
        and (r.get("labels") or {}).get("exposure") == "public"
    ]
    if len(candidates) != 1:
        raise MaterializationError(f"expected exactly one public MCP endpoint, found {len(candidates)}")

    route = materialize_mcp_route(candidates[0], installation, oidc_secret_ref)
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
