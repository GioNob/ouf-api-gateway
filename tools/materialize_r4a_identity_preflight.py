"""Materializza i preflight R4a HUMAN e il preflight M2M per il bundle governato."""
import json
import re


SPECS = {
    "ths-identity-preflight-create": ("POST", "/api/udp/v1/governance/identity/preflight", "urban.identity.preflight", "HUMAN", "OIDC", 2097152, 60),
    "ths-identity-preflight-read": ("GET", "/api/udp/v1/governance/identity/preflight", "urban.identity.preflight", "HUMAN", "OIDC", 65536, 10),
}


def require(value, name):
    if not isinstance(value, str) or not value:
        raise ValueError("R4A_BINDING_MISSING:" + name)
    return value


def strip_headers():
    return "return function() for k,_ in pairs(ngx.req.get_headers(0)) do if k:lower():sub(1,6)=='x-ouf-' then ngx.req.clear_header(k) end end end"


def actor_guard(actor, *, service_label=None):
    service_check = ""
    signature = "return function() "
    if service_label:
        signature = "return function(conf, ctx) "
        service_check = (
            f"local service=ctx.matched_route.value.labels[{json.dumps(service_label)}]; "
            "if type(service)~='string' or service=='' or "
            "(claims['client_id']~=service and claims['azp']~=service) then return ngx.exit(403) end; "
        )
    return (
        signature + "local cjson=require('cjson.safe'); "
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
        f"{service_check}end"
    )


def materialize(runtime, oidc_secret_ref, upstream_host, *, specs=SPECS, service_identity=None):
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
    for route_id, (method, path, capability, actor, identity, size, timeout) in specs.items():
        matches = [r for r in runtime.get("routes", []) if r.get("id") == route_id]
        if len(matches) != 1:
            raise ValueError("R4A_ROUTE_BINDING_MISSING:" + route_id)
        binding = matches[0]
        policy = binding.get("x-ouf-policy", {})
        cap = binding.get("x-ouf-capability", {})
        if (binding.get("uri") != path or binding.get("methods") != [method]
            or binding.get("service_id") != "ouf-udp-object-resolution"
            or binding.get("x-ouf-backend-binding") != {"service": upstream_host, "port": 8080, "path": path}
            or "vars" in binding or binding["labels"].get("exposure") != ("internal" if identity == "M2M" else "public")
            or binding.get("plugins", {}).get("proxy-rewrite", {}).get("uri") != path
            or cap.get("capabilityId") != capability or cap.get("owner") != "udp"
            or policy.get("requiredScope") != capability or policy.get("identity") != identity
            or policy.get("allowedActorTypes") != [actor]
            or policy.get("maxRequestBytes") != size or policy.get("timeoutSeconds") != timeout):
            raise ValueError("R4A_ROUTE_BINDING_CHANGED:" + route_id)
        service_label = None
        if identity == "M2M":
            if not service_identity or policy.get("allowedServiceIdentities") != [service_identity]:
                raise ValueError("R4A_SERVICE_BINDING_CHANGED")
            service_label = "ouf-source-onboarding-workload"
        elif policy.get("allowedServiceIdentities"):
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
            "serverless-post-function": {"phase": "access", "functions": [actor_guard(actor, service_label=service_label)]},
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
                       "ouf-capability": capability, "ouf-r4a": "identity-preflight",
                       **({service_label: service_identity} if service_label else {})},
            "plugins": plugins,
            "upstream": {"type": "roundrobin", "scheme": "http", "nodes": {upstream_host + ":8080": 1},
                         "retries": 0, "timeout": {"connect": 3, "send": 3, "read": timeout}},
        })
    return {"formatVersion": "1.0", "routes": routes, "upstreamHost": upstream_host}
