#!/usr/bin/env python3
"""Materialize selected internal M2M RouteBindings into governed APISIX routes."""
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
    value=obj.get(key)
    if not isinstance(value,str) or not value.strip():
        raise MaterializationError(f"missing or invalid {key}")
    return value.strip()

def lua_quote(value):
    return json.dumps(value)

def strip_untrusted_headers():
    quoted=",".join(lua_quote(h) for h in TRUSTED_HEADERS)
    return (
        "return function(conf, ctx) "
        f"local headers={{{quoted}}}; "
        "for _,name in ipairs(headers) do ngx.req.clear_header(name) end "
        "end"
    )

def workload_guard(allowed_services, allowed_actors):
    services=",".join(f"[{lua_quote(v)}]=true" for v in allowed_services)
    actors=",".join(f"[{lua_quote(v)}]=true" for v in allowed_actors)
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

def materialize_route(route, installation, oidc_secret_ref):
    labels=route.get("labels") or {}
    policy=route.get("x-ouf-policy")
    backend=route.get("x-ouf-backend-binding")
    capability=route.get("x-ouf-capability")
    if labels.get("exposure")!="internal":
        raise MaterializationError("only internal routes are supported")
    if not isinstance(policy,dict) or require_text(policy,"identity")!="M2M":
        raise MaterializationError("internal materializer requires M2M identity")
    if not isinstance(backend,dict):
        raise MaterializationError("compiled backend binding is required")
    if not isinstance(capability,dict):
        raise MaterializationError("governed capability metadata is required")
    allowed_services=policy.get("allowedServiceIdentities")
    if not isinstance(allowed_services,list) or not allowed_services or not all(isinstance(v,str) and v for v in allowed_services):
        raise MaterializationError("allowed service identities are required")
    if any(v.startswith("installation://") for v in allowed_services):
        raise MaterializationError("installation service identities must be projected before materialization")
    allowed_actors=policy.get("allowedActorTypes")
    if allowed_actors!=["SERVICE"]:
        raise MaterializationError("internal workload route must allow only SERVICE actor")
    scope=require_text(policy,"requiredScope")
    if not oidc_secret_ref.startswith(SECRET_REF_PREFIXES):
        raise MaterializationError("OIDC client secret must be an APISIX secret reference")
    issuer=require_text(installation,"issuerUrl").rstrip("/")
    audience=require_text(installation,"gatewayAudience")
    service=require_text(backend,"service")
    port=backend.get("port")
    backend_path=require_text(backend,"path")
    uri=require_text(route,"uri")
    methods=route.get("methods")
    if not isinstance(port,int) or port<1 or port>65535:
        raise MaterializationError("invalid backend port")
    if not re.fullmatch(r"[A-Za-z0-9._-]+",service):
        raise MaterializationError("invalid backend service")
    if not isinstance(methods,list) or len(methods)!=1 or methods[0] not in {"GET","POST","PUT","DELETE"}:
        raise MaterializationError("exactly one supported method is required")
    wildcard="*" in uri
    if wildcard and (not uri.endswith("/*") or uri.count("*")!=1 or backend_path!=uri):
        raise MaterializationError("wildcard route must preserve exact bounded namespace")

    plugins={
        "request-id":(route.get("plugins") or {}).get("request-id",{}),
        "limit-count":(route.get("plugins") or {}).get("limit-count",{}),
        "serverless-pre-function":{
            "phase":"rewrite",
            "functions":[strip_untrusted_headers()],
        },
        "openid-connect":{
            "client_id":audience,
            "client_secret":oidc_secret_ref,
            "discovery":issuer+"/.well-known/openid-configuration",
            "bearer_only":True,
            "unauth_action":"deny",
            "use_jwks":True,
            "ssl_verify":True,
            "required_scopes":[scope],
            "claim_validator":{"audience":{"required":True,"match_with_client_id":True}},
        },
        "serverless-post-function":{
            "phase":"access",
            "functions":[workload_guard(allowed_services,allowed_actors)],
        },
    }
    if not wildcard:
        plugins["proxy-rewrite"]={"uri":backend_path}

    return {
        "id":require_text(route,"id"),
        "uri":uri,
        "methods":methods,
        "labels":{
            "ouf-managed":"true",
            "ouf-installation":require_text(installation,"installationId"),
            "ouf-installation-revision":str(installation.get("revision")),
            "ouf-capability":require_text(capability,"capabilityId"),
            "ouf-exposure":"internal",
        },
        "plugins":plugins,
        "upstream":{
            "type":"roundrobin",
            "scheme":"http",
            "nodes":{f"{service}:{port}":1},
        },
    }

def materialize(runtime, route_ids, oidc_secret_ref):
    installation=runtime.get("x-ouf-installation")
    if not isinstance(installation,dict):
        raise MaterializationError("resolved installation metadata is required")
    wanted=list(dict.fromkeys(route_ids))
    if not wanted:
        raise MaterializationError("at least one route id is required")
    indexed={r.get("id"):r for r in runtime.get("routes",[]) if isinstance(r,dict) and isinstance(r.get("id"),str)}
    missing=[route_id for route_id in wanted if route_id not in indexed]
    if missing:
        raise MaterializationError("route not found: "+",".join(missing))
    routes=[materialize_route(indexed[route_id],installation,oidc_secret_ref) for route_id in wanted]
    return {
        "formatVersion":"1.0",
        "installationId":require_text(installation,"installationId"),
        "installationRevision":installation.get("revision"),
        "installationChecksum":require_text(installation,"checksum"),
        "routes":routes,
    }

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("--runtime",type=Path,required=True)
    p.add_argument("--route-id",action="append",required=True)
    p.add_argument("--oidc-client-secret-ref",required=True)
    p.add_argument("--output",type=Path,required=True)
    a=p.parse_args()
    runtime=json.loads(a.runtime.read_text())
    result=materialize(runtime,a.route_id,a.oidc_client_secret_ref)
    a.output.parent.mkdir(parents=True,exist_ok=True)
    a.output.write_text(json.dumps(result,indent=2,sort_keys=True)+"\n")

if __name__=="__main__":
    main()
