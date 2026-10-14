#!/usr/bin/env python3
"""Materialize governed HUMAN Onboarding lifecycle RouteBindings."""
import argparse
import json
import re
from pathlib import Path

class MaterializationError(RuntimeError):
    pass

SECRET_REF_PREFIXES=("$ENV://","$secret://")
TRUSTED_HEADERS=[
    "X-OUF-Gateway-Verified","X-OUF-Service-Principal","X-OUF-Principal-ID",
    "X-OUF-Tenant-ID","X-OUF-Actor-Type","X-OUF-Authentication-Context-Ref",
    "X-OUF-Token-Issuer","X-OUF-Token-Audience","X-OUF-Granted-Scopes",
]
ROUTE_IDS=(
    "trusted-human-onboarding-sources-get",
    "trusted-human-onboarding-sources-post",
    "trusted-human-onboarding-lifecycle-get",
    "trusted-human-onboarding-lifecycle-post",
    "trusted-human-onboarding-lifecycle-put",
    "trusted-human-onboarding-approvals-get",
    "trusted-human-onboarding-approvals-post",
    "trusted-human-managed-file-upload",
    "trusted-human-managed-file-actions-post",
    "trusted-human-managed-file-preview-get",
)

def text(obj,key):
    value=obj.get(key)
    if not isinstance(value,str) or not value.strip():
        raise MaterializationError(f"missing or invalid {key}")
    return value.strip()

def strip_untrusted_headers():
    headers=",".join(json.dumps(h) for h in TRUSTED_HEADERS)
    return (
        "return function(conf, ctx) "
        f"local headers={{{headers}}}; "
        "for _,name in ipairs(headers) do ngx.req.clear_header(name) end "
        "end"
    )

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
        "local claims=cjson.decode(ngx.decode_base64(payload) or ''); "
        "if type(claims)~='table' then return ngx.exit(401) end; "
        "if claims['ouf_actor_type']~='HUMAN' then return ngx.exit(403) end; "
        "end"
    )

def materialize_route(route,installation,oidc_secret_ref,streaming_runtime=False):
    labels=route.get("labels") or {}
    policy=route.get("x-ouf-policy")
    backend=route.get("x-ouf-backend-binding")
    capability=route.get("x-ouf-capability")
    if labels.get("exposure")!="public":
        raise MaterializationError("trusted HUMAN route must be public")
    if not isinstance(policy,dict) or text(policy,"identity")!="OIDC":
        raise MaterializationError("trusted HUMAN route requires OIDC")
    if policy.get("allowedActorTypes")!=["HUMAN"]:
        raise MaterializationError("trusted HUMAN route must allow only HUMAN")
    if not isinstance(backend,dict) or not isinstance(capability,dict):
        raise MaterializationError("compiled route metadata required")
    if not oidc_secret_ref.startswith(SECRET_REF_PREFIXES):
        raise MaterializationError("OIDC client secret must be an APISIX secret reference")
    issuer=text(installation,"issuerUrl").rstrip("/")
    audience=text(installation,"gatewayAudience")
    scope=text(policy,"requiredScope")
    service=text(backend,"service")
    port=backend.get("port")
    uri=text(route,"uri")
    backend_path=text(backend,"path")
    methods=route.get("methods")
    if not isinstance(port,int) or port<1 or port>65535 or not re.fullmatch(r"[A-Za-z0-9._-]+",service):
        raise MaterializationError("invalid backend")
    if route.get("id"," ").startswith("trusted-human-managed-file-") and (service!="ouf-onboarding" or port!=8080):
        raise MaterializationError("managed-file remote upstream requires a verified transport profile")
    if not isinstance(methods,list) or len(methods)!=1 or methods[0] not in {"GET","POST","PUT"}:
        raise MaterializationError("unsupported HUMAN lifecycle method")
    wildcard="*" in uri
    if wildcard and (not uri.endswith("/*") or uri.count("*")!=1 or backend_path!=uri):
        raise MaterializationError("wildcard HUMAN route must preserve bounded namespace")
    plugins={
        "request-id":(route.get("plugins") or {}).get("request-id",{}),
        "limit-count":(route.get("plugins") or {}).get("limit-count",{}),
        "client-control":{"max_body_size":int(policy.get("maxRequestBytes",5242880))},
        "serverless-pre-function":{"phase":"rewrite","functions":[strip_untrusted_headers()]},
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
            "set_access_token_header":False,
            "set_id_token_header":False,
            "set_userinfo_header":False,
        },
        "serverless-post-function":{"phase":"access","functions":[human_guard()]},
    }
    if route.get("id")=="trusted-human-managed-file-upload" and streaming_runtime:
        plugins["proxy-control"]={"request_buffering":False}
    if not wildcard:
        plugins["proxy-rewrite"]={"uri":backend_path}
    return {
        "id":text(route,"id"),
        "uri":uri,
        "methods":methods,
        "labels":{
            "ouf-managed":"true",
            "ouf-installation":text(installation,"installationId"),
            "ouf-installation-revision":str(installation.get("revision")),
            "ouf-capability":text(capability,"capabilityId"),
            "ouf-surface":"TRUSTED_HUMAN_ONBOARDING",
        },
        "plugins":plugins,
        "upstream":{
            "type":"roundrobin","scheme":"http",
            "nodes":{f"{service}:{port}":1},
            "retries":0,
            "timeout":{"connect":10,"send":10,"read":10},
        },
    }

def materialize(runtime,oidc_secret_ref,streaming_runtime=False):
    installation=runtime.get("x-ouf-installation")
    if not isinstance(installation,dict):
        raise MaterializationError("resolved installation metadata is required")
    indexed={r.get("id"):r for r in runtime.get("routes",[]) if isinstance(r,dict)}
    missing=[route_id for route_id in ROUTE_IDS if route_id not in indexed]
    if missing:
        raise MaterializationError("route not found: "+",".join(missing))
    routes=[materialize_route(indexed[route_id],installation,oidc_secret_ref,streaming_runtime) for route_id in ROUTE_IDS]
    return {
        "formatVersion":"1.0",
        "installationId":text(installation,"installationId"),
        "installationRevision":installation.get("revision"),
        "installationChecksum":text(installation,"checksum"),
        "routes":routes,
    }

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("--runtime",type=Path,required=True)
    p.add_argument("--oidc-client-secret-ref",required=True)
    p.add_argument("--streaming-runtime",action="store_true",help="Generate proxy-control only for a separately verified APISIX-Runtime")
    p.add_argument("--output",type=Path,required=True)
    a=p.parse_args()
    result=materialize(json.loads(a.runtime.read_text()),a.oidc_client_secret_ref,a.streaming_runtime)
    a.output.parent.mkdir(parents=True,exist_ok=True)
    a.output.write_text(json.dumps(result,indent=2,sort_keys=True)+"\n")

if __name__=="__main__":
    main()
