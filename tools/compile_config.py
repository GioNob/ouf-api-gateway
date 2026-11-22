#!/usr/bin/env python3
import argparse, hashlib, json, re, sys
from pathlib import Path

import yaml
from jsonschema import Draft202012Validator

# Keep the documented direct-script entry point.
if __package__ in (None, ''):
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from tools.apisix_request_schema import dispatch_validation
from tools.r2b_limits import ROUTE_CLASSES, limit_count
from tools.mcp_dispatch_contract import (
    EXECUTE_PATH, THS_LINK_PATH_PREFIX, THS_LINK_ROUTE_KEYS, THS_LINKS, capability_contracts,
    envelope_refs, manifest_execute_uri, result_ceiling, ths_link_schema_matches,
)

ROOT = Path(__file__).resolve().parents[1]
SCHEMAS = {"Capability": "capability-manifest-v1.json", "SourceRuntimeProfile": "source-runtime-profile-v1.json", "ExtractionRuntimeProfile": "extraction-runtime-profile-v1.json", "RouteBinding": "route-binding-v1.json", "McpEndpointBinding": "mcp-endpoint-binding-v1.json", "McpMediationBinding": "mcp-mediation-binding-v1.json"}

class ConfigError(RuntimeError): pass

def canonical(value): return json.dumps(value, sort_keys=True, separators=(",", ":"))
def ref(doc): return f"{doc['metadata']['id']}@{doc['metadata']['version']}"

def load_documents(config_root):
    documents=[]
    for path in sorted(config_root.rglob("*.yaml")):
        doc=yaml.safe_load(path.read_text())
        validate_document(path, doc)
        documents.append((path,doc))
    return documents


def validate_document(path, doc):
    kind=doc.get("kind") if isinstance(doc,dict) else None
    if kind not in SCHEMAS: raise ConfigError(f"{path}: unsupported kind {kind!r}")
    schema=json.loads((ROOT/"schemas"/SCHEMAS[kind]).read_text())
    errors=sorted(Draft202012Validator(schema).iter_errors(doc),key=lambda e:list(e.path))
    if errors: raise ConfigError(f"{path}: {errors[0].message}")


def ths_link_documents(config_root, contracts):
    for route_id, key in THS_LINK_ROUTE_KEYS.items():
        path = config_root / 'routes/northbound' / f'{route_id}.json'
        if not path.is_file():
            continue
        spec = json.loads(path.read_bytes())
        cap = spec.pop('capabilityId')
        # D-085 activation requires the exact capability ID selected from the MCP snapshot.
        if cap is None:
            continue
        contract = contracts.get(cap)
        if (not contract or contract['owner'] != 'onboarding'
                or contract.get('publicationState') != 'ACTIVE'
                or not ths_link_schema_matches(contract['inputSchema'], THS_LINKS[key])
                or spec['backendBinding']['path'] != THS_LINK_PATH_PREFIX + key):
            raise ConfigError(f'{path}: MCP THS link capability missing or inconsistent')
        try:
            uri = manifest_execute_uri(contract['gatewayBindingRef'])
        except ValueError as exc:
            raise ConfigError(f'{path}: {exc}') from exc
        version = {'version': '1.0.0', 'status': 'ACTIVE'}
        capability = {
            'apiVersion': 'ouf.trieste.it/v1', 'kind': 'Capability',
            'metadata': {'id': cap, **version},
            'spec': {'owner': contract['owner'], 'operationType': contract['operationClass'],
                     'scope': contract['requiredAuthorizationCapability'],
                     'classification': ['SECURITY_SENSITIVE'], 'mcp': {'toolEligible': contract['toolEligible']}},
        }
        binding = {
            'apiVersion': 'ouf.trieste.it/v1', 'kind': 'RouteBinding',
            'metadata': {'id': route_id, **version},
            'spec': {**spec, 'direction': 'northbound', 'exposure': 'internal',
                     'capabilityRef': cap + '@' + version['version'],
                     'match': {'method': 'POST', 'path': uri}},
        }
        for doc in (capability, binding):
            validate_document(path, doc)
            yield path, doc


def compile_config(config_root):
    contracts = capability_contracts()
    docs = load_documents(config_root) + list(ths_link_documents(config_root, contracts))
    indexed={}
    for path,doc in docs:
        key=(doc["kind"],ref(doc))
        if key in indexed: raise ConfigError(f"duplicate {key[0]} {key[1]}")
        indexed[key]=(path,doc)
    for path,profile in docs:
        if profile["kind"]=="ExtractionRuntimeProfile" and not indexed.get(("SourceRuntimeProfile",profile["spec"]["sourceRef"])):
            raise ConfigError(f"{path}: unresolved sourceRef {profile['spec']['sourceRef']}")
    routes=[]
    matches=set()
    selected_matches=set()
    for path,route in docs:
        if route["kind"]!="RouteBinding": continue
        spec=route["spec"]
        capability=indexed.get(("Capability",spec["capabilityRef"]))
        source=indexed.get(("SourceRuntimeProfile",spec["sourceRef"]))
        if not capability: raise ConfigError(f"{path}: unresolved capabilityRef {spec['capabilityRef']}")
        if not source: raise ConfigError(f"{path}: unresolved sourceRef {spec['sourceRef']}")
        extraction_ref=spec.get("extractionProfileRef")
        if extraction_ref and not indexed.get(("ExtractionRuntimeProfile",extraction_ref)):
            raise ConfigError(f"{path}: unresolved extractionProfileRef {extraction_ref}")
        allowed=spec["policy"].get("allowedServiceIdentities",[])
        if spec["exposure"]=="internal" and not allowed: raise ConfigError(f"{path}: internal route requires explicit service identities")
        if spec["exposure"]=="public" and spec["policy"]["identity"] not in ("OIDC","M2M"): raise ConfigError(f"{path}: public route requires token identity")
        endpoint_ref=source[1]["spec"]["endpointRef"]
        if not endpoint_ref.startswith(("service://","object://","registry://")):
            raise ConfigError(f"{path}: endpointRef must use a governed logical scheme")
        uri_regex=spec["match"].get("uriRegex")
        match=(spec["match"]["method"],spec["match"]["path"])
        if (match in matches or (uri_regex is None and any(item[:2]==match for item in selected_matches))
                or (uri_regex is not None and (match[0],match[1],uri_regex) in selected_matches)):
            raise ConfigError(f"{path}: duplicate route match {match[0]} {match[1]}")
        if uri_regex is None: matches.add(match)
        else: selected_matches.add((match[0],match[1],uri_regex))
        wildcard = "*" in spec["match"]["path"]
        if wildcard and (not spec["match"]["path"].endswith("/*") or spec["match"]["path"].count("*") != 1 or spec["backendBinding"]["path"] != spec["match"]["path"]):
            raise ConfigError(f"{path}: wildcard route must preserve its exact bounded namespace")
        if uri_regex and wildcard:
            prefix=spec["match"]["path"][:-1]
            if (not uri_regex.startswith("^"+prefix)
                    or not uri_regex.endswith("$") or len(uri_regex)>256):
                raise ConfigError(f"{path}: URI regex must be anchored within the wildcard namespace")
        elif uri_regex:
            # Outside a character class a hyphen is literal in PCRE.
            literal = re.escape(spec["match"]["path"]).replace(r"\-", "-")
            if uri_regex != "^" + literal + "$":
                raise ConfigError(f"{path}: URI regex must match the exact path")
        plugins = {"request-id": {"header_name":"X-Correlation-ID","include_in_response":True,"algorithm":"uuid"}, "limit-count": {"count":100,"time_window":60,"rejected_code":429}}
        if route["metadata"]["id"] in ROUTE_CLASSES:
            plugins["limit-count"] = limit_count(route["metadata"]["id"])
        if not wildcard:
            plugins["proxy-rewrite"] = {"uri": spec["backendBinding"]["path"]}
        capability_id = capability[1]["metadata"]["id"]
        contract = contracts.get(capability_id)
        if (contract and match[0] == 'POST' and match[1].startswith(EXECUTE_PATH + '/')
                and match[1] != EXECUTE_PATH + '/managed.file/upload'):
            schema = json.loads((ROOT / 'schemas/mcp-gateway-dispatch-v1.json').read_bytes())
            fields = schema['properties']
            fields['Arguments'] = envelope_refs(contract['inputSchema'])
            for field, value in {
                'CapabilityID': capability_id,
                'GatewayBindingRef': contract['gatewayBindingRef'],
                'Owner': capability[1]['spec']['owner'],
                'OperationClass': capability[1]['spec']['operationType'],
            }.items():
                fields[field] = {'const': value}
            result = fields['MaxResultBytes']
            result['maximum'] = result_ceiling(capability_id, result['maximum'])
            plugins['request-validation'] = dispatch_validation(schema, spec['policy']['maxRequestBytes'])
        selector={"vars": [["uri", "~~", uri_regex]]} if uri_regex else {}
        routes.append({
          "id": route["metadata"]["id"], "uri": spec["match"]["path"], "methods": [spec["match"]["method"]],
          **selector,
          "upstream_id": spec["sourceRef"], "service_id": spec["backendBinding"]["service"],
          "labels": {"capability": spec["capabilityRef"], "source": spec["sourceRef"], "exposure": spec["exposure"]},
          "x-ouf-backend-binding": {
            "service": spec["backendBinding"]["service"],
            "port": spec["backendBinding"]["port"],
            "path": spec["backendBinding"]["path"],
          },
          "plugins": plugins,
          "x-ouf-policy": {"identity": spec["policy"]["identity"], "allowedServiceIdentities": allowed, "allowedActorTypes": spec["policy"].get("allowedActorTypes",[]), "maxRequestBytes":spec["policy"]["maxRequestBytes"], "timeoutSeconds":spec["policy"]["timeoutSeconds"], "requiredScope": capability[1]["spec"]["scope"]},
          "x-ouf-capability": {"capabilityId": capability[1]["metadata"]["id"], "version": capability[1]["metadata"]["version"], "owner": capability[1]["spec"]["owner"], "operationType": capability[1]["spec"]["operationType"], "toolEligible": capability[1]["spec"]["mcp"]["toolEligible"], "humanRequired": capability[1]["spec"]["mcp"].get("humanRequired",False)},
          "x-ouf-query-contract": spec["match"].get("query",{}),
          "x-ouf-recovery-binding": {"owner": capability[1]["spec"]["owner"], "service": spec["backendBinding"]["service"], "pathTemplate": source[1]["spec"].get("ownerOutcomePath")} if source[1]["spec"].get("ownerOutcomePath") else None
        })
    for path,binding in docs:
        if binding["kind"]!="McpEndpointBinding": continue
        spec=binding["spec"]
        source=indexed.get(("SourceRuntimeProfile",spec["sourceRef"]))
        if not source: raise ConfigError(f"{path}: unresolved sourceRef {spec['sourceRef']}")
        endpoint_ref=source[1]["spec"]["endpointRef"]
        if not endpoint_ref.startswith("service://"):
            raise ConfigError(f"{path}: MCP endpoint source must use service://")
        match=(spec["match"]["method"],spec["match"]["path"])
        if match in matches or any(item[:2]==match for item in selected_matches): raise ConfigError(f"{path}: duplicate route match {match[0]} {match[1]}")
        matches.add(match)
        stripped=spec["trustedIdentity"]["stripClientHeaders"]
        projected=spec["trustedIdentity"]["claimProjection"]
        required_trusted={
          "X-OUF-Gateway-Verified","X-OUF-Service-Principal","X-OUF-Principal-ID",
          "X-OUF-Tenant-ID","X-OUF-Actor-Type","X-OUF-Authentication-Context-Ref",
          "X-OUF-Token-Issuer","X-OUF-Token-Audience","X-OUF-Granted-Scopes"
        }
        if not required_trusted.issubset(set(stripped)):
            raise ConfigError(f"{path}: all trusted identity headers must be stripped from client input")
        if set(projected) != required_trusted - {"X-OUF-Gateway-Verified"}:
            raise ConfigError(f"{path}: trusted identity claim projection is incomplete")
        plugins={
          "request-id":{"header_name":"X-Correlation-ID","include_in_response":True,"algorithm":"uuid"},
          "limit-count":{"count":60,"time_window":60,"rejected_code":429},
          "proxy-rewrite":{"uri":spec["backendBinding"]["path"]}
        }
        routes.append({
          "id":binding["metadata"]["id"],"uri":spec["match"]["path"],"methods":[spec["match"]["method"]],
          "upstream_id":spec["sourceRef"],"service_id":spec["backendBinding"]["service"],
          "labels":{"protocol":"MCP","source":spec["sourceRef"],"exposure":spec["exposure"]},
          "x-ouf-backend-binding":{
            "service":spec["backendBinding"]["service"],
            "port":spec["backendBinding"]["port"],
            "path":spec["backendBinding"]["path"]
          },
          "plugins":plugins,
          "x-ouf-protocol":{"name":"MCP","transport":"STREAMABLE_HTTP","stateless":True,"protocolVersion":"2026-07-28"},
          "x-ouf-policy":{
            "identity":spec["policy"]["identity"],
            "requiredAudience":spec["policy"]["requiredAudience"],
            "requiredScope":spec["policy"]["requiredScope"],
            "allowedActorTypes":spec["policy"]["allowedActorTypes"],
            "maxRequestBytes":spec["policy"]["maxRequestBytes"],
            "timeoutSeconds":spec["policy"]["timeoutSeconds"]
          },
          "x-ouf-trusted-identity":{
            "stripClientHeaders":sorted(stripped),
            "claimProjection":projected,
            "injectAfterVerification":{"X-OUF-Gateway-Verified":"true"}
          },
          "x-ouf-capability":None,
          "x-ouf-query-contract":{},
          "x-ouf-recovery-binding":None
        })
    for path,binding in docs:
        if binding["kind"]!="McpMediationBinding": continue
        spec=binding["spec"]
        match=(spec["match"]["method"],spec["match"]["path"])
        if match in matches or any(item[:2]==match for item in selected_matches): raise ConfigError(f"{path}: duplicate route match {match[0]} {match[1]}")
        matches.add(match)
        policy=spec["policy"]
        routes.append({
          "id":binding["metadata"]["id"],
          "uri":spec["match"]["path"],
          "methods":[spec["match"]["method"]],
          "upstream_id":None,
          "service_id":None,
          "labels":{"protocol":"MCP","mediation":spec["mode"],"exposure":"internal"},
          "plugins":{
            "request-id":{"header_name":"X-Correlation-ID","include_in_response":True,"algorithm":"uuid"},
            "limit-count":{"count":120,"time_window":60,"rejected_code":429}
          },
          "x-ouf-mediation":{
            "mode":spec["mode"],
            "serviceIdentityRef":policy["serviceIdentityRef"]
          },
          "x-ouf-policy":{
            "identity":policy["identity"],
            "requiredScope":policy.get("requiredScope"),
            "maxRequestBytes":policy["maxRequestBytes"],
            "timeoutSeconds":policy["timeoutSeconds"]
          },
          "x-ouf-capability":None,
          "x-ouf-query-contract":{},
          "x-ouf-recovery-binding":None
        })
    output={"formatVersion":"1.0","apisixVersion":"3.18.x","routes":sorted(routes,key=lambda r:r["id"])}
    output["configurationSha256"]=hashlib.sha256(canonical(output).encode()).hexdigest()
    return output

def main():
    parser=argparse.ArgumentParser(); parser.add_argument("--config",type=Path,default=ROOT/"ouf-config"); parser.add_argument("--output",type=Path,required=True); args=parser.parse_args()
    try: result=compile_config(args.config)
    except ConfigError as exc: parser.error(str(exc))
    args.output.parent.mkdir(parents=True,exist_ok=True); args.output.write_text(json.dumps(result,indent=2,sort_keys=True)+"\n")

if __name__=="__main__": main()
