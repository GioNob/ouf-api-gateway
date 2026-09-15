#!/usr/bin/env python3
import argparse, hashlib, json
from pathlib import Path

import yaml
from jsonschema import Draft202012Validator

ROOT = Path(__file__).resolve().parents[1]
SCHEMAS = {"Capability": "capability-manifest-v1.json", "SourceRuntimeProfile": "source-runtime-profile-v1.json", "ExtractionRuntimeProfile": "extraction-runtime-profile-v1.json", "RouteBinding": "route-binding-v1.json"}

class ConfigError(RuntimeError): pass

def canonical(value): return json.dumps(value, sort_keys=True, separators=(",", ":"))
def ref(doc): return f"{doc['metadata']['id']}@{doc['metadata']['version']}"

def load_documents(config_root):
    documents=[]
    for path in sorted(config_root.rglob("*.yaml")):
        doc=yaml.safe_load(path.read_text())
        kind=doc.get("kind") if isinstance(doc,dict) else None
        if kind not in SCHEMAS: raise ConfigError(f"{path}: unsupported kind {kind!r}")
        schema=json.loads((ROOT/"schemas"/SCHEMAS[kind]).read_text())
        errors=sorted(Draft202012Validator(schema).iter_errors(doc),key=lambda e:list(e.path))
        if errors: raise ConfigError(f"{path}: {errors[0].message}")
        documents.append((path,doc))
    return documents

def compile_config(config_root):
    docs=load_documents(config_root)
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
        match=(spec["match"]["method"],spec["match"]["path"])
        if match in matches: raise ConfigError(f"{path}: duplicate route match {match[0]} {match[1]}")
        matches.add(match)
        routes.append({
          "id": route["metadata"]["id"], "uri": spec["match"]["path"], "methods": [spec["match"]["method"]],
          "upstream_id": spec["sourceRef"], "service_id": spec["backendBinding"]["service"],
          "labels": {"capability": spec["capabilityRef"], "source": spec["sourceRef"], "exposure": spec["exposure"]},
          "plugins": {"request-id": {"header_name":"X-Correlation-ID","include_in_response":True,"algorithm":"uuid"}, "proxy-rewrite": {"uri": spec["backendBinding"]["path"]}, "limit-count": {"count":100,"time_window":60,"rejected_code":429}},
          "x-ouf-policy": {"identity": spec["policy"]["identity"], "allowedServiceIdentities": allowed, "allowedActorTypes": spec["policy"].get("allowedActorTypes",[]), "maxRequestBytes":spec["policy"]["maxRequestBytes"], "timeoutSeconds":spec["policy"]["timeoutSeconds"], "requiredScope": capability[1]["spec"]["scope"]},
          "x-ouf-capability": {"capabilityId": capability[1]["metadata"]["id"], "version": capability[1]["metadata"]["version"], "owner": capability[1]["spec"]["owner"], "operationType": capability[1]["spec"]["operationType"], "toolEligible": capability[1]["spec"]["mcp"]["toolEligible"], "humanRequired": capability[1]["spec"]["mcp"].get("humanRequired",False)},
          "x-ouf-query-contract": spec["match"].get("query",{})
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
