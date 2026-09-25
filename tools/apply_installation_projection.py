#!/usr/bin/env python3
import argparse, copy, hashlib, json
from pathlib import Path

INSTALLATION_MCP_REF = "installation://iam.workloadClients.mcpServer"
INSTALLATION_INGESTION_REF = "installation://iam.workloadClients.ingestion"
INSTALLATION_UDP_REF = "installation://iam.workloadClients.udp"
INSTALLATION_SEMANTIC_REF = "installation://iam.workloadClients.semantic"
INSTALLATION_AUDIENCE_REF = "installation://iam.gatewayAudience"

class ProjectionError(RuntimeError):
    pass

def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"))

def _require(obj, path):
    current = obj
    for part in path.split("."):
        if not isinstance(current, dict) or part not in current:
            raise ProjectionError(f"missing projection field {path}")
        current = current[part]
    if not isinstance(current, str) or not current.strip():
        raise ProjectionError(f"invalid projection field {path}")
    return current

def apply_projection(compiled, projection):
    out = copy.deepcopy(compiled)
    mcp_client = _require(projection, "iam.workloadClients.mcpServer")
    ingestion_client = _require(projection, "iam.workloadClients.ingestion")
    udp_client = _require(projection, "iam.workloadClients.udp")
    semantic_client = _require(projection, "iam.workloadClients.semantic")
    projected_mcp_client = _require(projection, "mcp.environment.MCP_OIDC_CLIENT_ID")
    if projected_mcp_client != mcp_client:
        raise ProjectionError("mcp workload identity disagrees with iam.workloadClients.mcpServer")
    audience = _require(projection, "gateway.requiredAudience")
    issuer = _require(projection, "gateway.issuerUrl")
    api_base = _require(projection, "gateway.publicApiBaseUrl")
    services = projection.get("services") or {}
    service_bindings = services.get("bindings") or {}
    if not isinstance(service_bindings, dict):
        raise ProjectionError("invalid projection field services.bindings")

    for route in out.get("routes", []):
        policy = route.get("x-ouf-policy") or {}
        allowed = policy.get("allowedServiceIdentities")
        if isinstance(allowed, list):
            resolved_allowed = []
            for value in allowed:
                if value == INSTALLATION_MCP_REF:
                    resolved_allowed.append(mcp_client)
                elif value == INSTALLATION_INGESTION_REF:
                    resolved_allowed.append(ingestion_client)
                elif value == INSTALLATION_UDP_REF:
                    resolved_allowed.append(udp_client)
                elif value == INSTALLATION_SEMANTIC_REF:
                    resolved_allowed.append(semantic_client)
                else:
                    resolved_allowed.append(value)
            if any(isinstance(value, str) and value.startswith("installation://") for value in resolved_allowed):
                raise ProjectionError("unresolved installation service identity")
            policy["allowedServiceIdentities"] = resolved_allowed
        if policy.get("requiredAudience") == INSTALLATION_AUDIENCE_REF:
            policy["requiredAudience"] = audience

        backend = route.get("x-ouf-backend-binding")
        if isinstance(backend, dict):
            service = backend.get("service")
            if isinstance(service, str) and service in service_bindings:
                runtime_service = service_bindings[service]
                if not isinstance(runtime_service, str) or not runtime_service.strip():
                    raise ProjectionError(f"invalid service binding for {service}")
                backend["service"] = runtime_service.strip()

        mediation = route.get("x-ouf-mediation")
        if isinstance(mediation, dict) and mediation.get("serviceIdentityRef") == INSTALLATION_MCP_REF:
            mediation["serviceIdentity"] = mcp_client

    out["x-ouf-installation"] = {
        "installationId": _require(projection, "installationId"),
        "revision": projection.get("revision"),
        "checksum": _require(projection, "checksum"),
        "issuerUrl": issuer,
        "gatewayAudience": audience,
        "publicApiBaseUrl": api_base,
        "mcpServiceIdentity": mcp_client,
        "ingestionServiceIdentity": ingestion_client,
        "udpServiceIdentity": udp_client,
        "semanticServiceIdentity": semantic_client,
        "serviceBindings": dict(sorted(service_bindings.items())),
    }
    base = dict(out)
    base.pop("configurationSha256", None)
    out["configurationSha256"] = hashlib.sha256(canonical(base).encode()).hexdigest()
    return out

def caddy_environment(projection):
    caddy = projection.get("caddy")
    if not isinstance(caddy, dict):
        raise ProjectionError("missing projection field caddy")
    required = {
        "OUF_BACKEND_NETWORK": "backendNetwork",
        "OUF_EDGE_NETWORK": "edgeNetwork",
        "OUF_INTERNAL_ISSUER_HOST": "internalIssuerHost",
        "OUF_INTERNAL_API_HOST": "internalApiHost",
        "OUF_OIDC_DISCOVERY_URL": "oidcDiscoveryUrl",
    }
    result = {}
    for env, field in required.items():
        value = caddy.get(field)
        if not isinstance(value, str) or not value.strip():
            raise ProjectionError(f"missing projection field caddy.{field}")
        result[env] = value
    return result

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--compiled", type=Path)
    parser.add_argument("--projection", type=Path, required=True)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--caddy-env", action="store_true")
    parser.add_argument("--get")
    args = parser.parse_args()

    projection = json.loads(args.projection.read_text())
    if args.get:
        current = projection
        for part in args.get.split("."):
            if not isinstance(current, dict) or part not in current:
                raise ProjectionError(f"missing projection field {args.get}")
            current = current[part]
        if not isinstance(current, (str, int)):
            raise ProjectionError(f"projection field {args.get} is not scalar")
        print(current)
        return
    if args.caddy_env:
        for key, value in caddy_environment(projection).items():
            print(f"{key}={value}")
        return
    if not args.compiled or not args.output:
        parser.error("--compiled and --output are required unless --caddy-env is used")
    compiled = json.loads(args.compiled.read_text())
    resolved = apply_projection(compiled, projection)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(resolved, indent=2, sort_keys=True) + "\n")

if __name__ == "__main__":
    main()
