#!/usr/bin/env python3
import argparse, copy, hashlib, json
from pathlib import Path

INSTALLATION_MCP_REF = "installation://iam.workloadClients.mcpServer"
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
    mcp_client = _require(projection, "mcp.environment.MCP_OIDC_CLIENT_ID")
    audience = _require(projection, "gateway.requiredAudience")
    issuer = _require(projection, "gateway.issuerUrl")
    api_base = _require(projection, "gateway.publicApiBaseUrl")

    for route in out.get("routes", []):
        policy = route.get("x-ouf-policy") or {}
        allowed = policy.get("allowedServiceIdentities")
        if isinstance(allowed, list):
            policy["allowedServiceIdentities"] = [
                mcp_client if value == INSTALLATION_MCP_REF else value
                for value in allowed
            ]
        if policy.get("requiredAudience") == INSTALLATION_AUDIENCE_REF:
            policy["requiredAudience"] = audience

        mediation = route.get("x-ouf-mediation")
        if isinstance(mediation, dict) and mediation.get("serviceIdentityRef") == INSTALLATION_MCP_REF:
            mediation["serviceIdentity"] = mcp_client

    out["x-ouf-installation"] = {
        "installationId": _require(projection, "installationId"),
        "revision": projection.get("revision"),
        "checksum": _require(projection, "checksum"),
        "issuerUrl": issuer,
        "publicApiBaseUrl": api_base,
        "mcpServiceIdentity": mcp_client,
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
    args = parser.parse_args()

    projection = json.loads(args.projection.read_text())
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
