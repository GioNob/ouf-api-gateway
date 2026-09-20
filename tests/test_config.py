import json, shutil
from pathlib import Path

import pytest, yaml
from tools.compile_config import ConfigError, compile_config

ROOT=Path(__file__).resolve().parents[1]

def isolated(tmp_path):
    target=tmp_path/"ouf-config"; shutil.copytree(ROOT/"ouf-config",target); return target

def test_compiles_onboarding_micro_pairwise_contract():
    contract=json.loads((ROOT/"tests/fixtures/onboarding-managed-file-contract.json").read_text())
    result=compile_config(ROOT/"ouf-config"); route=next(item for item in result["routes"] if item["id"]=="onboarding-managed-file-read")
    assert route["uri"]==contract["path"]
    assert route["methods"]==[contract["method"]]
    assert route["x-ouf-query-contract"][contract["queryParameter"]]=={"required":True,"pattern":contract["referencePattern"]}
    assert route["x-ouf-policy"]["allowedServiceIdentities"]==[contract["consumerIdentity"],"ouf-ingestion-runtime"]
    assert route["x-ouf-policy"]["maxRequestBytes"]==contract["maximumBytes"]
    assert route["service_id"]=="ouf-object-storage"
    assert route["plugins"]["request-id"]=={"header_name":"X-Correlation-ID","include_in_response":True,"algorithm":"uuid"}

def test_output_is_deterministic():
    assert compile_config(ROOT/"ouf-config")==compile_config(ROOT/"ouf-config")

def test_udp_recovery_binding_is_compiled_from_registry_configuration():
    result=compile_config(ROOT/"ouf-config")
    route=next(item for item in result["routes"] if item["id"]=="mcp-related-search")
    assert route["x-ouf-recovery-binding"]=={"owner":"udp","service":"ouf-udp-object-resolution","pathTemplate":"/internal/v1/attempt-outcomes/{backendRequestId}"}

def test_missing_exact_capability_version_fails_closed(tmp_path):
    root=isolated(tmp_path); path=next((root/"routes").rglob("*.yaml")); doc=yaml.safe_load(path.read_text()); doc["spec"]["capabilityRef"]="ouf.object-storage.content.read@2.0.0"; path.write_text(yaml.safe_dump(doc))
    with pytest.raises(ConfigError,match="unresolved capabilityRef"): compile_config(root)

def test_missing_exact_extraction_version_fails_closed(tmp_path):
    root=isolated(tmp_path); path=next((root/"routes").rglob("*.yaml")); doc=yaml.safe_load(path.read_text()); doc["spec"]["extractionProfileRef"]="onboarding-managed-file-profile@2.0.0"; path.write_text(yaml.safe_dump(doc))
    with pytest.raises(ConfigError,match="unresolved extractionProfileRef"): compile_config(root)

def test_client_controlled_physical_upstream_is_rejected(tmp_path):
    root=isolated(tmp_path); path=next((root/"source-runtime").glob("*.yaml")); doc=yaml.safe_load(path.read_text()); doc["spec"]["endpointRef"]="https://attacker.invalid/backend"; path.write_text(yaml.safe_dump(doc))
    with pytest.raises(ConfigError,match="governed logical scheme"): compile_config(root)

def test_internal_route_without_service_identity_is_rejected(tmp_path):
    root=isolated(tmp_path); path=next((root/"routes").rglob("*.yaml")); doc=yaml.safe_load(path.read_text()); doc["spec"]["policy"]["allowedServiceIdentities"]=[]; path.write_text(yaml.safe_dump(doc))
    with pytest.raises(ConfigError,match="explicit service identities"): compile_config(root)

def test_only_open_or_anonymous_classification_is_accepted(tmp_path):
    root=isolated(tmp_path); path=next((root/"capabilities").glob("*.yaml")); doc=yaml.safe_load(path.read_text()); doc["spec"]["classification"]=["PERSONAL"]; path.write_text(yaml.safe_dump(doc))
    with pytest.raises(ConfigError,match="not one of"): compile_config(root)


def test_remote_mcp_protocol_endpoint_is_compiled_without_fake_capability():
    result=compile_config(ROOT/"ouf-config")
    route=next(item for item in result["routes"] if item["id"]=="public-mcp-endpoint")
    assert route["uri"]=="/mcp"
    assert route["methods"]==["POST"]
    assert route["service_id"]=="ouf-mcp-server"
    assert route["x-ouf-capability"] is None
    assert route["x-ouf-protocol"]=={
        "name":"MCP",
        "transport":"STREAMABLE_HTTP",
        "stateless":True,
        "protocolVersion":"2026-07-28",
    }
    assert route["x-ouf-policy"]["identity"]=="OIDC"
    assert route["x-ouf-policy"]["requiredAudience"]=="installation://iam.gatewayAudience"
    assert route["x-ouf-policy"]["requiredScope"]=="mcp.connect"


def test_remote_mcp_protocol_endpoint_strips_all_client_trusted_headers():
    result=compile_config(ROOT/"ouf-config")
    route=next(item for item in result["routes"] if item["id"]=="public-mcp-endpoint")
    trusted=route["x-ouf-trusted-identity"]
    required={
        "X-OUF-Gateway-Verified","X-OUF-Service-Principal","X-OUF-Principal-ID",
        "X-OUF-Tenant-ID","X-OUF-Actor-Type","X-OUF-Authentication-Context-Ref",
        "X-OUF-Token-Issuer","X-OUF-Token-Audience","X-OUF-Granted-Scopes",
    }
    assert set(trusted["stripClientHeaders"])==required
    assert set(trusted["claimProjection"])==required-{"X-OUF-Gateway-Verified"}
    assert trusted["injectAfterVerification"]=={"X-OUF-Gateway-Verified":"true"}


def test_remote_mcp_protocol_endpoint_fails_closed_when_trusted_header_strip_is_incomplete(tmp_path):
    root=isolated(tmp_path)
    path=root/"protocol"/"mcp-endpoint.yaml"
    doc=yaml.safe_load(path.read_text())
    doc["spec"]["trustedIdentity"]["stripClientHeaders"].remove("X-OUF-Actor-Type")
    path.write_text(yaml.safe_dump(doc))
    with pytest.raises(ConfigError,match="trusted identity headers must be stripped"):
        compile_config(root)


def test_generic_mcp_mediation_routes_are_compiled_without_fake_capabilities():
    result=compile_config(ROOT/"ouf-config")
    execution=next(r for r in result["routes"] if r["id"]=="mcp-generic-execution")
    recovery=next(r for r in result["routes"] if r["id"]=="mcp-generic-recovery")
    assert execution["uri"]=="/internal/capabilities/v1/execute"
    assert execution["x-ouf-capability"] is None
    assert execution["x-ouf-mediation"]=={
        "mode":"EXECUTION",
        "serviceIdentityRef":"installation://iam.workloadClients.mcpServer",
    }
    assert execution["x-ouf-policy"]["requiredScope"] is None
    assert recovery["uri"]=="/internal/capabilities/v1/recovery"
    assert recovery["x-ouf-capability"] is None
    assert recovery["x-ouf-mediation"]["mode"]=="RECOVERY"
    assert recovery["x-ouf-policy"]["requiredScope"]=="mcp.attempt.recover"


def test_policy_bundle_route_is_real_authorization_capability():
    result=compile_config(ROOT/"ouf-config")
    route=next(r for r in result["routes"] if r["id"]=="mcp-authorization-policy-bundle-read")
    assert route["uri"]=="/internal/capabilities/v1/authorization/policy-bundle/active"
    assert route["service_id"]=="ouf-source-onboarding"
    assert route["plugins"]["proxy-rewrite"]["uri"]=="/api/internal/v1/authorization/policy-bundle/active"
    assert route["x-ouf-capability"]["capabilityId"]=="authorization.bundle.read"
    assert route["x-ouf-capability"]["owner"]=="authorization"
    assert route["x-ouf-policy"]["requiredScope"]=="authorization.bundle.read"
    assert route["x-ouf-policy"]["allowedServiceIdentities"]==[
        "installation://iam.workloadClients.mcpServer",
        "installation://iam.workloadClients.ingestion",
    ]
    assert route["x-ouf-policy"]["allowedActorTypes"]==["SERVICE"]
