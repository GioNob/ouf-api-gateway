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

def test_m2m_routes_compile_real_oidc_boundary_without_embedding_secret():
    result=compile_config(ROOT/"ouf-config")
    route=next(item for item in result["routes"] if item["id"]=="mcp-related-search")
    oidc=route["plugins"]["openid-connect"]
    assert oidc["bearer_only"] is True
    assert oidc["client_id"]=="ouf-api-gateway"
    assert oidc["client_secret"]=="$ENV://OUF_GATEWAY_OIDC_CLIENT_SECRET"
    assert oidc["discovery"]=="http://ouf-keycloak:8080/realms/ouf/.well-known/openid-configuration"
    assert oidc["introspection_endpoint"]=="http://ouf-keycloak:8080/realms/ouf/protocol/openid-connect/token/introspect"
    assert oidc["claim_validator"]["issuer"]["valid_issuers"]==["https://auth.ouf-lab.it/realms/ouf"]
    assert oidc["claim_validator"]["audience"]=={"claim":"aud","required":True,"match_with_client_id":True}
    assert oidc["set_access_token_header"] is False
    assert oidc["set_userinfo_header"] is True
    assert route["x-ouf-identity-normalization"]=={"subjectClaim":"ouf_subject","tenantClaim":"tenant_id","clientIdClaim":"client_id","actorType":"SERVICE"}

def test_current_gateway_contracts_use_authorization_actor_vocabulary():
    legacy=("HUMAN_USER","MCP_SERVER","SERVICE_IDENTITY")
    offenders=[]
    for root in (ROOT/"ouf-config", ROOT/"schemas"):
        for path in root.rglob("*"):
            if path.is_file() and path.suffix in {".yaml",".yml",".json"}:
                text=path.read_text()
                for value in legacy:
                    if value in text:
                        offenders.append(f"{path.relative_to(ROOT)}:{value}")
    assert offenders==[]

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
