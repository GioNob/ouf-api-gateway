import pytest

from tools.materialize_r4a_identity_preflight import SPECS, materialize
from ops.apisix.deploy_r4a_identity_preflight import validate


def runtime():
    routes = []
    for route_id, (method, path, cap, actor, identity, size, timeout) in SPECS.items():
        routes.append({
            "id": route_id, "uri": path, "methods": [method],
            "service_id": "ouf-udp-object-resolution",
            "plugins": {"proxy-rewrite": {"uri": path}},
            "x-ouf-capability": {"capabilityId": cap, "owner": "udp"},
            "x-ouf-policy": {"identity": identity, "allowedActorTypes": [actor],
                "allowedServiceIdentities": ["ouf-source-onboarding"] if identity == "M2M" else [],
                "requiredScope": cap, "maxRequestBytes": size, "timeoutSeconds": timeout},
        })
    return {"x-ouf-installation": {"issuerUrl": "https://iam.example/realms/ouf",
             "gatewayAudience": "ouf-api-gateway", "installationId": "lab"}, "routes": routes}


def test_exact_three_routes_preserve_bearer_for_owner_and_gate_service():
    result = materialize(runtime(), "$ENV://OUF_GATEWAY_OIDC_CLIENT_SECRET", "ouf-udp")
    routes = validate(result)
    assert len(routes) == 3
    assert all(r["upstream"]["nodes"] == {"ouf-udp:8080": 1} for r in routes)
    for route in routes:
        assert route["plugins"]["openid-connect"]["set_access_token_header"] is True
        assert route["plugins"]["openid-connect"]["required_scopes"] == [route["labels"]["ouf-capability"]]
    service = next(r for r in routes if r["id"] == "onboarding-identity-preflight-read")
    assert "ouf-source-onboarding" in service["plugins"]["serverless-post-function"]["functions"][0]


def test_legacy_actor_or_changed_binding_fails_closed():
    source = runtime()
    source["routes"][2]["x-ouf-policy"]["allowedActorTypes"] = ["SERVICE_IDENTITY"]
    with pytest.raises(ValueError, match="BINDING_CHANGED"):
        materialize(source, "$ENV://OUF_GATEWAY_OIDC_CLIENT_SECRET", "ouf-udp")
    source = runtime()
    source["routes"][0]["service_id"] = "other-service"
    with pytest.raises(ValueError, match="BINDING_CHANGED"):
        materialize(source, "$ENV://OUF_GATEWAY_OIDC_CLIENT_SECRET", "ouf-udp")
