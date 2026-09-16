import pytest

from tools.policy_enforcement import PolicyDenied, RequestIdentity, enforce


def route():
    return {"x-ouf-policy": {"identity": "MTLS_SERVICE", "allowedServiceIdentities": ["ouf-mcp-server"], "allowedActorTypes": ["MCP_SERVER"], "maxRequestBytes": 1024, "timeoutSeconds": 3, "requiredScope": "urban.object.related_search"}}


def identity(**changes):
    value = dict(authenticated=True, identity_mode="MTLS_SERVICE", service_principal_id="ouf-mcp-server", actor_type="MCP_SERVER", scopes=frozenset({"urban.object.related_search"}))
    value.update(changes)
    return RequestIdentity(**value)


def denied(code, current=None, size=10, current_route=None):
    with pytest.raises(PolicyDenied) as caught:
        enforce(current_route or route(), current or identity(), size)
    assert caught.value.code == code


def test_admitted_request_passes(): enforce(route(), identity(), 1024)
def test_unauthenticated_denied(): denied("AUTHENTICATION_REQUIRED", identity(authenticated=False))
def test_wrong_identity_mode_denied(): denied("IDENTITY_MODE_MISMATCH", identity(identity_mode="M2M"))
def test_wrong_service_denied(): denied("SERVICE_IDENTITY_DENIED", identity(service_principal_id="attacker"))
def test_wrong_actor_denied(): denied("ACTOR_TYPE_DENIED", identity(actor_type="SERVICE_IDENTITY"))
def test_missing_scope_denied(): denied("SCOPE_DENIED", identity(scopes=frozenset()))
def test_oversize_denied(): denied("REQUEST_TOO_LARGE", size=1025)
def test_missing_policy_fails_closed(): denied("ROUTE_POLICY_MISSING", current_route={"x-ouf-policy": None})
def test_missing_required_scope_fails_closed():
    value=route(); value["x-ouf-policy"].pop("requiredScope"); denied("SCOPE_DENIED", current_route=value)
