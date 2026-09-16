import json
import os
from pathlib import Path

import yaml

from tools.authorization_boundary import GatewayAuthorizationBoundary
from tools.identity_boundary import IdentityBoundary, TrustBinding, VerifiedCredential


class Verifier:
    def verify(self, raw):
        assert raw == "opaque"
        return VerifiedCredential(
            issuer="https://iam.example",
            subject="user:pairwise",
            audience=frozenset({"ouf-gateway"}),
            scopes=frozenset({"operations.status.read"}),
            credential_id="jti-pairwise",
            authentication_context_ref="acr:mfa",
            tenant_id="tenant:pairwise",
        )


def test_authorization_gateway_pairwise():
    root = os.environ.get("AUTHORIZATION_PAIRWISE_ROOT")
    if not root:
        import pytest
        pytest.skip("AUTHORIZATION_PAIRWISE_ROOT not set")

    sdk = json.loads((Path(root) / "contracts/authorization/authorization-sdk-v1.json").read_text())
    principal = sdk["properties"]["principal"]
    for field in ("subjectId", "tenantId", "actorType", "authenticationContextRef", "issuer", "audience", "scopes"):
        assert field in principal["required"]
    assert set(principal["properties"]["actorType"]["enum"]) == {"HUMAN", "SERVICE", "AI_AGENT"}
    assert sdk["x-ouf-integration-gate"]["scenarioNeutral"] is True

    capability = yaml.safe_load(Path("ouf-config/capabilities/ouf.system.status.yaml").read_text())
    capability_id = capability["metadata"]["id"]
    required_scope = capability["spec"]["scope"]
    assert capability_id == "ouf.system.status"
    assert required_scope == "operations.status.read"

    identity = IdentityBoundary(
        Verifier(),
        (TrustBinding(
            issuer="https://iam.example",
            subject="user:pairwise",
            service_principal_id="gateway-user-context",
            actor_type="HUMAN",
            required_audience="ouf-gateway",
            tenant_id="tenant:pairwise",
        ),),
    ).authenticate("opaque")

    assert identity.principal_id == "user:pairwise"
    assert identity.tenant_id == "tenant:pairwise"
    assert identity.issuer == "https://iam.example"
    assert "ouf-gateway" in identity.audience
    assert identity.authentication_context_ref == "acr:mfa"

    gate = GatewayAuthorizationBoundary()
    allowed = gate.authorize(identity, capability_id, required_scope)
    assert allowed.allowed is True
    assert allowed.decision_code == "ALLOW_COARSE"

    without_scope = identity.__class__(
        service_principal_id=identity.service_principal_id,
        principal_id=identity.principal_id,
        tenant_id=identity.tenant_id,
        actor_type=identity.actor_type,
        issuer=identity.issuer,
        audience=identity.audience,
        scopes=frozenset(),
        credential_id=identity.credential_id,
        authentication_context_ref=identity.authentication_context_ref,
    )
    denied = gate.authorize(without_scope, capability_id, required_scope)
    assert denied.allowed is False
    assert denied.decision_code == "SCOPE_MISSING"
