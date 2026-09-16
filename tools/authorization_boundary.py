from dataclasses import dataclass

from tools.identity_boundary import NormalizedIdentity


class AuthorizationRejected(RuntimeError): pass


@dataclass(frozen=True)
class CoarseAuthorizationDecision:
    allowed: bool
    decision_code: str
    capability_id: str
    required_scope: str


class GatewayAuthorizationBoundary:
    """Coarse Gateway enforcement only; fine-grained grants remain owner-local."""

    def authorize(self, identity: NormalizedIdentity, capability_id: str, required_scope: str) -> CoarseAuthorizationDecision:
        if not capability_id or not required_scope:
            raise AuthorizationRejected("CAPABILITY_CONTRACT_INVALID")
        if not identity.tenant_id:
            raise AuthorizationRejected("TENANT_CONTEXT_MISSING")
        if identity.actor_type not in {"HUMAN", "SERVICE", "AI_AGENT"}:
            raise AuthorizationRejected("ACTOR_TYPE_INVALID")
        if required_scope not in identity.scopes:
            return CoarseAuthorizationDecision(False, "SCOPE_MISSING", capability_id, required_scope)
        return CoarseAuthorizationDecision(True, "ALLOW_COARSE", capability_id, required_scope)
