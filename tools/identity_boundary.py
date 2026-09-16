from dataclasses import dataclass
from typing import Protocol


class IdentityRejected(RuntimeError): pass


@dataclass(frozen=True)
class VerifiedCredential:
    issuer: str
    subject: str
    audience: frozenset[str]
    scopes: frozenset[str]
    credential_id: str
    authentication_context_ref: str
    tenant_id: str = ""


@dataclass(frozen=True)
class NormalizedIdentity:
    service_principal_id: str
    principal_id: str
    tenant_id: str
    actor_type: str
    issuer: str
    audience: frozenset[str]
    scopes: frozenset[str]
    credential_id: str
    authentication_context_ref: str


class CredentialVerifier(Protocol):
    def verify(self, raw_credential: str) -> VerifiedCredential: ...


@dataclass(frozen=True)
class TrustBinding:
    issuer: str
    subject: str
    service_principal_id: str
    actor_type: str
    required_audience: str
    tenant_id: str = ""


class IdentityBoundary:
    """Normalizes only cryptographically verified credentials against governed bindings."""
    def __init__(self, verifier: CredentialVerifier, bindings: tuple[TrustBinding,...]):
        self.verifier=verifier
        self.bindings={(b.issuer,b.subject):b for b in bindings}

    def authenticate(self, raw_credential: str) -> NormalizedIdentity:
        if not raw_credential: raise IdentityRejected("CREDENTIAL_MISSING")
        try: verified=self.verifier.verify(raw_credential)
        except Exception as exc: raise IdentityRejected("CREDENTIAL_INVALID") from exc
        binding=self.bindings.get((verified.issuer,verified.subject))
        if binding is None: raise IdentityRejected("IDENTITY_UNBOUND")
        if binding.required_audience not in verified.audience: raise IdentityRejected("AUDIENCE_MISMATCH")
        if not verified.credential_id or not verified.authentication_context_ref: raise IdentityRejected("VERIFICATION_EVIDENCE_MISSING")
        tenant_id=verified.tenant_id or binding.tenant_id
        if not tenant_id: raise IdentityRejected("TENANT_CONTEXT_MISSING")
        if binding.actor_type not in {"HUMAN","SERVICE","AI_AGENT"}: raise IdentityRejected("ACTOR_TYPE_INVALID")
        return NormalizedIdentity(
            service_principal_id=binding.service_principal_id,
            principal_id=verified.subject,
            tenant_id=tenant_id,
            actor_type=binding.actor_type,
            issuer=verified.issuer,
            audience=verified.audience,
            scopes=verified.scopes,
            credential_id=verified.credential_id,
            authentication_context_ref=verified.authentication_context_ref,
        )
