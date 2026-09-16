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


@dataclass(frozen=True)
class NormalizedIdentity:
    service_principal_id: str
    actor_type: str
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
        return NormalizedIdentity(binding.service_principal_id,binding.actor_type,verified.scopes,verified.credential_id,verified.authentication_context_ref)
