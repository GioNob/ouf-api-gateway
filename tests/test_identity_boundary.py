import pytest
from tools.identity_boundary import IdentityBoundary,IdentityRejected,TrustBinding,VerifiedCredential


class Verifier:
    def __init__(self,value=None,error=None):self.value=value;self.error=error
    def verify(self,raw):
        if self.error:raise self.error
        return self.value


def credential(**changes):
    value=dict(issuer='https://iam.example',subject='workload:mcp',audience=frozenset({'ouf-gateway'}),scopes=frozenset({'urban.object.related_search'}),credential_id='jti-1',authentication_context_ref='authn-1');value.update(changes);return VerifiedCredential(**value)
def binding():return TrustBinding('https://iam.example','workload:mcp','ouf-mcp-server','MCP_SERVER','ouf-gateway')
def boundary(value=None):return IdentityBoundary(Verifier(value or credential()),(binding(),))

def test_verified_credential_is_normalized_from_governed_binding():
    identity=boundary().authenticate('opaque');assert identity.service_principal_id=='ouf-mcp-server' and identity.actor_type=='MCP_SERVER'
def test_caller_cannot_supply_identity_without_credential():
    with pytest.raises(IdentityRejected,match='CREDENTIAL_MISSING'):boundary().authenticate('')
def test_verifier_failure_is_fail_closed():
    with pytest.raises(IdentityRejected,match='CREDENTIAL_INVALID'):IdentityBoundary(Verifier(error=ValueError('bad')),(binding(),)).authenticate('bad')
def test_verified_but_unbound_subject_is_denied():
    with pytest.raises(IdentityRejected,match='IDENTITY_UNBOUND'):boundary(credential(subject='attacker')).authenticate('opaque')
def test_wrong_audience_is_denied():
    with pytest.raises(IdentityRejected,match='AUDIENCE_MISMATCH'):boundary(credential(audience=frozenset({'other'}))).authenticate('opaque')
def test_missing_verification_evidence_is_denied():
    with pytest.raises(IdentityRejected,match='VERIFICATION_EVIDENCE_MISSING'):boundary(credential(credential_id='')).authenticate('opaque')
def test_scopes_come_only_from_verified_credential():
    identity=boundary(credential(scopes=frozenset())).authenticate('opaque');assert identity.scopes==frozenset()
