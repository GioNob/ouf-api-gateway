import json

import pytest

from tools.compile_config import ROOT, compile_config
from tools.mcp_dispatch import BackendResponse, DispatchError, MCPDispatcher, TrustedIdentity


class Upstream:
    def __init__(self): self.calls = []
    def execute(self, *args):
        self.calls.append(args)
        return BackendResponse(200, b'{"items":[],"nextCursor":null,"partial":false}', {})


def test_search_binding_is_bounded_and_owner_scoped():
    compiled = compile_config(ROOT / 'ouf-config')
    route = next(r for r in compiled['routes'] if r['uri'] == '/internal/capabilities/v1/execute/urban.object.search')
    assert route['plugins']['proxy-rewrite']['uri'] == '/api/udp/v1/objects/search'
    assert route['x-ouf-policy']['requiredScope'] == 'urban.object.search'
    assert route['x-ouf-policy']['allowedActorTypes'] == ['HUMAN']
    source = json.loads((ROOT / 'tests/fixtures/mcp-related-search-dispatch.json').read_text())
    source.update(CapabilityID='urban.object.search', GatewayBindingRef='capability://urban.object.search', Arguments={'type':'ouf:Asset','pageSize':10})
    source['Identity']['ActorType'] = 'HUMAN'
    request_headers = {'X-Correlation-ID':source['CorrelationID'], 'Idempotency-Key':source['IdempotencyKey'], 'X-Tool-Attempt-ID':source['AttemptID']}
    identity = TrustedIdentity('ouf-mcp-server',source['Identity']['PrincipalID'],source['Identity']['TenantID'],'HUMAN',source['Identity']['AuthenticationContextRef'],source['AuthorizationDecisionRef'],frozenset({'urban.object.search'}))
    upstream = Upstream()
    dispatch = MCPDispatcher(compiled,upstream,service_identity='ouf-mcp-server')
    assert dispatch.dispatch(json.dumps(source).encode(),request_headers,identity).status == 200
    assert len(upstream.calls) == 1
    assert upstream.calls[0][:2] == ('ouf-udp-object-resolution','/api/udp/v1/objects/search')
    assert json.loads(upstream.calls[0][2]) == {'type':'ouf:Asset','pageSize':10}
    with pytest.raises(DispatchError):
        dispatch.dispatch(json.dumps(source).encode(),request_headers,TrustedIdentity('ouf-mcp-server',identity.principal_id,identity.tenant_id,'HUMAN',identity.authentication_context_ref,identity.authorization_decision_ref,frozenset()))
    assert len(upstream.calls) == 1
    for forbidden in ({'type':'*'}, {'type':'ouf:Asset','pageSize':101}, {'type':'ouf:Asset','sql':'select *'}):
        source['Arguments'] = forbidden
        with pytest.raises(DispatchError):
            dispatch.dispatch(json.dumps(source).encode(),request_headers,identity)
    assert len(upstream.calls) == 1
