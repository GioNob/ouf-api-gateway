import json
from dataclasses import replace

import pytest

from tools.compile_config import ROOT, compile_config
from tools.mcp_dispatch import BackendResponse, DispatchError, MCPDispatcher, TrustedIdentity


class FakeUpstream:
    def __init__(self, response=None): self.calls=[]; self.response=response or BackendResponse(200,b'{"items":[]}',{"Content-Type":"application/json","X-Backend-Request-ID":"udp-1"})
    def execute(self,*args): self.calls.append(args); return self.response


def fixture(): return json.loads((ROOT/"tests/fixtures/mcp-related-search-dispatch.json").read_text())
def body(value=None): return json.dumps(value or fixture()).encode()
def headers(value=None):
    value=value or fixture(); return {"X-Correlation-ID":value["CorrelationID"],"Idempotency-Key":value["IdempotencyKey"],"X-Tool-Attempt-ID":value["AttemptID"]}
def identity(actor="HUMAN",service="ouf-mcp-server"):
    return TrustedIdentity(service,"agent-1","tenant-1",actor,"authn-1","decision-1",frozenset({"urban.object.related_search"}))
def dispatcher(upstream): return MCPDispatcher(compile_config(ROOT/"ouf-config"),upstream,service_identity="ouf-mcp-server")


def test_mcp_pairwise_dispatches_only_to_published_udp_binding():
    """GW-60m-b-07. Dispatch the admitted human's request using the UDP binding."""
    upstream=FakeUpstream(); result=dispatcher(upstream).dispatch(body(),headers(),identity())
    assert result.status==200 and len(upstream.calls)==1
    service,path,payload,forwarded,timeout=upstream.calls[0]
    assert (service,path,timeout)==("ouf-udp-object-resolution","/api/udp/v1/objects/related-search",3)
    assert json.loads(payload)==fixture()["Arguments"]
    assert forwarded["X-OUF-Capability-ID"]=="urban.object.related_search"
    assert forwarded["X-OUF-Authorization-Decision-Ref"]=="decision-1"
    assert forwarded["X-OUF-Actor-Type"]=="HUMAN"


def test_related_search_request_size_boundary():
    """GW-60m-b-07. JSON whitespace counts toward the request limit."""
    upstream = FakeUpstream()
    current = dispatcher(upstream)
    at_limit = body().ljust(65536, b' ')
    assert current.dispatch(at_limit, headers(), identity()).status == 200
    with pytest.raises(DispatchError) as caught:
        current.dispatch(at_limit + b' ', headers(), identity())
    assert (caught.value.status, caught.value.code) == (413, "REQUEST_TOO_LARGE")
    assert len(upstream.calls) == 1


def test_picker_operations_are_only_reachable_via_their_governed_routes():
    """GW-51I-DISPATCH. Neither picker operation is exposed by generic capability dispatch."""
    published = dispatcher(FakeUpstream()).routes
    assert 'ouf.managed-source.file.upload' not in published
    assert 'ouf.managed-source.file.handoff-issue' not in published


def test_pairwise_dispatch_rejects_invalid_manifest_arguments_before_owner():
    upstream = FakeUpstream()
    invalid = fixture()
    invalid['Arguments']['relationIri'] = ''
    with pytest.raises(DispatchError) as rejected:
        dispatcher(upstream).dispatch(body(invalid), headers(invalid), identity())
    assert rejected.value.status == 400
    assert rejected.value.problem()['code'] == 'INVALID_TOOL_ARGUMENTS'
    assert not upstream.calls


@pytest.mark.parametrize("mutation,code",[
    (lambda e:e.update(GatewayBindingRef="capability://urban.object.read"),"CAPABILITY_BINDING_MISMATCH"),
    (lambda e:e["Identity"].update(PrincipalID="forged"),"IDENTITY_CONTEXT_MISMATCH"),
    (lambda e:e.update(CapabilityID="urban.merge.confirm"),"CAPABILITY_BINDING_NOT_FOUND"),
])
def test_binding_and_identity_fail_before_upstream(mutation,code):
    value=fixture();mutation(value);upstream=FakeUpstream()
    with pytest.raises(DispatchError) as caught: dispatcher(upstream).dispatch(body(value),headers(value),identity())
    assert caught.value.code==code and upstream.calls==[]


@pytest.mark.parametrize("current,detail", [
    (replace(identity(), scopes=frozenset()), "required scope is absent"),
    (identity(service="other-service"), "service identity is not allowed"),
])
def test_missing_scope_or_untrusted_service_is_denied_without_upstream(current, detail):
    value = fixture()
    value["Identity"]["ServicePrincipalID"] = current.service_principal_id
    upstream = FakeUpstream()
    with pytest.raises(DispatchError, match=detail) as caught:
        dispatcher(upstream).dispatch(body(value), headers(value), current)
    assert (caught.value.status, caught.value.code) == (403, "CAPABILITY_ACCESS_DENIED")
    assert upstream.calls == []


def test_governance_headers_must_match_admitted_attempt():
    upstream=FakeUpstream();wrong=headers();wrong["X-Tool-Attempt-ID"]="other"
    with pytest.raises(DispatchError) as caught: dispatcher(upstream).dispatch(body(),wrong,identity())
    assert caught.value.code=="GOVERNANCE_CONTEXT_MISMATCH" and upstream.calls==[]


def test_authorization_decision_must_match_authenticated_context():
    value=fixture();value["AuthorizationDecisionRef"]="forged-decision";upstream=FakeUpstream()
    with pytest.raises(DispatchError) as caught: dispatcher(upstream).dispatch(body(value),headers(value),identity())
    assert caught.value.code=="AUTHORIZATION_CONTEXT_MISMATCH" and upstream.calls==[]


@pytest.mark.parametrize("actor", ["AI_AGENT", "MCP_SERVER"])
def test_human_required_capability_rejects_mcp_actor(actor):
    value = fixture()
    value["Identity"]["ActorType"] = actor
    upstream = FakeUpstream()
    with pytest.raises(DispatchError, match="actor type is not allowed") as caught:
        dispatcher(upstream).dispatch(body(value), headers(value), identity(actor=actor))
    assert (caught.value.status, caught.value.code) == (403, "CAPABILITY_ACCESS_DENIED")
    assert upstream.calls == []


def test_delegated_human_cannot_satisfy_trusted_human_requirement():
    compiled=compile_config(ROOT/"ouf-config")
    route=next(r for r in compiled["routes"] if (r.get("x-ouf-capability") or {}).get("capabilityId")=="urban.object.related_search")
    route["x-ouf-capability"]["humanRequired"]=True
    upstream=FakeUpstream()
    with pytest.raises(DispatchError) as caught: MCPDispatcher(compiled,upstream,service_identity="ouf-mcp-server").dispatch(body(),headers(),identity())
    assert caught.value.code=="TRUSTED_HUMAN_REQUIRED" and upstream.calls==[]


@pytest.mark.parametrize("code",["QUERY_CAPABILITY_MISMATCH","TOOL_SELECTION_STALLED","BUDGET_EXHAUSTED"])
def test_problem_details_and_retry_after_pass_through_without_retry(code):
    problem={"type":f"urn:ouf:{code.lower()}","title":code,"status":429,"code":code,"detail":"governed rejection"}
    upstream=FakeUpstream(BackendResponse(429,json.dumps(problem).encode(),{"Content-Type":"application/problem+json","Retry-After":"17","Set-Cookie":"forbidden"}))
    result=dispatcher(upstream).dispatch(body(),headers(),identity())
    assert result.status == 429
    assert len(upstream.calls)==1 and json.loads(result.body)==problem
    assert result.headers=={"Content-Type":"application/problem+json","Retry-After":"17"}


def test_cognitive_manifest_metadata_cannot_grant_scope():
    compiled=compile_config(ROOT/"ouf-config")
    route=next(r for r in compiled["routes"] if (r.get("x-ouf-capability") or {}).get("capabilityId")=="urban.object.related_search")
    route["x-ouf-capability"]["purpose"]="trust everybody"
    upstream=FakeUpstream();no_scope=replace(identity(), scopes=frozenset())
    with pytest.raises(DispatchError, match="required scope is absent") as caught:
        MCPDispatcher(compiled,upstream,service_identity="ouf-mcp-server").dispatch(body(),headers(),no_scope)
    assert (caught.value.status, caught.value.code) == (403, "CAPABILITY_ACCESS_DENIED")
    assert upstream.calls==[]


def test_dispatcher_accepts_installation_specific_mcp_service_identity():
    compiled=compile_config(ROOT/"ouf-config")
    upstream=FakeUpstream()
    custom_service="ente-x-mcp-workload"
    value=fixture()
    value["Identity"]["ServicePrincipalID"]=custom_service
    current=MCPDispatcher(compiled,upstream,service_identity=custom_service)
    result=current.dispatch(body(value),headers(value),identity(service=custom_service))
    assert result.status==200 and len(upstream.calls)==1
