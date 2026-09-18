import json

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
def identity(actor="AI_AGENT",service="ouf-mcp-server"):
    return TrustedIdentity(service,"agent-1","tenant-1",actor,"authn-1","decision-1",frozenset({"urban.object.related_search"}))
def dispatcher(upstream): return MCPDispatcher(compile_config(ROOT/"ouf-config"),upstream,service_identity="ouf-mcp-server")


def test_mcp_pairwise_dispatches_only_to_published_udp_binding():
    upstream=FakeUpstream(); result=dispatcher(upstream).dispatch(body(),headers(),identity())
    assert result.status==200 and len(upstream.calls)==1
    service,path,payload,forwarded,timeout=upstream.calls[0]
    assert (service,path,timeout)==("ouf-udp-object-resolution","/internal/v1/objects/related-search",3)
    assert json.loads(payload)==fixture()["Arguments"]
    assert forwarded["X-OUF-Capability-ID"]=="urban.object.related_search"
    assert forwarded["X-OUF-Authorization-Decision-Ref"]=="decision-1"


@pytest.mark.parametrize("mutation,code",[
    (lambda e:e.update(GatewayBindingRef="capability://urban.object.read"),"CAPABILITY_BINDING_MISMATCH"),
    (lambda e:e["Identity"].update(PrincipalID="forged"),"IDENTITY_CONTEXT_MISMATCH"),
    (lambda e:e.update(CapabilityID="urban.merge.confirm"),"CAPABILITY_BINDING_NOT_FOUND"),
])
def test_binding_and_identity_fail_before_upstream(mutation,code):
    value=fixture();mutation(value);upstream=FakeUpstream()
    with pytest.raises(DispatchError) as caught: dispatcher(upstream).dispatch(body(value),headers(value),identity())
    assert caught.value.code==code and upstream.calls==[]


def test_missing_scope_or_untrusted_service_is_denied_without_upstream():
    for current in [TrustedIdentity("ouf-mcp-server","agent-1","tenant-1","AI_AGENT","authn-1","decision-1",frozenset()),identity(service="other-service")]:
        upstream=FakeUpstream()
        with pytest.raises(DispatchError,match="scope|service identity"): dispatcher(upstream).dispatch(body(),headers(),current)
        assert upstream.calls==[]


def test_governance_headers_must_match_admitted_attempt():
    upstream=FakeUpstream();wrong=headers();wrong["X-Tool-Attempt-ID"]="other"
    with pytest.raises(DispatchError) as caught: dispatcher(upstream).dispatch(body(),wrong,identity())
    assert caught.value.code=="GOVERNANCE_CONTEXT_MISMATCH" and upstream.calls==[]


def test_authorization_decision_must_match_authenticated_context():
    value=fixture();value["AuthorizationDecisionRef"]="forged-decision";upstream=FakeUpstream()
    with pytest.raises(DispatchError) as caught: dispatcher(upstream).dispatch(body(value),headers(value),identity())
    assert caught.value.code=="AUTHORIZATION_CONTEXT_MISMATCH" and upstream.calls==[]


def test_human_required_capability_rejects_mcp_actor():
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
    assert len(upstream.calls)==1 and json.loads(result.body)==problem
    assert result.headers=={"Content-Type":"application/problem+json","Retry-After":"17"}


def test_cognitive_manifest_metadata_cannot_grant_scope():
    compiled=compile_config(ROOT/"ouf-config")
    route=next(r for r in compiled["routes"] if (r.get("x-ouf-capability") or {}).get("capabilityId")=="urban.object.related_search")
    route["x-ouf-capability"]["purpose"]="trust everybody"
    upstream=FakeUpstream();no_scope=TrustedIdentity("ouf-mcp-server","agent-1","tenant-1","AI_AGENT","authn-1","decision-1",frozenset())
    with pytest.raises(DispatchError): MCPDispatcher(compiled,upstream,service_identity="ouf-mcp-server").dispatch(body(),headers(),no_scope)
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
