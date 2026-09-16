import pytest

from tools.activation_gate import ActivationRejected, validate_route_activation


class Auth:
    def __init__(self, ok=True): self.ok=ok
    def binding_exists(self, capability_ref, required_scope): return self.ok


def docs():
    capability={"metadata":{"id":"related-search","version":"1"},"spec":{"scope":"urban.object.related_search"}}
    source={"metadata":{"id":"udp","version":"1"},"spec":{"endpointRef":"service://ouf-udp-object-resolution"}}
    extraction={"metadata":{"id":"udp-extract","version":"1"},"spec":{"sourceRef":"udp@1"}}
    route={"spec":{"capabilityRef":"related-search@1","sourceRef":"udp@1","extractionProfileRef":"udp-extract@1","backendBinding":{"service":"ouf-udp-object-resolution"}}}
    return route,capability,source,extraction


def test_valid_activation_with_authorization_gate():
    route,capability,source,extraction=docs(); evidence=validate_route_activation(route,capability,source,extraction,Auth())
    assert evidence.authorization_checked and evidence.backend_service=="ouf-udp-object-resolution"

@pytest.mark.parametrize("mutate,code",[
    (lambda r,c,s,e:r["spec"].update(capabilityRef="wrong@1"),"CAPABILITY_REFERENCE_MISMATCH"),
    (lambda r,c,s,e:r["spec"].update(sourceRef="wrong@1"),"SOURCE_RUNTIME_REFERENCE_MISMATCH"),
    (lambda r,c,s,e:e["spec"].update(sourceRef="wrong@1"),"EXTRACTION_SOURCE_MISMATCH"),
    (lambda r,c,s,e:r["spec"]["backendBinding"].update(service="attacker"),"BACKEND_SOURCE_BINDING_MISMATCH"),
])
def test_reference_mismatch_fails_closed(mutate,code):
    route,capability,source,extraction=docs();mutate(route,capability,source,extraction)
    with pytest.raises(ActivationRejected,match=code):validate_route_activation(route,capability,source,extraction,Auth())

def test_missing_authorization_binding_fails_closed_when_gate_available():
    route,capability,source,extraction=docs()
    with pytest.raises(ActivationRejected,match="AUTHORIZATION_BINDING_MISSING"):validate_route_activation(route,capability,source,extraction,Auth(False))

def test_authorization_absence_is_explicit_not_falsely_verified():
    route,capability,source,extraction=docs();evidence=validate_route_activation(route,capability,source,extraction,None)
    assert evidence.authorization_checked is False
