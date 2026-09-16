from dataclasses import dataclass
from typing import Protocol


class ActivationRejected(RuntimeError):
    pass


class AuthorizationGate(Protocol):
    def binding_exists(self, capability_ref: str, required_scope: str) -> bool: ...


@dataclass(frozen=True)
class ActivationEvidence:
    capability_ref: str
    source_ref: str
    extraction_ref: str | None
    backend_service: str
    authorization_checked: bool


def validate_route_activation(route: dict, capability: dict, source: dict, extraction: dict | None, authorization: AuthorizationGate | None) -> ActivationEvidence:
    spec = route["spec"]
    capability_ref = spec["capabilityRef"]
    source_ref = spec["sourceRef"]
    if f"{capability['metadata']['id']}@{capability['metadata']['version']}" != capability_ref:
        raise ActivationRejected("CAPABILITY_REFERENCE_MISMATCH")
    if f"{source['metadata']['id']}@{source['metadata']['version']}" != source_ref:
        raise ActivationRejected("SOURCE_RUNTIME_REFERENCE_MISMATCH")
    extraction_ref = spec.get("extractionProfileRef")
    if extraction_ref:
        if extraction is None or f"{extraction['metadata']['id']}@{extraction['metadata']['version']}" != extraction_ref:
            raise ActivationRejected("EXTRACTION_REFERENCE_MISMATCH")
        if extraction["spec"]["sourceRef"] != source_ref:
            raise ActivationRejected("EXTRACTION_SOURCE_MISMATCH")
    backend = spec["backendBinding"]["service"]
    endpoint_ref = source["spec"]["endpointRef"]
    if endpoint_ref.startswith("service://") and endpoint_ref.removeprefix("service://").split("/", 1)[0] != backend:
        raise ActivationRejected("BACKEND_SOURCE_BINDING_MISMATCH")
    required_scope = capability["spec"]["scope"]
    authorization_checked = authorization is not None
    if authorization is not None and not authorization.binding_exists(capability_ref, required_scope):
        raise ActivationRejected("AUTHORIZATION_BINDING_MISSING")
    return ActivationEvidence(capability_ref, source_ref, extraction_ref, backend, authorization_checked)
