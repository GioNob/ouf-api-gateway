from dataclasses import dataclass


class PolicyDenied(RuntimeError):
    def __init__(self, status: int, code: str):
        super().__init__(code)
        self.status = status
        self.code = code


@dataclass(frozen=True)
class RequestIdentity:
    authenticated: bool
    identity_mode: str
    service_principal_id: str | None = None
    actor_type: str | None = None
    scopes: frozenset[str] = frozenset()


def enforce(route: dict, identity: RequestIdentity, content_length: int | None) -> None:
    """Enforce the compiled, registry-owned route policy before upstream I/O."""
    policy = route.get("x-ouf-policy")
    if not isinstance(policy, dict):
        raise PolicyDenied(503, "ROUTE_POLICY_MISSING")
    if not identity.authenticated:
        raise PolicyDenied(401, "AUTHENTICATION_REQUIRED")
    if identity.identity_mode != policy.get("identity"):
        raise PolicyDenied(403, "IDENTITY_MODE_MISMATCH")
    allowed_services = policy.get("allowedServiceIdentities") or []
    if allowed_services and identity.service_principal_id not in allowed_services:
        raise PolicyDenied(403, "SERVICE_IDENTITY_DENIED")
    allowed_actors = policy.get("allowedActorTypes") or []
    if allowed_actors and identity.actor_type not in allowed_actors:
        raise PolicyDenied(403, "ACTOR_TYPE_DENIED")
    required_scope = policy.get("requiredScope")
    if not required_scope or required_scope not in identity.scopes:
        raise PolicyDenied(403, "SCOPE_DENIED")
    maximum = policy.get("maxRequestBytes")
    if not isinstance(maximum, int) or maximum < 1:
        raise PolicyDenied(503, "ROUTE_POLICY_INVALID")
    if content_length is not None:
        if content_length < 0:
            raise PolicyDenied(400, "INVALID_CONTENT_LENGTH")
        if content_length > maximum:
            raise PolicyDenied(413, "REQUEST_TOO_LARGE")
