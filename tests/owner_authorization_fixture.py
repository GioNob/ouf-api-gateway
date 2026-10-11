"""Test fixture only. Not a runtime authorizer or implicit deployment grant."""
def fixture_owner_authorize(headers, capability, resource):
    return {"allowed": True, "identity": {"principal": headers["X-OUF-Principal-ID"],
            "tenant": headers["X-OUF-Tenant-ID"], "actor": "HUMAN", "authenticationContextRef": "fixture-authentication"},
            "policyRef": "fixture-policy:1", "permittedDetailLevel": "RESTRICTED_OPERATIONAL", "resource": resource}
