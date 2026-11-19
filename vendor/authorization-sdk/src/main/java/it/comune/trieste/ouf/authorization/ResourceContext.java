package it.comune.trieste.ouf.authorization;

import java.util.Map;

public record ResourceContext(
        String resourceType,
        String resourceId,
        String tenantId,
        String organizationId,
        Map<String, String> attributes) {

    public ResourceContext {
        resourceType = require(resourceType, "resourceType");
        tenantId = require(tenantId, "tenantId");
        attributes = attributes == null ? Map.of() : Map.copyOf(attributes);
    }

    private static String require(String value, String name) {
        if (value == null || value.isBlank()) {
            throw new IllegalArgumentException(name + " is required");
        }
        return value;
    }
}
