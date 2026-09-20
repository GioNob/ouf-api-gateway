package it.comune.trieste.ouf.authorization;

import java.util.Objects;
import java.util.Set;

public record PrincipalContext(
        String subjectId,
        String tenantId,
        ActorType actorType,
        String servicePrincipalId,
        String authenticationContextRef,
        String issuer,
        String audience,
        Set<String> scopes,
        @com.fasterxml.jackson.annotation.JsonInclude(com.fasterxml.jackson.annotation.JsonInclude.Include.NON_NULL) IdentityClaims claims) {

    public PrincipalContext(String subjectId,String tenantId,ActorType actorType,String servicePrincipalId,String authenticationContextRef,String issuer,String audience,Set<String> scopes){this(subjectId,tenantId,actorType,servicePrincipalId,authenticationContextRef,issuer,audience,scopes,null);}
    public record IdentityClaims(Set<String> externalRoleRefs,String acr,Set<String> amr,java.time.Instant authenticatedAt){
      public IdentityClaims{externalRoleRefs=externalRoleRefs==null?Set.of():Set.copyOf(externalRoleRefs);amr=amr==null?Set.of():Set.copyOf(amr);if(externalRoleRefs.size()>256||amr.size()>32)throw new IllegalArgumentException("identity claims limit");}
    }
    public PrincipalContext {
        subjectId = require(subjectId, "subjectId");
        tenantId = require(tenantId, "tenantId");
        actorType = Objects.requireNonNull(actorType, "actorType");
        authenticationContextRef = require(authenticationContextRef, "authenticationContextRef");
        issuer = require(issuer, "issuer");
        audience = require(audience, "audience");
        scopes = scopes == null ? Set.of() : Set.copyOf(scopes);
        if (actorType == ActorType.SERVICE && (servicePrincipalId == null || servicePrincipalId.isBlank())) {
            throw new IllegalArgumentException("servicePrincipalId is required for SERVICE actor");
        }
    }

    private static String require(String value, String name) {
        if (value == null || value.isBlank()) {
            throw new IllegalArgumentException(name + " is required");
        }
        return value;
    }

    public enum ActorType {
        HUMAN,
        SERVICE,
        AI_AGENT
    }
}
