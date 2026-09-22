package it.comune.trieste.ouf.authorization;

import java.time.Instant;
import java.util.List;
import java.util.Objects;
import java.util.Set;
import java.util.Map;

public final class AuthorizationPolicy {
    private AuthorizationPolicy() {}

    public record CapabilityDescriptor(
            String capabilityId,
            String operation,
            String requiredScope,
            Set<PrincipalContext.ActorType> allowedActors) {
        public CapabilityDescriptor {
            capabilityId = require(capabilityId, "capabilityId");
            operation = require(operation, "operation");
            requiredScope = require(requiredScope, "requiredScope");
            allowedActors = allowedActors == null ? Set.of() : java.util.Collections.unmodifiableSet(new java.util.TreeSet<>(allowedActors));
        }
    }

    public record Grant(
            String grantId,
            String capabilityId,
            String tenantId,
            String subjectId,
            String servicePrincipalId,
            String organizationId,
            Instant validFrom,
            Instant validUntil,
            @com.fasterxml.jackson.annotation.JsonInclude(com.fasterxml.jackson.annotation.JsonInclude.Include.NON_NULL) GrantConstraints constraints) {
        public Grant(String grantId,String capabilityId,String tenantId,String subjectId,String servicePrincipalId,String organizationId,Instant validFrom,Instant validUntil){this(grantId,capabilityId,tenantId,subjectId,servicePrincipalId,organizationId,validFrom,validUntil,null);}
        public Grant {
            grantId = require(grantId, "grantId");
            capabilityId = require(capabilityId, "capabilityId");
            tenantId = require(tenantId, "tenantId");
            validFrom = Objects.requireNonNull(validFrom, "validFrom");
            validUntil = Objects.requireNonNull(validUntil, "validUntil");
            if (!validUntil.isAfter(validFrom)) {
                throw new IllegalArgumentException("validUntil must be after validFrom");
            }
            if ((subjectId == null || subjectId.isBlank()) && (servicePrincipalId == null || servicePrincipalId.isBlank()) && (constraints==null || constraints.externalRoleRef()==null || constraints.externalRoleRef().isBlank())) {
                throw new IllegalArgumentException("grant requires subjectId or servicePrincipalId");
            }
        }

        boolean appliesTo(PrincipalContext principal, ResourceContext resource, Instant now) {
            if (!tenantId.equals(principal.tenantId()) || !tenantId.equals(resource.tenantId())) return false;
            if (now.isBefore(validFrom) || !now.isBefore(validUntil)) return false;
            if (organizationId != null && !organizationId.isBlank() && !organizationId.equals(resource.organizationId())) return false;
            if (subjectId != null && !subjectId.isBlank() && !subjectId.equals(principal.subjectId())) return false;
            return servicePrincipalId == null || servicePrincipalId.isBlank() || servicePrincipalId.equals(principal.servicePrincipalId());
        }
    }

    public record GrantConstraints(String effect,String externalRoleRef,String resourceType,String resourceId,
            Map<String,String> resourceAttributes,Set<String> allowedDataLabels,Set<String> allowedDetailLevels,
            String requiredAcr,Set<String> requiredAmr,Long maxAuthenticationAgeSeconds) {
        public GrantConstraints {
            effect=effect==null?"ALLOW":effect;
            for(String value:new String[]{externalRoleRef,resourceType,resourceId,requiredAcr})if(value!=null&&value.isBlank())throw new IllegalArgumentException("blank constraint");
            if(!Set.of("ALLOW","DENY").contains(effect))throw new IllegalArgumentException("invalid grant effect");
            resourceAttributes=resourceAttributes==null?Map.of():java.util.Collections.unmodifiableMap(new java.util.TreeMap<>(resourceAttributes));
            allowedDataLabels=allowedDataLabels==null?Set.of():java.util.Collections.unmodifiableSet(new java.util.TreeSet<>(allowedDataLabels));
            allowedDetailLevels=allowedDetailLevels==null?Set.of():java.util.Collections.unmodifiableSet(new java.util.TreeSet<>(allowedDetailLevels));
            requiredAmr=requiredAmr==null?Set.of():java.util.Collections.unmodifiableSet(new java.util.TreeSet<>(requiredAmr));
            if(resourceAttributes.size()>64||allowedDataLabels.size()>64||allowedDetailLevels.size()>16||requiredAmr.size()>32)throw new IllegalArgumentException("policy constraints limit");
            if(maxAuthenticationAgeSeconds!=null&&(maxAuthenticationAgeSeconds<1||maxAuthenticationAgeSeconds>86400))throw new IllegalArgumentException("authentication freshness limit");
        }
        boolean matches(PrincipalContext p,ResourceContext r,Instant now){
            var claims=p.claims();
            if(externalRoleRef!=null&&(claims==null||!claims.externalRoleRefs().contains(externalRoleRef)))return false;
            if(resourceType!=null&&!resourceType.equals(r.resourceType()))return false;
            if(resourceId!=null&&!resourceId.equals(r.resourceId()))return false;
            for(var e:resourceAttributes.entrySet())if(!e.getValue().equals(r.attributes().get(e.getKey())))return false;
            if(!allowedDataLabels.isEmpty()&&(r.attributes().get("dataAccessLabel")==null||!allowedDataLabels.contains(r.attributes().get("dataAccessLabel"))))return false;
            if(!allowedDetailLevels.isEmpty()&&(r.attributes().get("detailLevel")==null||!allowedDetailLevels.contains(r.attributes().get("detailLevel"))))return false;
            if(requiredAcr!=null&&(claims==null||!requiredAcr.equals(claims.acr())))return false;
            if(!requiredAmr.isEmpty()&&(claims==null||!claims.amr().containsAll(requiredAmr)))return false;
            if(maxAuthenticationAgeSeconds!=null&&(claims==null||claims.authenticatedAt()==null||now.isBefore(claims.authenticatedAt())||!now.isBefore(claims.authenticatedAt().plusSeconds(maxAuthenticationAgeSeconds))))return false;
            return true;
        }
    }

    public record PolicyBundle(
            String bundleId,
            long version,
            Instant publishedAt,
            List<CapabilityDescriptor> capabilities,
            List<Grant> grants) {
        public PolicyBundle {
            bundleId = require(bundleId, "bundleId");
            if (version < 1) throw new IllegalArgumentException("version must be positive");
            publishedAt = Objects.requireNonNull(publishedAt, "publishedAt");
            capabilities = capabilities == null ? List.of() : List.copyOf(capabilities);
            grants = grants == null ? List.of() : List.copyOf(grants);
            if(capabilities.size()>10000||grants.size()>10000)throw new IllegalArgumentException("bundle cardinality limit");
            var ids=new java.util.HashSet<String>();for(var c:capabilities)if(!ids.add(c.capabilityId()))throw new IllegalArgumentException("duplicate capability");
            var grantIds=new java.util.HashSet<String>();for(var g:grants)if(!grantIds.add(g.grantId())||!ids.contains(g.capabilityId()))throw new IllegalArgumentException("invalid grant reference");
        }
    }

    public record AuthorizationDecision(
            boolean allowed,
            String decisionCode,
            String decisionRef,
            String bundleId,
            long bundleVersion,
            @com.fasterxml.jackson.annotation.JsonInclude(com.fasterxml.jackson.annotation.JsonInclude.Include.NON_NULL) String permittedDetailLevel,
            @com.fasterxml.jackson.annotation.JsonInclude(com.fasterxml.jackson.annotation.JsonInclude.Include.NON_EMPTY) Map<String,String> resourceScope) {
        public AuthorizationDecision(boolean allowed,String decisionCode,String decisionRef,String bundleId,long bundleVersion){this(allowed,decisionCode,decisionRef,bundleId,bundleVersion,null,Map.of());}
        public AuthorizationDecision{resourceScope=resourceScope==null?Map.of():Map.copyOf(resourceScope);}
    }

    public static AuthorizationDecision evaluate(
            PolicyBundle bundle,
            PrincipalContext principal,
            ResourceContext resource,
            String capabilityId,
            String operation,
            Instant now) {
        Objects.requireNonNull(bundle, "bundle");
        Objects.requireNonNull(principal, "principal");
        Objects.requireNonNull(resource, "resource");
        Objects.requireNonNull(now, "now");
        String ref = bundle.bundleId() + ":" + bundle.version() + ":" + capabilityId;
        if (!principal.tenantId().equals(resource.tenantId())) {
            return deny("TENANT_MISMATCH", ref, bundle);
        }
        CapabilityDescriptor descriptor = bundle.capabilities().stream()
                .filter(c -> c.capabilityId().equals(capabilityId) && c.operation().equals(operation))
                .findFirst().orElse(null);
        if (descriptor == null) return deny("CAPABILITY_NOT_DECLARED", ref, bundle);
        if (!descriptor.allowedActors().contains(principal.actorType())) return deny("ACTOR_NOT_ALLOWED", ref, bundle);
        if (!principal.scopes().contains(descriptor.requiredScope())) return deny("SCOPE_MISSING", ref, bundle);
        String label=resource.attributes().get("dataAccessLabel"),detail=resource.attributes().get("detailLevel");
        if("true".equals(resource.attributes().get("requiresDataAccessLabel"))&&(label==null||label.isBlank()))return deny("DATA_LABEL_REQUIRED",ref,bundle);
        if("SECURITY_SENSITIVE".equals(detail)&&principal.actorType()!=PrincipalContext.ActorType.HUMAN)return deny("HUMAN_REQUIRED",ref,bundle);
        boolean allow=false;
        for(var grant:bundle.grants()){
            if(!grant.capabilityId().equals(capabilityId)||!grant.appliesTo(principal,resource,now))continue;
            var constraints=grant.constraints();
            if(constraints!=null&&!constraints.matches(principal,resource,now))continue;
            if(constraints!=null&&"DENY".equals(constraints.effect()))return deny("EXPLICIT_DENY",ref,bundle);
            if(label!=null&&!Set.of("OPEN","ANONYMOUS").contains(label)&&(constraints==null||!constraints.allowedDataLabels().contains(label)))continue;
            if(detail!=null&&!"PUBLIC_OPERATIONAL".equals(detail)&&(constraints==null||!constraints.allowedDetailLevels().contains(detail)))continue;
            allow=true;
        }
        if(!allow)return deny("NO_APPLICABLE_GRANT",ref,bundle);
        var scope=new java.util.LinkedHashMap<String,String>();scope.put("tenantId",resource.tenantId());scope.put("resourceType",resource.resourceType());
        if(resource.resourceId()!=null)scope.put("resourceId",resource.resourceId());
        for(String key:List.of("module","sourceRef","jobRef","dataAccessLabel"))if(resource.attributes().containsKey(key))scope.put(key,resource.attributes().get(key));
        return new AuthorizationDecision(true,"ALLOW",ref,bundle.bundleId(),bundle.version(),resource.attributes().getOrDefault("detailLevel","PUBLIC_OPERATIONAL"),scope);
    }

    private static AuthorizationDecision deny(String code, String ref, PolicyBundle bundle) {
        return new AuthorizationDecision(false, code, ref, bundle.bundleId(), bundle.version());
    }

    private static String require(String value, String name) {
        if (value == null || value.isBlank()) throw new IllegalArgumentException(name + " is required");
        return value;
    }
}
