package it.comune.trieste.ouf.authorization;

import jakarta.servlet.http.HttpServletRequest;
import java.util.*;

/** Shared servlet adapter: ignores client identity/capability headers and legacy capability attributes. */
public final class ServletAuthorization {
  public static final String RUNTIME=LocalAuthorization.class.getName(),RESOURCE=ResourceContext.class.getName();
  private static final String PIN=ServletAuthorization.class.getName()+".snapshot";
  private ServletAuthorization() {}
  public record Context(PrincipalContext principal,Set<String> capabilities,String decisionRef,LocalAuthorization.PolicySnapshot snapshot,Map<String,AuthorizationPolicy.AuthorizationDecision> decisions) {
    public Context(PrincipalContext principal,Set<String> capabilities,String decisionRef,LocalAuthorization.PolicySnapshot snapshot){this(principal,capabilities,decisionRef,snapshot,Map.of());}
    public Context{decisions=Map.copyOf(decisions);}
  }
  public static Context resolve(HttpServletRequest request) {
    if(!(request.getUserPrincipal() instanceof TrustedPrincipal trusted))throw new SecurityException("TRUSTED_PRINCIPAL_REQUIRED");
    Object runtime=request.getServletContext().getAttribute(RUNTIME);
    if(!(runtime instanceof LocalAuthorization engine))throw new SecurityException("NO_POLICY_BUNDLE");
    var principal=trusted.context();
    Object supplied=request.getAttribute(RESOURCE);
    // Domain adapters may supply only a server-resolved resource. Never parse this from a header/body.
    var resource=supplied instanceof ResourceContext r?r:new ResourceContext("capability",null,principal.tenantId(),null,Map.of());
    if(!resource.tenantId().equals(principal.tenantId()))throw new SecurityException("TENANT_MISMATCH");
    var snapshot=request.getAttribute(PIN) instanceof LocalAuthorization.PolicySnapshot p?p:engine.currentSnapshot();
    request.setAttribute(PIN,snapshot);engine.requireFresh(snapshot);
    Set<String> allowed=new HashSet<>();Map<String,AuthorizationPolicy.AuthorizationDecision> decisions=new HashMap<>();
    for(var c:snapshot.bundle().capabilities()){var decision=engine.evaluate(snapshot,principal,resource,c.capabilityId(),c.operation());decisions.put(c.capabilityId(),decision);if(decision.allowed())allowed.add(c.capabilityId());}
    return new Context(principal,Set.copyOf(allowed),snapshot.bundle().bundleId()+":"+snapshot.bundle().version(),snapshot,decisions);
  }
  public static Context require(HttpServletRequest request,String capability,boolean humanOnly){
    var c=resolve(request);
    if(humanOnly&&c.principal().actorType()!=PrincipalContext.ActorType.HUMAN)throw new SecurityException("HUMAN_REQUIRED");
    if(!c.capabilities().contains(capability))throw new SecurityException("CAPABILITY_DENIED:"+capability);
    return c;
  }
}
