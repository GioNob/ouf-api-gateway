package it.comune.trieste.ouf.authorization;

import jakarta.servlet.http.HttpServletRequest;
import java.util.*;
import it.comune.trieste.ouf.authorization.AuthorizationPolicy.*;

/** Owner-side resource decisions on the SAME immutable snapshot as request authentication. */
public final class OwnerAuthorization {
 private final LocalAuthorization engine;private final ServletAuthorization.Context context;
 private OwnerAuthorization(LocalAuthorization engine,ServletAuthorization.Context context){this.engine=engine;this.context=context;}
 public static OwnerAuthorization bind(HttpServletRequest request){
  var context=ServletAuthorization.resolve(request);
  return new OwnerAuthorization((LocalAuthorization)request.getServletContext().getAttribute(ServletAuthorization.RUNTIME),context);
 }
 public PrincipalContext principal(){return context.principal();}
 public String decisionRef(){return context.decisionRef();}
 /** Admission only: never sufficient to release data. Every result needs decide/require. */
 public Set<String> candidates(){
  engine.requireFresh(context.snapshot());var out=new HashSet<String>();
  for(var descriptor:context.snapshot().bundle().capabilities())if(descriptor.allowedActors().contains(principal().actorType())&&principal().scopes().contains(descriptor.requiredScope()))out.add(descriptor.capabilityId());
  return Set.copyOf(out);
 }
 public AuthorizationDecision decide(String capability,ResourceContext resource){
  var descriptor=context.snapshot().bundle().capabilities().stream().filter(c->c.capabilityId().equals(capability)).findFirst().orElse(null);
  return engine.evaluate(context.snapshot(),principal(),resource,capability,descriptor==null?"UNDECLARED":descriptor.operation());
 }
 public AuthorizationDecision require(String capability,ResourceContext resource){var decision=decide(capability,resource);if(!decision.allowed())throw new SecurityException("CAPABILITY_DENIED:"+capability+":"+decision.decisionCode());return decision;}
}
