package it.comune.trieste.ouf.authorization;
import static org.junit.jupiter.api.Assertions.*;
import it.comune.trieste.ouf.authorization.AuthorizationPolicy.*;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import java.util.*;
class OwnerAuthorizationTest {
 @Test void scopedGrantUsesOwnerResourceAndRequestSnapshot()throws Exception{
  var request=new MockHttpServletRequest();TestAuthorization.bind(request,"reader","HUMAN",Set.of("read"));
  var engine=(LocalAuthorization)request.getServletContext().getAttribute(ServletAuthorization.RUNTIME);var old=engine.currentSnapshot().bundle();var g=old.grants().getFirst();
  var c=new GrantConstraints("ALLOW",null,"object","42",Map.of(),Set.of("OPEN"),Set.of(),null,Set.of(),null);
  var scoped=new Grant(g.grantId(),g.capabilityId(),g.tenantId(),g.subjectId(),g.servicePrincipalId(),g.organizationId(),g.validFrom(),g.validUntil(),c);
  TestAuthorization.install(engine,new PolicyBundle(old.bundleId(),2,old.publishedAt(),old.capabilities(),List.of(scoped)));
  var owner=OwnerAuthorization.bind(request);var resource=new ResourceContext("object","42","tenant-a",null,Map.of("dataAccessLabel","OPEN"));
  assertTrue(owner.candidates().contains("read"));assertFalse(ServletAuthorization.resolve(request).capabilities().contains("read"));assertTrue(owner.require("read",resource).allowed());
  assertFalse(owner.decide("read",new ResourceContext("object","43","tenant-a",null,Map.of("dataAccessLabel","OPEN"))).allowed());
  TestAuthorization.install(engine,new PolicyBundle(old.bundleId(),3,old.publishedAt(),old.capabilities(),List.of()));assertTrue(owner.require("read",resource).allowed());
  var next=new MockHttpServletRequest(request.getServletContext());next.setUserPrincipal(request.getUserPrincipal());assertFalse(OwnerAuthorization.bind(next).decide("read",resource).allowed());
 }
}
