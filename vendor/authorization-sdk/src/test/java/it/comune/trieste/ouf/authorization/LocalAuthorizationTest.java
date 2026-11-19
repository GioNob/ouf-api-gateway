package it.comune.trieste.ouf.authorization;

import static org.assertj.core.api.Assertions.*;
import java.nio.file.*;
import java.time.*;
import java.util.*;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import it.comune.trieste.ouf.authorization.AuthorizationPolicy.*;

class LocalAuthorizationTest {
  @Test void noBundleAndUnverifiedPrincipalFailClosed(){
    var runtime=new LocalAuthorization(Clock.systemUTC(),Duration.ofMinutes(5));
    assertThatThrownBy(runtime::currentSnapshot).hasMessage("NO_POLICY_BUNDLE");
    var request=new MockHttpServletRequest();request.setUserPrincipal(()->"forged");
    request.setAttribute("ouf.capabilities",Set.of("read"));request.addHeader("X-OUF-Actor-Type","HUMAN");
    assertThatThrownBy(()->ServletAuthorization.resolve(request)).hasMessage("TRUSTED_PRINCIPAL_REQUIRED");
  }
  @Test void gatewayCoarseAllowCannotOverrideLocalDenyAndUnknownCapability(){
    var request=new MockHttpServletRequest();TestAuthorization.bind(request,"human","HUMAN",Set.of("read"));
    request.setAttribute("ouf.authorizedCapabilities",Set.of("write"));
    assertThat(ServletAuthorization.require(request,"read",false).capabilities()).containsExactly("read");
    assertThatThrownBy(()->ServletAuthorization.require(request,"write",false)).hasMessage("CAPABILITY_DENIED:write");
    request.setAttribute(ServletAuthorization.RESOURCE,new ResourceContext("object","42","other-tenant",null,Map.of()));
    assertThatThrownBy(()->ServletAuthorization.resolve(request)).hasMessage("TENANT_MISMATCH");
  }
  @Test void pinSurvivesAtomicSwapAndNextRequestUsesNewBundle()throws Exception{
    var request=new MockHttpServletRequest();TestAuthorization.bind(request,"human","HUMAN",Set.of("read"));
    var engine=(LocalAuthorization)request.getServletContext().getAttribute(ServletAuthorization.RUNTIME);
    var first=ServletAuthorization.require(request,"read",true);
    TestAuthorization.install(engine,new PolicyBundle("fixture",2,Instant.now(),List.of(),List.of()));
    assertThat(ServletAuthorization.require(request,"read",true).snapshot()).isSameAs(first.snapshot());
    var next=new MockHttpServletRequest(request.getServletContext());next.setUserPrincipal(request.getUserPrincipal());
    assertThatThrownBy(()->ServletAuthorization.require(next,"read",true)).hasMessage("CAPABILITY_DENIED:read");
  }
  @Test void tamperedIncompatibleAndRollbackBundlesNeverReplaceKnownGood()throws Exception{
    var engine=TestAuthorization.runtime("human","HUMAN",Set.of("read"));var before=engine.currentSnapshot();
    Path file=Files.createTempFile("tampered-", ".json");
    try {Files.writeString(file,"{}");
      assertThat(engine.refresh(new LocalAuthorization.BundleReference(file,"fixture",2,"0".repeat(64),1)).installed()).isFalse();
      assertThat(engine.refresh(new LocalAuthorization.BundleReference(file,"fixture",2,"0".repeat(64),2)).reason()).isEqualTo("INCOMPATIBLE_POLICY_BUNDLE");
      assertThat(engine.currentSnapshot()).isSameAs(before);
      TestAuthorization.install(engine,new PolicyBundle("fixture",2,Instant.now(),List.of(),List.of()));
      assertThatThrownBy(()->TestAuthorization.install(engine,before.bundle())).hasMessage("BUNDLE_ROLLBACK_REJECTED");
    }finally{Files.delete(file);}
  }
  @Test void serviceCannotUseHumanOnlyOperation(){
    var request=new MockHttpServletRequest();TestAuthorization.bind(request,"service","SERVICE",Set.of("approve"));
    assertThatThrownBy(()->ServletAuthorization.require(request,"approve",true)).hasMessage("HUMAN_REQUIRED");
  }
  @Test void stalePinnedSnapshotFailsClosed()throws Exception{
    final Instant[] now={Instant.parse("2026-09-16T00:00:00Z")};
    Clock clock=new Clock(){public ZoneId getZone(){return ZoneOffset.UTC;}public Clock withZone(ZoneId z){return this;}public Instant instant(){return now[0];}};
    var engine=new LocalAuthorization(clock,Duration.ofSeconds(10));
    TestAuthorization.install(engine,new PolicyBundle("test",1,now[0],List.of(),List.of()));
    var pinned=engine.currentSnapshot();now[0]=now[0].plusSeconds(10);
    assertThatThrownBy(()->engine.requireFresh(pinned)).hasMessage("STALE_POLICY_BUNDLE");assertThat(engine.health().ready()).isFalse();
  }
}
