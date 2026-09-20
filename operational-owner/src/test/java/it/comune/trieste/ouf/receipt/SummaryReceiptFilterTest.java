package it.comune.trieste.ouf.receipt;

import static org.junit.jupiter.api.Assertions.*;
import com.fasterxml.jackson.databind.*;
import it.comune.trieste.ouf.authorization.*;
import it.comune.trieste.ouf.authorization.AuthorizationPolicy.*;
import java.nio.file.*;
import java.time.*;
import java.util.*;
import java.util.concurrent.atomic.AtomicBoolean;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.springframework.mock.web.*;

class SummaryReceiptFilterTest {
  @TempDir Path tmp;
  final Clock clock=Clock.fixed(Instant.ofEpochSecond(1000),ZoneOffset.UTC);
  List<JsonNode> vectors()throws Exception{return new ObjectMapper().readValue(getClass().getResourceAsStream("/operational-receipts.json"),new com.fasterxml.jackson.core.type.TypeReference<List<JsonNode>>(){});}
  LocalAuthorization engine(String owner,boolean grant,long version)throws Exception{
    var engine=new LocalAuthorization(clock,Duration.ofSeconds(300));String cap="ouf."+owner+".operations.summary";
    var constraints=new GrantConstraints("ALLOW","ouf:viewer", "capability",null,Map.of(),Set.of(),Set.of("TENANT_OPERATIONAL"),null,Set.of(),null);
    var grants=grant?List.of(new Grant("g",cap,"tenant-a",null,null,null,Instant.EPOCH,Instant.ofEpochSecond(2000),constraints)):List.<Grant>of();
    TestAuthorization.install(engine,new PolicyBundle("bundle",version,Instant.EPOCH,List.of(new CapabilityDescriptor(cap,"READ","operations.status.read",Set.of(PrincipalContext.ActorType.HUMAN))),grants));return engine;
  }
  int call(JsonNode vector,String body,String receipt,LocalAuthorization engine,Clock requestClock,String targetOwner,String tenant)throws Exception{
    Path key=tmp.resolve("key");Files.writeString(key,"ab".repeat(32));
    var filter=new SummaryReceiptFilter(targetOwner,tenant,"https://auth.test/realms/ouf","gateway","workload",key,requestClock);
    var req=new MockHttpServletRequest("POST","/api/internal/v1/"+targetOwner+"/operations/summary");
    req.getServletContext().setAttribute(ServletAuthorization.RUNTIME,engine);req.setContent(body.getBytes(java.nio.charset.StandardCharsets.UTF_8));
    if(receipt!=null)req.addHeader(SummaryReceiptFilter.HEADER,receipt);
    req.addHeader("X-OUF-Principal-ID","forged-admin");req.addHeader("X-OUF-External-Role-Refs","ouf:admin");
    var res=new MockHttpServletResponse();var read=new AtomicBoolean();
    filter.doFilter(req,res,(request,response)->{
      read.set(true);var principal=(TrustedPrincipal)((jakarta.servlet.http.HttpServletRequest)request).getUserPrincipal();
      assertEquals("human-a",principal.getName());assertEquals(Set.of("ouf:viewer"),principal.context().claims().externalRoleRefs());
      assertEquals(body,new String(request.getInputStream().readAllBytes(),java.nio.charset.StandardCharsets.UTF_8));
      ((jakarta.servlet.http.HttpServletResponse)response).setStatus(204);
    });
    assertEquals(res.getStatus()==204,read.get());return res.getStatus();
  }
  @Test void realLuaReceiptsRequireRoleFreshPolicyAndBodyIntegrity()throws Exception{
    for(var v:vectors()){
      String owner=v.path("owner").asText(),body=v.path("body").asText(),receipt=v.path("receipt").asText();
      var auth=engine(owner,true,6);
      assertEquals(v.path("hasRole").asBoolean()?204:403,call(v,body,receipt,auth,clock,owner,"tenant-a"));
      assertEquals(403,call(v,body,receipt,engine(owner,false,6),clock,owner,"tenant-a"));
      assertEquals(403,call(v,body,receipt,engine(owner,true,7),clock,owner,"tenant-a"));
      assertEquals(403,call(v,body+" ",receipt,auth,clock,owner,"tenant-a"));
      assertEquals(403,call(v,body,null,auth,clock,owner,"tenant-a"));
      assertEquals(403,call(v,body,receipt,auth,Clock.offset(clock,Duration.ofSeconds(30)),owner,"tenant-a"));
      assertEquals(403,call(v,body,receipt,auth,clock,owner,"other"));
      assertEquals(403,call(v,body,receipt,auth,clock,owner.equals("gateway")?"ingestion":"gateway","tenant-a"));
    }
  }
}
