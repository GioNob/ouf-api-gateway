package it.comune.trieste.ouf.gateway;
import static org.assertj.core.api.Assertions.*;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.nio.file.*;
import java.sql.*;
import java.time.*;
import java.util.*;
import org.junit.jupiter.api.*;
import org.junit.jupiter.api.io.TempDir;
import org.springframework.mock.env.MockEnvironment;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.web.server.ResponseStatusException;
class GatewayIncidentsTest {
 @TempDir Path temp;
 final ObjectMapper json=new ObjectMapper();
 Path db;
 GatewayIncidents owner;
 @BeforeEach void setup()throws Exception{
  db=temp.resolve("incidents.db");owner=new GatewayIncidents(new MockEnvironment().withProperty("ouf.summary.database-file",db.toString()),json);
  try(var c=DriverManager.getConnection("jdbc:sqlite:"+db);var s=c.createStatement()){s.execute("create table gateway_incident_transition(sequence_id integer primary key autoincrement,incident_id text,projection text)");}
 }
 void emit(String id,String state,String visibility)throws Exception{
  emit(id,id,state,visibility);
 }
 void emit(String id,String dedupKey,String state,String visibility)throws Exception{
  var row=new LinkedHashMap<String,Object>(Map.of("incident_id",id,"module","GATEWAY","lifecycle_state",state,"severity","ERROR","last_seen_at",Instant.now().toString(),"visibility_class",visibility,"raw_log","secret","action_required",true));
  if(dedupKey!=null)row.put("dedup_key",dedupKey);
  try(var c=DriverManager.getConnection("jdbc:sqlite:"+db);var s=c.prepareStatement("insert into gateway_incident_transition(incident_id,projection) values(?,?)")){s.setString(1,id);s.setString(2,json.writeValueAsString(row));s.executeUpdate();}
 }
 @Test void snapshotSurvivesNewOwnerAndRecoveryAndBindsPrincipal()throws Exception{
  emit("a","OPEN","TENANT_OPERATIONAL");emit("b","OPEN","TENANT_OPERATIONAL");
  var first=owner.page(json.readTree("{\"limit\":1}"),"tenant:reader");
  assertThat(first.get("hasMore")).isEqualTo(true);assertThat(json.writeValueAsString(first)).doesNotContain("secret","raw_log");
  emit("a","RESOLVED","TENANT_OPERATIONAL");emit("c","OPEN","TENANT_OPERATIONAL");
  var query=json.createObjectNode().put("limit",1).put("cursor",(String)first.get("nextCursor"));
  var restarted=new GatewayIncidents(new MockEnvironment().withProperty("ouf.summary.database-file",db.toString()),json);
  var second=restarted.page(query,"tenant:reader");
  assertThat(second.get("hasMore")).isEqualTo(false);assertThat(json.writeValueAsString(second)).contains("\"incident_id\":\"a\"","\"lifecycle_state\":\"OPEN\"");
  assertThatThrownBy(()->restarted.page(query,"tenant:other")).isInstanceOf(ResponseStatusException.class);
 }
 @Test void restrictedEvidenceIsExplicitlyPartialAndDirectHeadersDoNotAuthenticate()throws Exception{
  emit("restricted","OPEN","RESTRICTED_OPERATIONAL");
  var result=owner.page(json.readTree("{}"),"tenant:reader");assertThat(result.get("items")).isEqualTo(List.of());assertThat(result.get("partial")).isEqualTo(true);
  var req=new MockHttpServletRequest();req.addHeader("X-OUF-Gateway-Verified","true");req.addHeader("X-OUF-Principal-ID","admin");
  assertThatThrownBy(()->owner.incidents(json.readTree("{}"),req)).isInstanceOf(ResponseStatusException.class);
 }
 @Test void visibilityRestrictionMustApplyToExistingCursor()throws Exception{
  emit("a","OPEN","TENANT_OPERATIONAL");emit("b","OPEN","TENANT_OPERATIONAL");
  var first=owner.page(json.readTree("{\"limit\":1}"),"tenant:reader");
  emit("a","OPEN","RESTRICTED_OPERATIONAL");
  var query=json.createObjectNode().put("limit",1).put("cursor",(String)first.get("nextCursor"));
  var second=owner.page(query,"tenant:reader");
  assertThat(second.get("items")).isEqualTo(List.of());
  assertThat(second.get("partial")).isEqualTo(true);
 }
 @Test void criticalFilterMustBeAccepted()throws Exception{
  assertThatCode(()->owner.page(json.readTree("{\"severity\":\"CRITICAL\"}"),"tenant:reader")).doesNotThrowAnyException();
 }
 @Test void newEpisodeVisibilityAppliesToAllEpisodesAndExistingCursor()throws Exception{
  emit("episode-1","shared","OPEN","TENANT_OPERATIONAL");
  emit("episode-1","shared","RESOLVED","TENANT_OPERATIONAL");
  emit("other","OPEN","TENANT_OPERATIONAL");
  var first=owner.page(json.readTree("{\"limit\":1}"),"tenant:reader");
  assertThat(first.get("hasMore")).isEqualTo(true);
  var query=json.createObjectNode().put("limit",1).put("cursor",(String)first.get("nextCursor"));
  emit("episode-2","shared","OPEN","RESTRICTED_OPERATIONAL");
  var hidden=owner.page(query,"tenant:reader");
  assertThat(hidden.get("items")).isEqualTo(List.of());
  assertThat(hidden.get("partial")).isEqualTo(true);
  assertThat(hidden.get("authorization")).isEqualTo("REDACTED");
  assertThat(hidden.get("hasMore")).isEqualTo(false);
  var historical=owner.page(json.createObjectNode().put("until",(String)first.get("until")),"tenant:reader");
  assertThat(json.valueToTree(historical.get("items")).size()).isEqualTo(1);
  assertThat(historical.get("partial")).isEqualTo(true);

  emit("episode-2","shared","OPEN","TENANT_OPERATIONAL");
  var restored=owner.page(query,"tenant:reader");
  var oldItems=json.valueToTree(restored.get("items"));
  assertThat(oldItems.size()).isEqualTo(1);
  assertThat(oldItems.get(0).path("incident_id").asText()).isEqualTo("episode-1");
  assertThat(oldItems.get(0).path("lifecycle_state").asText()).isEqualTo("RESOLVED");
  assertThat(restored.get("partial")).isEqualTo(false);
  var current=owner.page(json.readTree("{}"),"tenant:reader");
  var items=json.valueToTree(current.get("items"));
  assertThat(items.size()).isEqualTo(3);
  assertThat(items.get(0).path("incident_id").asText()).isEqualTo("episode-2");
  assertThat(items.get(0).path("lifecycle_state").asText()).isEqualTo("OPEN");
  assertThat(items.get(2).path("incident_id").asText()).isEqualTo("episode-1");
  assertThat(items.get(2).path("lifecycle_state").asText()).isEqualTo("RESOLVED");
  assertThat(current.get("partial")).isEqualTo(false);
 }
 @Test void historicalProjectionWithoutDedupKeyFailsClosed()throws Exception{
  emit("legacy",null,"RESOLVED","TENANT_OPERATIONAL");
  emit("other","OPEN","TENANT_OPERATIONAL");
  var first=owner.page(json.readTree("{\"limit\":1}"),"tenant:reader");
  emit("legacy","shared","RESOLVED","TENANT_OPERATIONAL");
  var query=json.createObjectNode().put("limit",1).put("cursor",(String)first.get("nextCursor"));
  var hidden=owner.page(query,"tenant:reader");
  assertThat(hidden.get("items")).isEqualTo(List.of());
  assertThat(hidden.get("partial")).isEqualTo(true);
  assertThat(hidden.get("authorization")).isEqualTo("REDACTED");
  assertThat(hidden.get("hasMore")).isEqualTo(false);
 }
 @Test void sameDedupKeyKeepsResolvedAndNewEpisodesDistinct()throws Exception{
  var start=Instant.now().minusSeconds(120);
  var closed=start.plusSeconds(30).toString();
  var next=start.plusSeconds(60).toString();
  var base=json.createObjectNode().put("module","GATEWAY").put("dedup_key","gateway:etcd:collector-health")
   .put("event_type","GATEWAY_ETCD_DEGRADED").put("severity","CRITICAL").put("visibility_class","TENANT_OPERATIONAL");
  var opened=base.deepCopy().put("incident_id","episode-1").put("lifecycle_state","OPEN")
   .put("first_seen_at",start.toString()).put("last_seen_at",start.toString()).put("occurrence_count",2).put("action_required",true);
  var resolved=opened.deepCopy().put("lifecycle_state","RESOLVED").put("last_seen_at",closed)
   .put("resolved_at",closed).put("action_required",false);
  var reopened=base.deepCopy().put("incident_id","episode-2").put("lifecycle_state","OPEN")
   .put("first_seen_at",next).put("last_seen_at",next).put("occurrence_count",1).put("action_required",true);
  try(var c=DriverManager.getConnection("jdbc:sqlite:"+db);var s=c.prepareStatement("insert into gateway_incident_transition(incident_id,projection) values(?,?)")){
   for(var row:List.of(opened,resolved,reopened)){s.setString(1,row.get("incident_id").asText());s.setString(2,json.writeValueAsString(row));s.executeUpdate();}
  }
  var result=owner.page(json.readTree("{}"),"tenant:reader");
  var items=json.valueToTree(result.get("items"));
  assertThat(items.size()).isEqualTo(2);
  assertThat(items.get(0).path("incident_id").asText()).isEqualTo("episode-2");
  assertThat(items.get(0).path("lifecycle_state").asText()).isEqualTo("OPEN");
  assertThat(items.get(0).path("first_seen_at").asText()).isEqualTo(next);
  assertThat(items.get(0).path("occurrence_count").asLong()).isEqualTo(1);
  assertThat(items.get(1).path("incident_id").asText()).isEqualTo("episode-1");
  assertThat(items.get(1).path("lifecycle_state").asText()).isEqualTo("RESOLVED");
  assertThat(items.get(1).path("resolved_at").asText()).isEqualTo(closed);
  assertThat(items.get(1).path("occurrence_count").asLong()).isEqualTo(2);
  assertThat(result.get("partial")).isEqualTo(false);assertThat(result.get("hasMore")).isEqualTo(false);
 }
}
