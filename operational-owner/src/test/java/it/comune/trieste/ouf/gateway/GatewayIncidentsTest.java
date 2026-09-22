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
  var row=Map.of("incident_id",id,"module","GATEWAY","lifecycle_state",state,"severity","ERROR","last_seen_at",Instant.now().toString(),"visibility_class",visibility,"raw_log","secret","action_required",true);
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
}
