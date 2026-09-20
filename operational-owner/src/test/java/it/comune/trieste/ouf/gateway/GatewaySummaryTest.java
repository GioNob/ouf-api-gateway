package it.comune.trieste.ouf.gateway;

import static org.assertj.core.api.Assertions.assertThat;

import com.fasterxml.jackson.databind.ObjectMapper;
import java.nio.file.Path;
import java.sql.DriverManager;
import java.time.Instant;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.springframework.mock.env.MockEnvironment;

class GatewaySummaryTest {
  private static final ObjectMapper JSON = new ObjectMapper();

  @TempDir Path temp;

  private Path store(boolean fresh) throws Exception {
    Path db=temp.resolve(fresh?"fresh.sqlite":"stale.sqlite");
    try(var connection=DriverManager.getConnection("jdbc:sqlite:"+db)){
      try(var stmt=connection.createStatement()){
        stmt.execute("""
          create table gateway_operational_incident(
            incident_id text primary key,dedup_key text not null unique,module text not null,event_type text not null,
            lifecycle_state text not null,severity text not null,first_seen_at text not null,last_seen_at text not null,
            resolved_at text,correlation_id text,endpoint_ref text,error_code text,impact_summary text not null,
            action_required integer not null,occurrence_count integer not null,visibility_class text not null)
          """);
        stmt.execute("""
          create table gateway_operational_collector_state(
            source text primary key,last_observed_at text not null,last_event_at text)
          """);
      }
      if(fresh){
        String now=Instant.now().toString();
        try(var insert=connection.prepareStatement("insert into gateway_operational_collector_state(source,last_observed_at) values(?,?)")){
          for(String source:new String[]{"APISIX","ETCD"}){
            insert.setString(1,source);insert.setString(2,now);insert.executeUpdate();
          }
        }
      }
    }
    return db;
  }

  private GatewaySummary owner(Path db){
    var env=new MockEnvironment()
      .withProperty("ouf.summary.database-file",db.toString())
      .withProperty("ouf.summary.max-evidence-age-seconds","120");
    return new GatewaySummary(env);
  }

  @Test
  void emptyButFreshStoreMayReportHealthy() throws Exception {
    Map<String,Object> result=owner(store(true)).summary(JSON.readTree("{}"));
    assertThat(result.get("status")).isEqualTo("HEALTHY");
    assertThat(result.get("partial")).isEqualTo(false);
  }

  @Test
  void missingCollectorEvidenceNeverBecomesHealthy() throws Exception {
    Map<String,Object> result=owner(store(false)).summary(JSON.readTree("{}"));
    assertThat(result.get("status")).isEqualTo("UNKNOWN");
    assertThat(result.get("partial")).isEqualTo(true);
  }

  @Test
  void staleCollectorEvidenceNeverBecomesHealthy() throws Exception {
    Path db=store(true);
    try(var connection=DriverManager.getConnection("jdbc:sqlite:"+db);
        var stmt=connection.prepareStatement("update gateway_operational_collector_state set last_observed_at=?")){
      stmt.setString(1,Instant.now().minusSeconds(121).toString());stmt.executeUpdate();
    }
    Map<String,Object> result=owner(db).summary(JSON.readTree("{}"));
    assertThat(result.get("status")).isEqualTo("UNKNOWN");
    assertThat(result.get("partial")).isEqualTo(true);
  }
}
