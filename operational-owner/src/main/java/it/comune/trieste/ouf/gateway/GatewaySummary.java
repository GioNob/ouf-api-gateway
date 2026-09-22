package it.comune.trieste.ouf.gateway;

import com.fasterxml.jackson.databind.JsonNode;
import java.nio.file.*;
import java.sql.*;
import java.time.*;
import java.util.*;
import org.springframework.core.env.Environment;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.server.ResponseStatusException;

/** Reads the existing Gateway-owned incident store. Creates no store and owns no domain data. */
@RestController
public class GatewaySummary {
  private static final Set<String> REQUIRED_COLLECTORS=Set.of("APISIX","ETCD");
  private final Path database;
  private final long maxEvidenceAgeSeconds;

  public GatewaySummary(Environment env){
    database=Path.of(env.getRequiredProperty("ouf.summary.database-file")).toAbsolutePath();
    try{maxEvidenceAgeSeconds=Long.parseLong(env.getRequiredProperty("ouf.summary.max-evidence-age-seconds"));}
    catch(RuntimeException e){throw new IllegalArgumentException("invalid ouf.summary.max-evidence-age-seconds",e);}
    if(maxEvidenceAgeSeconds<1||maxEvidenceAgeSeconds>3600)throw new IllegalArgumentException("ouf.summary.max-evidence-age-seconds outside bounds");
  }

  @PostMapping("/api/internal/v1/gateway/operations/summary")
  public Map<String,Object> summary(@RequestBody JsonNode query){
    if(!query.isObject())throw badRequest();
    query.fieldNames().forEachRemaining(k->{if(!Set.of("limit","since").contains(k))throw badRequest();});
    int limit=50;
    if(query.has("limit")){if(!query.get("limit").isIntegralNumber()||!query.get("limit").canConvertToInt())throw badRequest();limit=query.get("limit").asInt();}
    if(limit<1||limit>100)throw badRequest();
    Instant now=Instant.now(),since=now.minus(Duration.ofDays(1));
    if(query.has("since")){try{since=OffsetDateTime.parse(query.get("since").textValue()).toInstant();}catch(Exception e){throw badRequest();}}
    if(since.isAfter(now)||since.isBefore(now.minus(Duration.ofDays(30))))throw badRequest();
    if(!Files.isRegularFile(database))throw unavailable();

    try(var db=DriverManager.getConnection("jdbc:sqlite:"+database.toUri()+"?mode=ro")){
      db.setAutoCommit(false); // Pin counts, freshness, visibility and page to one read snapshot.
      long open=0,recovering=0,restricted=0;
      try(var stmt=db.createStatement()){
        stmt.setQueryTimeout(3);
        try(var rows=stmt.executeQuery("select lifecycle_state,visibility_class,count(*) as n from gateway_operational_incident group by lifecycle_state,visibility_class")){
          while(rows.next()){
            if(!Set.of("TENANT_OPERATIONAL","PUBLIC_OPERATIONAL").contains(rows.getString(2)))restricted+=rows.getLong(3);
            if("OPEN".equals(rows.getString(1)))open+=rows.getLong(3);
            if("RECOVERING".equals(rows.getString(1)))recovering+=rows.getLong(3);
          }
        }
      }

      boolean freshEvidence=collectorEvidenceFresh(db,now);
      var items=new ArrayList<Map<String,Object>>();
      boolean partial=restricted>0||!freshEvidence;
      try(var stmt=db.prepareStatement("select incident_id,module,event_type,lifecycle_state,severity,first_seen_at,last_seen_at,resolved_at,error_code,impact_summary,action_required,visibility_class from gateway_operational_incident where julianday(last_seen_at)>=julianday(?) and julianday(last_seen_at)<=julianday(?) and visibility_class in ('TENANT_OPERATIONAL','PUBLIC_OPERATIONAL') order by julianday(last_seen_at) desc,incident_id limit ?")){
        stmt.setQueryTimeout(3);stmt.setString(1,since.toString());stmt.setString(2,now.toString());stmt.setInt(3,limit+1);
        try(var rows=stmt.executeQuery()){
          while(rows.next()){
            if(items.size()>=limit){partial=true;break;}
            var item=new LinkedHashMap<String,Object>();
            for(String field:List.of("incident_id","module","event_type","lifecycle_state","severity","first_seen_at","last_seen_at","resolved_at","error_code","impact_summary","visibility_class")){
              String value=rows.getString(field);if(value!=null){if(value.length()>2048)throw unavailable();item.put(field,value);}
            }
            item.put("action_required",rows.getBoolean("action_required"));items.add(item);
          }
        }
      }

      var result=new LinkedHashMap<String,Object>();
      result.put("module","GATEWAY");result.put("items",items);result.put("partial",partial);
      result.put("status",restricted>0?"UNKNOWN":open>0?"DEGRADED":recovering>0?"RECOVERING":!freshEvidence?"UNKNOWN":"HEALTHY");
      result.put("visibilityClass","TENANT_OPERATIONAL");result.put("redacted",true);
      if(restricted==0){result.put("openIncidents",open);result.put("recoveringIncidents",recovering);}else result.put("authorization","REDACTED");
      return result;
    }catch(SQLException e){throw unavailable();}
  }

  private boolean collectorEvidenceFresh(Connection db,Instant now){
    var observed=new HashMap<String,Instant>();
    try(var stmt=db.createStatement()){
      stmt.setQueryTimeout(3);
      try(var rows=stmt.executeQuery("select source,last_observed_at from gateway_operational_collector_state")){
        while(rows.next()){
          try{observed.put(rows.getString(1),Instant.parse(rows.getString(2)));}
          catch(RuntimeException ignored){return false;}
        }
      }
    }catch(SQLException e){
      // A pre-collector store is valid historical evidence but cannot prove current health.
      return false;
    }
    for(String source:REQUIRED_COLLECTORS){
      Instant at=observed.get(source);
      if(at==null||at.isAfter(now.plusSeconds(5))||Duration.between(at,now).getSeconds()>maxEvidenceAgeSeconds)return false;
    }
    return true;
  }

  private static ResponseStatusException badRequest(){return new ResponseStatusException(HttpStatus.BAD_REQUEST,"INVALID_SUMMARY_QUERY");}
  private static ResponseStatusException unavailable(){return new ResponseStatusException(HttpStatus.SERVICE_UNAVAILABLE,"OPERATIONAL_STORE_UNAVAILABLE");}
}
