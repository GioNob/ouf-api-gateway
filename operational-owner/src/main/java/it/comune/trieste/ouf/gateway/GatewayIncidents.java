package it.comune.trieste.ouf.gateway;

import com.fasterxml.jackson.databind.*;
import it.comune.trieste.ouf.authorization.OwnerAuthorization;
import it.comune.trieste.ouf.authorization.ResourceContext;
import jakarta.servlet.http.HttpServletRequest;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.security.MessageDigest;
import java.sql.*;
import java.time.*;
import java.util.*;
import org.springframework.core.env.Environment;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.server.ResponseStatusException;

/** Read-only access to collector-owned SQLite history; receipts and policy are checked per page. */
@RestController
public class GatewayIncidents {
  private final Path database;
  private final ObjectMapper json;
  public GatewayIncidents(Environment env,ObjectMapper json){database=Path.of(env.getRequiredProperty("ouf.summary.database-file")).toAbsolutePath();this.json=json;}
  @PostMapping("/api/internal/v1/gateway/operations/incidents")
  public Map<String,Object> incidents(@RequestBody JsonNode query,HttpServletRequest request){
    try{
      var owner=OwnerAuthorization.bind(request);
      var decision=owner.require("ouf.gateway.operations.incidents",new ResourceContext("capability",null,owner.principal().tenantId(),null,Map.of("detailLevel","TENANT_OPERATIONAL")));
      if(!"TENANT_OPERATIONAL".equals(decision.permittedDetailLevel()))throw new SecurityException();
      return page(query,owner.principal().tenantId()+":"+owner.principal().subjectId());
    }catch(SecurityException e){throw new ResponseStatusException(HttpStatus.FORBIDDEN,"NOT_AUTHORIZED");}
  }
  record Cursor(long snapshot,long before,String since,String until,long expires,String binding){}
  Map<String,Object> page(JsonNode q,String principal){
    if(!q.isObject())throw bad();
    q.fieldNames().forEachRemaining(k->{if(!Set.of("limit","state","severity","sourceId","jobId","since","until","cursor").contains(k))throw bad();});
    int limit=50;
    if(q.has("limit")){if(!q.get("limit").isIntegralNumber()||!q.get("limit").canConvertToInt())throw bad();limit=q.get("limit").asInt();}
    if(limit<1||limit>100)throw bad();
    String state=field(q,"state"),severity=field(q,"severity"),source=field(q,"sourceId"),job=field(q,"jobId");
    if(state!=null&&!Set.of("OPEN","RECOVERING","RESOLVED").contains(state)||severity!=null&&!Set.of("WARNING","ERROR").contains(severity))throw bad();
    if(source!=null&&(source.isBlank()||source.length()>200))throw bad();
    if(job!=null&&!job.matches("[a-fA-F0-9]{8}(-[a-fA-F0-9]{4}){3}-[a-fA-F0-9]{12}"))throw bad();
    try{
      Instant now=Instant.now();
      String binding=HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(json.writeValueAsBytes(Arrays.asList(principal,state,severity,source,job,limit))));
      Cursor c;
      String token=field(q,"cursor");
      if(token!=null){
        if(token.length()>4096)throw bad();
        c=json.readValue(Base64.getUrlDecoder().decode(token),Cursor.class);
        if(!binding.equals(c.binding)||c.snapshot<0||c.before<0||c.expires<=now.getEpochSecond()||c.expires>now.plusSeconds(960).getEpochSecond())throw bad();
        for(String key:List.of("since","until"))if(q.has(key)&&!Instant.parse(field(q,key)).equals(Instant.parse(key.equals("since")?c.since:c.until)))throw bad();
      }else{
        Instant until=q.has("until")?Instant.parse(field(q,"until")):now;
        Instant since=q.has("since")?Instant.parse(field(q,"since")):until.minus(Duration.ofDays(1));
        c=new Cursor(0,Long.MAX_VALUE,since.toString(),until.toString(),now.plusSeconds(900).getEpochSecond(),binding);
      }
      Instant since=Instant.parse(c.since),until=Instant.parse(c.until);
      if(since.isAfter(until)||until.isAfter(now.plusSeconds(1))||Duration.between(since,until).compareTo(Duration.ofDays(30))>0)throw bad();
      if(!Files.isRegularFile(database))throw unavailable();
      try(var db=DriverManager.getConnection("jdbc:sqlite:"+database.toUri()+"?mode=ro")){
        db.setAutoCommit(false);
        if(token==null){try(var stmt=db.createStatement();var row=stmt.executeQuery("select coalesce(max(sequence_id),0) from gateway_incident_transition")){row.next();c=new Cursor(row.getLong(1),Long.MAX_VALUE,c.since,c.until,c.expires,c.binding);}}
        // Gateway incidents refer to endpoints, not Ingestion source/run identities.
        if(source!=null||job!=null)return Map.of("items",List.of(),"partial",false,"hasMore",false);
        String sql="""
          with latest as (select incident_id,max(sequence_id) seq from gateway_incident_transition
            where sequence_id<=? and julianday(json_extract(projection,'$.last_seen_at'))<=julianday(?) group by incident_id)
          select t.sequence_id,t.projection from gateway_incident_transition t join latest l on l.seq=t.sequence_id
          where t.sequence_id<? and julianday(json_extract(projection,'$.last_seen_at'))>=julianday(?)
          and (? is null or json_extract(projection,'$.lifecycle_state')=?)
          and (? is null or json_extract(projection,'$.severity')=?) order by t.sequence_id desc limit ?
          """;
        var items=new ArrayList<Map<String,Object>>();boolean partial=false,more=false;long before=c.before;int scanned=0;
        try(var stmt=db.prepareStatement(sql)){
          stmt.setQueryTimeout(3);stmt.setLong(1,c.snapshot);stmt.setString(2,c.until);stmt.setLong(3,c.before);stmt.setString(4,c.since);
          stmt.setString(5,state);stmt.setString(6,state);stmt.setString(7,severity);stmt.setString(8,severity);stmt.setInt(9,limit+1);
          try(var rows=stmt.executeQuery()){while(rows.next()){
            if(scanned++==limit){more=true;break;}before=rows.getLong(1);
            JsonNode row=json.readTree(rows.getString(2));
            if(!Set.of("TENANT_OPERATIONAL","PUBLIC_OPERATIONAL").contains(row.path("visibility_class").asText())){partial=true;continue;}
            var item=new LinkedHashMap<String,Object>();
            for(String key:List.of("incident_id","module","event_type","lifecycle_state","severity","first_seen_at","last_seen_at","resolved_at","error_code","impact_summary","visibility_class","correlation_id","endpoint_ref")){
              JsonNode value=row.get(key);if(value!=null&&!value.isNull()){if(!value.isTextual()||value.asText().length()>2048)throw unavailable();item.put(key,value.asText());}
            }
            item.put("action_required",row.path("action_required").asBoolean());item.put("occurrence_count",row.path("occurrence_count").asLong());items.add(item);
          }}
        }
        var out=new LinkedHashMap<String,Object>();out.put("items",items);out.put("partial",partial);out.put("hasMore",more);out.put("since",c.since);out.put("until",c.until);out.put("authorization",partial?"REDACTED":"AUTHORIZED");
        if(more)out.put("nextCursor",Base64.getUrlEncoder().withoutPadding().encodeToString(json.writeValueAsBytes(new Cursor(c.snapshot,before,c.since,c.until,c.expires,c.binding))));
        return out;
      }
    }catch(ResponseStatusException e){throw e;}catch(SQLException e){throw unavailable();}catch(Exception e){throw bad();}
  }
  private static String field(JsonNode q,String key){var v=q.get(key);if(v==null)return null;if(!v.isTextual())throw bad();return v.asText();}
  private static ResponseStatusException bad(){return new ResponseStatusException(HttpStatus.BAD_REQUEST,"INVALID_INCIDENT_QUERY");}
  private static ResponseStatusException unavailable(){return new ResponseStatusException(HttpStatus.SERVICE_UNAVAILABLE,"OPERATIONAL_STORE_UNAVAILABLE");}
}
