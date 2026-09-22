package it.comune.trieste.ouf.receipt;

import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.databind.*;
import it.comune.trieste.ouf.authorization.*;
import jakarta.servlet.*;
import jakarta.servlet.http.*;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.security.*;
import java.time.*;
import java.util.*;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import org.springframework.web.filter.OncePerRequestFilter;

/** Private producer authentication. Only a verified, body-bound receipt creates a principal. */
public final class SummaryReceiptFilter extends OncePerRequestFilter {
  public static final String HEADER="X-OUF-Operational-Receipt";
  private final String owner,tenant,issuer,audience,workload;
  private final Path keyFile;
  private final Clock clock;
  private final ObjectMapper json=new ObjectMapper().enable(JsonParser.Feature.STRICT_DUPLICATE_DETECTION).enable(DeserializationFeature.FAIL_ON_TRAILING_TOKENS);
  public SummaryReceiptFilter(String owner,String tenant,String issuer,String audience,String workload,Path keyFile,Clock clock){
    this.owner=owner;this.tenant=tenant;this.issuer=issuer;this.audience=audience;this.workload=workload;this.keyFile=keyFile;this.clock=clock;
    if(!Set.of("ingestion","gateway").contains(owner))throw new IllegalArgumentException("invalid producer");
  }
  private String path(String operation){return "/api/internal/v1/"+owner+"/operations/"+operation;}
  private String capability(String operation){return "ouf."+owner+".operations."+operation;}
  @Override protected boolean shouldNotFilter(HttpServletRequest r){return !Set.of(path("summary"),path("incidents")).contains(r.getRequestURI());}
  @Override protected void doFilterInternal(HttpServletRequest req,HttpServletResponse res,FilterChain chain)throws IOException,ServletException{
    String operation=req.getRequestURI().endsWith("/incidents")?"incidents":"summary";
    String requiredScope=operation.equals("incidents")?"operations.incident.read":"operations.status.read";
    if(!"POST".equals(req.getMethod())){res.sendError(405);return;}
    byte[] key;
    try{
      for(String s:List.of(tenant,issuer,audience,workload))if(s.isBlank())throw new IllegalStateException();
      if(keyFile==null)throw new IllegalStateException();
      String secret=Files.readString(keyFile,StandardCharsets.US_ASCII).strip();
      if(!secret.matches("[a-fA-F0-9]{64}"))throw new IllegalStateException();
      key=secret.getBytes(StandardCharsets.US_ASCII);
    }catch(Exception e){res.sendError(503,"OWNER_IDENTITY_UNAVAILABLE");return;}
    byte[] body=req.getInputStream().readNBytes(65537);
    if(body.length>65536){res.sendError(413);return;}
    HttpServletRequest wrapped;
    JsonNode receipt;
    try{
      String signed=req.getHeader(HEADER);
      if(signed==null||signed.length()>16384)throw new SecurityException();
      String[] parts=signed.split("\\.",-1);
      if(parts.length!=2||!parts[0].matches("[A-Za-z0-9_-]+")||!parts[1].matches("[A-Za-z0-9_-]+"))throw new SecurityException();
      Mac mac=Mac.getInstance("HmacSHA256");mac.init(new SecretKeySpec(key,"HmacSHA256"));
      if(!MessageDigest.isEqual(mac.doFinal(("ouf-operational-owner-v1."+parts[0]).getBytes(StandardCharsets.US_ASCII)),Base64.getUrlDecoder().decode(parts[1])))throw new SecurityException();
      receipt=json.readTree(Base64.getUrlDecoder().decode(parts[0]));
      long now=clock.instant().getEpochSecond();
      if(!receipt.isObject()||!receipt.path("v").isIntegralNumber()||receipt.path("v").asInt()!=1||!receipt.path("iat").isIntegralNumber()||!receipt.path("exp").isIntegralNumber())throw new SecurityException();
      long issued=receipt.path("iat").asLong(),expires=receipt.path("exp").asLong();
      if(issued>now||expires<=now||expires<=issued||expires-issued>30)throw new SecurityException();
      Map<String,String> expected=Map.of("purpose","operational-summary-owner","method","POST","path",path(operation),"capability",capability(operation),"tenant",tenant,"issuer",issuer,"audience",audience,"workload",workload);
      for(var e:expected.entrySet())if(!e.getValue().equals(text(receipt,e.getKey())))throw new SecurityException();
      if(!HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(body)).equals(text(receipt,"bodyHash")))throw new SecurityException();
      Set<String> roles=words(receipt,"roles",true),scopes=words(receipt,"scope",false);
      if(roles.size()>32||!scopes.contains(requiredScope))throw new SecurityException();
      var principal=new TrustedPrincipal(new PrincipalContext(text(receipt,"subject"),tenant,PrincipalContext.ActorType.HUMAN,text(receipt,"client"),text(receipt,"acr"),issuer,audience,scopes,new PrincipalContext.IdentityClaims(roles,text(receipt,"acr"),Set.of(),null)));
      wrapped=new HttpServletRequestWrapper(req){
        @Override public Principal getUserPrincipal(){return principal;}
        @Override public String getRemoteUser(){return principal.getName();}
        @Override public ServletInputStream getInputStream(){var stream=new ByteArrayInputStream(body);return new ServletInputStream(){public int read(){return stream.read();}public boolean isFinished(){return stream.available()==0;}public boolean isReady(){return true;}public void setReadListener(ReadListener l){throw new UnsupportedOperationException();}};}
        @Override public BufferedReader getReader(){return new BufferedReader(new InputStreamReader(getInputStream(),StandardCharsets.UTF_8));}
      };
    }catch(Exception e){res.sendError(403,"INVALID_OPERATIONAL_RECEIPT");return;}
    try{
      var auth=OwnerAuthorization.bind(wrapped);
      var decision=auth.require(capability(operation),new ResourceContext("capability",null,tenant,null,Map.of("detailLevel","TENANT_OPERATIONAL")));
      if(!"TENANT_OPERATIONAL".equals(decision.permittedDetailLevel())||!decision.decisionRef().equals(text(receipt,"decisionRef")))throw new SecurityException("STALE_DECISION");
    }catch(SecurityException e){res.sendError(403,"NOT_AUTHORIZED");return;}
    chain.doFilter(wrapped,res);
  }
  private static String text(JsonNode n,String key){var v=n.get(key);if(v==null||!v.isTextual()||v.asText().isBlank()||v.asText().length()>4096||v.asText().chars().anyMatch(Character::isISOControl))throw new SecurityException();return v.asText();}
  private static Set<String> words(JsonNode n,String key,boolean empty){
    if(empty&&n.path(key).isTextual()&&n.path(key).asText().isEmpty())return Set.of();
    return Set.copyOf(Arrays.asList(text(n,key).split(" ")));
  }
}
