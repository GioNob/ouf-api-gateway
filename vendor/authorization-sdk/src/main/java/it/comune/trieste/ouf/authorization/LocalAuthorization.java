package it.comune.trieste.ouf.authorization;

import com.fasterxml.jackson.databind.*;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import java.nio.file.*;
import java.security.*;
import java.time.*;
import java.util.*;
import java.util.concurrent.atomic.AtomicReference;
import it.comune.trieste.ouf.authorization.AuthorizationPolicy.*;

/** Local evaluation only. Refresh is an explicit configuration/control-plane operation. */
public final class LocalAuthorization {
  public static final int MAX_BYTES=5*1024*1024;
  private final AtomicReference<PolicySnapshot> active=new AtomicReference<>();
  private final Clock clock;
  private final Duration maxStaleness;
  private volatile String lastError;
  public LocalAuthorization(Clock clock,Duration maxStaleness) {
    this.clock=Objects.requireNonNull(clock);this.maxStaleness=Objects.requireNonNull(maxStaleness);
    if(maxStaleness.isNegative()||maxStaleness.isZero()||maxStaleness.compareTo(Duration.ofHours(24))>0)throw new IllegalArgumentException("maxStaleness must be >0 and <=24h");
  }
  public record BundleReference(Path path,String bundleId,long version,String sha256,int schemaMajor) {}
  public record PolicySnapshot(PolicyBundle bundle,String sha256,Instant verifiedAt) {}
  public record BundleRefreshResult(boolean installed,String reason) {}
  public record AuthorizationHealth(boolean ready,String bundleId,long version,Instant verifiedAt,String lastError) {}

  public BundleRefreshResult refresh(BundleReference ref) {
    try {
      Objects.requireNonNull(ref);
      if(ref.schemaMajor()!=1)throw new IllegalArgumentException("INCOMPATIBLE_POLICY_BUNDLE");
      if(ref.sha256()==null||!ref.sha256().matches("[a-f0-9]{64}"))throw new IllegalArgumentException("BUNDLE_HASH_REQUIRED");
      byte[] bytes;
      try(var in=Files.newInputStream(ref.path())){bytes=in.readNBytes(MAX_BYTES+1);}
      if(bytes.length>MAX_BYTES)throw new IllegalArgumentException("BUNDLE_TOO_LARGE");
      String hash=HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(bytes));
      if(!hash.equals(ref.sha256()))throw new IllegalArgumentException("BUNDLE_HASH_MISMATCH");
      var json=new ObjectMapper().registerModule(new JavaTimeModule()).enable(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES,DeserializationFeature.FAIL_ON_TRAILING_TOKENS);
      var bundle=json.readValue(bytes,PolicyBundle.class);
      if(!bundle.bundleId().equals(ref.bundleId())||bundle.version()!=ref.version())throw new IllegalArgumentException("BUNDLE_REFERENCE_MISMATCH");
      if(bundle.capabilities().size()>10000||bundle.grants().size()>10000)throw new IllegalArgumentException("BUNDLE_CARDINALITY_LIMIT");
      var ids=new HashSet<String>();
      for(var c:bundle.capabilities())if(!ids.add(c.capabilityId()))throw new IllegalArgumentException("DUPLICATE_CAPABILITY");
      var grants=new HashSet<String>();
      for(var g:bundle.grants())if(!grants.add(g.grantId())||!ids.contains(g.capabilityId()))throw new IllegalArgumentException("INVALID_GRANT_REFERENCE");
      var next=new PolicySnapshot(bundle,hash,clock.instant());
      // Validation and parsing happen outside the CAS. A racing stale refresh cannot replace a newer version.
      for(;;){var old=active.get();
        if(old!=null){
          if(!old.bundle().bundleId().equals(bundle.bundleId()))throw new IllegalArgumentException("BUNDLE_LINEAGE_CHANGE_REQUIRES_RESTART");
          if(bundle.version()<old.bundle().version())throw new IllegalArgumentException("BUNDLE_ROLLBACK_REJECTED");
          if(bundle.version()==old.bundle().version()&&!hash.equals(old.sha256()))throw new IllegalArgumentException("IMMUTABLE_BUNDLE_CHANGED");
        }
        if(old!=null&&next.verifiedAt().isBefore(old.verifiedAt()))throw new IllegalArgumentException("OLDER_REFRESH_REJECTED");
        if(active.compareAndSet(old,next))break;
      }
      lastError=null;return new BundleRefreshResult(true,"INSTALLED");
    }catch(Exception e){lastError=e instanceof IllegalArgumentException?e.getMessage():"BUNDLE_LOAD_FAILED";return new BundleRefreshResult(false,lastError);}
  }
  public void refreshFailure(String code){lastError=code;}
  public PolicySnapshot currentSnapshot(){var p=active.get();requireFresh(p);return p;}
  public void requireFresh(PolicySnapshot p){
    if(p==null)throw new SecurityException("NO_POLICY_BUNDLE");
    if(clock.instant().isBefore(p.verifiedAt())||!clock.instant().isBefore(p.verifiedAt().plus(maxStaleness)))throw new SecurityException("STALE_POLICY_BUNDLE");
  }
  public AuthorizationDecision evaluate(PolicySnapshot snapshot,PrincipalContext principal,ResourceContext resource,String capability,String operation){
    requireFresh(snapshot);return AuthorizationPolicy.evaluate(snapshot.bundle(),principal,resource,capability,operation,clock.instant());
  }
  public AuthorizationDecision evaluate(PrincipalContext principal,ResourceContext resource,String capability,String operation){return evaluate(currentSnapshot(),principal,resource,capability,operation);}
  public AuthorizationHealth health(){var p=active.get();boolean ready=true;try{requireFresh(p);}catch(SecurityException e){ready=false;}return new AuthorizationHealth(ready,p==null?null:p.bundle().bundleId(),p==null?0:p.bundle().version(),p==null?null:p.verifiedAt(),lastError);}
}
