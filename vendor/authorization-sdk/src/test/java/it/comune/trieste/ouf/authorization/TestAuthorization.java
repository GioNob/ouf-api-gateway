package it.comune.trieste.ouf.authorization;

import java.nio.file.*;
import java.security.*;
import java.time.*;
import java.util.*;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import jakarta.servlet.ServletContext;
import org.springframework.mock.web.MockHttpServletRequest;
import it.comune.trieste.ouf.authorization.AuthorizationPolicy.*;

/** Explicit test fixture, published only in the tests classifier, never in the runtime JAR. */
public final class TestAuthorization {
  public static LocalAuthorization runtime(String subject,String actor,Set<String> caps){
    try {
      var type=PrincipalContext.ActorType.valueOf(actor);var now=Instant.now();
      var descriptors=caps.stream().sorted().map(c->new CapabilityDescriptor(c,"EXECUTE",c,Set.of(type))).toList();
      var grants=caps.stream().sorted().map(c->new Grant("grant:"+c,c,"tenant-a",subject,null,null,now.minusSeconds(60),now.plusSeconds(3600))).toList();
      var runtime=new LocalAuthorization(Clock.systemUTC(),Duration.ofHours(1));
      install(runtime,new PolicyBundle("fixture",1,now,descriptors,grants));return runtime;
    }catch(Exception e){throw new IllegalStateException(e);}
  }
  public static void install(LocalAuthorization runtime,PolicyBundle bundle)throws Exception {
    byte[] bytes=new ObjectMapper().registerModule(new JavaTimeModule()).writeValueAsBytes(bundle);
    Path path=Files.createTempFile("ouf-policy-", ".json");
    try{Files.write(path,bytes);var result=runtime.refresh(new LocalAuthorization.BundleReference(path,bundle.bundleId(),bundle.version(),HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(bytes)),1));if(!result.installed())throw new IllegalStateException(result.reason());}
    finally{Files.deleteIfExists(path);}
  }
  public static TrustedPrincipal principal(String subject,String actor,Set<String> caps){
    return new TrustedPrincipal(new PrincipalContext(subject,"tenant-a",PrincipalContext.ActorType.valueOf(actor),"SERVICE".equals(actor)?subject:null,"fixture-authentication","fixture-issuer","fixture-audience",caps));
  }
  public static void bind(MockHttpServletRequest request,String subject,String actor,Set<String> caps){
    request.setUserPrincipal(principal(subject,actor,caps));
    request.getServletContext().setAttribute(ServletAuthorization.RUNTIME,runtime(subject,actor,caps));
  }
}
