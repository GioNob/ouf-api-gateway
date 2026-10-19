package it.comune.trieste.ouf.onboarding;
import static org.assertj.core.api.Assertions.*;
import com.fasterxml.jackson.databind.ObjectMapper;
import it.comune.trieste.ouf.onboarding.api.PermissionDelegationVerifier;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.util.*;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/** CI-only fixture: executes the actual pinned Gateway Lua and the actual Java owner verifier. */
class SourceRevisionGatewayPairwiseTest {
  @Test void actualGatewayRevisionReceiptsReachOnlyTheIntendedJavaOwner(@TempDir Path directory)throws Exception {
    String root=Objects.requireNonNull(System.getenv("OUF_REVISION_GATEWAY_ROOT"));
    Path vectors=directory.resolve("vectors.json");
    var process=new ProcessBuilder("python","-m","tests.source_revision_vectors",vectors.toString())
        .directory(Path.of(root).toFile()).redirectError(ProcessBuilder.Redirect.INHERIT).start();
    assertThat(process.waitFor(10,TimeUnit.SECONDS)).isTrue();assertThat(process.exitValue()).isZero();
    Path key=directory.resolve("key");Files.writeString(key,"ab".repeat(32));var json=new ObjectMapper();
    var verifier=new PermissionDelegationVerifier(json,key.toString(),"https://auth.test/realms/ouf","gateway","workload");
    var rows=json.readTree(Files.readString(vectors));assertThat(rows.size()).isEqualTo(3);
    for(var row:rows){
      byte[] body=row.required("body").asText().getBytes(StandardCharsets.UTF_8);
      String proof=row.required("proof").asText(),path=row.required("path").asText(),cap=row.required("capability").asText();
      var caller=verifier.verifySourceRevision(proof,path,cap,body);
      assertThat(caller.principal().subjectId()).isEqualTo("human-a");assertThat(caller.principal().tenantId()).isEqualTo("tenant-a");
      assertThatThrownBy(()->verifier.verifyManagedFile(proof,path,cap,body)).isInstanceOf(SecurityException.class);
      assertThatThrownBy(()->verifier.verifySourceRevision(proof,path+"/changed",cap,body)).isInstanceOf(SecurityException.class);
      assertThatThrownBy(()->verifier.verifySourceRevision(proof,path,cap,"changed".getBytes(StandardCharsets.UTF_8))).isInstanceOf(SecurityException.class);
    }
  }
}
