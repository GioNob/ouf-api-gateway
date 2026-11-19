package it.comune.trieste.ouf.authorization;
import static org.assertj.core.api.Assertions.*;
import com.fasterxml.jackson.databind.*;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import java.time.Instant;
import org.junit.jupiter.api.Test;
class CommonConformanceTest {
 @Test void sharedJavaGoDecisionVectors()throws Exception{
  var json=new ObjectMapper().registerModule(new JavaTimeModule());
  try(var in=getClass().getResourceAsStream("/authorization-conformance-v1.json")){
   var root=json.readTree(in);var bundle=json.treeToValue(root.get("bundle"),AuthorizationPolicy.PolicyBundle.class);
   for(var c:root.get("cases")){
    var current=c.has("bundle")?json.treeToValue(c.get("bundle"),AuthorizationPolicy.PolicyBundle.class):bundle;
    var d=AuthorizationPolicy.evaluate(current,json.treeToValue(c.get("principal"),PrincipalContext.class),json.treeToValue(c.get("resource"),ResourceContext.class),c.get("capabilityId").asText(),c.get("operation").asText(),Instant.parse(c.get("now").asText()));
    assertThat(d.decisionCode()).as(c.get("id").asText()).isEqualTo(c.get("decisionCode").asText());
    assertThat(d.allowed()).isEqualTo("ALLOW".equals(c.get("decisionCode").asText()));
    if(d.allowed()){assertThat(d.resourceScope()).containsEntry("tenantId","tenant-a");assertThat(d.permittedDetailLevel()).isNotBlank();}
    assertThat(d.bundleId()).isEqualTo("conformance");assertThat(d.bundleVersion()).isEqualTo(7);
   }
  }
 }
}
