package it.comune.trieste.ouf.gateway;

import it.comune.trieste.ouf.receipt.SummaryReceiptFilter;
import java.nio.file.Path;
import java.time.Clock;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.*;
import org.springframework.core.env.Environment;

@Configuration
public class SummaryIdentityConfiguration {
  @Bean FilterRegistrationBean<SummaryReceiptFilter> operationalSummaryIdentity(Environment env){
    String key=env.getProperty("ouf.summary.receipt-key-file");
    var filter=new SummaryReceiptFilter("gateway",env.getProperty("ouf.summary.tenant-id",""),env.getProperty("ouf.summary.issuer",""),env.getProperty("ouf.summary.audience",""),env.getProperty("ouf.summary.workload",""),key==null?null:Path.of(key),Clock.systemUTC());
    var registration=new FilterRegistrationBean<>(filter);registration.setOrder(-100);registration.addUrlPatterns("/api/internal/v1/gateway/operations/summary");return registration;
  }
}
