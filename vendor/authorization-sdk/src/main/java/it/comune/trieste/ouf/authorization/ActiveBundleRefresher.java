package it.comune.trieste.ouf.authorization;

import com.fasterxml.jackson.databind.*;
import java.net.URI;
import java.net.http.*;
import java.nio.file.*;
import java.time.*;
import java.util.concurrent.*;

/** Bounded authenticated control-plane refresh, separate from the pure decision path. */
public final class ActiveBundleRefresher implements AutoCloseable {
 private final LocalAuthorization runtime;private final URI endpoint;private final Path tokenFile;private final HttpClient http;
 private final ScheduledExecutorService worker=Executors.newSingleThreadScheduledExecutor(r->{var t=new Thread(r,"ouf-authorization-refresh");t.setDaemon(true);return t;});
 public ActiveBundleRefresher(LocalAuthorization runtime,URI endpoint,Path tokenFile,Duration interval){
  if(!"https".equals(endpoint.getScheme())||endpoint.getUserInfo()!=null||endpoint.getFragment()!=null)throw new IllegalArgumentException("Authorization registry requires HTTPS without embedded credentials");
  if(interval.toSeconds()<1||interval.toSeconds()>3600)throw new IllegalArgumentException("refresh interval 1..3600 seconds");
  this.runtime=runtime;this.endpoint=endpoint;this.tokenFile=tokenFile;this.http=HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(3)).followRedirects(HttpClient.Redirect.NEVER).build();
  worker.scheduleWithFixedDelay(this::refreshSafely,0,interval.toSeconds(),TimeUnit.SECONDS);
 }
 private void refreshSafely(){try{refresh();}catch(Exception e){runtime.refreshFailure("POLICY_REFRESH_FAILURE");}}
 public void refresh()throws Exception{
  String token=Files.readString(tokenFile).strip();if(token.isBlank()||token.length()>16384||token.contains("\n")||token.contains("\r"))throw new IllegalArgumentException("WORKLOAD_TOKEN_INVALID");
  var request=HttpRequest.newBuilder(endpoint).timeout(Duration.ofSeconds(5)).header("Authorization","Bearer "+token).header("Accept","application/json").GET().build();
  var future=http.sendAsync(request, info -> new BoundedBody(LocalAuthorization.MAX_BYTES+65536));
  HttpResponse<byte[]> response;
  try { response=future.get(5,TimeUnit.SECONDS); } catch(Exception e) { future.cancel(true); throw e; }
  {
   if(response.statusCode()!=200)throw new IllegalStateException("POLICY_REFRESH_HTTP_FAILURE");
   byte[] raw=response.body();
   var json=new ObjectMapper().enable(DeserializationFeature.FAIL_ON_TRAILING_TOKENS);var node=json.readTree(raw);
   for(var it=node.fieldNames();it.hasNext();)if(!java.util.Set.of("bundleId","bundleVersion","activatedAt","bundle","contentHash").contains(it.next()))throw new IllegalArgumentException("UNKNOWN_ACTIVE_FIELD");
   if(!node.required("bundleVersion").isIntegralNumber()||!node.required("bundleVersion").canConvertToLong())throw new IllegalArgumentException("INVALID_ACTIVE_VERSION");
   byte[] bundle=json.writeValueAsBytes(node.required("bundle"));
   Path temporary=Files.createTempFile("ouf-auth-bundle-", ".json");
   try{Files.write(temporary,bundle);var result=runtime.refresh(new LocalAuthorization.BundleReference(temporary,node.required("bundleId").asText(),node.required("bundleVersion").asLong(),node.required("contentHash").asText(),1));if(!result.installed())throw new IllegalStateException(result.reason());}
   finally{Files.deleteIfExists(temporary);}
  }
 }
 static final class BoundedBody implements HttpResponse.BodySubscriber<byte[]> {
  private final HttpResponse.BodySubscriber<byte[]> delegate=HttpResponse.BodySubscribers.ofByteArray();
  private final int maximum; private int received; private java.util.concurrent.Flow.Subscription subscription;
  BoundedBody(int maximum){this.maximum=maximum;}
  public CompletionStage<byte[]> getBody(){return delegate.getBody();}
  public void onSubscribe(java.util.concurrent.Flow.Subscription subscription){this.subscription=subscription;delegate.onSubscribe(subscription);}
  public void onNext(java.util.List<java.nio.ByteBuffer> chunks){
   for(var chunk:chunks){if(chunk.remaining()>maximum-received){subscription.cancel();delegate.onError(new IllegalArgumentException("ACTIVE_ENVELOPE_TOO_LARGE"));return;}received+=chunk.remaining();}
   delegate.onNext(chunks);
  }
  public void onError(Throwable error){delegate.onError(error);}
  public void onComplete(){delegate.onComplete();}
 }
 @Override public void close(){worker.shutdownNow();}
}
