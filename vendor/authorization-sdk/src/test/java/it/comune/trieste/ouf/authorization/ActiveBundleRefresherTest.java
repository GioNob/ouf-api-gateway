package it.comune.trieste.ouf.authorization;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;
import java.nio.ByteBuffer;
import java.util.List;
import java.util.concurrent.Flow;
class ActiveBundleRefresherTest {
 @Test void oversizedBodyCancelsBeforeAccumulation(){
  boolean[] cancelled={false};var body=new ActiveBundleRefresher.BoundedBody(4);
  body.onSubscribe(new Flow.Subscription(){public void request(long n){} public void cancel(){cancelled[0]=true;}});
  body.onNext(List.of(ByteBuffer.wrap(new byte[5])));
  assertTrue(cancelled[0]);assertThrows(Exception.class,()->body.getBody().toCompletableFuture().get());
 }
 @Test void boundedChunksAreRetained(){
  var body=new ActiveBundleRefresher.BoundedBody(4);
  body.onSubscribe(new Flow.Subscription(){public void request(long n){} public void cancel(){}});
  body.onNext(List.of(ByteBuffer.wrap(new byte[]{1,2}),ByteBuffer.wrap(new byte[]{3,4})));body.onComplete();
  assertArrayEquals(new byte[]{1,2,3,4},body.getBody().toCompletableFuture().join());
 }
}
