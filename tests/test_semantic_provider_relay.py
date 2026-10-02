from dataclasses import replace
from email.message import Message
import io,json,socket,ssl,shutil,subprocess,tempfile,threading,time,unittest
from pathlib import Path
from unittest.mock import Mock,patch
from http.server import BaseHTTPRequestHandler,HTTPServer
from urllib.parse import urlencode,parse_qs
from tools import semantic_provider_relay as relay
from tools.semantic_provider_boundary import PREFIX,HEAD,PATTERNS,MIDDLE,TAIL,ProviderRequestDenied
from tools.southbound_security import SouthboundDenied


def form(artifact='CLASS'):
    return urlencode({'query':PREFIX+HEAD+PATTERNS[artifact]+MIDDLE+'Place'+TAIL,'format':'application/sparql-results+json'}).encode()

def answers(host,port,**kwargs):
    return [(socket.AF_INET,socket.SOCK_STREAM,6,'',('93.184.216.34',port))]

class Response(io.BytesIO):
    def __init__(self,body=b'{}',status=200,media='application/json',headers=()):
        super().__init__(body);self.status=status;self.headers=Message();self.headers.add_header('Content-Type',media)
        for key,value in headers:self.headers.add_header(key,value)

class Connection:
    def __init__(self,response):self.response=response;self.calls=[];self.closed=False
    def request(self,*args,**kwargs):self.calls.append((args,kwargs))
    def getresponse(self):return self.response
    def close(self):self.closed=True

class RelayTest(unittest.TestCase):
    def setUp(self):self.binding=relay.ProviderBinding('https://provider.example:9443/sparql',('https://vocab.example/class/',))

    def test_six_exact_queries_use_fixed_destination_and_no_credentials(self):
        for artifact in PATTERNS:
            connection=Connection(Response(b'{"results":{"bindings":[]}}'));seen=[]
            def factory(*args):seen.append(args[:4]);return connection
            relay.search(self.binding,form(artifact),resolver=answers,connection_factory=factory)
            self.assertEqual(seen[0][:3],('provider.example',9443,'93.184.216.34'))
            self.assertEqual(connection.calls[0][0],('POST','/sparql'))
            self.assertNotIn('Authorization',connection.calls[0][1]['headers'])
            self.assertTrue(connection.closed)

    def test_uri_is_only_query_data_and_asserted_scope_is_explicit(self):
        connection=Connection(Response(b'<https://vocab.example/class/Place> <http://example/type> <http://example/Class> .',media='text/turtle'));destinations=[]
        def resolver(host,port,**kwargs):destinations.append(host);return answers(host,port,**kwargs)
        response=relay.fetch(self.binding,urlencode({'uri':'https://vocab.example/class/Place'}).encode(),resolver=resolver,connection_factory=lambda *args:connection)
        self.assertEqual(destinations,['provider.example'])
        self.assertEqual(response.rdf_scope,'OUTGOING_ASSERTED_SUBJECT_TRIPLES')
        query=parse_qs(connection.calls[0][1]['body'].decode())['query'][0]
        self.assertIn('CONSTRUCT { <https://vocab.example/class/Place>',query);self.assertNotIn('LIMIT',query)

    def test_bad_grammar_or_uri_fails_before_dns(self):
        resolver=Mock()
        for body in [b'query=DROP+ALL&format=application%2Fsparql-results%2Bjson',form()+b'&endpoint=https://evil.example']:
            with self.assertRaises(ProviderRequestDenied):relay.search(self.binding,body,resolver=resolver)
        for uri in ['http://169.254.169.254/latest/meta-data','https://vocab.example/class/Place> SERVICE <https://evil.example','https://foreign.example/Place']:
            with self.assertRaises(ProviderRequestDenied):relay.fetch(self.binding,urlencode({'uri':uri}).encode(),resolver=resolver)
        resolver.assert_not_called()

    def test_mixed_public_and_forbidden_dns_answers_fail_closed(self):
        for address in ['127.0.0.1','169.254.169.254','10.0.0.5','100.64.0.5']:
            def resolver(*args,**kwargs):return answers(*args,**kwargs)+[(socket.AF_INET,socket.SOCK_STREAM,6,'',(address,9443))]
            with self.assertRaises(SouthboundDenied):relay.exchange(self.binding,b'x',accepted={'application/json'},resolver=resolver)

    def test_bad_status_media_encoding_framing_and_bounds_close_connection(self):
        cases=[Response(status=302),Response(status=401),Response(media='text/html'),Response(headers=[('Content-Encoding','gzip')]),Response(body=b'x'*11),Response(headers=[('Content-Length','11')]),Response(headers=[('Content-Length','2'),('Transfer-Encoding','chunked')]),Response(headers=[('Content-Length','2'),('Content-Length','2')]),Response(headers=[('Transfer-Encoding','invalid')]),Response(headers=[('Content-Length','5')])]
        for response in cases:
            connection=Connection(response)
            with self.assertRaises(relay.RelayDenied):relay.exchange(replace(self.binding,max_response_bytes=10),b'x',accepted={'application/json'},resolver=answers,connection_factory=lambda *args:connection)
            self.assertTrue(connection.closed);self.assertTrue(response.closed)

    def test_search_result_shape_and_count_bounds(self):
        for body in [b'{}',b'not-json',b'{"results":{"bindings":{}}}',json.dumps({'results':{'bindings':[{}]*51}}).encode()]:
            connection=Connection(Response(body))
            with self.assertRaisesRegex(relay.RelayDenied,'PROVIDER_SEARCH_RESULT_INVALID'):relay.search(self.binding,form(),resolver=answers,connection_factory=lambda *args:connection)

    def test_deadline_covers_dns_and_body_work(self):
        def resolver(*args,**kwargs):time.sleep(2);return answers(*args,**kwargs)
        with self.assertRaisesRegex(relay.RelayDenied,'PROVIDER_TIMEOUT'):relay.exchange(replace(self.binding,timeout_seconds=1),b'x',accepted={'application/json'},resolver=resolver)
        with self.assertRaisesRegex(relay.RelayDenied,'PROVIDER_TIMEOUT'):
            with relay.request_deadline(0.05):time.sleep(0.2)

    def test_unbounded_worker_thread_is_rejected(self):
        errors=[]
        def run():
            try:
                with relay.request_deadline(1):errors.append('unexpected')
            except relay.RelayDenied as error:errors.append(str(error))
        thread=threading.Thread(target=run);thread.start();thread.join(timeout=2)
        self.assertEqual(errors,['BOUNDED_WORKER_PROCESS_REQUIRED'])

@unittest.skipUnless(shutil.which('openssl'),'TLS fixture requires OpenSSL')
class PinnedTLSRelayTest(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(dir=Path.cwd());self.addCleanup(self.temp.cleanup)
        root=Path(self.temp.name);certificate,key=root/'certificate.pem',root/'key.pem'
        subprocess.run(['openssl','req','-x509','-newkey','rsa:2048','-nodes','-days','1','-subj','/CN=provider.example','-addext','subjectAltName=DNS:provider.example','-out',str(certificate),'-keyout',str(key)],capture_output=True,check=True,timeout=15)
        self.requests=[];self.connections=[];owner=self
        class Handler(BaseHTTPRequestHandler):
            def log_message(self,*args):pass
            def do_POST(self):
                owner.requests.append((self.path,dict(self.headers),parse_qs(self.rfile.read(int(self.headers['Content-Length'])).decode())))
                raw=b'{"results":{"bindings":[]}}';self.send_response(200);self.send_header('Content-Type','application/sparql-results+json');self.send_header('Content-Length',str(len(raw)));self.end_headers();self.wfile.write(raw)
        self.server=HTTPServer(('127.0.0.1',0),Handler)
        context=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);context.load_cert_chain(certificate,key);self.server.socket=context.wrap_socket(self.server.socket,server_side=True)
        threading.Thread(target=self.server.serve_forever,daemon=True).start();self.addCleanup(self.server.server_close);self.addCleanup(self.server.shutdown)
        self.binding=relay.ProviderBinding('https://provider.example:'+str(self.server.server_port)+'/sparql',('https://vocab.example/class/',),ca_file=str(certificate))
        original=socket.socket
        class FixtureSocket(original):
            def connect(self,address):
                if address[0]=='93.184.216.34':owner.connections.append(address);return super().connect(('127.0.0.1',owner.server.server_port))
                return super().connect(address)
        self.fixture_socket=FixtureSocket

    def test_numeric_pin_and_trusted_registered_tls_hostname(self):
        with patch.object(relay.socket,'socket',self.fixture_socket):response=relay.search(self.binding,form(),resolver=answers)
        self.assertEqual(response.media_type,'application/sparql-results+json');self.assertEqual(self.connections,[('93.184.216.34',self.server.server_port)])
        self.assertEqual(self.requests[0][0],'/sparql');self.assertEqual(self.requests[0][1]['Host'],'provider.example:'+str(self.server.server_port));self.assertNotIn('Authorization',self.requests[0][1])

    def test_untrusted_tls_prevents_http_request(self):
        with patch.object(relay.socket,'socket',self.fixture_socket),self.assertRaisesRegex(relay.RelayDenied,'PROVIDER_UNAVAILABLE'):relay.search(replace(self.binding,ca_file=None),form(),resolver=answers)
        self.assertEqual(self.requests,[])

if __name__=='__main__':unittest.main()
