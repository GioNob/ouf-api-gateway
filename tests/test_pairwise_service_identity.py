"""Run the actual loopback fixture used by the Go MCP pairwise gate."""
import json
import os
import subprocess
import sys
import threading
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from tools.compile_config import ROOT


def test_pairwise_server_passes_governed_service_identity_and_starts(tmp_path):
    calls = []
    class Owner(BaseHTTPRequestHandler):
        def do_POST(self):
            calls.append((self.path, self.headers.get('X-OUF-Capability-ID')))
            self.rfile.read(int(self.headers.get('Content-Length','0')))
            self.send_response(200);self.send_header('Content-Type','application/json');self.end_headers();self.wfile.write(b'{"items":[]}')
        def log_message(self,*_): pass
    owner = ThreadingHTTPServer(('127.0.0.1',0),Owner)
    thread=threading.Thread(target=owner.serve_forever,daemon=True);thread.start()
    service='tenant-installation-mcp'
    env=dict(os.environ,PAIRWISE_WORKLOAD_TOKEN='test-only-token',PAIRWISE_UDP_URL=f'http://127.0.0.1:{owner.server_port}',PAIRWISE_MCP_SERVICE_IDENTITY=service)
    process=subprocess.Popen([sys.executable,str(ROOT/'tools/pairwise_server.py')],env=env,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
    try:
        # Bound startup wait without leaving the child alive on a constructor failure.
        port=[]
        reader=threading.Thread(target=lambda:port.append(process.stdout.readline()),daemon=True);reader.start();reader.join(10)
        assert not reader.is_alive(), 'pairwise fixture did not start within 10s'
        assert port and port[0].strip().isdigit(), 'pairwise fixture failed before readiness'
        url=f'http://127.0.0.1:{port[0].strip()}/internal/capabilities/v1/execute/urban.object.related_search'
        fixture=json.loads((ROOT/'tests/fixtures/mcp-related-search-dispatch.json').read_text())
        fixture['Identity']['ServicePrincipalID']=service
        headers={'Authorization':'Bearer test-only-token','Content-Type':'application/json','X-Correlation-ID':fixture['CorrelationID'],'Idempotency-Key':fixture['IdempotencyKey'],'X-Tool-Attempt-ID':fixture['AttemptID']}
        request=urllib.request.Request(url,data=json.dumps(fixture).encode(),headers=headers,method='POST')
        with urllib.request.urlopen(request,timeout=3) as response:
            assert response.status==200 and response.read()==b'{"items":[]}'
        assert calls==[('/internal/v1/objects/related-search','urban.object.related_search')]
        fixture['Identity']['ServicePrincipalID']='forged-service'
        request=urllib.request.Request(url,data=json.dumps(fixture).encode(),headers=headers,method='POST')
        try:
            urllib.request.urlopen(request,timeout=3)
            raise AssertionError('forged service accepted')
        except urllib.error.HTTPError as exc:
            assert exc.code==403
        assert len(calls)==1
    finally:
        process.terminate()
        process.communicate(timeout=5)
        owner.shutdown();owner.server_close();thread.join(5)


def test_pairwise_fixture_cannot_bind_a_public_interface():
    env=dict(os.environ,PAIRWISE_WORKLOAD_TOKEN='test-only-token',PAIRWISE_UDP_URL='http://127.0.0.1:1')
    result=subprocess.run([sys.executable,str(ROOT/'tools/pairwise_server.py'),'--listen','0.0.0.0:0'],env=env,capture_output=True,text=True,timeout=5)
    assert result.returncode!=0
    assert 'must bind loopback' in result.stderr
    assert not result.stdout.strip()
