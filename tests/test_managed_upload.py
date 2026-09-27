import base64
import hashlib
import hmac
import json

import pytest

from tests.test_execute_delegation import Engine, Denied, INSTALL, KEY, human, proof, runtime, workload
from tools.delegation_functions import function
from tools.materialize_managed_upload import materialize

CAP='ouf.managed-source.file.upload'
URI='/internal/capabilities/v1/execute/managed.file/upload'
PATH='/api/internal/v1/onboarding/managed-file-mcp/upload'
CSV=b'\xef\xbb\xbfcinema,indirizzo\r\nA,Trieste\r\n'

def execute(changes=None,delegation=None,uri=URI):
    headers={
        'X-OUF-Delegation':delegation or proof(dict(human(),scope='mcp.connect '+CAP)),
        'Content-Type':'text/csv','Content-Length':str(len(CSV)),
        'X-Content-SHA256':'sha256:'+hashlib.sha256(CSV).hexdigest(),
        'X-OUF-File-ID':'file_123','Idempotency-Key':'upload-once',
        'X-OUF-Managed-File-Receipt':'forged','Cookie':'secret',
    }
    headers.update(changes or {})
    engine=Engine(workload(),headers,uri=uri)
    engine.body=CSV
    engine.lua.globals()[b'ngx'][b'req'][b'read_body']=lambda:pytest.fail('Gateway buffered the CSV')
    engine.lua.globals()[b'ngx'][b'req'][b'get_body_data']=lambda:pytest.fail('Gateway read the CSV')
    engine.lua.execute(function('execute_managed_upload',INSTALL,'TEST_KEY','OWNER_KEY').encode())(None,None)
    return engine

def test_signed_metadata_and_exact_unmodified_stream():
    engine=execute()
    assert engine.body==CSV
    encoded,signature=engine.headers[b'x-ouf-managed-file-receipt'].split(b'.')
    pad=lambda s:s+b'='*((4-len(s)%4)%4)
    receipt=json.loads(base64.urlsafe_b64decode(pad(encoded)))
    assert receipt['purpose']=='managed-file-upload-owner' and receipt['path']==PATH
    assert receipt['expectedHash']=='sha256:'+hashlib.sha256(CSV).hexdigest()
    assert receipt['expectedLength']==len(CSV) and receipt['fileId']=='file_123'
    assert receipt['subject']=='human-a' and receipt['tenant']=='tenant-a'
    assert hmac.compare_digest(base64.urlsafe_b64decode(pad(signature)),
        hmac.new(KEY.encode(),b'ouf-managed-file-upload-v1.'+encoded,hashlib.sha256).digest())
    assert b'authorization' not in engine.headers and b'x-ouf-delegation' not in engine.headers
    assert b'x-ouf-file-id' not in engine.headers

@pytest.mark.parametrize('change',[
    {'Content-Type':'application/json'}, {'Content-Length':'0'},
    {'Content-Length':'10485761'}, {'Content-Length':'100000000'},
    {'X-Content-SHA256':'sha256:'+'A'*64}, {'X-OUF-File-ID':'other'},
    {'Idempotency-Key':'../../wrong'},
])
def test_invalid_stream_metadata_never_reaches_owner(change):
    with pytest.raises(Denied):execute(change)

def test_wrong_scope_or_path_is_denied():
    with pytest.raises(Denied):execute(delegation=proof(dict(human(),scope='mcp.connect')))
    with pytest.raises(Denied):execute(uri=URI+'/other')

def test_route_never_adds_body_validation_or_json_buffering():
    route=materialize(runtime(),'$ENV://OIDC_SECRET','DELEGATION_KEY','OWNER_KEY')
    from ops.apisix.deploy_managed_file_upload import validate
    validate(route)
    assert route['id']=='mcp-managed-file-upload' and route['methods']==['POST']
    assert route['plugins']['proxy-control']=={'request_buffering':False}
    assert 'request-validation' not in route['plugins']
    assert route['plugins']['request-id']['header_name']=='X-Correlation-ID'
    before=' '.join(route['plugins']['serverless-pre-function']['functions'])
    assert "n~='x-ouf-delegation'" in before and "n~='x-ouf-file-id'" in before
    assert 'ngx.req.read_body' not in before
    assert route['plugins']['client-control']=={'max_body_size':10485760}
    assert route['upstream']['nodes']=={'ouf-onboarding:8080':1}
    assert route['upstream']['retries']==0
