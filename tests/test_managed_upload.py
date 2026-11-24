import base64
import hashlib
import hmac
import json

import pytest

from tests.test_execute_delegation import Engine, Denied, INSTALL, KEY, human, proof, runtime, workload
from tests.test_value_type_schemas import matched_route_context, routes
from tools.delegation_functions import function
from tools.materialize_managed_upload import materialize

CAP='ouf.managed-source.file.upload'
URI='/internal/capabilities/v1/execute/managed.file/upload'
PATH='/api/internal/v1/onboarding/managed-file-mcp/upload'
CSV=b'\xef\xbb\xbfcinema,indirizzo\r\nA,Trieste\r\n'

XLSX = 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'

def execute(changes=None,delegation=None,uri=URI, *, data=CSV, allowed='text/csv,' + XLSX, route=None, stable_json=False):
    headers={
        'X-OUF-Delegation':delegation or proof(dict(human(),scope='mcp.connect '+CAP)),
        'Content-Type':'text/csv','Content-Length':str(len(data)),
        'X-Content-SHA256':'sha256:'+hashlib.sha256(data).hexdigest(),
        'X-OUF-File-ID':'file_123','Idempotency-Key':'upload-once',
        'X-OUF-Managed-File-Receipt':'forged','Cookie':'secret',
    }
    headers.update(changes or {})
    headers = {name: value for name, value in headers.items() if value is not None}
    engine=Engine(workload(),headers,uri=uri)
    if stable_json:
        # Lua table iteration order varies by VM. Pin the encoder for the wire vector.
        module = engine.modules[b'cjson.safe']
        encode = module[b'encode']
        module[b'encode'] = lambda v: json.dumps(json.loads(encode(v)), sort_keys=True, separators=(',', ':')).encode()
    engine.body=data
    engine.lua.globals()[b'ngx'][b'req'][b'read_body']=lambda:pytest.fail('Gateway buffered the CSV')
    engine.lua.globals()[b'ngx'][b'req'][b'get_body_data']=lambda:pytest.fail('Gateway read the CSV')
    if route is None:
        route = {'desc': allowed}
        post = function('execute_managed_upload', INSTALL, 'TEST_KEY', 'OWNER_KEY')
    else:
        post, = route['plugins']['serverless-post-function']['functions']
    engine.lua.execute(post.encode())(None, matched_route_context(engine, route))
    return engine

def test_signed_metadata_and_exact_unmodified_stream():
    engine=execute()
    assert engine.body==CSV
    encoded,signature=engine.headers[b'x-ouf-managed-file-receipt'].split(b'.')
    pad=lambda s:s+b'='*((4-len(s)%4)%4)
    receipt=json.loads(base64.urlsafe_b64decode(pad(encoded)))
    assert receipt['v'] == 1 and 'mediaType' not in receipt
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
    with pytest.raises(Denied) as rejected:
        execute(change)
    assert rejected.value.args == (400,)
    assert json.loads(rejected.value.response_body)['code'] == 'INVALID_TOOL_ARGUMENTS'

def test_csv_receipt_bytes_from_3d69cb4():
    receipt = execute(stable_json=True).headers[b'x-ouf-managed-file-receipt']
    assert hashlib.sha256(receipt).hexdigest() == 'cf7ef0b383f123216f39e196ccb2777e0d1ca670f5cc817ee5217b4125a54302'


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


@pytest.mark.parametrize('name,status', [
    ('Content-Type', 400), ('Content-Length', 400), ('X-Content-SHA256', 400),
    ('X-OUF-File-ID', 400), ('Idempotency-Key', 400), ('X-OUF-Delegation', 403),
])
def test_missing_upload_header(name, status):
    with pytest.raises(Denied) as denied:
        execute({name: None})
    assert denied.value.args == (status,)


def test_xlsx_signed_stream(routes):
    route = routes['mcp-managed-file-upload']
    data = b'PK\\x03\\x04synthetic stream'
    engine = execute({'Content-Type': XLSX}, data=data, route=route)
    assert engine.body == data and engine.headers[b'content-type'] == XLSX.encode()
    encoded, signature = engine.headers[b'x-ouf-managed-file-receipt'].split(b'.')
    expected = hmac.digest(KEY.encode(), b'ouf-managed-file-upload-v2.' + encoded, 'sha256')
    assert base64.urlsafe_b64encode(expected).rstrip(b'=') == signature
    receipt = json.loads(base64.urlsafe_b64decode(encoded + b'=='))
    assert (receipt['v'], receipt['mediaType'], receipt['expectedLength']) == (2, XLSX, len(data))
    assert receipt['expectedHash'] == 'sha256:' + hashlib.sha256(data).hexdigest()
    assert receipt['path'] == PATH and receipt['idempotencyKey'] == 'upload-once'
    with pytest.raises(Denied, match='400'):
        execute({'Content-Type': XLSX}, allowed='text/csv')
    with pytest.raises(Denied, match='400'):
        execute(allowed=XLSX)


@pytest.mark.parametrize('value', [None, '', [], 'text/csv,', '*/*', 'text/csv, text/plain'])
def test_invalid_installation_value_blocks_upload(value):
    rt = runtime()
    if value is None:
        del rt['x-ouf-installation']['managedUploadMediaTypes']
    else:
        rt['x-ouf-installation']['managedUploadMediaTypes'] = value
    with pytest.raises(ValueError, match='GATEWAY_INSTALLATION_VALUE'):
        materialize(rt, '$ENV://OIDC_SECRET', 'DELEGATION_KEY', 'OWNER_KEY')
