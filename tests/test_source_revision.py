import base64
import copy
import hashlib
import hmac
import json
from pathlib import Path
import pytest
from jsonschema import Draft202012Validator, FormatChecker
from tests.test_execute_delegation import Denied, Engine, INSTALL, KEY, human, proof, workload
from tests.test_file_loop_coherence import retained_installation
from tests.test_managed_file_mcp import request as managed_request
from tools.delegation_functions import function
from tools.materialize_onboarding_review import materialize as reviews
from tools.materialize_source_revision import materialize, MODES

ROOT = Path(__file__).resolve().parents[1]
VERSION = '22222222-2222-4222-8222-222222222222'


def request(mode='prepare', command_read=False):
    cap, operation, _ = MODES[mode]
    e = managed_request()
    args = {'sourceId': 'api-fixture', 'onboardingVersionId': VERSION}
    if mode == 'prepare' or command_read:
        args = {'sourceId': 'api-fixture', 'parentVersionId': VERSION, 'commandKey': 'same-revision-1'}
    if mode == 'prepare':
        args.update(expectedVersion=4, configurationHash='sha256:'+'a'*64,
            publicationEffect='NEW_PUBLICATION_MAY_START_ACQUISITION', changes=[{
                'propertyIri': 'urn:name', 'sourceField': 'urn:name', 'reconciliation': {
                    'policyRef': 'urn:ouf:policy:linked-object-property-reconciliation:v1',
                    'cardinality': 'SINGLE', 'normalizerRef': 'EXACT_TYPED', 'normalizerVersion': 1, 'validity': 'SOURCE_INTERVAL'}}])
    e.update(CapabilityID=cap, GatewayBindingRef='capability://'+cap, OperationClass=operation,
        Arguments=args, IdempotencyKey='same-revision-1')
    return e


def execute(mode='prepare', body=None, delegation=None, uri=None, now=1000):
    e = body or request(mode)
    headers = {'X-OUF-Delegation': delegation or proof(dict(human(), scope=e['CapabilityID'])),
        'X-Correlation-ID': e['CorrelationID'], 'Idempotency-Key': e['IdempotencyKey'],
        'X-Tool-Attempt-ID': e['AttemptID'], 'X-OUF-Source-Revision-Receipt': 'forged', 'Authorization': 'Bearer forged'}
    engine = Engine(dict(workload(), exp=now+300), headers, e, now=now, uri=uri or '/internal/capabilities/v1/execute/source.revision/'+mode)
    engine.modules[b'resty.openssl.digest'] = engine.lua.table_from({b'new': lambda _: engine.lua.table_from({b'final': lambda _, data: hashlib.sha256(data).digest()})})
    engine.modules[b'resty.string'] = engine.lua.table_from({b'to_hex': lambda data: data.hex().encode()})
    engine.lua.execute(function('execute_source_revision', INSTALL, 'TEST_KEY', 'OWNER_KEY').encode())(None, None)
    return engine


@pytest.mark.parametrize('mode', MODES)
def test_real_lua_separates_revision_receipt_and_retains_exact_command_bytes(mode):
    e = request(mode);engine = execute(mode, e)
    encoded, signature = engine.headers[b'x-ouf-source-revision-receipt'].split(b'.')
    decode = lambda x: base64.urlsafe_b64decode(x+b'='*((4-len(x)%4)%4))
    assert hmac.compare_digest(decode(signature), hmac.new(KEY.encode(), b'ouf-source-revision-owner-v1.'+encoded, hashlib.sha256).digest())
    receipt = json.loads(decode(encoded))
    assert receipt['purpose'] == 'source-revision-owner'
    assert receipt['path'] == '/api/internal/v1/onboarding/source-revision-mcp/'+mode
    assert receipt['bodyHash'] == hashlib.sha256(engine.body).hexdigest()
    assert receipt['subject'] == 'human-a' and receipt['tenant'] == 'tenant-a'
    assert json.loads(engine.body) == e
    assert b'authorization' not in engine.headers and b'x-ouf-delegation' not in engine.headers
    assert b'x-ouf-managed-file-receipt' not in engine.headers


@pytest.mark.parametrize('case', ['scope', 'actor', 'operation', 'owner', 'intent', 'path'])
def test_no_legacy_scope_or_caller_approval_or_arbitrary_path(case):
    e = request();delegation = None;uri = None
    if case == 'scope': delegation = proof(dict(human(), scope='ouf.managed-source.onboarding.review.prepare'))
    if case == 'actor': delegation = proof(dict(human(), ouf_actor_type='AI_AGENT', scope=e['CapabilityID']))
    if case == 'operation': e['OperationClass'] = 'READ'
    if case == 'owner': e['Owner'] = 'authorization'
    if case == 'intent': e['Arguments']['commandKey'] = 'different-intent'
    if case == 'path': uri = '/untrusted/prepare'
    with pytest.raises(Denied): execute(body=e, delegation=delegation, uri=uri)


def test_additive_materialization_preserves_browser_and_every_existing_route():
    rt, existing = retained_installation();existing = reviews(existing, rt, 'DELEGATION_KEY', 'ONBOARDING_OWNER_KEY')
    before = copy.deepcopy(existing);result = materialize(existing, rt, 'DELEGATION_KEY', 'ONBOARDING_OWNER_KEY')
    assert existing == before and result['routes'][:-2] == before['routes']
    for route in result['routes'][-2:]:
        mode = route['uri'].rsplit('/', 1)[1]
        validator = Draft202012Validator(route['plugins']['request-validation']['body_schema'], format_checker=FormatChecker())
        assert validator.is_valid(request(mode))
        if mode == 'read': assert validator.is_valid(request(mode, command_read=True))
        assert route['upstream']['retries'] == 0
        assert route['upstream']['nodes'] == {'ouf-onboarding:8080': 1}
        for field in ('approvedBy', 'confirm', 'url', 'configuration', 'authorityOrder'):
            bad = request(mode);bad['Arguments'][field] = True
            assert not validator.is_valid(bad)
    with pytest.raises(ValueError, match='reconcile'): materialize(result, rt, 'DELEGATION_KEY', 'ONBOARDING_OWNER_KEY')
    rt['routes'] = copy.deepcopy(rt['routes'])
    next(r for r in rt['routes'] if r['id'] == 'mcp-source-revision-prepare')['x-ouf-backend-binding']['path'] = '/wrong'
    with pytest.raises(ValueError, match='binding mismatch'): materialize(before, rt, 'DELEGATION_KEY', 'ONBOARDING_OWNER_KEY')


@pytest.mark.parametrize('mode', MODES)
def test_closed_schema_and_ambiguous_read_selector(mode):
    schema = json.loads((ROOT/f'schemas/mcp-gateway-source-revision-{mode}-dispatch-v1.json').read_text())
    validator = Draft202012Validator(schema, format_checker=FormatChecker());assert validator.is_valid(request(mode))
    bad = request(mode);bad['Arguments']['sourceId'] = '../escape';assert not validator.is_valid(bad)
    bad = request(mode);bad['Arguments']['approvedBy'] = 'caller';assert not validator.is_valid(bad)
    if mode == 'prepare':
        for field, value in [('changes', []), ('expectedVersion', True), ('expectedVersion', -1), ('configurationHash', 'unpinned'), ('publicationEffect', 'NO_ACQUISITION')]:
            bad = request(mode);bad['Arguments'][field] = value;assert not validator.is_valid(bad)
        bad = request(mode);bad['Arguments']['changes'][0]['authorityOrder'] = ['preferred'];assert not validator.is_valid(bad)
    else:
        bad = request(mode, command_read=True);bad['Arguments']['onboardingVersionId'] = VERSION;assert not validator.is_valid(bad)
        bad = request(mode);del bad['Arguments']['onboardingVersionId'];assert not validator.is_valid(bad)
