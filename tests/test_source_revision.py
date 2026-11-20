import base64
import copy
import hashlib
import hmac
import json
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator, FormatChecker

from tests.test_execute_delegation import Denied, Engine, INSTALL, envelope, human, proof, workload
from tests.test_file_loop_coherence import retained_installation
from tools.delegation_functions import function
from tools.materialize_onboarding_review import materialize as reviews
from tools.materialize_source_revision import materialize, MODES

ROOT = Path(__file__).resolve().parents[1]
OWNER_KEY = hashlib.sha256(b'revision-owner-test-fixture').hexdigest().encode()
VERSION = '22222222-2222-4222-8222-222222222222'


def owner_example():
    """Arguments from the owner's published CSV replacement example."""
    return {
        'sourceId': 'source-example',
        'parentVersionId': '00000000-0000-4000-8000-000000000001',
        'expectedVersion': 7,
        'configurationHash': 'sha256:' + 'a' * 64,
        'commandKey': 'second-upload-1',
        'publicationEffect': 'NEW_PUBLICATION_MAY_START_ACQUISITION',
        'assetRef': {
            'assetId': '00000000-0000-4000-8000-000000000002',
            'profileId': '00000000-0000-4000-8000-000000000003',
        },
        'newColumns': [
            {'column': 'note', 'decision': 'EXCLUDE'},
            {'column': 'prezzo', 'decision': 'MAP', 'mapping': {
                'propertyIri': 'urn:example:prezzo',
                'transform': 'DECIMAL_DOT_V1',
                'reconciliation': {
                    'policyRef': 'urn:ouf:policy:linked-object-property-reconciliation:v1',
                    'cardinality': 'SINGLE', 'normalizerRef': 'EXACT_TYPED',
                    'normalizerVersion': 1, 'validity': 'UNBOUNDED',
                },
            }},
        ],
    }


def request(mode='prepare', command_read=False):
    cap, operation, _ = MODES[mode]
    e = envelope()
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
        Owner='onboarding', Arguments=args, IdempotencyKey='same-revision-1')
    return e


def execute(mode='prepare', body=None, delegation=None, uri=None, headers=None, claims=None):
    e = body or request(mode)
    incoming = {'X-OUF-Delegation': delegation or proof(dict(human(), scope=e['CapabilityID'])),
        'X-Correlation-ID': e['CorrelationID'], 'Idempotency-Key': e['IdempotencyKey'],
        'X-Tool-Attempt-ID': e['AttemptID'], 'X-OUF-Source-Revision-Receipt': 'forged', 'X-OUF-Managed-File-Receipt': 'forged',
        'Cookie': 'caller-session'}
    incoming.update(headers or {})
    engine = Engine(claims or workload(), incoming, e, uri=uri or '/internal/capabilities/v1/execute/source.revision/'+mode)
    engine.lua.globals()[b'OWNER_KEY'] = OWNER_KEY
    engine.lua.execute(b'os.getenv=function(name) if name == "OWNER_KEY" then return OWNER_KEY end return TEST_KEY end')
    engine.lua.execute(function('execute_source_revision', INSTALL, 'TEST_KEY', 'OWNER_KEY').encode())(None, None)
    return engine


@pytest.mark.parametrize('mode', MODES)
def test_real_lua_separates_revision_receipt_and_retains_exact_command_bytes(mode):
    e = request(mode)
    engine = execute(mode, e)
    encoded, signature = engine.headers[b'x-ouf-source-revision-receipt'].split(b'.')
    expected = hmac.digest(OWNER_KEY, b'ouf-source-revision-owner-v1.' + encoded, 'sha256')
    assert hmac.compare_digest(decode(signature), expected)
    receipt = json.loads(decode(encoded))
    assert receipt['purpose'] == 'source-revision-owner'
    assert receipt['path'] == '/api/internal/v1/onboarding/source-revision-mcp/'+mode
    assert receipt['bodyHash'] == hashlib.sha256(engine.body).hexdigest()
    assert receipt['subject'] == e['Identity']['PrincipalID']
    assert receipt['tenant'] == e['Identity']['TenantID']
    assert engine.body == json.dumps(e).encode()
    assert b'authorization' not in engine.headers and b'x-ouf-delegation' not in engine.headers
    assert b'cookie' not in engine.headers and b'x-ouf-managed-file-receipt' not in engine.headers


def decode(value):
    return base64.urlsafe_b64decode(value + b'=' * (-len(value) % 4))


@pytest.mark.parametrize('case', ['scope', 'actor', 'operation', 'owner', 'intent', 'path'])
def test_no_legacy_scope_or_caller_approval_or_arbitrary_path(case):
    e = request()
    delegation = uri = None
    if case == 'scope': delegation = proof(dict(human(), scope='ouf.managed-source.onboarding.review.prepare'))
    if case == 'actor': delegation = proof(dict(human(), ouf_actor_type='AI_AGENT', scope=e['CapabilityID']))
    if case == 'operation': e['OperationClass'] = 'READ'
    if case == 'owner': e['Owner'] = 'authorization'
    if case == 'intent': e['Arguments']['commandKey'] = 'different-intent'
    if case == 'path': uri = '/untrusted/prepare'
    with pytest.raises(Denied): execute(body=e, delegation=delegation, uri=uri)


def test_additive_materialization_preserves_browser_and_every_existing_route():
    rt, existing = retained_installation()
    existing = reviews(existing, rt, 'DELEGATION_KEY', 'ONBOARDING_OWNER_KEY')
    # Model another installation using its own projected host and backend port.
    host, port = 'owner.example.invalid', 19443
    for binding in rt['routes']:
        if binding['id'] in ('mcp-source-revision-prepare', 'mcp-source-revision-read'):
            rt['x-ouf-installation']['serviceBindings'][binding['service_id']] = host
            binding['x-ouf-backend-binding'].update(service=host, port=port)
    review = next(r for r in existing['routes'] if r['id'] == 'trusted-human-onboarding-review')
    review['upstream']['nodes'] = {f'{host}:{port}': 1}
    before = copy.deepcopy(existing)
    result = materialize(existing, rt, 'DELEGATION_KEY', 'ONBOARDING_OWNER_KEY')
    assert existing == before and result['routes'][:-2] == before['routes']
    assert {r['id'] for r in result['routes'][-2:]} == {'mcp-source-revision-'+mode for mode in MODES}
    for route in result['routes'][-2:]:
        mode = route['uri'].rsplit('/', 1)[1]
        validator = Draft202012Validator(route['plugins']['request-validation']['body_schema'], format_checker=FormatChecker())
        assert validator.is_valid(request(mode))
        if mode == 'read': assert validator.is_valid(request(mode, command_read=True))
        assert route['upstream']['retries'] == 0
        assert route['upstream']['nodes'] == review['upstream']['nodes']
        for field in ('approvedBy', 'confirm', 'url', 'configuration', 'authorityOrder'):
            bad = request(mode)
            bad['Arguments'][field] = True
            assert not validator.is_valid(bad)
    with pytest.raises(ValueError, match='reconcile'): materialize(result, rt, 'DELEGATION_KEY', 'ONBOARDING_OWNER_KEY')
    collision = copy.deepcopy(before)
    collision['routes'].append({'id': 'other', 'uris': [result['routes'][-1]['uri']]})
    with pytest.raises(ValueError, match='reconcile'):
        materialize(collision, rt, 'DELEGATION_KEY', 'ONBOARDING_OWNER_KEY')
    review['upstream']['nodes'] = {}
    with pytest.raises(ValueError, match='native HUMAN'):
        materialize(existing, rt, 'DELEGATION_KEY', 'ONBOARDING_OWNER_KEY')
    next(r for r in rt['routes'] if r['id'] == 'mcp-source-revision-prepare')['x-ouf-backend-binding']['path'] = '/wrong'
    with pytest.raises(ValueError, match='binding mismatch'): materialize(before, rt, 'DELEGATION_KEY', 'ONBOARDING_OWNER_KEY')


@pytest.mark.parametrize('mode', MODES)
def test_closed_schema_and_ambiguous_read_selector(mode):
    schema = json.loads((ROOT/f'schemas/mcp-gateway-source-revision-{mode}-dispatch-v1.json').read_text())
    validator = Draft202012Validator(schema, format_checker=FormatChecker())
    validator.validate(request(mode))
    for field, value in [('sourceId', '../escape'), ('approvedBy', 'caller')]:
        bad = request(mode)
        bad['Arguments'][field] = value
        assert not validator.is_valid(bad)
    if mode == 'prepare':
        for field, value in [('changes', []), ('expectedVersion', True), ('expectedVersion', -1), ('configurationHash', 'unpinned'), ('publicationEffect', 'NO_ACQUISITION')]:
            bad = request(mode)
            bad['Arguments'][field] = value
            assert not validator.is_valid(bad)
        bad = request(mode)
        bad['Arguments']['changes'][0]['authorityOrder'] = ['preferred']
        assert not validator.is_valid(bad)
    else:
        bad = request(mode, command_read=True)
        bad['Arguments']['onboardingVersionId'] = VERSION
        assert not validator.is_valid(bad)
        bad = request(mode)
        del bad['Arguments']['onboardingVersionId']
        assert not validator.is_valid(bad)


def prepare_validator():
    schema = json.loads((ROOT / 'schemas/mcp-gateway-source-revision-prepare-dispatch-v1.json').read_bytes())
    return Draft202012Validator(schema, format_checker=FormatChecker())


def asset_request():
    args = owner_example()
    return dict(request(), Arguments=args, IdempotencyKey=args['commandKey'])


def test_owner_example_and_single_intent():
    validator = prepare_validator()
    e = asset_request()
    validator.validate(e)
    columns = e['Arguments'].pop('newColumns')
    validator.validate(e)
    e['Arguments']['newColumns'] = []
    validator.validate(e)
    del e['Arguments']['newColumns']
    asset = e['Arguments'].pop('assetRef')
    assert not validator.is_valid(e)
    e['Arguments']['changes'] = request()['Arguments']['changes']
    validator.validate(e)
    e['Arguments']['newColumns'] = columns
    assert not validator.is_valid(e)
    del e['Arguments']['newColumns']
    e['Arguments']['assetRef'] = asset
    assert not validator.is_valid(e)


@pytest.mark.parametrize('field', ['assetId', 'profileId'])
def test_asset_requires_both_uuids(field):
    e = asset_request()
    asset = e['Arguments']['assetRef']
    del asset[field]
    assert not prepare_validator().is_valid(e)
    asset[field] = 'invalid'
    assert not prepare_validator().is_valid(e)


@pytest.mark.parametrize('path', [
    (), ('assetRef',), ('newColumns', 0), ('newColumns', 1, 'mapping'),
    ('newColumns', 1, 'mapping', 'reconciliation'),
])
def test_asset_objects_are_closed(path):
    e = asset_request()
    target = e['Arguments']
    for key in path:
        target = target[key]
    target['unknown'] = True
    assert not prepare_validator().is_valid(e)


def test_mapping_required_exactly_for_map():
    e = asset_request()
    excluded, mapped = e['Arguments']['newColumns']
    mapping = mapped.pop('mapping')
    validator = prepare_validator()
    assert not validator.is_valid(e)
    mapped['mapping'] = mapping
    excluded['mapping'] = mapping
    assert not validator.is_valid(e)


@pytest.mark.parametrize(('field', 'value'), [
    ('propertyIri', 'relative'), ('transform', 'AUTO'), ('accessLabel', 'unknown'),
    ('reconciliation', {}), ('authorityOrder', ['a', 'a']),
    ('authorityOrder', [str(i) for i in range(33)]),
    ('comparison', {'comparator': 'DECIMAL_V1'}),
])
def test_invalid_new_column_mapping(field, value):
    e = asset_request()
    e['Arguments']['newColumns'][1]['mapping'][field] = value
    assert not prepare_validator().is_valid(e)


def test_new_column_limits_and_optional_mapping_fields():
    e = asset_request()
    columns = e['Arguments']['newColumns']
    mapping = columns[1]['mapping']
    mapping.update(accessLabel='RESTRICTED', authorityOrder=[str(i) for i in range(32)],
                   comparison={'comparator': 'DECIMAL_V1', 'assertionRef': 'urn:example:comparison'})
    columns.extend({'column': str(i), 'decision': 'EXCLUDE'} for i in range(1022))
    validator = prepare_validator()
    validator.validate(e)
    columns.append({'column': 'extra', 'decision': 'EXCLUDE'})
    assert not validator.is_valid(e)


@pytest.mark.parametrize('version', [0, 7, 9007199254740991])
@pytest.mark.parametrize('headers', [{}, {'If-Match': '*'}])
def test_asset_etag_uses_exact_signed_integer(version, headers):
    e = asset_request()
    e['Arguments']['expectedVersion'] = version
    engine = execute(body=e, headers=headers)
    assert engine.headers[b'if-match'] == f'W/"ov:{version}"'.encode()
    assert engine.body == json.dumps(e).encode()
    encoded = engine.headers[b'x-ouf-source-revision-receipt'].split(b'.')[0]
    receipt = json.loads(decode(encoded))
    assert receipt['bodyHash'] == hashlib.sha256(engine.body).hexdigest()


@pytest.mark.parametrize('mode', MODES)
def test_other_requests_retain_candidate_etag_behavior(mode):
    assert b'if-match' not in execute(mode).headers
    assert execute(mode, headers={'If-Match': '*'}).headers[b'if-match'] == b'*'


@pytest.mark.parametrize('mode,other', [('prepare', 'read'), ('read', 'prepare')])
def test_each_operation_requires_its_own_scope(mode, other):
    with pytest.raises(Denied):
        execute(mode, delegation=proof(dict(human(), scope=MODES[other][0])))


@pytest.mark.parametrize('header', ['X-Correlation-ID', 'X-Tool-Attempt-ID', 'Idempotency-Key'])
def test_admission_headers_must_match(header):
    with pytest.raises(Denied) as denied:
        execute(headers={header: 'different'})
    assert denied.value.args == (409,)


@pytest.mark.parametrize('field', ['azp', 'tenant_id'])
def test_workload_and_tenant_bound_to_delegation(field):
    with pytest.raises(Denied):
        execute(claims=dict(workload(), **{field: 'different'}))


def test_exact_body_size_bound_including_buffered_requests():
    e = asset_request()
    column = e['Arguments']['newColumns'][0]
    column['column'] += 'a' * (65536 - len(json.dumps(e).encode()))
    assert len(execute(body=e).body) == 65536
    column['column'] += 'a'
    with pytest.raises(Denied) as denied:
        execute(body=e)
    assert denied.value.args == (413,)
