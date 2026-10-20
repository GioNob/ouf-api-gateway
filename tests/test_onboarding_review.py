import base64
import copy
import hashlib
import hmac
import json
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator, FormatChecker

from tests.test_execute_delegation import Denied, KEY, human, proof
from tests.test_file_loop_coherence import retained_installation
from tests.test_managed_file_mcp import request as managed_request, execute
from tools.materialize_onboarding_review import materialize, MODES

ROOT = Path(__file__).resolve().parents[1]


def request(mode='review-prepare'):
    cap, operation = MODES[mode]
    e = managed_request()
    args = {'sourceId': 'teatri', 'onboardingVersionId': '22222222-2222-4222-8222-222222222222'}
    if mode == 'review-prepare':
        args.update(expectedVersion=0, commandKey='teatri-review-1')
    e.update(CapabilityID=cap, GatewayBindingRef='capability://'+cap, OperationClass=operation,
             Arguments=args, IdempotencyKey='teatri-review-1')
    return e


@pytest.mark.parametrize('mode', MODES)
def test_review_receipt_preserves_human_owner_scope_and_exact_bytes(mode):
    e = request(mode)
    engine = execute(mode, body=e)
    encoded, signature = engine.headers[b'x-ouf-managed-file-receipt'].split(b'.')
    decode = lambda x: base64.urlsafe_b64decode(x+b'='*((4-len(x)%4)%4))
    assert hmac.compare_digest(decode(signature), hmac.new(KEY.encode(), b'ouf-managed-file-owner-v1.'+encoded, hashlib.sha256).digest())
    receipt = json.loads(decode(encoded))
    assert receipt['capability'] == MODES[mode][0]
    assert receipt['path'] == '/api/internal/v1/onboarding/managed-file-mcp/'+mode
    assert receipt['subject'] == 'human-a' and receipt['tenant'] == 'tenant-a'
    assert receipt['bodyHash'] == hashlib.sha256(engine.body).hexdigest()
    assert json.loads(engine.body) == e
    assert b'authorization' not in engine.headers and b'x-ouf-delegation' not in engine.headers


@pytest.mark.parametrize('case', ['scope', 'actor', 'operation', 'capability', 'intent'])
def test_review_does_not_inherit_old_scope_or_confer_confirmation(case):
    e = request();delegation = None
    if case == 'scope': delegation = proof(dict(human(), scope='mcp.connect ouf.managed-source.onboarding.create'))
    if case == 'actor': delegation = proof(dict(human(), ouf_actor_type='AI_AGENT', scope=e['CapabilityID']))
    if case == 'operation': e['OperationClass'] = 'READ'
    if case == 'capability': e['CapabilityID'] = 'ouf.onboarding.configuration.write'
    if case == 'intent': e['Arguments']['commandKey'] = 'different-intent'
    with pytest.raises(Denied): execute('review-prepare', body=e, delegation=delegation)


def test_additive_review_and_first_party_browser_boundary():
    rt, existing = retained_installation();before = copy.deepcopy(existing)
    result = materialize(existing, rt, 'DELEGATION_KEY', 'ONBOARDING_OWNER_KEY')
    assert existing == before and result['routes'][:-6] == before['routes']
    for route in result['routes'][-6:-4]:
        mode = route['uri'].rsplit('/', 1)[1]
        validator = Draft202012Validator(route['plugins']['request-validation']['body_schema'], format_checker=FormatChecker())
        assert validator.is_valid(request(mode))
        for field, value in [('approvedBy', 'agent'), ('confirm', True), ('url', 'https://untrusted.invalid')]:
            bad = request(mode);bad['Arguments'][field] = value
            assert not validator.is_valid(bad)
        assert route['upstream']['retries'] == 0
        assert route['plugins']['openid-connect']['bearer_only'] is True
    page = result['routes'][-4]
    assert page['uri'] == '/trusted-human/onboarding/*'
    assert page['methods'] == ['GET', 'POST'] and page['upstream']['nodes'] == {'ouf-onboarding:8080': 1}
    assert 'openid-connect' not in page['plugins']  # OAuth session/CSRF stay at existing owner.
    assert 'authorization' in page['plugins']['serverless-pre-function']['functions'][0]
    assert page['upstream']['timeout']['read'] == 60
    assert result['routes'][-3]['uri'] == '/trusted-human/semantic/*'
    with pytest.raises(ValueError, match='reconcile'): materialize(result, rt, 'DELEGATION_KEY', 'ONBOARDING_OWNER_KEY')


def test_activation_uses_human_readiness_and_separate_service_hash_read():
    from tests.test_execute_delegation import Engine
    rt, existing = retained_installation()
    # The attestation POST may already exist; adding GET must preserve it.
    post = {'id': 'retained-compatibility-post', 'uri': '/api/internal/v1/onboarding/compatibility/ingestion-runtime', 'methods': ['POST']}
    existing['routes'].append(post)
    result = materialize(existing, rt, 'DELEGATION_KEY', 'ONBOARDING_OWNER_KEY')
    readiness, compatibility = result['routes'][-2:]
    assert readiness['uri'] == '/api/trusted-human/v1/ingestion/onboarding-readiness'
    assert readiness['methods'] == ['POST']
    assert readiness['upstream']['nodes'] == {'ouf-ingestion-runtime:8080': 1}
    assert readiness['upstream']['retries'] == 0 and readiness['upstream']['timeout']['read'] == 35
    assert readiness['plugins']['openid-connect']['required_scopes'] == ['ouf.onboarding.configuration.write']
    assert readiness['plugins']['openid-connect']['set_access_token_header'] is False
    # Run the generated actor guard; original bearer remains owned by the caller.
    for actor in ('HUMAN', 'AI_AGENT', 'SERVICE'):
        engine = Engine(dict(human(), ouf_actor_type=actor))
        bearer = engine.headers[b'authorization']
        guard = engine.lua.execute(readiness['plugins']['serverless-post-function']['functions'][0].encode())
        if actor == 'HUMAN':
            guard(None, None)
            assert engine.headers[b'authorization'] == bearer
        else:
            with pytest.raises(Denied): guard(None, None)
    assert compatibility['methods'] == ['GET']
    assert compatibility['upstream']['nodes'] == {'ouf-onboarding:8080': 1}
    assert compatibility['upstream']['retries'] == 0 and compatibility['upstream']['timeout']['read'] == 10
    assert compatibility['plugins']['openid-connect']['required_scopes'] == ['ouf.onboarding.configuration.read']
    assert post in result['routes']
    query = next(r for r in rt['routes'] if r['id'] == compatibility['id'])['x-ouf-query-contract']
    validator = Draft202012Validator(query, format_checker=FormatChecker())
    valid = {'sourceId': 'teatri', 'onboardingVersionId': '22222222-2222-4222-8222-222222222222', 'configurationHash': 'sha256:'+'a'*64}
    assert validator.is_valid(valid)
    for missing in valid:
        assert not validator.is_valid({k:v for k,v in valid.items() if k != missing})
    assert not validator.is_valid(dict(valid, configurationHash='unpinned'))


def test_review_schema_bounds_and_login_custody():
    schema = json.loads((ROOT/'schemas/mcp-gateway-onboarding-review-prepare-dispatch-v1.json').read_text())
    validator = Draft202012Validator(schema, format_checker=FormatChecker())
    for field, value in [('sourceId', 'x'*161), ('sourceId', '../escape'), ('onboardingVersionId', 'not-uuid'),
                         ('expectedVersion', -1), ('expectedVersion', True), ('expectedVersion', 9007199254740992),
                         ('commandKey', ''), ('commandKey', 'bad key')]:
        e = request();e['Arguments'][field] = value
        assert not validator.is_valid(e)
    rt, existing = retained_installation()
    login = next(r for r in existing['routes'] if r.get('id') == 'authorization-ths-login')
    login['upstream']['nodes'] = {'untrusted:8080': 1}
    with pytest.raises(ValueError, match='OAuth login'): materialize(existing, rt, 'DELEGATION_KEY', 'ONBOARDING_OWNER_KEY')


@pytest.mark.parametrize("datatype", ["string", "decimal", "date"])
def test_nested_execution_proposal_is_bounded_and_preserved_by_owner_receipt(datatype):
    publication = '00000000-0000-4000-8000-000000000002'
    iri = 'https://schema.org/name'
    policy = {'ref': 'identity-policy', 'version': '1', 'tenantId': 'tenant-a', 'canonicalClass': 'https://schema.org/PerformingArtsTheater',
              'sourceId': 'teatri', 'maxCandidates': 10, 'allowAutoNew': True,
              'signals': [{'id': 'name', 'semanticRef': iri+'@'+publication, 'comparator': 'TEXT_V1',
                           'excludesOnDisagreement': False, 'uniqueWithinScope': False, 'assertionRef': 'reviewed-assertion'}],
              'sufficientRules': [{'id': 'name-rule', 'signalIds': ['name'], 'assertionRef': 'reviewed-rule'}]}
    proposal = {'semanticBindings': [{'semanticId': 'urn:fixture:ontology', 'semanticVersion': '1',
                'revisionId': '00000000-0000-4000-8000-000000000001', 'publicationSetId': publication}],
                'semanticPublicationSetRef': publication,
                'udp': {'resolution': {'strategyId': 'GOVERNED_IDENTITY', 'strategyVersion': '1', 'policyRef': 'identity-policy', 'governedIdentity': policy},
                        'materialization': {'policyRef': 'authority-policy', 'properties': [{'sourceField': 'nome', 'propertyIri': iri,
                         'datatype': 'http://www.w3.org/2001/XMLSchema#'+datatype, 'accessLabel': 'OPEN', 'authorityOrder': ['teatri']}],
                         'bitemporalProperties': [], 'checkpointInterval': 1}},
                'limits': {'maxRows': 100, 'maxColumns': 20, 'maxCellChars': 1000}}
    e = request();e['Arguments']['executionProposal'] = proposal
    schema = json.loads((ROOT/'schemas/mcp-gateway-onboarding-review-prepare-dispatch-v1.json').read_text())
    validator = Draft202012Validator(schema, format_checker=FormatChecker())
    assert validator.is_valid(e)
    assert json.loads(execute('review-prepare', body=e).body) == e
    bad = copy.deepcopy(e);bad['Arguments']['executionProposal']['udp']['sql'] = 'arbitrary'
    assert not validator.is_valid(bad)
    bad = copy.deepcopy(e);bad['Arguments']['executionProposal']['udp']['materialization']['properties'][0]['datatype'] = 'http://www.w3.org/2001/XMLSchema#integer'
    assert not validator.is_valid(bad)
    bad = copy.deepcopy(e);bad['Arguments']['executionProposal']['limits']['maxRows'] = 1000001
    assert not validator.is_valid(bad)


def write_owner_vectors(path):
    vectors = []
    for mode in MODES:
        e = execute(mode, body=request(mode))
        vectors.append({'path': '/api/internal/v1/onboarding/managed-file-mcp/'+mode,
                        'proof': e.headers[b'x-ouf-managed-file-receipt'].decode(), 'body': e.body.decode()})
    Path(path).write_text(json.dumps(vectors)+'\n')
