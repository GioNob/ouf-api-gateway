"""GW-62D-SCHEMA / FORWARD. Validate and forward unit arguments on release routes."""
import json

import pytest
from jsonschema import Draft7Validator, Draft202012Validator, FormatChecker

from tests.extraction_unit_cases import ASSET, OTHER, CONTRACT, UNIT, unit_cases
from tests.test_onboarding_review import execution_proposal
from tests.test_dispatch_schema_contract import dispatch_body
from tests.test_execute_delegation import Engine, human, proof, workload
from tests.test_value_type_schemas import matched_route_context, routes, run_dispatch_rewrite
from tools.gateway_release_bundle import canonical, digest
from tools.mcp_dispatch_contract import MANIFEST, capability_contracts


@pytest.mark.parametrize('tool,vectors', list(unit_cases()))
def test_unit_dispatch(routes, tool, vectors):
    row = next(r for r in capability_contracts().values() if r.get('toolName') == tool)
    source = Draft202012Validator(row['inputSchema'], format_checker=FormatChecker())
    cap = row['capabilityId']
    route, = (r for r in routes.values() if r['plugins'].get('request-validation', {})
              .get('body_schema', {}).get('properties', {}).get('CapabilityID') == {'const': cap})
    schema = route['plugins']['request-validation']['body_schema']
    gateway = Draft7Validator(schema, format_checker=FormatChecker())
    for args, valid in vectors:
        body = dispatch_body(schema, args)
        body['IdempotencyKey'] = args.get('commandKey', body['IdempotencyKey'])
        assert gateway.is_valid(body) == source.is_valid(args) == valid, (tool, args)
        if valid:
            headers = {'X-OUF-Delegation': proof(dict(human(), scope=cap)), 'Idempotency-Key': body['IdempotencyKey'],
                       'X-Correlation-ID': body['CorrelationID'], 'X-Tool-Attempt-ID': body['AttemptID']}
            engine = Engine(workload(), headers, body, uri=route['uri'])
            original = engine.body
            ctx = matched_route_context(engine, route)
            run_dispatch_rewrite(engine, route, ctx)
            post, = route['plugins']['serverless-post-function']['functions']
            engine.lua.execute(post.encode())(None, ctx)
            assert engine.body == original
            if tool == 'source.onboarding.revision.prepare' and 'unitProfileRef' in args:
                assert engine.headers[b'if-match'] == f'W/"ov:{args["expectedVersion"]}"'.encode()


def test_local_plan_and_upload_manifest():
    schemas = {row['toolName']: row['inputSchema'] for row in json.loads(MANIFEST.read_bytes())['capabilities']
               if row.get('toolName')}
    plan = Draft202012Validator(schemas['source.analysis.plan'])
    base = {'expectedRevision': 0, 'work': [{'tool': 'semantic.search', 'arguments': {}, 'columns': [0]}]}
    assert plan.is_valid(dict(base, assetId=ASSET, profileId=OTHER))
    assert plan.is_valid(dict(base, unitProfileRef=UNIT))
    assert not plan.is_valid(dict(base, unitProfileRef=UNIT, assetId=ASSET))
    assert not plan.is_valid(dict(base, unitProfileRef=UNIT, profileId=OTHER))
    assert not plan.is_valid(base)
    upload = Draft202012Validator(schemas['source.file.upload'])
    file = {'file_id': 'file_1', 'download_url': 'https://example.org/attachment'}
    for mime, valid in [('text/csv', True), ('application/vnd.openxmlformats-officedocument.spreadsheetml.sheet', True),
                        ('application/json', False)]:
        assert upload.is_valid({'file': dict(file, mime_type=mime)}) == valid
    assert upload.is_valid({'file': file})


def test_historical_preview_and_proposal_fragments():
    """GW-62D-PREDECESSOR. Canonical schema bytes from 3d69cb4."""
    rows = capability_contracts()
    preview = rows['ouf.managed-source.preview']['inputSchema']
    assert digest(canonical(preview['oneOf'][:-3])) == '6e237f6562fe96099883e4102c4a5b6994e7378feac31de58c684ea1aa31b717'
    review = rows['ouf.managed-source.onboarding.review.prepare']['inputSchema']
    legacy, managed = review['properties']['executionProposal']['oneOf']
    assert digest(canonical(legacy)) == 'd1e43087b1940816c90eec6b4769b6d467716a2d19e26c055f3d1c54fc7f4b97'
    args = dict(execution_proposal('string'), contract=CONTRACT)
    assert not Draft202012Validator(legacy).is_valid(args)
    assert Draft202012Validator(managed).is_valid(args)
