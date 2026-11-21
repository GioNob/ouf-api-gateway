from copy import deepcopy

import pytest
from jsonschema import Draft202012Validator, FormatChecker

from tests.test_managed_file_mcp import ASSET, OTHER, request as file_request
from tests.test_onboarding_review import request as review_request
from tests.test_source_revision import request as revision_request
from tools.gateway_release_bundle import release_routes

REFERENCE = {'profileId': OTHER, 'profileVersion': 1, 'unitRef': 'table:0', 'schemaHash': 'sha256:' + 'a'*64}


@pytest.fixture(scope='module')
def validators():
    return {r['id']: Draft202012Validator(r['plugins']['request-validation']['body_schema'],
                                           format_checker=FormatChecker()) for r in release_routes()}


@pytest.mark.parametrize('mode', ['preview', 'profile'])
def test_view_selection(validators, mode):
    check = validators['mcp-managed-file-' + mode].is_valid
    envelope = file_request(mode)
    assert check(envelope)
    args = {'assetId': ASSET, 'profileId': OTHER, 'offset': 0, 'limit': 128}
    for view, ref, valid in [('UNITS', {}, True), ('UNIT', {'unitRef': 'table:0'}, True),
                             ('UNITS', {'unitRef': 'table:0'}, False), ('UNIT', {}, False),
                             ('UNIT', {'unitRef': ''}, False), ('UNIT', {'unitRef': 1}, False)]:
        assert check(dict(envelope, Arguments=dict(args, view=view, **ref))) == valid
    for delta in ({'limit': 129}, {'offset': -1}, {'view': 'unknown'}, {'tenant': 'another'}):
        assert not check(dict(envelope, Arguments={**args, 'view': 'UNITS', **delta}))
    assert not check(dict(envelope, Arguments={'view': 'UNITS', 'assetId': ASSET}))


@pytest.mark.parametrize('mode', ['create', 'review-prepare', 'revision-prepare'])
def test_immutable_reference(validators, mode):
    if mode == 'revision-prepare':
        check = validators['mcp-source-revision-prepare'].is_valid
        envelope = revision_request()
    else:
        check = validators['mcp-managed-file-' + mode].is_valid
        envelope = file_request(mode) if mode == 'create' else review_request()
    assert check(envelope)
    args = envelope['Arguments']
    args['unitProfileRef'] = REFERENCE
    assert check(envelope)
    if mode == 'create':
        del args['assetId'], args['profileId']
    if mode == 'revision-prepare':
        del args['changes']
        args['newColumns'] = []
    assert check(envelope)
    for field in REFERENCE:
        changed = deepcopy(args)
        del changed['unitProfileRef'][field]
        assert not check(dict(envelope, Arguments=changed))
    for delta in ({'unitRef': ''}, {'profileId': 'invalid'}, {'profileVersion': 0}, {'profileVersion': True},
                  {'schemaHash': 'sha256:' + 'A'*64}, {'schemaHash': REFERENCE['schemaHash'] + '\n'},
                  {'assetId': ASSET}):
        assert not check(dict(envelope, Arguments=dict(args, unitProfileRef={**REFERENCE, **delta})))
    if mode == 'review-prepare':
        assert not check(dict(envelope, Arguments=dict(args, assetId=ASSET)))
    else:
        del args['unitProfileRef']
        assert not check(envelope)
        if mode == 'create':
            assert not check(dict(envelope, Arguments=dict(args, assetId=ASSET)))
            assert not check(dict(envelope, Arguments=dict(args, profileId=OTHER)))
        else:
            args['assetRef'] = {'assetId': ASSET, 'profileId': OTHER}
            assert check(dict(envelope, Arguments=dict(args, unitProfileRef=REFERENCE)))
            assert not check(dict(envelope, Arguments=dict(args, changes=revision_request()['Arguments']['changes'])))
