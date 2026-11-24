"""Explicit F1/F2 vectors for the MCP, the release and native APISIX."""
from tests.test_managed_file_mcp import ASSET, OTHER, request
from tests.test_onboarding_review import execution_proposal, request as review_request
from tests.test_value_type_schemas import dispatch

UNIT = {'profileId': OTHER, 'profileVersion': 1, 'unitRef': 'sheet:0', 'schemaHash': 'sha256:' + '0' * 64}
CONTRACT = 'ouf.managed-unit-execution-proposal.v1'


def unit_cases():
    inventory = {'view': 'UNITS', 'profileId': OTHER}
    unit = dict(inventory, view='UNIT', unitRef='sheet:0')
    cursor = dict(unit, distinctValuesCursor='next-1')
    yield 'source.file.preview', [
        (inventory, True), (dict(inventory, assetId=ASSET, offset=63, limit=64), True),
        (dict(inventory, offset=64), False), (dict(inventory, limit=65), False),
        (dict(inventory, unitRef='sheet:0'), False), ({'view': 'UNITS'}, False),
        (dict(unit, offset=1023, limit=128), True), (dict(unit, limit=129), False),
        (dict(unit, unitRef='sheet:01'), False), (dict(unit, profileId=OTHER.replace('0', 'F')), False),
        (cursor, True), (dict(cursor, offset=0), False), (dict(cursor, limit=1), False),
        (dict(cursor, distinctValuesCursor=''), False), (dict(unit, layer='hidden'), False),
    ]

    def profile(rows):
        return {'assetId': ASSET, 'readOptions': {'xlsx': {'headerRows': rows}}}

    yield 'source.file.profile', [
        (profile({'sheet:0': 1, 'sheet:9999': 1048576}), True), (profile({}), False),
        (profile({'table:0': 1}), False), (profile({'sheet:0': 1048577}), False),
        (profile({'sheet:0': True}), False), (profile({f'sheet:{i}': 1 for i in range(65)}), False),
        ({'assetId': ASSET, 'readOptions': {'csv': {}}}, False),
    ]
    create = request('create')['Arguments']
    del create['assetId'], create['profileId']
    yield 'source.onboarding.create', [
        (dict(create, unitProfileRef=UNIT), True),
        (dict(create, assetId=ASSET, profileId=OTHER, unitProfileRef=UNIT), True),
        (create, False), (dict(create, unitProfileRef=dict(UNIT, profileVersion=0)), False),
        (dict(create, unitProfileRef=dict(UNIT, schemaHash='bad')), False),
        (dict(create, unitProfileRef=dict(UNIT, unknown=True)), False),
    ]
    review = dict(review_request()['Arguments'], unitProfileRef=UNIT)
    legacy = execution_proposal('string')
    proposal = dict(legacy, contract=CONTRACT)
    yield 'source.onboarding.review.prepare', [
        (review, True), (dict(review, executionProposal=legacy), True), (dict(review, executionProposal=proposal), True),
        (dict(review, executionProposal=dict(legacy, contract='typed-csv:v2')), False),
        (dict(review, executionProposal=dict(proposal, udp=dict(proposal['udp'], spatial={}))), False),
        (dict(review, candidateAction='WITHDRAW', executionProposal=proposal), False),
    ]
    revision = dispatch('source.onboarding.revision.prepare')['Arguments']
    asset = revision.pop('assetRef')
    replacement = dict(revision, unitProfileRef=UNIT)
    changes = [{'propertyIri': 'urn:property', 'sourceField': 'column', 'reconciliation': {
        'policyRef': 'urn:ouf:policy:linked-object-property-reconciliation:v1', 'cardinality': 'SINGLE',
        'normalizerRef': 'EXACT_TYPED', 'normalizerVersion': 1, 'validity': 'UNBOUNDED'}}]
    change_request = {key: value for key, value in revision.items() if key != 'newColumns'}
    yield 'source.onboarding.revision.prepare', [
        (replacement, True), (dict(replacement, assetRef=asset), False),
        (dict(change_request, changes=changes), True),
        (dict(change_request, changes=changes, unitProfileRef=UNIT), False), (revision, False),
        (dict(replacement, unitProfileRef=dict(UNIT, profileVersion=2147483648)), False),
    ]
