"""Pinned MCP inputs must survive APISIX validation without widening the boundary."""
import copy
import json
from pathlib import Path

import pytest
from jsonschema import Draft7Validator

from tests.test_execute_delegation import envelope, runtime
from tools.materialize_permission_proposals import materialize

ROOT = Path(__file__).resolve().parents[1]
READ = 'authorization.permissions.read'
PROPOSE = 'authorization.permissions.propose'

def role_change():
    return {'operation': 'REPLACE_ROLES', 'reason': 'Assign reviewed viewer role',
            'roleCatalogue': {'issuer': 'https://iam.example/realms/ente',
                'roles': [{'roleId': 'viewer', 'displayName': 'Viewer',
                           'permissions': [{'capabilityId': 'ouf.system.status'}]}],
                'assignments': [{'assignmentId': 'nominal', 'roleId': 'viewer',
                    'subjectId': 'human-a', 'validFrom': '2026-09-20T00:00:00Z',
                    'validUntil': '2027-09-20T00:00:00Z'}]}}

def cases():
    values = [(READ, {'subjectId': 'human-a', 'limit': 100}, True),
              (READ, {'view': 'GRANTS', 'subjectId': 'human-a', 'limit': 100}, True),
              (READ, {'view': 'GRANTS', 'externalRoleRef': 'ente:staff'}, True),
              (READ, {'view': 'ROLES'}, True),
              (READ, {'view': 'ROLES', 'subjectId': 'human-a'}, False),
              (READ, {'view': 'ADMIN'}, False),
              (READ, {'subjectId': 'human-a', 'externalRoleRef': 'ente:staff'}, False),
              (READ, {'view': 'GRANTS'}, False),
              (READ, {'view': 'ROLES', 'confirm': True}, False),
              (PROPOSE, role_change(), True)]
    organizational = role_change()
    assignment = organizational['roleCatalogue']['assignments'][0]
    del assignment['subjectId']
    assignment['externalRoleRef'] = 'ente:staff'
    values.append((PROPOSE, organizational, True))
    for kind in ('both_selectors', 'no_selector', 'confirm', 'extra_grant', 'nested_unknown'):
        bad = role_change()
        a = bad['roleCatalogue']['assignments'][0]
        if kind == 'both_selectors': a['externalRoleRef'] = 'ente:staff'
        if kind == 'no_selector': del a['subjectId']
        if kind == 'confirm': bad['confirm'] = True
        if kind == 'extra_grant': bad['grantId'] = 'unrelated'
        if kind == 'nested_unknown': a['superadmin'] = True
        values.append((PROPOSE, bad, False))
    values.append((PROPOSE, {'operation': 'PUBLISH', 'reason': 'forbidden'}, False))
    return values

def dispatch(capability, arguments):
    value = envelope()
    value.update(CapabilityID=capability, GatewayBindingRef='capability://'+capability,
                 Owner='authorization', OperationClass='READ' if capability == READ else 'COMMAND',
                 Arguments=copy.deepcopy(arguments))
    return value

def test_gateway_inputs_match_pinned_mcp_manifest():
    fixture = json.loads((ROOT/'tests/fixtures/permission-inputs-mcp-5615fdc.json').read_text())
    schemas = json.loads((ROOT/'schemas/mcp-gateway-permissions-dispatch-v1.json').read_text())['oneOf']
    for schema in schemas:
        cap = schema['properties']['CapabilityID']['const']
        assert schema['properties']['Arguments'] == fixture['schemas'][cap]

@pytest.mark.parametrize('capability,arguments,allowed', cases())
def test_materialized_route_accepts_only_valid_inputs(capability, arguments, allowed):
    doc = materialize(runtime(), '$ENV://OIDC_SECRET', 'DELEGATION_KEY', 'OWNER_KEY')
    mode = 'read' if capability == READ else 'propose'
    route = next(r for r in doc['routes'] if r['id'] == 'mcp-permissions-'+mode)
    validator = Draft7Validator(route['plugins']['request-validation']['body_schema'])
    assert validator.is_valid(dispatch(capability, arguments)) is allowed
