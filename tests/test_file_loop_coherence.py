"""A proposal rollout must retain the already deployed CSV/chatbot route set."""
import copy

import pytest

from tests.test_execute_delegation import runtime
from tools.materialize_managed_file_mcp import materialize as managed
from tools.materialize_managed_upload import materialize as upload
from tools.materialize_object_search import materialize as objects
from tools.materialize_semantic_read import materialize as semantic_read
from tools.materialize_semantic_proposals import add_to_existing


def retained_installation():
    rt = runtime()
    args = (rt, '$ENV://OIDC_SECRET', 'DELEGATION_KEY', 'AUTHORIZATION_OWNER_KEY')
    existing = objects(*args, 'UDP_OWNER_KEY')
    existing['routes'].extend(r for r in managed(*args)['routes']
                              if r.get('labels', {}).get('ouf-mediation') == 'managed-file-delegation-v1')
    existing['routes'].append(upload(*args))
    return rt, semantic_read(existing, rt['x-ouf-installation'], 'DELEGATION_KEY', 'SEMANTIC_READ_KEY',
                            {'scheme': 'http', 'nodes': {'ouf-semantic-registry:8080': 1}},
                            {'search': 'retained-semantic-search', 'get': 'retained-semantic-get'})


def test_new_proposals_preserve_complete_retained_file_loop_and_security():
    rt, existing = retained_installation()
    before = copy.deepcopy(existing)
    result = add_to_existing(existing, rt, 'DELEGATION_KEY', 'SEMANTIC_PROPOSAL_KEY')
    assert existing == before
    assert result['routes'][:-4] == before['routes']
    paths = {r['uri'] for r in result['routes'] if 'uri' in r}
    assert {'/internal/capabilities/v1/execute/managed.file/'+mode
            for mode in ('upload', 'handoff', 'profile', 'preview', 'create')} <= paths
    assert {'/internal/capabilities/v1/execute/semantic/'+mode
            for mode in ('search', 'get', 'create', 'validate', 'review', 'read')} <= paths
    assert '/internal/capabilities/v1/execute/urban.object.search' in paths
    assert '/internal/capabilities/v1/execute/ouf.operations.incidents' in paths
    assert '/mcp' in paths
    for route in result['routes'][-4:]:
        assert route['upstream']['retries'] == 0
        assert set(('openid-connect', 'limit-count', 'request-validation', 'serverless-pre-function')) <= route['plugins'].keys()
        assert not any(word in route['uri'] for word in ('approve', 'publish', 'confirm'))


def test_additive_materialization_denies_collision_and_untrusted_template():
    rt, existing = retained_installation()
    result = add_to_existing(existing, rt, 'DELEGATION_KEY', 'SEMANTIC_PROPOSAL_KEY')
    with pytest.raises(ValueError, match='reconcile'):
        add_to_existing(result, rt, 'DELEGATION_KEY', 'SEMANTIC_PROPOSAL_KEY')
    collision = copy.deepcopy(existing)
    collision['routes'].append({'id': 'semantic-proposal-create', 'uri': '/unrelated'})
    with pytest.raises(ValueError, match='reconcile'):
        add_to_existing(collision, rt, 'DELEGATION_KEY', 'SEMANTIC_PROPOSAL_KEY')
    for name in ('openid-connect', 'limit-count', 'request-validation', 'serverless-pre-function'):
        changed = copy.deepcopy(existing)
        template = next(r for r in changed['routes'] if r['uri'] == '/internal/capabilities/v1/execute')
        del template['plugins'][name]
        with pytest.raises(ValueError, match='authenticated bounded'):
            add_to_existing(changed, rt, 'DELEGATION_KEY', 'SEMANTIC_PROPOSAL_KEY')
