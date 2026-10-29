"""Qualify discovery on the retained file, semantic proposal and HUMAN review routes."""
import copy
from tests.test_file_loop_coherence import retained_installation
from tools.materialize_onboarding_review import materialize as reviews
from tools.materialize_source_revision import materialize as revisions
from tools.materialize_semantic_proposals import add_to_existing as proposals
from tools.materialize_semantic_discovery import materialize as discovery


def test_discovery_preserves_the_complete_file_review_and_revision_chain():
    runtime, existing = retained_installation()
    existing = proposals(existing, runtime, 'DELEGATION_KEY', 'SEMANTIC_PROPOSAL_KEY')
    existing = reviews(existing, runtime, 'DELEGATION_KEY', 'ONBOARDING_OWNER_KEY')
    existing = revisions(existing, runtime, 'DELEGATION_KEY', 'ONBOARDING_OWNER_KEY')
    before = copy.deepcopy(existing)
    upstream = {'scheme': 'http', 'nodes': {'semantic-fixture:8080': 1}}
    names = ('request', 'status', 'candidates')
    result = discovery(existing, runtime['x-ouf-installation'], 'DELEGATION_KEY',
                       'DISCOVERY_KEY', upstream, {name: 'fixture-discovery-'+name for name in names})
    assert existing == before and result['routes'][:-3] == before['routes']
    paths = {route.get('uri') for route in result['routes']}
    assert {'/internal/capabilities/v1/execute/managed.file/'+name
            for name in ('upload', 'handoff', 'profile', 'preview', 'create')} <= paths
    assert {'/internal/capabilities/v1/execute/semantic/'+name
            for name in ('search', 'get', 'create', 'validate', 'review', 'read')} <= paths
    assert {'/internal/capabilities/v1/execute/source.revision/'+name
            for name in ('prepare', 'read')} <= paths
    human = [r for r in before['routes'] if r.get('uri', '').startswith('/trusted-human/')]
    assert human and [r for r in result['routes'] if r.get('uri', '').startswith('/trusted-human/')] == human
    for route, name in zip(result['routes'][-3:], names):
        assert route['uri'] == '/internal/capabilities/v1/execute/semantic/discovery/'+name
        assert route['plugins']['proxy-rewrite']['uri'] == '/api/internal/v1/semantic/discovery/'+name
        assert route['upstream']['retries'] == 0
        assert not any(word in route['uri'] for word in ('adopt', 'approve', 'publish', 'confirm'))
