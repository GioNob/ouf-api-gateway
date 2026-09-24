from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]


def test_authorization_bundle_deployer_has_persistent_snapshot_and_rollback():
    raw=(ROOT/"ops/apisix/deploy_authorization_bundle_route.py").read_text()
    assert 'ROUTE_ID="mcp-authorization-policy-bundle-read"' in raw
    assert 'BACKUP=' in raw
    assert 'previous.json' in raw
    assert 'restore(previous,admin)' in raw
    assert 'AUTHORIZATION_BUNDLE_ROUTE_ACTIVE' in raw
    assert 'AUTHORIZATION_BUNDLE_ROUTE_RESTORED' in raw


def test_authorization_bundle_deployer_requires_all_three_service_identities():
    raw=(ROOT/"ops/apisix/deploy_authorization_bundle_route.py").read_text()
    assert '("ouf-mcp-server","ouf-ingestion","ouf-udp")' in raw
    assert 'required service identity missing' in raw
