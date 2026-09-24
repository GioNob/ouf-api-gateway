from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]


def test_prepare_udp_authorization_retrofit_is_narrow_and_read_only():
    raw=(ROOT/"ops/udp/prepare_authorization_retrofit.py").read_text()
    assert "ONLY_AUTHORIZATION_ENV_ADDED=true" in raw
    assert "RUNNING_CONTAINER_UNCHANGED=true" in raw
    assert "OUF_AUTHORIZATION_REGISTRY_URL" in raw
    assert "OUF_AUTHORIZATION_REGISTRY_TOKEN_FILE" in raw
    assert "OUF_AUTHORIZATION_REFRESH_SECONDS" in raw
    assert "OUF_AUTHORIZATION_MAX_STALENESS_SECONDS" in raw
    assert "OUF_UDP_SEARCH_OWNER_KEY_FILE" in raw
    assert "docker","inspect","ouf-udp"" in raw
    assert "docker","stop"" not in raw
    assert "docker","rm"" not in raw


def test_rollout_udp_authorization_retrofit_has_rollback_and_preserves_search_mount():
    raw=(ROOT/"ops/udp/rollout_authorization_retrofit.py").read_text()
    assert "UDP_AUTH_RETROFIT_DRY_RUN_OK=true" in raw
    assert "UDP_AUTH_RETROFIT_STAGED=true" in raw
    assert "UDP_AUTH_RETROFIT_ROLLBACK_RESTORED=true" in raw
    assert "udp-search-owner.key" in raw
    assert "/run/ouf-udp-auth" in raw
    assert "ouf-udp-preauth-" in raw
    assert "wait_ready" in raw
