import pytest

from tools.pairwise_server import HTTPUpstream


def test_pairwise_upstream_rejects_any_non_udp_binding_before_network():
    upstream=HTTPUpstream("http://127.0.0.1:1")
    with pytest.raises(RuntimeError,match="governed UDP binding"): upstream.execute("attacker","/internal/v1/objects/related-search",b"{}",{},1)
    with pytest.raises(RuntimeError,match="governed UDP binding"): upstream.execute("ouf-udp-object-resolution","http://attacker.invalid",b"{}",{},1)


def test_pairwise_recovery_rejects_non_registry_path_before_network():
    upstream = HTTPUpstream("http://127.0.0.1:1")
    with pytest.raises(RuntimeError, match="governed UDP binding"):
        upstream.recover("attacker", "/internal/v1/attempt-outcomes/backend-1", {}, 1)
    with pytest.raises(RuntimeError, match="governed UDP binding"):
        upstream.recover("ouf-udp-object-resolution", "http://attacker.invalid", {}, 1)
