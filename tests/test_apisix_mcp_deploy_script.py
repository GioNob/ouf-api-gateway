from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_mcp_deploy_script_is_fail_closed_and_secret_safe():
    script = (ROOT / "ops" / "apisix" / "deploy_mcp_route.sh").read_text()
    assert "OUF_APISIX_MATERIALIZATION" in script
    assert "OUF_APISIX_ADMIN_KEY_FILE" in script
    assert "OUF_APISIX_CONTAINER" in script
    assert "--network \"container:$APISIX_CONTAINER\"" in script
    assert "APISIX_OIDC_SECRET_ENV_MISSING" in script
    assert "APISIX_MCP_NEGATIVE_HTTP" in script
    assert "restore" in script
    assert "X-API-KEY" in script
    assert "cat \"$ADMIN_KEY_FILE\"" in script
    assert "echo \"$ADMIN_KEY_FILE\"" not in script
