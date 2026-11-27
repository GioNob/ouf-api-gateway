from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_mcp_deploy_script_is_fail_closed_and_secret_safe():
    script = (ROOT / "ops" / "apisix" / "deploy_mcp_route.sh").read_text()
    assert "governed Gateway release" in script
    assert script.splitlines()[-1] == "exit 1"
    assert "docker" not in script and "curl" not in script
