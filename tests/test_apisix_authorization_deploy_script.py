import shutil
import subprocess
from pathlib import Path


def test_shell_installer_retired():
    script = Path(__file__).resolve().parents[1] / 'ops/apisix/deploy_authorization_bundle_route.sh'
    result = subprocess.run([shutil.which('bash'), str(script)], capture_output=True, text=True)
    assert result.returncode and 'governed Gateway release' in result.stderr
