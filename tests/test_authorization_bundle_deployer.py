import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]

@pytest.mark.parametrize('script', ['deploy_authorization_bundle_route.py', 'deploy_managed_file_upload.py'])
@pytest.mark.parametrize('action', ['--materialization', '--restore'])
def test_standalone_installer_retired(script, action):
    result = subprocess.run([sys.executable, ROOT / 'ops/apisix' / script, action, 'absent'],
                            capture_output=True, text=True)
    assert result.returncode and 'governed Gateway release' in result.stderr
