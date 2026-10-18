"""Fresh, nonproduction real-Lua vectors consumed immediately by the Java owner verifier."""
import json
import sys
import time
from pathlib import Path
from tests.test_source_revision import execute, request
from tests.test_execute_delegation import Engine, human


def write(path):
    rows = []
    for mode, command_read in [('prepare', False), ('read', False), ('read', True)]:
        now = int(time.time());envelope = request(mode, command_read=command_read)
        signer = Engine(dict(human(), scope=envelope['CapabilityID'], exp=now+60), now=now)
        signer.run('issue_delegation')
        engine = execute(mode, envelope, delegation=signer.headers[b'x-ouf-delegation'].decode(), now=now)
        rows.append({'path': '/api/internal/v1/onboarding/source-revision-mcp/'+mode,
            'capability': envelope['CapabilityID'], 'body': engine.body.decode(),
            'proof': engine.headers[b'x-ouf-source-revision-receipt'].decode()})
    Path(path).write_text(json.dumps(rows)+'\n')


if __name__ == '__main__':
    write(sys.argv[1])
