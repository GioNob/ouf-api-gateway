"""Synthetic inputs for the Linux container smoke test; run from the repository root."""
import json
from pathlib import Path
import sys

from tests.test_iam_keycloak_decisions import profile
from tools.operational_incidents import SQLiteOperationalIncidentStore


def generate(root):
    def save(name, data):
        (root / 'config' / name).write_text(json.dumps(data), encoding='utf-8')

    def endpoint(url):
        return dict(url=url, caFile='/pki/ca.pem', clientCertFile='/pki/gateway.pem', clientKeyFile='/pki/gateway.key')

    SQLiteOperationalIncidentStore(root / 'authority-store' / 'gateway.db').close()
    (root / 'iam-store' / 'iam.db').touch()
    p = profile()
    save('profile.json', p)
    save('iam.json', dict(profileFile='/config/profile.json', resourceServer='fixture-verifier',
                          secretEnv='FIXTURE_IAM', caFile='/pki/ca.pem', store='/state/iam.db',
                          gatewayTlsPrincipal='urn:fixture:gateway'))
    cfg = dict(contract='ouf.analysis.installation.v1', store='/state/gateway.db',
               manifestFile='/app/contracts/mcp-capabilities.json', issuer=p['trust']['issuer'],
               audience='gateway', workload='worker', delegationKeyEnv='FIXTURE_DELEGATION',
               introspection=endpoint(p['trust']['introspection']), decisions=endpoint(p['trust']['decisions']),
               reservations=endpoint('https://owner.invalid/reservations'), execute=endpoint('https://owner.invalid'),
               timeoutSeconds=2, mandateTtlSeconds=60, proofTtlSeconds=10, maxResultBytes=1024,
               dispatchEnabled=False, capacity=dict(processes=1, threadsPerProcess=8, instanceConnections=8))
    save('authority.json', cfg)
    cfg['capacity']['threadsPerProcess'] = 9
    save('mismatch.json', cfg)


if __name__ == '__main__':
    generate(Path(sys.argv[1]))
