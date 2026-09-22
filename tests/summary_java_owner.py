"""CI-only launcher for the real Gateway operational owner and a synthetic policy."""
import contextlib
import hashlib
import json
import socket
import subprocess
import time
import urllib.request
from datetime import datetime,timedelta,timezone
from pathlib import Path
from tools.operational_incidents import SQLiteOperationalIncidentStore

@contextlib.contextmanager
def java_owner(jar, folder, installation, policy_bundle=None):
    folder=Path(folder)
    with socket.socket() as s:s.bind(('127.0.0.1',0));port=s.getsockname()[1]
    now=datetime.now(timezone.utc)
    cap='ouf.gateway.operations.summary'
    bundle={'bundleId':'bundle','version':6,'publishedAt':now.isoformat(),
            'capabilities':[{'capabilityId':cap,'operation':'READ','requiredScope':'operations.status.read','allowedActors':['HUMAN']}],
            'grants':[{'grantId':'synthetic-viewer','capabilityId':cap,'tenantId':'tenant-a',
                       'validFrom':(now-timedelta(minutes=5)).isoformat(),'validUntil':(now+timedelta(hours=1)).isoformat(),
                       'constraints':{'externalRoleRef':'ouf:viewer','resourceType':'capability','allowedDetailLevels':['TENANT_OPERATIONAL']}}]}
    if policy_bundle is not None:bundle=policy_bundle
    raw=json.dumps(bundle,separators=(',',':')).encode();policy=folder/'policy.json';policy.write_bytes(raw)
    key=folder/'receipt.key';key.write_text('12'*32);key.chmod(0o600)
    db=folder/'gateway.db'
    with contextlib.closing(SQLiteOperationalIncidentStore(db)) as store:
        store.open_incident(dedup_key='visible',event_type='FAILURE',severity='ERROR',error_code='SAFE',impact_summary='A normalized failure',visibility_class='TENANT_OPERATIONAL')
        store.mark_collector_observed('APISIX')
        store.mark_collector_observed('ETCD')
    args=['java','-jar',str(Path(jar).resolve()),f'--server.port={port}',
          f'--ouf.summary.database-file={db}',f'--ouf.summary.receipt-key-file={key}',
          '--ouf.summary.max-evidence-age-seconds=120',
          '--ouf.summary.tenant-id=tenant-a',f"--ouf.summary.issuer={installation['issuerUrl']}",
          f"--ouf.summary.audience={installation['gatewayAudience']}",f"--ouf.summary.workload={installation['mcpServiceIdentity']}",
          f'--ouf.authorization.bundle-file={policy}','--ouf.authorization.bundle-id=bundle','--ouf.authorization.bundle-version=6',
          '--ouf.authorization.bundle-sha256='+hashlib.sha256(raw).hexdigest()]
    with (folder/'owner.log').open('wb') as log:
        proc=subprocess.Popen(args,stdout=log,stderr=subprocess.STDOUT)
        try:
            for _ in range(60):
                if proc.poll() is not None:raise AssertionError((folder/'owner.log').read_text()[-6000:])
                try:
                    with urllib.request.urlopen(f'http://127.0.0.1:{port}/actuator/health',timeout=1) as r:
                        if r.status==200:break
                except OSError:time.sleep(.5)
            else:raise AssertionError('Gateway owner startup timeout')
            yield port,db
        finally:
            proc.terminate()
            try:proc.wait(timeout=10)
            except subprocess.TimeoutExpired:proc.kill();proc.wait()
