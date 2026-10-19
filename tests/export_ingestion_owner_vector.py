"""Public fixtures emitted by the real generated Lua for the Java owner boundary gate."""
import json,sys
from pathlib import Path
from tests.test_ingestion_read_materialization import invoke,CAPABILITIES

def export(path):
 vectors=[]
 for cap in CAPABILITIES:
  e=invoke(cap)
  vectors.append({'capability':cap,'body':e.body.decode(),'proof':e.headers[b'x-ouf-ingestion-read-receipt'].decode(),
   'path':'/api/internal/v1/ingestion/operations/'+CAPABILITIES[cap],
   'correlationId':e.headers[b'x-correlation-id'].decode(),'attemptId':e.headers[b'x-tool-attempt-id'].decode(),
   'idempotencyKey':e.headers[b'idempotency-key'].decode()})
 value={'schema':'ouf.ingestion-read-owner-public-test-vectors.v1','now':1000,'fixtureKeyAscii':'cd'*32,
  'issuer':'https://auth.test/realms/ouf','audience':'gateway','workload':'workload','vectors':vectors}
 Path(path).write_text(json.dumps(value,sort_keys=True,indent=2)+'\n')
if __name__=='__main__':export(sys.argv[1])
