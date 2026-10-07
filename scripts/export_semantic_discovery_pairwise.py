#!/usr/bin/env python3
"""Synthetic short-lived discovery receipts from the actual Gateway Lua."""
import argparse
import json
import time
from pathlib import Path
from tests.test_execute_delegation import Engine, human, workload, INSTALL
from tests.test_semantic_discovery_execute import request
from tools.delegation_functions import function

def export():
    now=int(time.time())
    h=human();h.update(exp=now+300,sub="reader",scope="mcp.connect ouf.semantic.discovery")
    signer=Engine(h,now=now);signer.run('issue_delegation')
    fixtures=[]
    for name in ('request','status','candidates'):
        e=request(name);e['Identity']['PrincipalID']='reader'
        headers={'X-OUF-Delegation':signer.headers[b'x-ouf-delegation'].decode(),
                 'X-Correlation-ID':e['CorrelationID'],'Idempotency-Key':e['IdempotencyKey'],
                 'X-Tool-Attempt-ID':e['AttemptID']}
        w=workload();w.update(exp=now+300)
        engine=Engine(w,headers,e,now=now,uri='/internal/capabilities/v1/execute/semantic/discovery/'+name)
        engine.lua.execute(function('execute_semantic_discovery',INSTALL,'DELEGATION_KEY','DISCOVERY_KEY').encode())(None,None)
        fixtures.append({'operation':name,'body':engine.body.decode(),'receipt':engine.headers[b'x-ouf-semantic-discovery-receipt'].decode()})
    return fixtures

if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--output',type=Path,required=True)
    args=p.parse_args();args.output.write_text(json.dumps(export()))
