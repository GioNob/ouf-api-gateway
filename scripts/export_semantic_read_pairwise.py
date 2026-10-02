#!/usr/bin/env python3
"""Export a synthetic, short-lived receipt using actual Gateway Lua for Java owner tests."""
import argparse
import json
import time
from pathlib import Path
from tests.test_execute_delegation import Engine, human, workload, INSTALL
from tests.test_semantic_read_execute import request
from tools.delegation_functions import function


def export():
    now=int(time.time())
    h=human();h.update(exp=now+300,scope="mcp.connect ouf.semantic.search")
    signer=Engine(h,now=now);signer.run('issue_delegation')
    e=request('search')
    headers={'X-OUF-Delegation':signer.headers[b'x-ouf-delegation'].decode(),
             'X-Correlation-ID':e['CorrelationID'],'Idempotency-Key':e['IdempotencyKey'],
             'X-Tool-Attempt-ID':e['AttemptID']}
    w=workload();w.update(exp=now+300)
    engine=Engine(w,headers,e,now=now,uri='/api/internal/v1/semantic/consultation/search')
    engine.lua.execute(function('execute_semantic_read',INSTALL,'DELEGATION_KEY','SEMANTIC_KEY').encode())(None,None)
    return {'body':engine.body.decode(),'receipt':engine.headers[b'x-ouf-semantic-read-receipt'].decode()}

if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--output',type=Path,required=True)
    args=p.parse_args();args.output.write_text(json.dumps(export()))
