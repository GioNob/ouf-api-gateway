"""Synthetic short-lived receipts from real Gateway Lua, for owner integration CI."""
import argparse
import json
import time
import uuid
from pathlib import Path
from tests.test_execute_delegation import Engine, human, workload, INSTALL
from tests.test_semantic_proposal_execute import OPS, request
from tools.delegation_functions import function

def export():
    now=int(time.time());key='pairwise-'+str(uuid.uuid4());namespace='urn:pairwise:'+str(uuid.uuid4())+':'
    out={}
    for name in OPS:
        e=request(name);e['Arguments']['proposalKey']=key
        if name=='create':
            c=e['Arguments']['commands'][0];c.update(namespace=namespace,semanticId=namespace+'Teatro')
        h=human();h.update(exp=now+300,scope='mcp.connect '+('ouf.semantic.propose' if name=='read' else OPS[name]))
        signer=Engine(h,now=now);signer.run('issue_delegation')
        headers={'X-OUF-Delegation':signer.headers[b'x-ouf-delegation'].decode(),'X-Correlation-ID':e['CorrelationID'],'Idempotency-Key':e['IdempotencyKey'],'X-Tool-Attempt-ID':e['AttemptID']}
        w=workload();w.update(exp=now+300)
        engine=Engine(w,headers,e,now=now,uri='/internal/capabilities/v1/execute/semantic/proposals/'+name)
        engine.lua.execute(function('execute_semantic_proposal',INSTALL,'DELEGATION_KEY','SEMANTIC_KEY').encode())(None,None)
        out[name]={'body':engine.body.decode(),'receipt':engine.headers[b'x-ouf-semantic-proposal-receipt'].decode()}
    return out
if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--output',type=Path,required=True)
    args=p.parse_args();args.output.write_text(json.dumps(export()))
