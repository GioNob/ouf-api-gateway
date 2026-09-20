"""Generate a real Lua owner receipt for the JVM pairwise test; synthetic identities only."""
import sys,json,time,hashlib
from tests.test_execute_delegation import Engine,INSTALL,human,workload,envelope
from tools.delegation_functions import function
args=json.load(sys.stdin);now=int(time.time())
INSTALL.update(issuerUrl=args['issuer'],gatewayAudience='gateway',mcpServiceIdentity='ouf-mcp-server')
cap='authorization.permissions.propose'
claims=human()
claims.update(iss=INSTALL['issuerUrl'],aud='gateway',sub='giovanni',scope=cap,exp=now+300)
ingress=Engine(claims,now=now);ingress.run('issue_delegation')
proof=ingress.headers[b'x-ouf-delegation'].decode()
e=envelope();e.update(CapabilityID=cap,GatewayBindingRef='capability://'+cap,Owner='authorization',OperationClass='COMMAND',Arguments=args['change']);e['Identity']['PrincipalID']='giovanni'
service=workload();service.update(iss=INSTALL['issuerUrl'],aud='gateway',azp='ouf-mcp-server',exp=now+300)
headers={'X-OUF-Delegation':proof,'X-Correlation-ID':e['CorrelationID'],'Idempotency-Key':e['IdempotencyKey'],'X-Tool-Attempt-ID':e['AttemptID']}
engine=Engine(service,headers,e,now=now)
engine.modules[b'resty.openssl.digest']=engine.lua.table_from({b'new':lambda algorithm:engine.lua.table_from({b'final':lambda _,data:hashlib.sha256(data).digest()})})
engine.modules[b'resty.string']=engine.lua.table_from({b'to_hex':lambda data:data.hex().encode()})
engine.lua.execute(function('execute_permissions',INSTALL,'TEST_KEY','OWNER_KEY').encode())(None,None)
print(json.dumps({'receipt':engine.headers[b'x-ouf-authorization-receipt'].decode(),'body':engine.body.decode()}))
