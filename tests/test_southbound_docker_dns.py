"""Real Docker embedded DNS boundary, only isolated local peers; no external DNS."""
import hashlib
import ipaddress
import json
import os
import re
import subprocess
import time
import unittest
import uuid
from tools.materialize_southbound_kernel import materialize


SERVER = r'''
import json,socket,struct,threading

def response(raw,peer,transport):
 if len(raw)<12:return b''
 tx,flags,qd,an,ns,ar=struct.unpack('!6H',raw[:12])
 if qd!=1:return b''
 p=12; labels=[]
 while p<len(raw) and raw[p]:
  n=raw[p];p+=1;labels.append(raw[p:p+n].decode('ascii'));p+=n
 p+=1
 if p+4>len(raw):return b''
 qtype,qclass=struct.unpack('!2H',raw[p:p+4]);question=raw[12:p+4]
 print(json.dumps({'peer':peer[0],'transport':transport,'name':'.'.join(labels),'qtype':qtype}),flush=True)
 payload=socket.inet_pton(socket.AF_INET,'192.0.2.100') if qtype==1 else socket.inet_pton(socket.AF_INET6,'2001:db8::100')
 return struct.pack('!6H',tx,0x8180,1,1,0,0)+question+b'\xc0\x0c'+struct.pack('!HHIH',qtype,1,30,len(payload))+payload

def udp():
 s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);s.bind(('0.0.0.0',53))
 while True:
  raw,peer=s.recvfrom(4096);s.sendto(response(raw,peer,'udp'),peer)

def exact(s,n):
 b=b''
 while len(b)<n:
  chunk=s.recv(n-len(b))
  if not chunk:raise OSError('short frame')
  b+=chunk
 return b

def tcp():
 s=socket.socket();s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1);s.bind(('0.0.0.0',53));s.listen()
 while True:
  c,peer=s.accept();c.settimeout(2)
  try:
   raw=exact(c,struct.unpack('!H',exact(c,2))[0]);reply=response(raw,peer,'tcp');c.sendall(struct.pack('!H',len(reply))+reply)
  except OSError:pass
  finally:c.close()
threading.Thread(target=udp,daemon=True).start()
threading.Thread(target=tcp,daemon=True).start()
print('READY',flush=True)
threading.Event().wait()
'''


QUERY = r'''
import json,socket,struct,sys
host,transport,label,qtype=sys.argv[1:];qtype=int(qtype)
question=b''.join(bytes([len(p)])+p.encode('ascii') for p in label.split('.'))+b'\0'+struct.pack('!2H',qtype,1)
raw=struct.pack('!6H',0x3712,0x0100,1,0,0,0)+question
s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM if transport=='udp' else socket.SOCK_STREAM);s.settimeout(0.8)
def exact(n):
 b=b''
 while len(b)<n:
  v=s.recv(n-len(b))
  if not v:raise OSError('short reply')
  b+=v
 return b
try:
 if transport=='udp':s.sendto(raw,(host,53));reply=s.recv(4096)
 else:
  s.connect((host,53));s.sendall(struct.pack('!H',len(raw))+raw);reply=exact(struct.unpack('!H',exact(2))[0])
 h=struct.unpack('!6H',reply[:12]);print(json.dumps({'admitted':h[0]==0x3712 and h[1]&15==0 and h[3]==1}))
except OSError:print(json.dumps({'admitted':False}))
finally:s.close()
'''


def stable(value):
    if isinstance(value,dict): return {k:stable(v) for k,v in value.items() if k not in ('packets','bytes','expires')}
    if isinstance(value,list): return [stable(v) for v in value]
    return value


def fingerprint(value): return hashlib.sha256(json.dumps(stable(value),sort_keys=True).encode()).hexdigest()


@unittest.skipUnless(os.environ.get('OUF_SOUTHBOUND_DOCKER_DNS_TEST')=='1','real root Docker DNS fixture is opt-in')
class DockerDNSBoundaryTest(unittest.TestCase):
    def test_embedded_dns_forwards_from_registered_container_and_denies_bypass(self):
        self.assertEqual(os.geteuid(),0)
        image=os.environ['OUF_SOUTHBOUND_DOCKER_KERNEL_IMAGE']
        self.assertRegex(image,r'^[A-Za-z0-9][A-Za-z0-9._:/-]*@sha256:[0-9a-f]{64}$')
        suffix=uuid.uuid4().hex[:8]; network='ouf-dns-fixture-'+suffix; bridge='oufd-'+suffix; table='ouf_dns_'+suffix
        names={role:'ouf-dns-'+role+'-'+suffix for role in ('server','other','client','bypass')}
        created=[]; net=False; guarded=False; before=None
        def run(*cmd,raw=None):
            return subprocess.run(cmd,input=raw,text=True,capture_output=True,timeout=30,check=True).stdout.strip()
        def rules(): return json.loads(run('nft','-j','list','ruleset'))
        def without_owned(value):
            value['nftables']=[v for v in value['nftables'] if not any(isinstance(x,dict)
                and x.get('family') in ('inet','bridge') and (x.get('table')==table or k=='table' and x.get('name')==table)
                for k,x in v.items())]
            return value
        def replace(cfg):
            nonlocal guarded
            if guarded:
                run('nft','-f','-',raw='delete table inet '+table+'\ndelete table bridge '+table+'\n'); guarded=False
            run('nft','-f','-',raw='create table inet '+table+'\ncreate table bridge '+table+'\n'+materialize(cfg)['nftRules']); guarded=True
        def start(role,dns=None):
            cmd=['docker','run','--pull=never','-d','--name',names[role],'--network',network,'--restart=no',
                 '--user','10006:10006','--read-only','--cap-drop=ALL','--security-opt','no-new-privileges',
                 '--sysctl','net.ipv4.ip_unprivileged_port_start=0','--pids-limit','64']
            if dns: cmd += ['--dns',dns]
            cmd += [image,'python3','-B','-c',SERVER if role in ('server','other') else 'import time;time.sleep(240)']
            run(*cmd); created.append(names[role])
            info=json.loads(run('docker','inspect',names[role]))[0]
            self.assertEqual(set(info['NetworkSettings']['Networks']),{network})
            ip=info['NetworkSettings']['Networks'][network]['IPAddress']
            self.assertEqual(ipaddress.ip_address(ip).version,4)
            if dns:self.assertEqual(info['HostConfig']['Dns'],[dns])
            return ip
        def queries(role):
            lines=run('docker','logs',names[role]).splitlines()
            return [json.loads(line) for line in lines if line.startswith('{')]
        def probe(role,target,transport,qtype=1):
            label=uuid.uuid4().hex+'.fixture.invalid'
            value=json.loads(run('docker','exec',names[role],'python3','-B','-c',QUERY,target,transport,label,str(qtype)))
            return value['admitted']
        try:
            run('docker','image','inspect',image)  # Never pull or build from the fixture.
            existing=[v['ifname'] for v in json.loads(run('ip','-j','link','show'))]
            self.assertNotIn(bridge,existing)
            tables=json.loads(run('nft','-j','list','tables'))
            self.assertFalse(any(v.get('table',{}).get('name')==table for v in tables['nftables']))
            # Egress-capable bridge exercises the embedded proxy; guard precedes all containers.
            run('docker','network','create','--driver','bridge','--opt','com.docker.network.bridge.name='+bridge,network);net=True
            cfg={'tableName':table,'guardedInterfaces':[bridge],'existingInterfaces':existing,'staticFlows':[],'providerFlows':[]}
            replace(cfg)
            server=start('server'); other=start('other')
            client=start('client',server); bypass=start('bypass',server)
            for role in ('server','other'):
                deadline=time.monotonic()+8
                while 'READY' not in run('docker','logs',names[role]):
                    if time.monotonic()>=deadline:self.fail('local DNS fixture not ready')
                    time.sleep(0.1)
            before=fingerprint(without_owned(rules()))
            for transport in ('udp','tcp'):
                self.assertFalse(probe('client','127.0.0.11',transport),'embedded proxy bypassed default deny')
            self.assertEqual(queries('server'),[])
            cfg['staticFlows']=[{'purpose':'DNS','source':client,'destination':server,'protocol':transport,'port':53}
                                for transport in ('udp','tcp')]
            replace(cfg)
            for transport in ('udp','tcp'):
                for qtype in (1,28): self.assertTrue(probe('client','127.0.0.11',transport,qtype),'embedded DNS path not proven')
                self.assertTrue(probe('client',server,transport))
                self.assertFalse(probe('client',other,transport),'unselected DNS resolver admitted')
                self.assertFalse(probe('bypass','127.0.0.11',transport),'unregistered container DNS proxy bypass')
            evidence=queries('server')
            self.assertEqual({v['peer'] for v in evidence},{client},'proxy forwarded outside container source boundary')
            self.assertEqual({v['transport'] for v in evidence},{'udp','tcp'})
            self.assertEqual({v['qtype'] for v in evidence},{1,28})
            self.assertEqual(queries('other'),[])
            cfg['staticFlows']=[]; replace(cfg)
            count=len(queries('server'))
            for transport in ('udp','tcp'): self.assertFalse(probe('client','127.0.0.11',transport))
            self.assertEqual(len(queries('server')),count)
            self.assertEqual(fingerprint(without_owned(rules())),before)
            print('SOUTHBOUND_DOCKER_DNS=PASS REAL_DOCKER_EMBEDDED_DNS=true UDP_TCP_A_AAAA=true'
                  ' FORWARDED_SOURCE_BOUND_TO_CONTAINER=true DEFAULT_DENY=true UNSELECTED_RESOLVER_DENIED=true'
                  ' UNREGISTERED_WORKLOAD_DENIED=true RULE_REMOVAL_DENIES=true SHARED_RULE_STRUCTURE_UNCHANGED=true'
                  ' PROVIDER_CALLS=0 EXTERNAL_DNS_CALLS=0 NOT_RELEASE_ACCEPTANCE=true')
        finally:
            for name in reversed(created): run('docker','rm','-f',name)
            if guarded: run('nft','-f','-',raw='delete table inet '+table+'\ndelete table bridge '+table+'\n')
            if net: run('docker','network','rm',network)
            print('SOUTHBOUND_DOCKER_DNS_CLEANUP=PASS OWN_TEST_CONTAINERS_NETWORK_AND_TABLE_REMOVED=true')


if __name__=='__main__': unittest.main()
