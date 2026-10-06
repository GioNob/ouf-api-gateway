#!/usr/bin/env python3
"""Privately copy an existing OIDC validator client secret; no IAM/runtime mutation."""
import argparse
import hashlib
import hmac
import json
import os
from pathlib import Path
import re
import stat

from scripts import inventory_semantic_provider_candidate_inputs as inputs


class Blocked(inputs.Blocked): pass


def digest(raw): return hashlib.sha256(raw).hexdigest()
def encoded(value): return json.dumps(value,sort_keys=True,separators=(',',':')).encode()


def credential(value):
    # A bounded single-line printable value can be passed through Docker env-file
    # later without shell interpretation. No value is ever included in errors.
    if not isinstance(value,str) or not re.fullmatch(r'[!-~]{16,1024}',value):
        raise Blocked('VALIDATOR_CREDENTIAL_INVALID')
    return value.encode('ascii')


def read_iam(args,resource,fields,query=None):
    command=[args.docker_path,'exec',args.iam_container,args.kcadm_path,'get',resource,'-r',args.realm,'--fields',fields]
    if query: command += ['-q',query]
    return json.loads(inputs.run(command,iam=True))


def profile(args,client):
    if not re.fullmatch('[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}',client): raise Blocked('CLIENT_BINDING_INVALID')
    rows=read_iam(args,'clients','id,clientId,enabled,publicClient,serviceAccountsEnabled,clientAuthenticatorType','clientId='+client)
    if not isinstance(rows,list) or len(rows)!=1: raise Blocked('VALIDATOR_CLIENT_NOT_UNIQUE')
    row=rows[0]
    if row.get('clientId')!=client or row.get('enabled') is not True or row.get('publicClient') is not False \
            or row.get('clientAuthenticatorType')!='client-secret' or not re.fullmatch('[A-Za-z0-9-]{1,128}',row.get('id','')):
        raise Blocked('VALIDATOR_CLIENT_PROFILE_DRIFT')
    # serviceAccountsEnabled is recorded, not required or modified: this client
    # verifies bearer tokens and is not the Semantic calling workload.
    return {k:row.get(k) for k in ('id','clientId','enabled','publicClient','serviceAccountsEnabled','clientAuthenticatorType')}


def directory(path):
    if not path.is_absolute() or '..' in path.parts: raise Blocked('PRIVATE_ROOT_INVALID')
    for parent in (path,*path.parents):
        s=parent.lstat()
        if not stat.S_ISDIR(s.st_mode) or s.st_uid!=0 or s.st_mode & 0o022:
            raise Blocked('PRIVATE_ROOT_INVALID')


def write(path,raw,uid=0,gid=0):
    fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
    try:
        os.fchown(fd,uid,gid);os.fchmod(fd,0o600)
        with os.fdopen(fd,'wb',closefd=False) as stream: stream.write(raw);stream.flush();os.fsync(stream.fileno())
    finally: os.close(fd)


def local_secret(path,uid,gid):
    inputs.file_metadata(path,uid,gid,0o600,limit=1024)
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
    try: raw=os.read(fd,1025)
    finally:os.close(fd)
    try:return credential(raw.decode('ascii'))
    except Exception:raise Blocked('PRIVATE_CREDENTIAL_INVALID') from None


def operate(args):
    if os.geteuid()!=0: raise Blocked('ROOT_REQUIRED')
    if not re.fullmatch('[0-9a-f]{40}',args.source_commit): raise Blocked('SOURCE_BINDING_INVALID')
    directory(args.credential_root.parent)
    if args.mode!='verify' and os.path.lexists(args.credential_root): raise Blocked('CREDENTIAL_ROOT_EXISTS_RECONCILE')
    inventory=inputs.inventory(args)
    client=inventory['oidcClient']['clientId']
    before=profile(args,client)
    trust,trust_hash=inputs.private_json(args.trust_root/'trust-receipt.json')
    tls,tls_hash=inputs.private_json(args.tls_root/'tls-runtime-receipt.json')
    runtime,runtime_hash=inputs.private_json(args.runtime_root/'stage-receipt.json')
    uid,gid=trust['intent']['gateway']['uid'],trust['intent']['gateway']['gid']
    if type(uid)!=int or type(gid)!=int or min(uid,gid)<=0: raise Blocked('NON_ROOT_VALIDATOR_ROLE_REQUIRED')
    sources={p.name:digest(p.read_bytes()) for p in (Path(__file__),Path(inputs.__file__))}
    intent={'schema':'ouf.semantic-southbound-validator-credential.v1','sourceCommit':args.source_commit,
        'sourceHashes':sources,'clientProfile':before,'realm':args.realm,'uid':uid,'gid':gid,
        'trustReceiptHash':trust_hash,'tlsReceiptHash':tls_hash,'runtimeReceiptHash':runtime_hash,
        'purpose':'OIDC_BEARER_TOKEN_VALIDATOR_ONLY','clientCredentialsGrantRequested':False,
        'iamConfigurationChanged':False,'secretRotated':False,'providerCalls':0,'notReleaseAcceptance':True}
    target=args.credential_root/'client-secret'
    if args.mode=='plan':return intent
    if args.mode=='verify':
        directory(args.credential_root)
        if stat.S_IMODE(args.credential_root.stat().st_mode)!=0o700: raise Blocked('PRIVATE_ROOT_INVALID')
        saved,_=inputs.private_json(args.credential_root/'credential-receipt.json')
        sealed,_=inputs.private_json(args.credential_root/'credential-intent.json')
        if saved['intent']!=intent or sealed!=intent: raise Blocked('PRIVATE_RECEIPT_DRIFT')
    # Only this selected existing client; no POST/PUT/DELETE, grant or secret reset.
    resource='clients/'+before['id']+'/client-secret'
    secret=credential(read_iam(args,resource,'value').get('value'))
    if profile(args,client)!=before: raise Blocked('VALIDATOR_CLIENT_CHANGED_DURING_READ')
    current=credential(read_iam(args,resource,'value').get('value'))
    if not hmac.compare_digest(secret,current): raise Blocked('VALIDATOR_SECRET_CHANGED_DURING_READ')
    if profile(args,client)!=before: raise Blocked('VALIDATOR_CLIENT_CHANGED_DURING_READ')
    if args.mode=='verify':
        if not hmac.compare_digest(local_secret(target,uid,gid),secret) or saved['credentialHash']!=digest(secret):
            raise Blocked('PRIVATE_CREDENTIAL_DRIFT_NO_OVERWRITE')
        return intent
    args.credential_root.mkdir(mode=0o700)
    write(args.credential_root/'credential-intent.json',encoded(intent))
    write(target,secret,uid,gid)
    if not hmac.compare_digest(local_secret(target,uid,gid),secret): raise Blocked('PRIVATE_READBACK_FAILED')
    write(args.credential_root/'credential-receipt.json',encoded({'intent':intent,'credentialHash':digest(secret),
        'privateCopyCreated':True,'credentialMounted':False,'containerEnvironmentInstalled':False,
        'tokenAdmissionProven':False,'notReleaseAcceptance':True}))
    return intent


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--mode',required=True,choices=('plan','apply','verify'))
    for name in ('tls-root','trust-root','runtime-root','credential-root'):p.add_argument('--'+name,type=Path,required=True)
    for name in ('gateway-container','iam-container','realm','docker-path','openssl-path','kcadm-path','source-commit'):
        p.add_argument('--'+name,required=True)
    p.add_argument('--minimum-cert-seconds',type=int,required=True)
    args=p.parse_args()
    try:
        if not 1<=args.minimum_cert_seconds<=86400:raise Blocked('CERTIFICATE_WINDOW_INVALID')
        intent=operate(args)
        print('SEMANTIC_SOUTHBOUND_VALIDATOR_CREDENTIAL=PASS MODE='+args.mode+' PRIVATE_COPY_CREATED='+str(args.mode=='apply').lower()+
              ' SECRET_RETRIEVED='+str(args.mode!='plan').lower()+' SECRET_ROTATED=false IAM_CONFIGURATION_UNCHANGED=true'+
              ' NO_CONTAINER_OR_ROUTE_CHANGED=true NO_TOKEN_GRANT_REQUEST=true NO_PROVIDER_CALL=true NOT_RELEASE_ACCEPTANCE=true NO_SECRETS_PRINTED=true')
        if args.mode!='plan': print('SEMANTIC_SOUTHBOUND_VALIDATOR_CREDENTIAL_RECEIPT='+str(args.credential_root/'credential-receipt.json')+' PRIVATE=true')
    except Exception as error:
        code=str(error) if isinstance(error,inputs.Blocked) else 'VALIDATOR_CREDENTIAL_PREPARATION_FAILED'
        print('SEMANTIC_SOUTHBOUND_VALIDATOR_CREDENTIAL=BLOCKED CODE='+code+' DO_NOT_RERUN_BLINDLY=true NO_SECRETS_PRINTED=true')
        raise SystemExit(1) from None


if __name__=='__main__':main()
