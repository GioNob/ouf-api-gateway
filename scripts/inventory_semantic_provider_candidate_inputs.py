#!/usr/bin/env python3
"""Read sealed candidate inputs and OIDC client metadata; never retrieve credentials."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess


class Blocked(ValueError): pass


def run(command, iam=False):
    value=subprocess.run(command,capture_output=True,text=True,timeout=20)
    if value.returncode:
        if iam and any(s in (value.stdout+value.stderr).lower() for s in
                       ('session has expired','not logged in','invalid_grant')):
            raise Blocked('KCADM_SESSION_EXPIRED')
        raise Blocked('READ_ONLY_INPUT_QUERY_FAILED')
    if len(value.stdout)>2_000_000: raise Blocked('READBACK_TOO_LARGE')
    return value.stdout


def file_metadata(path,uid,gid,mode,limit=131072):
    if not path.is_absolute() or '..' in path.parts: raise Blocked('PATH_UNSAFE')
    for parent in path.parents:
        s=parent.lstat()
        if not stat.S_ISDIR(s.st_mode) or s.st_uid!=0 or s.st_mode & 0o022: raise Blocked('ANCESTOR_UNSAFE')
    s=path.lstat()
    if not stat.S_ISREG(s.st_mode) or s.st_uid!=uid or s.st_gid!=gid or s.st_nlink!=1 \
            or stat.S_IMODE(s.st_mode)!=mode or s.st_size>limit: raise Blocked('ARTIFACT_METADATA_DRIFT')


def private_json(path):
    file_metadata(path,0,0,0o600)
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
    try: raw=os.read(fd,131073)
    finally: os.close(fd)
    if len(raw)>131072: raise Blocked('RECEIPT_TOO_LARGE')
    return json.loads(raw),hashlib.sha256(raw).hexdigest()


def inventory(args):
    if os.geteuid()!=0: raise Blocked('ROOT_REQUIRED')
    for name in (args.gateway_container,args.iam_container,args.realm):
        if not re.fullmatch('[A-Za-z0-9][A-Za-z0-9_.-]{0,127}',name): raise Blocked('ROLE_BINDING_UNSAFE')
    for value in (args.docker_path,args.openssl_path,args.kcadm_path):
        if not re.fullmatch('/[A-Za-z0-9_./-]+',value) or '..' in Path(value).parts: raise Blocked('EXECUTABLE_BINDING_UNSAFE')
    tls,_=private_json(args.tls_root/'tls-runtime-receipt.json')
    trust,trust_hash=private_json(args.trust_root/'trust-receipt.json')
    stage,stage_hash=private_json(args.runtime_root/'stage-receipt.json')
    binding,binding_hash=private_json(args.runtime_root/'binding.json')
    plan,plan_hash=private_json(args.runtime_root/'runtime-plan.json')
    if tls['intent']['trustReceiptHash']!=trust_hash or tls['intent']['stageReceiptHash']!=stage_hash \
            or stage['bindingHash']!=binding_hash or stage['planHash']!=plan_hash \
            or trust['verified'] is not True or tls['notReleaseAcceptance'] is not True:
        raise Blocked('PREPARED_RECEIPT_BINDING_DRIFT')
    intent=trust['intent']; gateway=intent['gateway']; adapter=intent['adapterImage']
    if tls['intent']['gateway']!=gateway or tls['intent']['adapterImage']!=adapter: raise Blocked('TLS_ROLE_DRIFT')
    uid,gid=intent['adapterUid'],intent['adapterGid']
    file_metadata(args.tls_root/'adapter.json',uid,gid,0o600)
    # Configuration has only file references, never key material; verify its sealed content.
    config_raw=(args.tls_root/'adapter.json').read_bytes()
    if hashlib.sha256(config_raw).hexdigest()!=tls['outputHashes']['adapter.json'] \
            or json.loads(config_raw)!=binding['adapter'] or plan['adapterConfiguration']!=binding['adapter']:
        raise Blocked('ADAPTER_CONFIGURATION_DRIFT')
    for name in ('ca.crt','trust-bundle.pem'):
        file_metadata(args.trust_root/name,0,0,0o644,limit=1048576)
        raw=(args.trust_root/name).read_bytes()
        if b'PRIVATE KEY' in raw or hashlib.sha256(raw).hexdigest()!=trust['artifactHashes'][name]:
            raise Blocked('PUBLIC_TRUST_CONTENT_DRIFT')
    for role,r_uid,r_gid,hostname in (
            ('adapter',uid,gid,intent['adapterHostname']),
            ('southbound',gateway['uid'],gateway['gid'],intent['southboundHostname'])):
        for name in ('server.crt','server.key','provider-receipt.key'):
            file_metadata(args.trust_root/role/name,r_uid,r_gid,0o600)
        cert=(args.trust_root/role/'server.crt').read_bytes()
        if b'PRIVATE KEY' in cert or hashlib.sha256(cert).hexdigest()!=trust['artifactHashes'][role+'/server.crt']:
            raise Blocked('LEAF_CERTIFICATE_CONTENT_DRIFT')
        run([args.openssl_path,'verify','-CAfile',str(args.trust_root/'ca.crt'),
             '-purpose','sslserver','-verify_hostname',hostname,str(args.trust_root/role/'server.crt')])
        run([args.openssl_path,'x509','-in',str(args.trust_root/role/'server.crt'),
             '-noout','-checkend',str(args.minimum_cert_seconds)])
    current=json.loads(run([args.docker_path,'inspect','--type','container','--format',
        '{"id":{{json .Id}},"image":{{json .Image}},"running":{{json .State.Running}},"user":{{json .Config.User}}}',args.gateway_container]))
    if any(current[k]!=gateway[k] for k in current): raise Blocked('LIVE_GATEWAY_DRIFT')
    image=json.loads(run([args.docker_path,'image','inspect',adapter['id']]))[0]
    if image['Id']!=adapter['id'] or image['Config']['User']!=adapter['runtimeUser'] \
            or image['Config'].get('Entrypoint')!=['python3','-B','-m','tools.semantic_provider_adapter'] \
            or image['Config']['Labels'].get('ouf.component')!='semantic-provider-transport' \
            or image['Config']['Labels']['org.opencontainers.image.revision']!=adapter['sourceCommit'] \
            or image['Config']['Labels']['ouf.payload.sha256']!=adapter['payloadHash']:
        raise Blocked('STAGED_ADAPTER_IMAGE_DRIFT')
    routes=plan['southboundRoutes']['routes']
    clients={r['plugins']['openid-connect']['client_id'] for r in routes}
    if len(clients)!=1: raise Blocked('OIDC_CLIENT_BINDING_AMBIGUOUS')
    client=clients.pop()
    if not re.fullmatch('[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}',client): raise Blocked('OIDC_CLIENT_BINDING_UNSAFE')
    rows=json.loads(run([args.docker_path,'exec',args.iam_container,args.kcadm_path,'get','clients',
        '-r',args.realm,'-q','clientId='+client,'--fields',
        'clientId,enabled,publicClient,serviceAccountsEnabled,clientAuthenticatorType'],iam=True))
    if len(rows)!=1 or rows[0].get('clientId')!=client: raise Blocked('OIDC_CLIENT_NOT_UNIQUE')
    row=rows[0]
    return {'schema':'ouf.semantic-provider-candidate-input-inventory.v1',
        'preparedReceiptsAndAdapterConfigurationVerified':True,'leafCertificateValidityProven':True,
        'minimumCertificateSeconds':args.minimum_cert_seconds,'privateKeyContentRead':False,
        'privateKeyMetadataVerified':True,'keyPairContentIntegrityRecheckRequiredBeforeMount':True,
        'gatewayRoleUnchanged':True,'adapterImageReused':True,'adapterRuntimeUser':adapter['runtimeUser'],
        'oidcClient':{'clientId':client,'enabled':row.get('enabled') is True,'publicClient':row.get('publicClient') is True,
            'serviceAccountsEnabled':row.get('serviceAccountsEnabled') is True,
            'clientAuthenticatorType':row.get('clientAuthenticatorType')},
        'oidcCredentialRetrieved':False,'southboundCredentialProvisioningProven':False,
        'candidateCreationReady':False,'candidateContainersCreated':0,'providerCalls':0,
        'readOnly':True,'noSecretsPrinted':True,'notReleaseAcceptance':True}


def main():
    p=argparse.ArgumentParser(description=__doc__)
    for name in ('tls-root','trust-root','runtime-root'): p.add_argument('--'+name,type=Path,required=True)
    for name in ('gateway-container','iam-container','realm','docker-path','openssl-path','kcadm-path'):
        p.add_argument('--'+name,required=True)
    p.add_argument('--minimum-cert-seconds',type=int,required=True)
    args=p.parse_args()
    try:
        if not 1<=args.minimum_cert_seconds<=86400: raise Blocked('CERTIFICATE_WINDOW_INVALID')
        print('SEMANTIC_PROVIDER_CANDIDATE_INPUTS='+json.dumps(inventory(args),sort_keys=True))
        print('SEMANTIC_PROVIDER_CANDIDATE_INPUT_INVENTORY=PASS READ_ONLY=true NO_CREDENTIAL_RETRIEVED=true'
              ' NO_CONTAINER_CREATED=true NO_ROUTE_OR_IAM_WRITES=true NO_PROVIDER_CALL=true NO_SECRETS_PRINTED=true')
    except Exception as error:
        code=str(error) if isinstance(error,Blocked) else 'CANDIDATE_INPUT_INVENTORY_FAILED'
        print('SEMANTIC_PROVIDER_CANDIDATE_INPUT_INVENTORY=BLOCKED CODE='+code+' NO_CHANGES=true NO_SECRETS_PRINTED=true')
        raise SystemExit(1) from None


if __name__=='__main__': main()
