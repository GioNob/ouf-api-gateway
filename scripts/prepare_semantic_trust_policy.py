"""Prepare an explicitly authorized private verification policy; never link consumers."""
import argparse
import ast
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import tempfile
import time
import types
import fcntl


class BootBlocked(ValueError):
    pass


def load_helper(path, expected):
    # Compile the exact checked bytes, not a second import/read susceptible to drift.
    if not path.is_absolute() or '..' in path.parts:
        raise BootBlocked('TRUSTED_HELPER_PATH_REQUIRED')
    for p in (path.parent, *path.parent.parents):
        st = p.lstat()
        if not stat.S_ISDIR(st.st_mode) or st.st_uid != 0 or st.st_mode & 0o022:
            raise BootBlocked('TRUSTED_HELPER_ANCESTOR_REQUIRED')
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        st = os.fstat(fd); raw = os.read(fd, 131073)
        if (not stat.S_ISREG(st.st_mode) or st.st_uid != 0 or st.st_gid != 0
            or stat.S_IMODE(st.st_mode) != 0o600 or st.st_nlink != 1 or st.st_size > 131072
            or len(raw) != st.st_size or hashlib.sha256(raw).hexdigest() != expected
            or (st.st_dev, st.st_ino, st.st_size, st.st_mtime_ns, st.st_ctime_ns)
                != tuple(getattr(os.fstat(fd), k) for k in ('st_dev','st_ino','st_size','st_mtime_ns','st_ctime_ns'))):
            raise BootBlocked('SEALED_HELPER_REQUIRED')
    finally:
        os.close(fd)
    module = types.ModuleType('sealed_key_custody_helper'); module.__file__ = str(path)
    exec(compile(raw, str(path), 'exec'), module.__dict__)
    return module, raw


def validator(h, root, auth_hash, protocol_hash):
    # Execute only the actual pure policy functions, never operational module bodies/imports.
    paths = (root/'semantic_provider_deployment_authentication.py', root/'semantic_provider_deployment_protocol.py')
    raw = tuple(h.private(p) for p in paths)
    h.require(tuple(h.digest(r) for r in raw) == (auth_hash, protocol_hash), 'SEALED_POLICY_VALIDATOR_DRIFT')
    auth, protocol = (ast.parse(r) for r in raw)
    selected = []
    for tree, names in ((auth, {'require', 'decode', 'policy'}), (protocol, {'identity'})):
        nodes = [n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name in names]
        h.require(len(nodes) == len(names) and {n.name for n in nodes} == names
            and all(not n.decorator_list for n in nodes), 'PURE_POLICY_FUNCTIONS_REQUIRED')
        selected.extend(nodes)
    roles = [n.value for n in auth.body if isinstance(n, ast.Assign)
        and any(isinstance(t, ast.Name) and t.id == 'ROLES' for t in n.targets)]
    h.require(len(roles) == 1, 'POLICY_ROLE_CONSTANT_REQUIRED')
    role_set = ast.literal_eval(roles[0])
    h.require(role_set == {'DEPLOYMENT_INTENT','CREATION_ATTESTATION','FINAL_DEPLOYMENT_APPROVAL'}, 'EXACT_POLICY_ROLES_REQUIRED')
    scope = {'json': json, 're': re, 'ROLES': role_set, 'PreexecDenied': h.Blocked}
    exec(compile(ast.Module(body=selected, type_ignores=[]), 'sealed-pure-policy-validator', 'exec'), scope)
    return scope['policy'], paths, raw


def verify_self_test(h, a, role, der, signature, deadline):
    # Workspace belongs to the new policy root. Existing custody root remains read-only.
    with tempfile.TemporaryDirectory(prefix='.policy-self-test-', dir=a.snapshot_root) as tmp:
        p = Path(tmp); msg = p/'message'; pub = p/'public.der'; sig = p/'signature'
        for path, data in ((msg, h.message(a, role, der[12:])), (pub, der), (sig, signature)):
            path.write_bytes(data); path.chmod(0o600)
        argv = [str(a.openssl_path), 'pkeyutl', '-verify', '-pubin', '-keyform', 'DER',
            '-inkey', str(pub), '-sigfile', str(sig), '-rawin', '-in', str(msg)]
        h.command(argv, deadline)
        msg.write_bytes(msg.read_bytes()+b' altered')
        h.command(argv, deadline, allowed=(1,))


def execute(a):
    h, helper_raw = load_helper(a.helper_source, a.helper_sha256)
    h.require(os.geteuid() == 0 and a.authorize_private_role_policy_only, 'EXPLICIT_PRIVATE_POLICY_AUTHORIZATION_REQUIRED')
    for v in h.bindings(a).values():
        h.require(re.fullmatch('[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}', v), 'EXPLICIT_IDENTITIES_REQUIRED')
    h.require(a.installer_key_ref != a.attestor_key_ref and a.installer_issuer_ref != a.attestor_issuer_ref,
        'SEPARATE_GRANTS_REQUIRED')
    for k in ('helper_sha256','source_sha256','dossier_sha256','authority_plan_sha256',
        'package_receipt_sha256','custody_receipt_sha256','draft_sha256','auth_source_sha256',
        'protocol_source_sha256','openssl_sha256'):
        h.require(re.fullmatch('[0-9a-f]{64}', getattr(a,k)), 'EXPLICIT_SOURCE_HASH_REQUIRED')
    h.require(re.fullmatch('[0-9a-f]{40}', a.source_commit) and re.fullmatch('[0-9a-f]{40}', a.custody_source_commit), 'SOURCE_COMMIT_REQUIRED')
    source_path = Path(__file__).absolute(); source_raw = h.private(source_path)
    h.require(h.digest(source_raw) == a.source_sha256, 'POLICY_HELPER_SOURCE_DRIFT')
    parse, parser_paths, parser_raw = validator(h, a.validator_source_root, a.auth_source_sha256, a.protocol_source_sha256)
    inventory = h.inputs(a); backend = h.backend(a.openssl_path, a.openssl_sha256)
    h.ancestors(a.custody_root/'placeholder'); st = a.custody_root.lstat()
    h.require(stat.S_ISDIR(st.st_mode) and st.st_uid == st.st_gid == 0 and stat.S_IMODE(st.st_mode) == 0o700,
        'PRIVATE_CUSTODY_ROOT_REQUIRED')
    custody_metadata = h.attrs(st)
    names = ('key-custody-receipt.json','authority-draft.json','installer.der','attestor.der','installer.self-test.sig','attestor.self-test.sig')
    # Do not enumerate custody or read either .pem private key.
    raw = {n:h.private(a.custody_root/n) for n in names}
    h.require(h.digest(raw[names[0]]) == a.custody_receipt_sha256 and h.digest(raw[names[1]]) == a.draft_sha256,
        'CUSTODY_RECEIPT_OR_DRAFT_DRIFT')
    receipt, old = h.decode(raw[names[0]]), h.decode(raw[names[1]])
    h.require(receipt['schema'] == 'ouf.semantic-authority-key-custody-receipt.v1'
        and receipt['state'] == 'PRIVATE_KEYS_PREPARED_DRAFT_ONLY' and receipt['bindings'] == h.bindings(a)
        and receipt['inventoryHashes'] == {n:h.digest(r) for n,r in inventory.items()}
        and receipt['sourceSha256'] == a.helper_sha256 and receipt['sourceCommit'] == a.custody_source_commit
        and receipt['opensslSha256'] == a.openssl_sha256
        and receipt['keysPresent'] == receipt['selfTestSignaturesPresent'] == 2
        and receipt['deploymentSignaturesIssued'] == 0 and receipt['keyCustodyProvisioningAuthorized'] is True
        and all(receipt[k] is False for k in ('roleSigningAuthorized','trustPolicyProvisioned','startAuthorized'))
        and all(receipt['outputHashes'][n] == h.digest(raw[n]) for n in names[1:]), 'COMPLETED_PRIVATE_CUSTODY_REQUIRED')
    created = receipt['createdAt']; now = int(time.time())
    h.require(type(created) is int and created <= now < created+90*86400, 'ORIGINAL_PROPOSED_VALIDITY_REQUIRED')
    keys = []; grants = []
    for role in ('installer','attestor'):
        der = raw[role+'.der']; signature = raw[role+'.self-test.sig']
        h.require(len(der) == 44 and der.startswith(h.PREFIX) and len(signature) == 64, 'ED25519_PUBLIC_BINDING_REQUIRED')
        roles = ['DEPLOYMENT_INTENT','FINAL_DEPLOYMENT_APPROVAL'] if role == 'installer' else ['CREATION_ATTESTATION']
        key = {'keyRef':getattr(a,role+'_key_ref'),'issuerRef':getattr(a,role+'_issuer_ref'),'publicKey':der[12:].hex()}
        keys.append({**key,'proposedRoles':roles,'authorized':False})
        grants.append({**key,'roles':roles,'notBefore':created,'expiresAt':created+90*86400,'state':'ACTIVE'})
    h.require(keys[0]['publicKey'] != keys[1]['publicKey'] and raw[names[1]] == h.encoded(h.draft(a,keys,created)),
        'EXACT_INACTIVE_SOURCE_DRAFT_REQUIRED')
    policy = {'schema':'ouf.semantic-deployment-trust-policy.v1','installationRef':a.installation_ref,'entityRef':a.entity_ref,'keys':grants}
    policy_raw = h.encoded(policy)
    h.require(parse(policy_raw,a.installation_ref,a.entity_ref,now) == policy, 'REAL_POLICY_PARSER_REQUIRED')
    # This source parser checks format/bindings; builder separately enforces original time validity above.
    root = a.snapshot_root
    h.require(root != a.custody_root and a.custody_root not in root.parents and root not in a.custody_root.parents
        and root != a.inventory_root and a.inventory_root not in root.parents and root not in a.inventory_root.parents,
        'SEPARATE_POLICY_SNAPSHOT_REQUIRED')
    h.ancestors(root/'placeholder')
    fd = os.open(root,os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        st = os.fstat(fd)
        h.require(st.st_uid == st.st_gid == 0 and stat.S_IMODE(st.st_mode) == 0o700, 'PRIVATE_POLICY_ROOT_REQUIRED')
        try: fcntl.flock(fd,fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError: raise h.Blocked('POLICY_LOCK_BUSY') from None
        anchor_fields = ('st_dev','st_ino','st_uid','st_gid','st_mode')
        anchor = lambda: (tuple(getattr(os.fstat(fd),k) for k in anchor_fields)
            == tuple(getattr(root.lstat(),k) for k in anchor_fields)
            == tuple(getattr(st,k) for k in anchor_fields))
        outputs = {'trust-policy.json','policy-preparation-receipt.json'}
        present = h.entries(root)
        h.require(present <= outputs | {'source'}, 'UNEXPECTED_POLICY_OUTPUT_NO_REPLAY')
        if a.mode != 'verify': h.require(not present.intersection(outputs), 'EXISTING_OR_PARTIAL_POLICY_NO_REPLAY')
        deadline = time.monotonic()+30
        for role in ('installer','attestor'):
            verify_self_test(h,a,role,raw[role+'.der'],raw[role+'.self-test.sig'],deadline)
        def stable():
            return (anchor() and h.attrs(a.custody_root.lstat()) == custody_metadata and h.private(source_path) == source_raw and h.private(a.helper_source) == helper_raw
                and tuple(h.private(p) for p in parser_paths) == parser_raw and h.inputs(a) == inventory
                and h.backend(a.openssl_path,a.openssl_sha256) == backend
                and {n:h.private(a.custody_root/n) for n in names} == raw
                and created <= time.time() < created+90*86400)
        h.require(stable(), 'POLICY_INPUT_READBACK_DRIFT')
        result = {'schema':'ouf.semantic-trust-policy-preparation-report.v1','mode':a.mode,'keyCount':2,'roleCount':3,
            'originalValidityPreserved':True,'policyHash':h.digest(policy_raw),'privateKeysRead':0,'keysGenerated':0,
            'selfTestSignaturesIssued':0,'deploymentSignaturesIssued':0,'realPolicyParserValidated':True,
            'publicKeyBindingsVerified':True,'custodyReceiptVerified':True,'currentPrivateKeyBindingsReverified':False,
            'policyGrantState':'ACTIVE','privatePolicyPreparationAuthorized':True,'policyActiveInArtifact':a.mode!='plan','policyActiveInConsumer':False,'policyConsumerLinked':False,
            'trustPolicyInstalled':False,'roleSigningAuthorized':False,'mandatesIssued':0,
            'providerCalls':0,'dnsCalls':0,'iamCalls':0,'runtimeRegistered':False,'startAuthorized':False,
            'deploymentAuthorityProven':False,'rulesChanged':False,'unitsChanged':False,'containersChanged':False,
            'atomicSnapshotProven':False,'notReleaseAcceptance':True,'noSecretsPrinted':True,
            'evidencePublished':a.mode=='apply'}
        expected = {'schema':'ouf.semantic-trust-policy-preparation-receipt.v1','state':'PRIVATE_ROLE_VERIFICATION_POLICY_PREPARED',
            'bindings':h.bindings(a),'policyHash':h.digest(policy_raw),'sourceCommit':a.source_commit,
            'sourceSha256':a.source_sha256,'helperSha256':a.helper_sha256,'authSourceSha256':a.auth_source_sha256,
            'protocolSourceSha256':a.protocol_source_sha256,'opensslSha256':a.openssl_sha256,
            'custodyReceiptHash':a.custody_receipt_sha256,'draftHash':a.draft_sha256,
            'inventoryHashes':{n:h.digest(r) for n,r in inventory.items()},'originalNotBefore':created,
            'originalExpiresAt':created+90*86400,'privatePolicyPreparationAuthorized':True,
            'policyConsumerLinked':False,'trustPolicyInstalled':False,'roleSigningAuthorized':False,
            'deploymentSignaturesIssued':0,'mandatesIssued':0,'startAuthorized':False}
        if a.mode == 'apply':
            h.exclusive(root,'trust-policy.json',raw=policy_raw)
            h.require(stable(), 'POLICY_INPUT_READBACK_DRIFT')
            h.exclusive(root,'policy-preparation-receipt.json',raw=h.encoded(expected))
        if a.mode != 'plan':
            stored = h.private(root/'trust-policy.json'); stored_receipt = h.private(root/'policy-preparation-receipt.json')
            h.require(stored == policy_raw and stored_receipt == h.encoded(expected)
                and parse(stored,a.installation_ref,a.entity_ref,int(time.time())) == policy
                and stable() and h.entries(root) <= outputs | {'source'}, 'EXACT_PRIVATE_POLICY_READBACK_REQUIRED')
            result['receiptHash'] = h.digest(stored_receipt)
        return result
    finally: os.close(fd)


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--mode',choices=('plan','apply','verify'),required=True)
    for n in ('inventory-root','custody-root','snapshot-root','openssl-path','helper-source','validator-source-root'):
        p.add_argument('--'+n,type=Path,required=True)
    for n in ('installation-ref','entity-ref','installer-issuer-ref','attestor-issuer-ref','installer-key-ref','attestor-key-ref',
        'helper-sha256','source-sha256','source-commit','custody-source-commit','openssl-sha256','auth-source-sha256','protocol-source-sha256',
        'custody-receipt-sha256','draft-sha256','dossier-sha256','authority-plan-sha256','package-receipt-sha256'):
        p.add_argument('--'+n,required=True)
    p.add_argument('--authorize-private-role-policy-only',action='store_true');a=p.parse_args()
    try:
        r=execute(a)
        print('SEMANTIC_TRUST_POLICY_PREPARATION='+json.dumps(r,sort_keys=True))
        print('SEMANTIC_TRUST_POLICY_PREPARATION=PASS MODE='+a.mode+' PRIVATE_POLICY_ONLY=true CONSUMER_LINKED=false START_AUTHORIZED=false NO_SECRETS_PRINTED=true')
        return 0
    except (OSError,ValueError,KeyError,TypeError,AttributeError,RecursionError,RuntimeError,SyntaxError,subprocess.SubprocessError) as e:
        reason=str(e) if isinstance(e,BootBlocked) or (type(e).__name__=='Blocked'
            and type(e).__module__=='sealed_key_custody_helper') else 'PRIVATE_POLICY_INPUT_UNPROVEN'
        if not re.fullmatch('[A-Z_]{1,80}',reason):reason='PRIVATE_POLICY_INPUT_UNPROVEN'
        print('SEMANTIC_TRUST_POLICY_PREPARATION=BLOCKED MODE='+a.mode+' REASON='+reason+' START_AUTHORIZED=false NO_SECRETS_PRINTED=true')
        return 1


if __name__=='__main__':raise SystemExit(main())
