"""Explicit private Ed25519 custody and an inert draft; never operational authority."""
import argparse
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import selectors
import stat
import subprocess
import tempfile
import time


class Blocked(ValueError):
    pass


def require(ok, reason='AUTHORITY_KEY_CUSTODY_UNPROVEN'):
    if not ok:
        raise Blocked(reason)


def encoded(v):
    return json.dumps(v, sort_keys=True, separators=(',', ':'), ensure_ascii=True).encode()


def digest(v):
    return hashlib.sha256(v).hexdigest()


def decode(raw):
    def pairs(items):
        out = {}
        for k, v in items:
            require(k not in out, 'DUPLICATE_FIELD')
            out[k] = v
        return out
    require(0 < len(raw) <= 131072, 'INPUT_BOUNDS')
    return json.loads(raw, object_pairs_hook=pairs,
        parse_constant=lambda _: (_ for _ in ()).throw(Blocked('INVALID_JSON')))


def attrs(st):
    return tuple(getattr(st, k) for k in ('st_dev', 'st_ino', 'st_uid', 'st_gid',
        'st_mode', 'st_nlink', 'st_size', 'st_mtime_ns', 'st_ctime_ns'))


def ancestors(path):
    require(path.is_absolute() and '..' not in path.parts, 'ABSOLUTE_TRUSTED_PATH_REQUIRED')
    for p in (path.parent, *path.parent.parents):
        st = p.lstat()
        require(stat.S_ISDIR(st.st_mode) and st.st_uid == 0 and not st.st_mode & 0o022,
            'TRUSTED_ANCESTOR_REQUIRED')


def private(path):
    ancestors(path)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        st = os.fstat(fd)
        require(stat.S_ISREG(st.st_mode) and st.st_uid == st.st_gid == 0
            and stat.S_IMODE(st.st_mode) == 0o600 and st.st_nlink == 1 and st.st_size <= 131072,
            'PRIVATE_FILE_REQUIRED')
        raw = os.read(fd, 131073)
        require(len(raw) == st.st_size and attrs(st) == attrs(os.fstat(fd)), 'PRIVATE_FILE_DRIFT')
        return raw
    finally:
        os.close(fd)


def backend(path, expected):
    ancestors(path)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        st = os.fstat(fd)
        require(stat.S_ISREG(st.st_mode) and st.st_uid == 0 and not st.st_mode & 0o022
            and st.st_mode & 0o111 and 0 < st.st_size <= 33554432, 'TRUSTED_OPENSSL_REQUIRED')
        hashed = hashlib.sha256(); size = 0
        while size <= st.st_size:
            part = os.read(fd, 65536)
            if not part:
                break
            size += len(part); hashed.update(part)
        require(size == st.st_size and hashed.hexdigest() == expected
            and attrs(st) == attrs(os.fstat(fd)), 'OPENSSL_HASH_DRIFT')
        return attrs(st)
    finally:
        os.close(fd)


def command(argv, deadline, allowed=(0,), pass_fds=()):
    require(time.monotonic() < deadline, 'COMMAND_DEADLINE')
    child = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL, pass_fds=pass_fds,
        env={'PATH': '/usr/bin:/bin', 'LC_ALL': 'C', 'OPENSSL_CONF': '/dev/null'})
    try:
        with selectors.DefaultSelector() as sel:
            sel.register(child.stdout, selectors.EVENT_READ)
            chunks = []; size = 0
            while True:
                remaining = deadline-time.monotonic()
                require(remaining > 0 and sel.select(remaining), 'COMMAND_DEADLINE')
                raw = os.read(child.stdout.fileno(), 4096)
                if not raw:
                    break
                size += len(raw); require(size <= 4096, 'COMMAND_OUTPUT_LIMIT'); chunks.append(raw)
            code = child.wait(timeout=max(0.001, deadline-time.monotonic()))
            require(code in allowed, 'COMMAND_FAILED')
            return code, b''.join(chunks)
    finally:
        if child.poll() is None:
            child.kill()
        child.wait(); child.stdout.close()


PREFIX = bytes.fromhex('302a300506032b6570032100')
FILES = tuple(f'{role}.{kind}' for role in ('installer', 'attestor') for kind in ('pem', 'der', 'self-test.sig')) + ('authority-draft.json', 'key-custody-receipt.json')
INPUTS = ('target-dossier.json', 'authority-plan.json', 'inventory-receipt.json')


def exclusive(root, name, raw=None, writer=None):
    path = root/name
    fd = os.open(path, os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        os.fchmod(fd, 0o600)
        if writer:
            writer(path)
            require(attrs(os.fstat(fd)) == attrs(path.lstat()), 'EXCLUSIVE_OUTPUT_INODE_DRIFT')
        else:
            with os.fdopen(os.dup(fd), 'wb') as f:
                f.write(raw); f.flush()
        os.fsync(fd)
    finally:
        os.close(fd)
    with_dir = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(with_dir)
    finally:
        os.close(with_dir)
    actual = private(path)
    require(actual == raw if raw is not None else 0 < len(actual) <= 4096, 'PUBLICATION_READBACK_FAILED')
    return actual


def public_key(openssl, path, deadline):
    before = private(path)
    metadata = attrs(path.lstat())
    _, der = command([str(openssl), 'pkey', '-in', str(path), '-pubout', '-outform', 'DER'], deadline)
    require(attrs(path.lstat()) == metadata, 'KEY_BINDING_DRIFT')
    require(len(der) == 44 and der.startswith(PREFIX) and private(path) == before, 'ED25519_KEY_REQUIRED')
    return der


def message(a, role, public):
    # Deliberately outside OUF-DEPLOYMENT-EVIDENCE\x00V1\x00 and all operational schemas.
    return b'OUF-KEY-CUSTODY-SELF-TEST\x00V1\x00' + encoded({'installationRef': a.installation_ref,
        'entityRef': a.entity_ref, 'keyRef': getattr(a, role+'_key_ref'), 'publicKey': public.hex()})


def verify_signature(a, root, role, deadline):
    msg = message(a, role, private(root/(role+'.der'))[12:])
    sig = private(root/(role+'.self-test.sig')); require(len(sig) == 64, 'SELF_TEST_SIGNATURE_REQUIRED')
    with tempfile.TemporaryDirectory(prefix='.self-test-', dir=root) as tmp:
        p = Path(tmp)/'message'; p.write_bytes(msg); p.chmod(0o600)
        argv = [str(a.openssl_path), 'pkeyutl', '-verify', '-pubin', '-keyform', 'DER',
            '-inkey', str(root/(role+'.der')), '-sigfile', str(root/(role+'.self-test.sig')), '-rawin', '-in', str(p)]
        command(argv, deadline)
        p.write_bytes(msg+b' altered')
        code, _ = command(argv, deadline, allowed=(1,))
        require(code == 1, 'ALTERED_SELF_TEST_ACCEPTED')


def bindings(a):
    return {k: getattr(a, k) for k in ('installation_ref', 'entity_ref', 'installer_issuer_ref',
        'attestor_issuer_ref', 'installer_key_ref', 'attestor_key_ref')}


def draft(a, keys, created):
    return {'schema': 'ouf.semantic-authority-key-custody-draft.v1', 'state': 'DRAFT_NOT_AUTHORIZED',
        'installationRef': a.installation_ref, 'entityRef': a.entity_ref, 'keys': keys,
        'proposedNotBefore': created, 'proposedExpiresAt': created+90*86400,
        'keyCustodyProvisioningAuthorized': True, 'roleSigningAuthorized': False,
        'trustPolicyProvisioned': False, 'deploymentAuthorityProven': False,
        'mandatesIssued': 0, 'startAuthorized': False}


def inputs(a):
    raw = {n: private(a.inventory_root/n) for n in INPUTS}
    dossier, plan, inv = (decode(raw[n]) for n in INPUTS)
    require(digest(raw[INPUTS[0]]) == a.dossier_sha256 and digest(raw[INPUTS[1]]) == a.authority_plan_sha256,
        'INVENTORY_HASH_DRIFT')
    require(dossier['installationRef'] == plan['installationRef'] == a.installation_ref
        and plan['schema'] == 'ouf.semantic-deployment-authority-provisioning-plan.v1'
        and plan['state'] == 'DRAFT_NOT_AUTHORIZED' and plan['entityRef'] is None
        and plan['trustPolicyProvisioned'] is False and plan['startAuthorized'] is False,
        'INERT_PLAN_BINDING_REQUIRED')
    require(inv['schema'] == 'ouf.semantic-target-acceptance-inventory.v1'
        and inv['dossierHash'] == a.dossier_sha256 and inv['authorityPlanHash'] == a.authority_plan_sha256
        and inv['sourcePackageReceiptHash'] == a.package_receipt_sha256
        and inv['candidateCount'] == 2 and inv['mountCount'] == 8
        and all(inv[k] is True for k in ('candidatesNeverStarted', 'sourceCustodyVerified', 'stableAcrossReads', 'readOnlyTarget', 'privateEvidenceOnly'))
        and all(inv[k] is False for k in ('deploymentAuthorityProven', 'startAuthorized', 'runtimeRegistrationAuthorized', 'environmentRead', 'mountContentsRead', 'rulesChanged', 'unitsChanged', 'containersChanged'))
        and all(inv[k] == 0 for k in ('keysGenerated', 'signaturesIssued', 'providerCalls', 'dnsCalls', 'iamCalls', 'privateKeysRead')),
        'COMPLETED_PRIVATE_INVENTORY_REQUIRED')
    return raw


def entries(root):
    names = set()
    with os.scandir(root) as scan:
        for index, entry in enumerate(scan):
            require(index < len(FILES)+1, 'UNEXPECTED_PRIVATE_OUTPUT_NO_REPLAY')
            names.add(entry.name)
    return names


def execute(a):
    require(os.geteuid() == 0, 'ROOT_REQUIRED')
    require(a.authorize_key_generation_only is True, 'EXPLICIT_KEY_CUSTODY_AUTHORIZATION_REQUIRED')
    for k, v in bindings(a).items():
        require(re.fullmatch('[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}', v), 'EXPLICIT_IDENTITIES_REQUIRED')
    require(a.installer_key_ref != a.attestor_key_ref and a.installer_issuer_ref != a.attestor_issuer_ref,
        'SEPARATE_INSTALLER_ATTESTOR_REQUIRED')
    for k in ('dossier_sha256', 'authority_plan_sha256', 'package_receipt_sha256', 'openssl_sha256', 'source_sha256'):
        require(re.fullmatch('[0-9a-f]{64}', getattr(a, k)), 'EXPLICIT_HASH_REQUIRED')
    require(re.fullmatch('[0-9a-f]{40}', a.source_commit), 'SOURCE_COMMIT_REQUIRED')
    # The downloaded helper itself is private/pinned; no dependency imports.
    require(digest(private(Path(__file__).absolute())) == a.source_sha256, 'HELPER_SOURCE_DRIFT')
    source = private(Path(__file__).absolute())
    saved = inputs(a); binary = backend(a.openssl_path, a.openssl_sha256)
    def stable():
        return (inputs(a) == saved and backend(a.openssl_path, a.openssl_sha256) == binary
            and private(Path(__file__).absolute()) == source)
    root = a.snapshot_root; ancestors(root/'placeholder')
    lock = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        before = os.fstat(lock)
        require(before.st_uid == before.st_gid == 0 and stat.S_IMODE(before.st_mode) == 0o700,
            'PRIVATE_DIRECTORY_REQUIRED')
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise Blocked('KEY_CUSTODY_LOCK_BUSY') from None
        anchor = lambda: (os.fstat(lock).st_dev, os.fstat(lock).st_ino) == (root.lstat().st_dev, root.lstat().st_ino)
        require(anchor(), 'SNAPSHOT_DIRECTORY_DRIFT')
        present = entries(root)
        require(present <= set(FILES) | {'source'}, 'UNEXPECTED_PRIVATE_OUTPUT_NO_REPLAY')
        deadline = time.monotonic()+30
        if a.mode in ('plan', 'apply'):
            require(not present.intersection(FILES), 'EXISTING_OR_PARTIAL_CUSTODY_NO_REPLAY')
        if a.mode == 'plan':
            require(stable() and anchor(), 'INPUT_DRIFT')
            return {'schema': 'ouf.semantic-authority-key-custody-report.v1', 'mode': 'plan', 'keysGenerated': 0,
                'privateKeysRead': 0, 'selfTestSignaturesIssued': 0, 'evidencePublished': False}
        if a.mode == 'apply':
            created = int(time.time()); keys = []
            for role in ('installer', 'attestor'):
                def generate(path):
                    _, out = command([str(a.openssl_path), 'genpkey', '-algorithm', 'ED25519', '-out', str(path)], deadline)
                    require(out == b'', 'PRIVATE_KEY_STDOUT_FORBIDDEN')
                exclusive(root, role+'.pem', writer=generate)
                der = public_key(a.openssl_path, root/(role+'.pem'), deadline)
                exclusive(root, role+'.der', raw=der)
                with tempfile.TemporaryDirectory(prefix='.self-test-', dir=root) as tmp:
                    p = Path(tmp)/'message'; p.write_bytes(message(a, role, der[12:])); p.chmod(0o600)
                    def sign(path):
                        command([str(a.openssl_path), 'pkeyutl', '-sign', '-rawin', '-inkey', str(root/(role+'.pem')),
                            '-in', str(p), '-out', str(path)], deadline)
                    exclusive(root, role+'.self-test.sig', writer=sign)
                verify_signature(a, root, role, deadline)
                keys.append({'keyRef': getattr(a, role+'_key_ref'), 'issuerRef': getattr(a, role+'_issuer_ref'),
                    'publicKey': der[12:].hex(), 'proposedRoles': ['DEPLOYMENT_INTENT', 'FINAL_DEPLOYMENT_APPROVAL'] if role == 'installer' else ['CREATION_ATTESTATION'], 'authorized': False})
            require(keys[0]['publicKey'] != keys[1]['publicKey'], 'DISTINCT_PUBLIC_KEYS_REQUIRED')
            exclusive(root, 'authority-draft.json', raw=encoded(draft(a, keys, created)))
            receipt = {'schema': 'ouf.semantic-authority-key-custody-receipt.v1', 'state': 'PRIVATE_KEYS_PREPARED_DRAFT_ONLY',
                'bindings': bindings(a), 'sourceCommit': a.source_commit, 'sourceSha256': a.source_sha256,
                'opensslSha256': a.openssl_sha256, 'createdAt': created,
                'inventoryHashes': {n: digest(raw) for n, raw in saved.items()},
                'outputHashes': {n: digest(private(root/n)) for n in FILES if n != FILES[-1]},
                'keysPresent': 2, 'selfTestSignaturesPresent': 2, 'deploymentSignaturesIssued': 0,
                'keyCustodyProvisioningAuthorized': True, 'roleSigningAuthorized': False,
                'trustPolicyProvisioned': False, 'startAuthorized': False}
            require(stable() and anchor(), 'INPUT_DRIFT')
            exclusive(root, FILES[-1], raw=encoded(receipt))  # only completion marker, published last
        # verify checks the recorded, inactive draft and actual Ed25519 keys; no regeneration/signing.
        receipt_raw = private(root/FILES[-1]); receipt = decode(receipt_raw)
        require(entries(root) <= set(FILES) | {'source'}
            and receipt['schema'] == 'ouf.semantic-authority-key-custody-receipt.v1'
            and receipt['state'] == 'PRIVATE_KEYS_PREPARED_DRAFT_ONLY' and receipt['bindings'] == bindings(a)
            and receipt['sourceCommit'] == a.source_commit and receipt['sourceSha256'] == a.source_sha256
            and receipt['opensslSha256'] == a.openssl_sha256
            and receipt['inventoryHashes'] == {n: digest(raw) for n, raw in saved.items()}
            and receipt['outputHashes'] == {n: digest(private(root/n)) for n in FILES if n != FILES[-1]}
            and receipt['keysPresent'] == receipt['selfTestSignaturesPresent'] == 2
            and receipt['deploymentSignaturesIssued'] == 0
            and receipt['keyCustodyProvisioningAuthorized'] is True
            and all(receipt[k] is False for k in ('roleSigningAuthorized', 'trustPolicyProvisioned', 'startAuthorized')),
            'EXACT_CUSTODY_RECEIPT_REQUIRED')
        created = receipt['createdAt']; require(type(created) is int and created <= time.time() < created+90*86400,
            'PROPOSED_VALIDITY_EXPIRED_OR_CLOCK_REGRESSED')
        keys = []
        for role in ('installer', 'attestor'):
            der = public_key(a.openssl_path, root/(role+'.pem'), deadline)
            require(private(root/(role+'.der')) == der, 'PUBLIC_PRIVATE_KEY_DRIFT')
            verify_signature(a, root, role, deadline)
            keys.append({'keyRef': getattr(a, role+'_key_ref'), 'issuerRef': getattr(a, role+'_issuer_ref'),
                'publicKey': der[12:].hex(), 'proposedRoles': ['DEPLOYMENT_INTENT', 'FINAL_DEPLOYMENT_APPROVAL'] if role == 'installer' else ['CREATION_ATTESTATION'], 'authorized': False})
        require(keys[0]['publicKey'] != keys[1]['publicKey'] and private(root/'authority-draft.json') == encoded(draft(a, keys, created)), 'INACTIVE_DRAFT_DRIFT')
        require(stable() and private(root/FILES[-1]) == receipt_raw and anchor(), 'FINAL_READBACK_DRIFT')
        return {'schema': 'ouf.semantic-authority-key-custody-report.v1', 'mode': a.mode,
            'keysGenerated': 2 if a.mode == 'apply' else 0, 'keysPresent': 2, 'privateKeysRead': 2,
            'selfTestSignaturesIssued': 2 if a.mode == 'apply' else 0, 'selfTestSignaturesPresent': 2,
            'alteredSelfTestRejected': True, 'publicPrivateBindingVerified': True,
            'draftHash': receipt['outputHashes']['authority-draft.json'], 'receiptHash': digest(receipt_raw), 'evidencePublished': a.mode == 'apply'}
    finally:
        os.close(lock)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--mode', choices=('plan', 'apply', 'verify'), required=True)
    for n in ('inventory-root', 'snapshot-root', 'openssl-path'):
        parser.add_argument('--'+n, type=Path, required=True)
    for n in ('installation-ref', 'entity-ref', 'installer-issuer-ref', 'attestor-issuer-ref', 'installer-key-ref',
              'attestor-key-ref', 'dossier-sha256', 'authority-plan-sha256', 'package-receipt-sha256',
              'openssl-sha256', 'source-sha256', 'source-commit'):
        parser.add_argument('--'+n, required=True)
    parser.add_argument('--authorize-key-generation-only', action='store_true')
    a = parser.parse_args()
    try:
        result = execute(a)
        result.update(keyCustodyProvisioningAuthorized=True, roleSigningAuthorized=False, trustPolicyProvisioned=False,
            deploymentAuthorityProven=False, deploymentSignaturesIssued=0, mandatesIssued=0, runtimeRegistered=False,
            startAuthorized=False, providerCalls=0, dnsCalls=0, iamCalls=0, rulesChanged=False, unitsChanged=False,
            containersChanged=False, atomicSnapshotProven=False, notReleaseAcceptance=True, noSecretsPrinted=True)
        print('SEMANTIC_AUTHORITY_KEY_CUSTODY='+json.dumps(result, sort_keys=True))
        print('SEMANTIC_AUTHORITY_KEY_CUSTODY=PASS MODE='+a.mode+' PRIVATE_KEYS_ONLY=true POLICY_ACTIVE=false START_AUTHORIZED=false NO_SECRETS_PRINTED=true')
        return 0
    except (OSError, ValueError, KeyError, TypeError, AttributeError, RecursionError, subprocess.SubprocessError) as e:
        reason = str(e) if isinstance(e, Blocked) else 'CUSTODY_INPUT_OR_COMMAND_UNPROVEN'
        if not re.fullmatch('[A-Z_]{1,80}', reason):
            reason = 'AUTHORITY_KEY_CUSTODY_UNPROVEN'
        print('SEMANTIC_AUTHORITY_KEY_CUSTODY=BLOCKED MODE='+a.mode+' REASON='+reason+' START_AUTHORIZED=false NO_SECRETS_PRINTED=true')
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
