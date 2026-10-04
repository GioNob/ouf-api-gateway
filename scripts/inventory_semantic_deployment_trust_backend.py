"""Read-only source custody and public Ed25519 verification preflight.

Only RFC 8032 section 7.1 test 2 PUBLIC key/signature/message are used. No private
key, key generation, signing, authority issuance or runtime operation exists.
The operator-attestation file is separately pinned by the delivery command.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import tempfile
import time

PUBLIC_KEY = bytes.fromhex('302a300506032b6570032100'
    '3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c')
SIGNATURE = bytes.fromhex('92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da'
    '085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00')
FLAGS = ('admissionPreparerInstalled', 'runtimeAdapterInstalled', 'externalProducerInstalled',
         'runtimeRegistered', 'startAuthorized', 'rulesChanged', 'unitsChanged', 'containersChanged')



def require(value, reason):
    if not value: raise RuntimeError(reason)


def signature(info):
    return tuple(getattr(info, k) for k in ('st_dev', 'st_ino', 'st_uid', 'st_gid', 'st_mode',
        'st_nlink', 'st_size', 'st_mtime_ns', 'st_ctime_ns'))


def parents(path):
    require(path.is_absolute() and '..' not in path.parts, 'EXPLICIT_TRUST_PATH_REQUIRED')
    for parent in (path.parent, *path.parent.parents):
        info = parent.lstat()
        require(stat.S_ISDIR(info.st_mode) and info.st_uid == 0 and not info.st_mode & 0o022,
                'TRUSTED_ANCESTOR_REQUIRED')


def read_private(path):
    parents(path)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        before = os.fstat(fd)
        require(stat.S_ISREG(before.st_mode) and before.st_uid == before.st_gid == 0
                and stat.S_IMODE(before.st_mode) == 0o600 and before.st_nlink == 1
                and before.st_size <= 131072, 'PRIVATE_TRUST_INPUT_REQUIRED')
        raw = os.read(fd, 131073)
        require(len(raw) <= 131072 and signature(before) == signature(os.fstat(fd)), 'TRUST_INPUT_DRIFT')
        return raw
    finally: os.close(fd)


def parse(raw):
    def unique(pairs):
        value = {}
        for key, item in pairs:
            require(key not in value, 'DUPLICATE_TRUST_INPUT_KEY'); value[key] = item
        return value
    return json.loads(raw, object_pairs_hook=unique)


def package_snapshot(root, expected):
    require(expected['packageRoot'] == str(root), 'OPERATOR_PACKAGE_ROOT_DRIFT')
    receipt = expected['receipt']; actual_raw = read_private(root/'source-package-receipt.json')
    require(parse(actual_raw) == receipt
            and receipt['schema'] == 'ouf.semantic-deployment-source-package.v4'
            and re.fullmatch('[0-9a-f]{40}', receipt['sourceCommit'])
            and all(receipt[k] is False for k in FLAGS) and receipt['providerCalls'] == 0
            and receipt['notReleaseAcceptance'] is True and receipt['noSecretsPrinted'] is True,
            'SOURCE_ONLY_OPERATOR_RECEIPT_DRIFT')
    hashes = receipt['sourceHashes']; require(type(hashes) is dict and len(hashes) == 18,
            'EXACT_V4_SOURCE_COUNT_REQUIRED')
    for relative, expected_hash in hashes.items():
        require(re.fullmatch('(scripts|tools)/[A-Za-z0-9_]+[.]py', relative)
                and re.fullmatch('[0-9a-f]{64}', expected_hash), 'EXACT_PRIVATE_SOURCE_BINDING_REQUIRED')
        require(hashlib.sha256(read_private(root/'source'/relative)).hexdigest() == expected_hash,
                'OPERATOR_SOURCE_PACKAGE_DRIFT')
    return {'sourceCommit': receipt['sourceCommit'], 'sourceCount': len(hashes),
            'sourcePackageReceiptHash': hashlib.sha256(actual_raw).hexdigest()}


def binary(path):
    require(path.is_absolute() and '..' not in path.parts, 'EXPLICIT_OPENSSL_PATH_REQUIRED')
    try: resolved = path.resolve(strict=True)
    except FileNotFoundError: return None
    parents(resolved)
    fd = os.open(resolved, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        before = os.fstat(fd)
        require(stat.S_ISREG(before.st_mode) and before.st_uid == 0 and not before.st_mode & 0o022
                and before.st_mode & 0o111 and before.st_size <= 64000000, 'TRUSTED_OPENSSL_EXECUTABLE_REQUIRED')
        h = hashlib.sha256(); count = 0
        while True:
            chunk = os.read(fd, 65536)
            if not chunk: break
            count += len(chunk); require(count <= 64000000, 'OPENSSL_BINARY_UNBOUNDED'); h.update(chunk)
        require(signature(before) == signature(os.fstat(fd)), 'OPENSSL_BINARY_DRIFT')
        return {'opensslPath': str(resolved), 'opensslHash': h.hexdigest()}
    finally: os.close(fd)


def run(path, args, deadline, fds=()):
    remaining = deadline-time.monotonic(); require(remaining > 0, 'TRUST_INVENTORY_DEADLINE_MISSED')
    with tempfile.TemporaryFile() as out:
        result = subprocess.run([path, *args], stdin=subprocess.DEVNULL, stdout=out, stderr=subprocess.DEVNULL,
            timeout=min(3, remaining), pass_fds=fds,
            env={'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LC_ALL': 'C', 'OPENSSL_CONF': '/dev/null'})
        out.seek(0); raw = out.read(32769); require(len(raw) <= 32768, 'OPENSSL_OUTPUT_UNBOUNDED')
        return result.returncode, raw


def verify_public_vector(path, deadline, message=b'\x72', signature_bytes=SIGNATURE):
    # Public, fixed-size vector files only; no /proc or inherited-fd dependency.
    with tempfile.TemporaryDirectory(prefix='ouf-public-vector-') as directory:
        paths = []
        for name, payload in zip(('public.der', 'signature.bin', 'message.bin'),
                                 (PUBLIC_KEY, signature_bytes, message)):
            target = Path(directory)/name
            target.write_bytes(payload); target.chmod(0o600); paths.append(str(target))
        args = ['pkeyutl', '-verify', '-pubin', '-rawin', '-keyform', 'DER',
                '-inkey', paths[0], '-sigfile', paths[1], '-in', paths[2]]
        return run(path, args, deadline)[0]


def backend_snapshot(path, deadline):
    before = binary(path)
    empty = {'opensslAvailable': False, 'opensslPath': str(path), 'opensslHash': None,
             'opensslVersion': None, 'ed25519VerificationProven': False,
             'alteredMessageRejected': False, 'alteredSignatureRejected': False}
    if before is None: return empty
    code, output = run(before['opensslPath'], ['version'], deadline)
    version = re.match(rb'OpenSSL ([0-9]+[.][0-9]+[.][0-9]+[a-z]?)\b', output)
    require(code == 0 and version is not None, 'OPENSSL_VERSION_UNPROVEN')
    positive = verify_public_vector(before['opensslPath'], deadline)
    wrong_message = verify_public_vector(before['opensslPath'], deadline, message=b'\x73')
    altered = bytes([SIGNATURE[0] ^ 1])+SIGNATURE[1:]
    wrong_signature = verify_public_vector(before['opensslPath'], deadline, signature_bytes=altered)
    require(binary(path) == before, 'OPENSSL_BINARY_CHANGED_DURING_PROBE')
    return {**empty, **before, 'opensslAvailable': True, 'opensslVersion': version.group(1).decode('ascii'),
            'ed25519VerificationProven': positive == 0,
            'alteredMessageRejected': positive == 0 and wrong_message == 1,
            'alteredSignatureRejected': positive == 0 and wrong_signature == 1}


def inventory(package_root, attestation_path, openssl_path):
    expected_raw = read_private(attestation_path); expected = parse(expected_raw)
    require(expected['schema'] == 'ouf.semantic-deployment-package.operator-attestation.v1',
            'EXACT_OPERATOR_ATTESTATION_REQUIRED')
    deadline = time.monotonic()+20
    first = {**package_snapshot(package_root, expected), **backend_snapshot(openssl_path, deadline)}
    second = {**package_snapshot(package_root, expected), **backend_snapshot(openssl_path, deadline)}
    require(first == second and read_private(attestation_path) == expected_raw, 'TRUST_INVENTORY_CHANGED_ACROSS_READS')
    return {'schema': 'ouf.semantic-deployment-trust-backend-inventory.v1', **second,
            'sourceCustodyVerified': True, 'stableAcrossReads': True, 'atomicSnapshotProven': False,
            'publicTestVector': 'RFC8032-7.1-TEST2', 'readOnly': True, 'privateKeysRead': 0,
            'keysGenerated': 0, 'signaturesIssued': 0, 'deploymentAuthorityProven': False,
            'keyGenerationAuthorized': False, 'runtimeRegistrationAuthorized': False,
            'startAuthorized': False, 'providerCalls': 0, 'dnsCalls': 0, 'iamCalls': 0,
            'notReleaseAcceptance': True, 'noSecretsPrinted': True}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--package-root', type=Path, required=True)
    parser.add_argument('--operator-attestation', type=Path, required=True)
    parser.add_argument('--openssl-path', type=Path, required=True)
    args = parser.parse_args()
    try:
        require(os.geteuid() == 0 and sys.flags.isolated and sys.dont_write_bytecode,
                'ROOT_ISOLATED_NO_BYTECODE_REQUIRED')
        value = inventory(args.package_root, args.operator_attestation, args.openssl_path)
        print('SEMANTIC_DEPLOYMENT_TRUST_BACKEND='+json.dumps(value, sort_keys=True))
        print('SEMANTIC_DEPLOYMENT_TRUST_BACKEND_INVENTORY=PASS READ_ONLY=true'
              ' NO_KEYS_CREATED_OR_READ=true NO_SIGNATURE_ISSUED=true NO_IAM_OR_DNS_CALL=true'
              ' NO_RULE_UNIT_CONTAINER_CHANGED=true START_AUTHORIZED=false NO_SECRETS_PRINTED=true')
        return 0
    except Exception as error:
        reason = str(error)
        if not re.fullmatch('[A-Z_]{1,80}', reason): reason = 'TRUST_BACKEND_INVENTORY_UNPROVEN'
        print('SEMANTIC_DEPLOYMENT_TRUST_BACKEND_INVENTORY=BLOCKED REASON='+reason+' NO_SECRETS_PRINTED=true')
        return 1


if __name__ == '__main__': raise SystemExit(main())
