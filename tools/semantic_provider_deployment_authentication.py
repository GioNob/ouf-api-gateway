"""Bounded detached Ed25519 verification for explicitly provisioned local mandates.

No default authority, key generation, signing, network or runtime operation.
Trusted integration must source-seal this module and explicitly provision policy
and public-key bindings. This verifier is compatible with the protocol callback.
"""
import copy
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import tempfile
import time

from tools.semantic_provider_deployment_protocol import identity, hashed
from tools.semantic_provider_preexec import PreexecDenied

ROLES = {'DEPLOYMENT_INTENT', 'CREATION_ATTESTATION', 'FINAL_DEPLOYMENT_APPROVAL'}
DOMAIN = b'OUF-DEPLOYMENT-EVIDENCE\x00V1\x00'
DER_PREFIX = bytes.fromhex('302a300506032b6570032100')


def require(value, reason):
    if not value: raise PreexecDenied(reason)


def attributes(info):
    return tuple(getattr(info, k) for k in ('st_dev','st_ino','st_uid','st_gid','st_mode',
        'st_nlink','st_size','st_mtime_ns','st_ctime_ns'))


def ancestors(path):
    require(path.is_absolute() and '..' not in path.parts, 'EXPLICIT_AUTHENTICATION_PATH_REQUIRED')
    for parent in (path.parent, *path.parent.parents):
        info = parent.lstat()
        require(stat.S_ISDIR(info.st_mode) and info.st_uid == 0 and not info.st_mode & 0o022,
                'TRUSTED_AUTHENTICATION_ANCESTOR_REQUIRED')


def private_bytes(path, limit=131072):
    ancestors(path)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        before = os.fstat(fd)
        require(stat.S_ISREG(before.st_mode) and before.st_uid == before.st_gid == 0
                and stat.S_IMODE(before.st_mode) == 0o600 and before.st_nlink == 1
                and before.st_size <= limit, 'PRIVATE_AUTHENTICATION_INPUT_REQUIRED')
        raw = os.read(fd, limit+1)
        require(len(raw) == before.st_size and attributes(before) == attributes(os.fstat(fd)),
                'AUTHENTICATION_INPUT_DRIFT')
        return raw
    finally: os.close(fd)


def decode(raw, limit):
    require(type(raw) is bytes and 0 < len(raw) <= limit, 'BOUNDED_AUTHENTICATION_RECORD_REQUIRED')
    def unique(pairs):
        value = {}
        for key, item in pairs:
            require(key not in value, 'DUPLICATE_AUTHENTICATION_KEY'); value[key] = item
        return value
    try:
        value = json.loads(raw, object_pairs_hook=unique,
            parse_constant=lambda _: (_ for _ in ()).throw(ValueError()))
    except PreexecDenied: raise
    except (ValueError, RecursionError, UnicodeError):
        raise PreexecDenied('INVALID_AUTHENTICATION_JSON') from None
    require(type(value) is dict, 'EXACT_AUTHENTICATION_OBJECT_REQUIRED')
    return value


def binding(value):
    require(type(value) is dict and set(value) == {'path','sha256'}
            and type(value['path']) is str and hashed(value['sha256']),
            'EXPLICIT_AUTHENTICATION_BINDING_REQUIRED')
    ancestors(Path(value['path']))
    return copy.deepcopy(value)


def policy(raw, installation, entity, now):
    value = decode(raw, 65536)
    require(set(value) == {'schema','installationRef','entityRef','keys'}
            and value['schema'] == 'ouf.semantic-deployment-trust-policy.v1'
            and (value['installationRef'],value['entityRef']) == (installation,entity)
            and type(value['keys']) is list and 1 <= len(value['keys']) <= 32,
            'EXACT_LOCAL_TRUST_POLICY_REQUIRED')
    seen = set()
    for key in value['keys']:
        require(type(key) is dict and set(key) == {'keyRef','issuerRef','roles','publicKey',
                'notBefore','expiresAt','state'} and identity(key['keyRef'])
                and identity(key['issuerRef']) and key['keyRef'] not in seen
                and type(key['roles']) is list and 1 <= len(key['roles']) <= 3
                and all(type(r) is str and r in ROLES for r in key['roles'])
                and len(set(key['roles'])) == len(key['roles'])
                and type(key['publicKey']) is str and re.fullmatch('[0-9a-f]{64}',key['publicKey'])
                and type(key['notBefore']) is int and type(key['expiresAt']) is int
                and 0 <= key['notBefore'] < key['expiresAt']
                and key['state'] in ('ACTIVE','REVOKED'), 'EXACT_LOCAL_KEY_MANDATE_REQUIRED')
        seen.add(key['keyRef'])
    return value


def signing_bytes(raw, header):
    """Public producer contract; signs exact record bytes plus role/scope/key frame."""
    require(type(raw) is bytes and 0 < len(raw) <= 131072, 'BOUNDED_SIGNED_PAYLOAD_REQUIRED')
    require(type(header) is dict and set(header) == {'schema','algorithm','keyRef','role',
            'issuerRef','installationRef','entityRef','payloadHash'}, 'EXACT_SIGNATURE_HEADER_REQUIRED')
    require(header['schema'] == 'ouf.semantic-deployment-detached-signature.v1'
            and header['algorithm'] == 'Ed25519' and type(header['role']) is str
            and header['role'] in ROLES
            and all(identity(header[k]) for k in ('keyRef','issuerRef','installationRef','entityRef'))
            and header['payloadHash'] == hashlib.sha256(raw).hexdigest(), 'EXACT_SIGNING_FRAME_SCOPE_REQUIRED')
    encoded = json.dumps(header, sort_keys=True, separators=(',',':'), ensure_ascii=True).encode('ascii')
    return DOMAIN+len(encoded).to_bytes(4,'big')+encoded+len(raw).to_bytes(4,'big')+raw


class DetachedAuthenticator:
    def __init__(self, policy_binding, signature_directory, openssl_binding, clock=time.time):
        self.policy_binding = binding(policy_binding)
        require(type(openssl_binding) is dict and set(openssl_binding) == {'path','sha256','version'}
                and type(openssl_binding['version']) is str
                and re.fullmatch('[0-9]+[.][0-9]+[.][0-9]+[a-z]?',openssl_binding['version']),
                'EXACT_OPENSSL_VERSION_BINDING_REQUIRED')
        self.openssl_binding = {**binding({k:openssl_binding[k] for k in ('path','sha256')}),
                                'version':openssl_binding['version']}
        self.signature_directory = Path(signature_directory)
        ancestors(self.signature_directory/'placeholder')
        info = self.signature_directory.lstat()
        require(stat.S_ISDIR(info.st_mode) and info.st_uid == info.st_gid == 0
                and stat.S_IMODE(info.st_mode) == 0o700, 'PRIVATE_SIGNATURE_DIRECTORY_REQUIRED')
        self.clock = clock

    def read_policy(self):
        raw = private_bytes(Path(self.policy_binding['path']), 65536)
        require(hashlib.sha256(raw).hexdigest() == self.policy_binding['sha256'],
                'LOCAL_TRUST_POLICY_REVOKED_OR_CHANGED')
        return raw

    def executable(self):
        path = Path(self.openssl_binding['path']); ancestors(path)
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        try:
            before = os.fstat(fd)
            require(stat.S_ISREG(before.st_mode) and before.st_uid == 0
                    and not before.st_mode & 0o022 and before.st_mode & 0o111
                    and before.st_size <= 64000000, 'TRUSTED_AUTHENTICATION_EXECUTABLE_REQUIRED')
            h = hashlib.sha256(); total = 0
            while True:
                raw = os.read(fd, 65536)
                if not raw: break
                total += len(raw); require(total <= 64000000, 'AUTHENTICATION_EXECUTABLE_UNBOUNDED'); h.update(raw)
            require(h.hexdigest() == self.openssl_binding['sha256']
                    and attributes(before) == attributes(os.fstat(fd)), 'AUTHENTICATION_EXECUTABLE_DRIFT')
        finally: os.close(fd)
        return str(path)

    def verify(self, payload, public_key, signature):
        executable = self.executable()
        # A root-owned executable that merely exits zero is not a verifier.
        with tempfile.TemporaryFile() as output:
            try:
                result = subprocess.run([executable,'version'],stdin=subprocess.DEVNULL,
                    stdout=output,stderr=subprocess.DEVNULL,timeout=2,
                    env={'PATH':'/usr/bin:/bin','LC_ALL':'C','OPENSSL_CONF':'/dev/null'})
            except (OSError, subprocess.TimeoutExpired):
                raise PreexecDenied('DETACHED_VERIFICATION_UNPROVEN') from None
            output.seek(0); raw = output.read(257)
        version = re.match(rb'OpenSSL ([0-9]+[.][0-9]+[.][0-9]+[a-z]?)\b',raw)
        require(result.returncode == 0 and len(raw) <= 256 and version is not None
                and version.group(1).decode('ascii') == self.openssl_binding['version'],
                'DETACHED_OPENSSL_VERSION_UNPROVEN')
        with tempfile.TemporaryDirectory(prefix='ouf-detached-verification-') as directory:
            paths = []
            for name, raw in zip(('public.der','signature.bin','frame.bin'),
                                 (DER_PREFIX+public_key,signature,payload)):
                path = Path(directory)/name; path.write_bytes(raw); path.chmod(0o600); paths.append(str(path))
            try:
                result = subprocess.run([executable,'pkeyutl','-verify','-pubin','-rawin',
                    '-keyform','DER','-inkey',paths[0],'-sigfile',paths[1],'-in',paths[2]],
                    stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                    timeout=2, env={'PATH':'/usr/bin:/bin','LC_ALL':'C','OPENSSL_CONF':'/dev/null'})
            except (OSError, subprocess.TimeoutExpired):
                raise PreexecDenied('DETACHED_VERIFICATION_UNPROVEN') from None
        self.executable()
        require(result.returncode == 0, 'DETACHED_SIGNATURE_INVALID')

    def __call__(self, raw, role, issuer, installation, entity):
        require(type(raw) is bytes and 0 < len(raw) <= 131072 and type(role) is str
                and role in ROLES and all(identity(v) for v in (issuer,installation,entity)),
                'EXACT_AUTHENTICATION_SCOPE_REQUIRED')
        now = self.clock(); policy_raw = self.read_policy()
        configured = policy(policy_raw, installation, entity, now)
        payload_hash = hashlib.sha256(raw).hexdigest()
        path = self.signature_directory/(payload_hash+'.'+role+'.json')
        signature_raw = private_bytes(path,4096); record = decode(signature_raw,4096)
        require(set(record) == {'schema','algorithm','keyRef','role','issuerRef','installationRef',
                'entityRef','payloadHash','signature'}
                and record['schema'] == 'ouf.semantic-deployment-detached-signature.v1'
                and record['algorithm'] == 'Ed25519' and identity(record['keyRef'])
                and (record['role'],record['issuerRef'],record['installationRef'],record['entityRef'],record['payloadHash'])
                    == (role,issuer,installation,entity,payload_hash)
                and type(record['signature']) is str and re.fullmatch('[0-9a-f]{128}',record['signature']),
                'EXACT_DETACHED_SIGNATURE_REQUIRED')
        keys = [k for k in configured['keys'] if k['keyRef'] == record['keyRef']
                and k['issuerRef'] == issuer and role in k['roles'] and k['state'] == 'ACTIVE'
                and k['notBefore'] <= now < k['expiresAt']]
        require(len(keys) == 1, 'ACTIVE_LOCAL_ROLE_MANDATE_REQUIRED')
        header = {k:v for k,v in record.items() if k != 'signature'}
        self.verify(signing_bytes(raw,header), bytes.fromhex(keys[0]['publicKey']), bytes.fromhex(record['signature']))
        finished = self.clock()
        require(finished >= now and keys[0]['notBefore'] <= finished < keys[0]['expiresAt'],
                'LOCAL_MANDATE_EXPIRED_OR_CLOCK_REGRESSED')
        require(self.read_policy() == policy_raw and private_bytes(path,4096) == signature_raw,
                'AUTHENTICATION_REVOKED_DURING_VERIFICATION')
        return True
