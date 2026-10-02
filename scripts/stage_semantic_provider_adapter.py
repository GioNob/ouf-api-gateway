#!/usr/bin/env python3
"""Stage only a pinned provider adapter image; never start a runtime container.

No credential/configuration mounts, IAM/route/policy/database operations or
provider calls. Plan is read-only; interrupted apply requires reconciliation.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import urllib.request
from urllib.parse import urlsplit

# Hashes cover the entire minimal build context, not the downloaded helper.
PAYLOAD_HASHES = {"Dockerfile.semantic-provider":"b2cc4828a2cc9424c2a3b31793d9094dbade41d8d7485ca43b32d2dcd80873e7","tools/semantic_provider_adapter.py":"718f031cd4116d233c3075ee74da2f28170b5ed4efcac1a77deef154f7fd320c","tools/semantic_provider_admission.py":"dca670d1f0ced678db6af9810199da07419901a21523385e0ebea623b608bbfc","tools/semantic_provider_boundary.py":"cae2b1d5970349ce1ebc95fb44ca4dd1bd67d93e43900ad4cbeabb3d5fbd6e69","tools/semantic_provider_relay.py":"04b33da9b3d599872c19ea20d3775141ef99c5989c7fb7175be6926b74cc7f6f","tools/southbound_security.py":"5953e6143fb7141b62a2d5cc26d8cf85ee74147d9eefaa923460f8e1706eb0ec"}
ENTRYPOINT = ['python3', '-B', '-m', 'tools.semantic_provider_adapter']


class Blocked(RuntimeError):
    pass


def run(args, timeout=30, optional=False):
    result = subprocess.run(args, capture_output=True, text=True, timeout=timeout)
    if result.returncode and not optional:
        raise Blocked('COMMAND_FAILED')
    return result


def inspect(docker, reference):
    try:
        value = json.loads(run([docker, 'inspect', reference]).stdout)
        if not isinstance(value, list) or len(value) != 1:
            raise ValueError()
        return value[0]
    except (ValueError, KeyError):
        raise Blocked('INSPECT_UNPROVEN') from None


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':')).encode()).hexdigest()


def gateway_snapshot(args):
    doc = inspect(args.docker_path, args.gateway_container)
    if doc.get('Id') != args.expected_gateway_id or not (doc.get('State') or {}).get('Running'):
        raise Blocked('GATEWAY_ID_OR_RUNNING_MISMATCH')
    raw = run([args.docker_path, 'exec', args.gateway_container, 'apisix', 'version']).stdout
    versions = re.findall(r'(?m)^\s*(\d+\.\d+\.\d+)\s*$', raw)
    if versions != [args.expected_gateway_version] or args.expected_gateway_version != '3.18.0':
        raise Blocked('TESTED_GATEWAY_VERSION_UNPROVEN')
    # Hash sensitive inspect fields; never persist/print their values.
    selected = {key: doc.get(key) for key in ('Id', 'Image', 'Config', 'HostConfig', 'Mounts', 'NetworkSettings')}
    selected['state'] = {k: doc['State'].get(k) for k in ('Running', 'Pid', 'StartedAt')}
    return {'id': doc['Id'], 'image': doc.get('Image'), 'configurationHash': digest(selected),
            'version': versions[0]}


def private_ancestors(path):
    for item in (path, *path.parents):
        info = item.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or stat.S_IMODE(info.st_mode) & 0o022:
            raise Blocked('PRIVATE_ROOT_ANCESTOR_UNSAFE')


def write_exclusive(path, raw):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, 'wb', closefd=False) as stream:
            stream.write(raw); stream.flush(); os.fsync(stream.fileno())
    finally:
        os.close(fd)


def validate(args):
    if os.geteuid() != 0:
        raise Blocked('ROOT_REQUIRED')
    if not re.fullmatch(r'[0-9a-f]{40}', args.source_commit) or not re.fullmatch(r'[0-9a-f]{64}', args.expected_gateway_id):
        raise Blocked('IMMUTABLE_SOURCE_OR_GATEWAY_ID_REQUIRED')
    if not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,127}', args.gateway_container):
        raise Blocked('GATEWAY_BINDING_INVALID')
    if not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._:/-]*@sha256:[0-9a-f]{64}', args.base_image):
        raise Blocked('DIGEST_PINNED_BASE_REQUIRED')
    if not re.fullmatch(r'[a-z0-9][a-z0-9._/-]*:[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}', args.image_tag):
        raise Blocked('STAGE_IMAGE_TAG_INVALID')
    if not 1 <= args.runtime_uid <= 2147483647 or not 1 <= args.runtime_gid <= 2147483647:
        raise Blocked('NON_ROOT_RUNTIME_IDS_REQUIRED')
    parsed = urlsplit(args.source_url_base)
    if parsed.scheme != 'https' or not parsed.hostname or parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise Blocked('SOURCE_ORIGIN_UNSAFE')
    if not args.snapshot_root.is_absolute() or '..' in args.snapshot_root.parts:
        raise Blocked('SNAPSHOT_ROOT_INVALID')
    private_ancestors(args.snapshot_root.parent)
    if not PAYLOAD_HASHES or any(not re.fullmatch(r'[0-9a-f]{64}', value) for value in PAYLOAD_HASHES.values()):
        raise Blocked('REVIEWED_PAYLOAD_HASHES_REQUIRED')


def intent(args):
    return {'schema': 'ouf.semantic-provider-image-stage.v1', 'sourceCommit': args.source_commit,
            'sourceURLBase': args.source_url_base.rstrip('/'), 'baseImage': args.base_image,
            'imageTag': args.image_tag, 'runtimeUser': str(args.runtime_uid)+':'+str(args.runtime_gid),
            'payloadHashes': PAYLOAD_HASHES, 'payloadHash': digest(PAYLOAD_HASHES),
            'gateway': gateway_snapshot(args)}


def base_snapshot(args):
    raw = run([args.docker_path, 'image', 'inspect', args.base_image]).stdout
    try:
        docs = json.loads(raw)
        if len(docs) != 1 or not re.fullmatch(r'sha256:[0-9a-f]{64}', docs[0]['Id']):
            raise ValueError()
        # Docker resolves the digest-pinned reference; signature provenance is a
        # separate supply-chain gate, never inferred from the repository tag.
        return docs[0]['Id']
    except (ValueError, KeyError, TypeError):
        raise Blocked('BASE_IMAGE_UNPROVEN') from None


def check_staged_image(args, desired):
    raw = run([args.docker_path, 'image', 'inspect', args.image_tag]).stdout
    try:
        image = json.loads(raw)[0]; cfg = image['Config']; labels = cfg.get('Labels') or {}
        if cfg.get('User') != desired['runtimeUser'] or cfg.get('Entrypoint') != ENTRYPOINT \
                or labels.get('org.opencontainers.image.revision') != desired['sourceCommit'] \
                or labels.get('ouf.payload.sha256') != desired['payloadHash'] \
                or labels.get('ouf.component') != 'semantic-provider-transport' \
                or not re.fullmatch(r'sha256:[0-9a-f]{64}', image['Id']):
            raise ValueError()
        return image['Id']
    except (ValueError, KeyError, TypeError):
        raise Blocked('STAGED_IMAGE_CONTRACT_MISMATCH') from None


def acquire_payload(args, context):
    class NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, request, fp, code, message, headers, url):
            raise Blocked('SOURCE_REDIRECT_FORBIDDEN')
    opener = urllib.request.build_opener(NoRedirect())
    for relative, expected in PAYLOAD_HASHES.items():
        url = args.source_url_base.rstrip('/')+'/'+args.source_commit+'/'+relative
        with opener.open(url, timeout=20) as response:
            # No redirect outside the explicitly selected pinned source URL.
            if response.geturl() != url:
                raise Blocked('SOURCE_REDIRECT_FORBIDDEN')
            raw = response.read(131073)
        if len(raw) > 131072 or hashlib.sha256(raw).hexdigest() != expected:
            raise Blocked('SOURCE_PAYLOAD_HASH_MISMATCH')
        target = context/relative; target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        write_exclusive(target, raw)


def operate(args):
    validate(args)
    desired = intent(args)
    if args.mode == 'verify':
        private_ancestors(args.snapshot_root)
        receipt_path = args.snapshot_root/'stage-receipt.json'
        info = receipt_path.lstat()
        if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or stat.S_IMODE(info.st_mode) != 0o600 or info.st_nlink != 1:
            raise Blocked('STAGE_RECEIPT_UNSAFE')
        saved = json.loads(receipt_path.read_text())
        if saved.get('intent') != desired:
            raise Blocked('STAGE_RECEIPT_OR_LIVE_DRIFT')
        if check_staged_image(args, desired) != saved.get('imageId'):
            raise Blocked('STAGE_IMAGE_ID_DRIFT')
        return saved
    if args.snapshot_root.exists() or args.snapshot_root.is_symlink():
        raise Blocked('STAGE_ROOT_EXISTS_RECONCILE')
    found = run([args.docker_path, 'image', 'inspect', args.image_tag], optional=True)
    if found.returncode == 0:
        raise Blocked('STAGE_TAG_EXISTS_RECONCILE')
    base_id = base_snapshot(args)
    if gateway_snapshot(args) != desired['gateway']:
        raise Blocked('GATEWAY_CHANGED_DURING_PLAN')
    if args.mode == 'plan':
        return {'intent': desired, 'baseImageId': base_id, 'readOnly': True}
    args.snapshot_root.mkdir(mode=0o700)
    write_exclusive(args.snapshot_root/'build-intent.json', json.dumps(desired, sort_keys=True).encode())
    context = args.snapshot_root/'context'; context.mkdir(mode=0o700)
    acquire_payload(args, context)
    if gateway_snapshot(args) != desired['gateway'] or base_snapshot(args) != base_id:
        raise Blocked('INPUT_CHANGED_BEFORE_BUILD')
    print('SEMANTIC_PROVIDER_ADAPTER_BUILD_STARTED=true', flush=True)
    build = [args.docker_path, 'build', '--pull=false', '--network=none', '--file', str(context/'Dockerfile.semantic-provider'),
             '--tag', args.image_tag]
    for key, value in {'PYTHON_BASE_IMAGE': args.base_image, 'SOURCE_REVISION': args.source_commit,
                       'PAYLOAD_SHA256': desired['payloadHash'], 'RUNTIME_UID': args.runtime_uid, 'RUNTIME_GID': args.runtime_gid}.items():
        build.extend(['--build-arg', key+'='+str(value)])
    build.append(str(context))
    run(build, timeout=600)
    image_id = check_staged_image(args, desired)
    if gateway_snapshot(args) != desired['gateway']:
        raise Blocked('GATEWAY_CHANGED_DURING_BUILD')
    saved = {'intent': desired, 'baseImageId': base_id, 'imageId': image_id,
             'noRuntimeContainersCreated': True, 'noRouteWrites': True, 'noIAMWrites': True,
             'noPolicyPublication': True, 'providerCalls': 0, 'notReleaseAcceptance': True}
    write_exclusive(args.snapshot_root/'stage-receipt.json', json.dumps(saved, sort_keys=True).encode())
    return saved


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--mode', choices=('plan', 'apply', 'verify'), required=True)
    parser.add_argument('--docker-path', default='docker')
    parser.add_argument('--gateway-container', required=True)
    parser.add_argument('--expected-gateway-id', required=True)
    parser.add_argument('--expected-gateway-version', required=True)
    parser.add_argument('--source-url-base', required=True)
    parser.add_argument('--source-commit', required=True)
    parser.add_argument('--base-image', required=True)
    parser.add_argument('--image-tag', required=True)
    parser.add_argument('--runtime-uid', required=True, type=int)
    parser.add_argument('--runtime-gid', required=True, type=int)
    parser.add_argument('--snapshot-root', required=True, type=Path)
    args = parser.parse_args()
    try:
        result = operate(args)
        public = {'mode': args.mode, 'sourceCommit': args.source_commit, 'baseImage': args.base_image,
                  'imageTag': args.image_tag, 'runtimeUser': result['intent']['runtimeUser'],
                  'imageId': result.get('imageId'), 'readOnly': args.mode != 'apply'}
        print('SEMANTIC_PROVIDER_ADAPTER_IMAGE='+json.dumps(public, sort_keys=True))
        print('SEMANTIC_PROVIDER_ADAPTER_STAGE=PASS NO_RUNTIME_CONTAINER_CREATED=true NO_ROUTE_WRITES=true NO_IAM_WRITES=true NO_POLICY_PUBLICATION=true NO_PROVIDER_CALL=true NOT_RELEASE_ACCEPTANCE=true NO_SECRETS_PRINTED=true')
        if args.mode != 'plan':
            print('SEMANTIC_PROVIDER_ADAPTER_STAGE_RECEIPT='+str(args.snapshot_root/'stage-receipt.json')+' PRIVATE=true')
    except Exception as error:
        code = str(error) if isinstance(error, Blocked) else 'UNCLASSIFIED_STAGE_FAILURE'
        print('SEMANTIC_PROVIDER_ADAPTER_STAGE=BLOCKED CODE='+code+' DO_NOT_RERUN_BLINDLY=true NO_SECRETS_PRINTED=true')
        raise SystemExit(1) from None


if __name__ == '__main__': main()
