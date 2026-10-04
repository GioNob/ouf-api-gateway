"""Read-only target dossier and inert authority plan; no signing, key reads or activation."""
import argparse
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import selectors
import stat
import subprocess
import time


class Blocked(ValueError):
    pass


def require(ok, reason='TARGET_ACCEPTANCE_INVENTORY_UNPROVEN'):
    if not ok:
        raise Blocked(reason)


def encoded(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True).encode()


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def decode(raw):
    def pairs(items):
        out = {}
        for k, v in items:
            require(k not in out)
            out[k] = v
        return out
    require(type(raw) is bytes and 0 < len(raw) <= 131072)
    return json.loads(raw, object_pairs_hook=pairs,
        parse_constant=lambda _: (_ for _ in ()).throw(Blocked()))


def attributes(info):
    return tuple(getattr(info, k) for k in ('st_dev', 'st_ino', 'st_mode', 'st_uid', 'st_gid',
        'st_nlink', 'st_size', 'st_mtime_ns', 'st_ctime_ns'))


def ancestors(path):
    require(path.is_absolute() and '..' not in path.parts)
    for parent in (path.parent, *path.parent.parents):
        info = parent.lstat()
        require(stat.S_ISDIR(info.st_mode) and info.st_uid == 0 and not info.st_mode & 0o022, 'TRUSTED_ANCESTOR_REQUIRED')


def private(path):
    ancestors(path)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        before = os.fstat(fd)
        require(stat.S_ISREG(before.st_mode) and before.st_uid == before.st_gid == 0
            and stat.S_IMODE(before.st_mode) == 0o600 and before.st_nlink == 1 and before.st_size <= 131072, 'PRIVATE_INPUT_METADATA_REQUIRED')
        raw = os.read(fd, 131073)
        require(len(raw) == before.st_size and attributes(before) == attributes(os.fstat(fd)))
        return raw
    finally:
        os.close(fd)


def bounded(argv, deadline):
    require(time.monotonic() < deadline, 'LOCAL_COMMAND_DEADLINE')
    child = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL, env={'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LC_ALL': 'C'})
    try:
        with selectors.DefaultSelector() as selector:
            selector.register(child.stdout, selectors.EVENT_READ)
            chunks = []; size = 0
            while True:
                remaining = deadline-time.monotonic()
                require(remaining > 0 and selector.select(remaining), 'LOCAL_COMMAND_DEADLINE')
                raw = os.read(child.stdout.fileno(), 16384)
                if not raw:
                    break
                size += len(raw); require(size <= 131072, 'LOCAL_COMMAND_OUTPUT_LIMIT'); chunks.append(raw)
            require(child.wait(timeout=max(0.001, deadline-time.monotonic())) == 0, 'LOCAL_COMMAND_EXIT_NONZERO')
            return b''.join(chunks)
    finally:
        if child.poll() is None:
            child.kill()
        child.wait(); child.stdout.close()


CONTAINER = ('{"id":{{json .Id}},"name":{{json .Name}},"image":{{json .Image}},'
    '"status":{{json .State.Status}},"running":{{json .State.Running}},"pid":{{json .State.Pid}},'
    '"restarting":{{json .State.Restarting}},"started":{{json .State.StartedAt}},'
    '"runtime":{{json .HostConfig.Runtime}},"restart":{{json .HostConfig.RestartPolicy.Name}},'
    '"transaction":{{json (index .Config.Labels "ouf.semantic.candidate.transaction")}},'
    '"manifest":{{json (index .Config.Labels "ouf.semantic.candidate.manifest")}},'
    '"user":{{json .Config.User}},"entrypoint":{{json .Config.Entrypoint}},"command":{{json .Config.Cmd}},'
    '"workdir":{{json .Config.WorkingDir}},"health":{{json .Config.Healthcheck.Test}},'
    '"privileged":{{json .HostConfig.Privileged}},"readOnly":{{json .HostConfig.ReadonlyRootfs}},'
    '"memory":{{json .HostConfig.Memory}},"swap":{{json .HostConfig.MemorySwap}},'
    '"pids":{{json .HostConfig.PidsLimit}},"capDrop":{{json .HostConfig.CapDrop}},'
    '"capAdd":{{json .HostConfig.CapAdd}},"devices":{{json .HostConfig.Devices}},'
    '"deviceRequests":{{json .HostConfig.DeviceRequests}},"ports":{{json .HostConfig.PortBindings}},'
    '"dns":{{json .HostConfig.Dns}},"mode":{{json .HostConfig.NetworkMode}},'
    '"mounts":{{json .Mounts}},"networks":{{json .NetworkSettings.Networks}}}')
# Docker 29 omits empty optional image Config keys. index is safe on the
# CLI's raw-map fallback; identity/RootFS/Config remain required, never defaulted.
IMAGE = ('{"id":{{json .Id}},"rootfs":{{json .RootFS}},"user":{{json (or (index .Config "User") "")}},'
    '"entrypoint":{{json (index .Config "Entrypoint")}},"command":{{json (index .Config "Cmd")}},'
    '"workdir":{{json (or (index .Config "WorkingDir") "")}},"volumes":{{json (index .Config "Volumes")}}')

NETWORK = '{"id":{{json .Id}},"name":{{json .Name}},"driver":{{json .Driver}},"ipv6":{{json .EnableIPv6}}}'


def mount_metadata(path):
    # Metadata only, never open mount contents (including keys/env files).
    ancestors(path)
    info = path.lstat()
    require((stat.S_ISREG(info.st_mode) or stat.S_ISDIR(info.st_mode)) and not info.st_mode & 0o022, 'MOUNT_SOURCE_TYPE_OR_PERMISSIONS')
    return {'kind': 'directory' if stat.S_ISDIR(info.st_mode) else 'file',
        'attributes': list(attributes(info)), 'contentsRead': False, 'contentsAccepted': False}


def collect(manifest, journal, query, metadata=mount_metadata):
    require(type(manifest['containers']) is list and len(manifest['containers']) == 2)
    require(re.fullmatch('[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}', manifest['installation']))
    ids = journal['candidateIds']
    require(type(ids) is dict and len(ids) == 2 and len(set(ids.values())) == 2
        and all(type(v) is str and re.fullmatch('[0-9a-f]{64}', v) for v in ids.values())
        and set(ids) == {s['name'] for s in manifest['containers']})
    require(re.fullmatch('[0-9a-f]{32}', journal['transaction']))
    rows = []
    for spec in manifest['containers']:
        name = spec['name']; row = query('container', ids[name]); image = query('image', spec['image'])
        require(re.fullmatch('sha256:[0-9a-f]{64}', spec['image']) and image['id'] == spec['image']
            and row['image'] == spec['image'] and row['id'] == ids[name] and row['name'] == '/'+name, 'CANDIDATE_IMAGE_ID_DRIFT')
        require(row['status'] == 'created' and row['running'] is False and row['restarting'] is False
            and row['pid'] == 0 and row['started'].startswith('0001-01-01T') and row['restart'] == 'no'
            and row['transaction'] == journal['transaction'] and row['manifest'] == journal['manifestHash'], 'NEVER_STARTED_OWNERSHIP_REQUIRED')
        require(re.fullmatch('[A-Za-z0-9][A-Za-z0-9_.-]{0,127}', row['runtime']), 'EXPLICIT_RUNTIME_NAME_REQUIRED')
        require(row['user'] == spec['user'] and row['entrypoint'] == image['entrypoint']
            and row['command'] == (spec['command'] or image['command']) and row['workdir'] == image['workdir']
            and not image['volumes'] and row['health'] == ['NONE'], 'SELECTED_STARTUP_DRIFT')
        require(row['privileged'] is False and row['readOnly'] is spec['readOnlyRoot']
            and row['memory'] == spec['memoryBytes'] and row['swap'] == spec['memoryBytes']
            and row['pids'] == spec['pidsLimit'] and set(row['capDrop'] or []) == {'ALL'}
            and not any(row[k] for k in ('capAdd', 'devices', 'deviceRequests', 'ports'))
            and row['dns'] == spec['dnsServers'], 'SELECTED_HOST_RESTRICTIONS_DRIFT')
        rootfs = image['rootfs']
        require(type(rootfs) is dict and rootfs['Type'] == 'layers' and type(rootfs['Layers']) is list
            and 1 <= len(rootfs['Layers']) <= 256
            and all(type(x) is str and re.fullmatch('sha256:[0-9a-f]{64}', x) for x in rootfs['Layers']), 'IMAGE_LAYER_DESCRIPTOR_UNPROVEN')
        mounts = spec['mounts']; require(type(mounts) is list and 1 <= len(mounts) <= 32)
        expected = {(m['source'], m['target']) for m in mounts}
        actual = {(m['Source'], m['Destination']) for m in row['mounts']}
        require(len(expected) == len(mounts) == len(row['mounts']) and actual == expected
            and all(m['readOnly'] is True for m in mounts)
            and all(m['Type'] == 'bind' and m['RW'] is False and m['Propagation'] == 'rprivate' for m in row['mounts']), 'CONFIGURED_MOUNTS_DRIFT')
        observed_mounts = [{'source': m['source'], 'target': m['target'],
            'readOnly': True, 'metadata': metadata(Path(m['source']))} for m in mounts]
        nets = spec['networks']; require(type(nets) is list and 1 <= len(nets) <= 32)
        require(len({n['name'] for n in nets}) == len(nets) and set(row['networks']) == {n['name'] for n in nets}
            and row['mode'] in (nets[0]['id'], nets[0]['name']))
        for net in nets:
            require(re.fullmatch('[0-9a-f]{64}', net['id']))
            ipaddress.IPv4Address(net['ipv4']); attachment = row['networks'][net['name']]
            fact = query('network', net['id'])
            require(fact['id'] == net['id'] and fact['name'] == net['name'] and fact['driver'] == 'bridge'
                and fact['ipv6'] is False and attachment['NetworkID'] in ('', None, net['id'])
                and (attachment.get('IPAMConfig') or {}).get('IPv4Address') == net['ipv4']
                and not attachment.get('GlobalIPv6Address') and name in (attachment.get('Aliases') or []), 'CONFIGURED_NETWORK_BINDING_DRIFT')
        # Selected inspect is evidence, never the full OCI/application acceptance hash.
        rows.append({'containerId': row['id'], 'name': name, 'image': image, 'selectedConfiguration': row,
            'mountMetadata': observed_mounts, 'environmentRead': False, 'fullCreationAcceptanceProven': False})
    return {'installationRef': manifest['installation'], 'candidates': sorted(rows, key=lambda r: r['containerId'])}


def inventory(manifest, journal, query, metadata=mount_metadata):
    first = collect(manifest, journal, query, metadata)
    require(first == collect(manifest, journal, query, metadata), 'TARGET_CHANGED_BETWEEN_READS')
    return first


def package(root, commit, manifest_hash):
    for directory in (root, root/'source', root/'source/scripts', root/'source/tools'):
        ancestors(directory/'placeholder'); info = directory.lstat()
        require(stat.S_IMODE(info.st_mode) == 0o700 and info.st_uid == info.st_gid == 0)
    raw = private(root/'sources.sha256'); require(digest(raw) == manifest_hash)
    sources = {}
    for line in raw.decode('ascii').splitlines():
        match = re.fullmatch('([0-9a-f]{64})  ((?:scripts|tools)/[A-Za-z0-9_]+[.]py)', line)
        require(match is not None)
        h, name = match.groups(); require(name not in sources); sources[name] = h
    require(len(sources) == 26)
    receipt_raw = private(root/'source-package-receipt.json'); receipt = decode(receipt_raw)
    require(receipt['schema'] == 'ouf.semantic-local-producers-source-package.v8'
        and receipt['sourceCommit'] == commit and receipt['sourceManifestHash'] == manifest_hash
        and receipt['sourceHashes'] == sources and receipt['sourceCount'] == 26
        and receipt['sourceCustodyVerified'] is True)
    require(all(receipt[k] == 0 for k in ('keysGenerated', 'privateKeysRead', 'signaturesIssued', 'providerCalls', 'sourceBodiesExecuted'))
        and all(receipt[k] is False for k in ('runtimeRegistered', 'startAuthorized', 'rulesChanged', 'unitsChanged', 'containersChanged')))
    for name, h in sources.items():
        require(digest(private(root/'source'/name)) == h)
    return {'manifest': raw, 'receipt': receipt_raw, 'sources': sources}


def authority_plan(installation):
    # Deliberately different from runnable trust policy/configuration schemas.
    return {'schema': 'ouf.semantic-deployment-authority-provisioning-plan.v1', 'installationRef': installation,
        'entityRef': None, 'state': 'DRAFT_NOT_AUTHORIZED', 'policySchema': 'ouf.semantic-deployment-trust-policy.v1',
        'roles': [{'role': role, 'issuerRef': None, 'keyRef': None, 'publicKey': None, 'authorized': False}
            for role in ('DEPLOYMENT_INTENT', 'CREATION_ATTESTATION', 'FINAL_DEPLOYMENT_APPROVAL')],
        'nodeAttestorLocalToRuntime': True, 'centralAuthorityRequired': False,
        'applicationIamIsInfrastructureAuthority': False, 'trustPolicyProvisioned': False,
        'mandatesIssued': 0, 'startAuthorized': False,
        'requiredDecisions': ['ENTITY_AND_AUTHORITY_IDENTITIES', 'KEY_PROVISIONING_AND_VALIDITY',
            'IMAGE_PROVENANCE_AND_FULL_OCI_ACCEPTANCE', 'EXTERNAL_MOUNT_CONTENTS_AND_MUTABILITY']}


def publish(root, name, raw):
    path = root/name
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, 'wb', closefd=False) as stream:
            stream.write(raw); stream.flush(); os.fsync(stream.fileno())
    finally:
        os.close(fd)
    fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)
    require(private(path) == raw)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('manifest-root', 'creation-root', 'package-root', 'snapshot-root', 'docker-path'):
        parser.add_argument('--'+name, required=True, type=Path)
    for name in ('expected-manifest-hash', 'expected-creation-journal-hash', 'creation-source-commit',
                 'package-source-commit', 'source-manifest-sha256'):
        parser.add_argument('--'+name, required=True)
    parser.add_argument('--diagnose', action='store_true', help='Read-only diagnostic; no evidence publication or authority')
    args = parser.parse_args()
    phase = 'ARGUMENTS'
    try:
        require(os.geteuid() == 0)
        for k in ('expected_manifest_hash', 'expected_creation_journal_hash', 'source_manifest_sha256'):
            require(re.fullmatch('[0-9a-f]{64}', getattr(args, k)))
        for k in ('creation_source_commit', 'package_source_commit'):
            require(re.fullmatch('[0-9a-f]{40}', getattr(args, k)))
        phase = 'PRIVATE_SNAPSHOT'
        root = args.snapshot_root; ancestors(root/'placeholder'); st = root.lstat()
        require(st.st_uid == st.st_gid == 0 and stat.S_IMODE(st.st_mode) == 0o700)
        if not args.diagnose:
            require(not any(os.path.lexists(root/n) for n in ('target-dossier.json', 'authority-plan.json', 'inventory-receipt.json')), 'EVIDENCE_EXISTS_NO_REPLAY')
        phase = 'PINNED_CANDIDATE_INPUTS'
        paths = [args.manifest_root/'stopped-manifest.json', args.creation_root/'creation-journal.json']
        raw = [private(p) for p in paths]; manifest, journal = map(decode, raw)
        require(digest(raw[0]) == args.expected_manifest_hash and digest(raw[1]) == args.expected_creation_journal_hash
            and manifest['schema'] == 'ouf.semantic-provider-stopped-manifest.v1' and manifest['startAuthorized'] is False
            and journal['schema'] == 'ouf.semantic-provider-stopped-create.v1' and journal['state'] == 'CREATED_STOPPED'
            and journal['manifestHash'] == digest(raw[0]) and journal['sourceCommit'] == args.creation_source_commit
            and journal['startAuthorized'] is False)
        phase = 'SOURCE_PACKAGE_CUSTODY'
        sealed = package(args.package_root, args.package_source_commit, args.source_manifest_sha256)
        phase = 'LOCAL_DOCKER_ENDPOINT'
        docker = args.docker_path; ancestors(docker); binary = docker.lstat()
        require(stat.S_ISREG(binary.st_mode) and binary.st_uid == 0 and binary.st_mode & 0o111 and not binary.st_mode & 0o022)
        socket = Path('/run/docker.sock'); ancestors(socket); sock = socket.lstat()
        require(stat.S_ISSOCK(sock.st_mode) and sock.st_uid == 0 and not sock.st_mode & 0o002)
        require(not os.path.lexists(root/'config.json'))
        deadline = time.monotonic()+30
        def query(kind, identity):
            nonlocal phase
            phase = {'container': 'CONTAINER_INSPECT', 'image': 'IMAGE_INSPECT', 'network': 'NETWORK_INSPECT'}[kind]
            verb, template = {'container': (['inspect', '--type', 'container'], CONTAINER),
                'image': (['image', 'inspect'], IMAGE), 'network': (['network', 'inspect'], NETWORK)}[kind]
            return decode(bounded([str(docker), '--config', str(root), '--host', 'unix:///run/docker.sock',
                *verb, '--format', template, identity], deadline))
        def observe_mount(path):
            nonlocal phase
            phase = 'MOUNT_SOURCE_METADATA'
            return mount_metadata(path)
        dossier = inventory(manifest, journal, query, observe_mount)
        phase = 'READBACK_STABILITY'
        require(raw == [private(p) for p in paths] and sealed == package(args.package_root, args.package_source_commit, args.source_manifest_sha256))
        require(attributes(sock) == attributes(socket.lstat()) and attributes(binary) == attributes(docker.lstat()))
        phase = 'EVIDENCE_BOUNDS'
        plan = authority_plan(dossier['installationRef']); dossier_raw = encoded(dossier); plan_raw = encoded(plan)
        require(len(dossier_raw) <= 131072 and len(plan_raw) <= 131072 and time.monotonic() < deadline)
        result = {'schema': 'ouf.semantic-target-acceptance-inventory.v1', 'candidateCount': 2,
            'mountCount': sum(len(x['mountMetadata']) for x in dossier['candidates']),
            'dossierHash': digest(dossier_raw), 'authorityPlanHash': digest(plan_raw),
            'sourcePackageReceiptHash': digest(sealed['receipt']), 'sourceCustodyVerified': True,
            'candidatesNeverStarted': True, 'stableAcrossReads': True, 'atomicSnapshotProven': False,
            'readOnlyTarget': True, 'privateEvidenceOnly': True, 'fullCreationAcceptanceProven': False,
            'mountContentsRead': False, 'environmentRead': False, 'deploymentAuthorityProven': False,
            'runtimeRegistrationAuthorized': False, 'startAuthorized': False, 'keysGenerated': 0,
            'privateKeysRead': 0, 'signaturesIssued': 0, 'providerCalls': 0, 'dnsCalls': 0, 'iamCalls': 0,
            'rulesChanged': False, 'unitsChanged': False, 'containersChanged': False,
            'notReleaseAcceptance': True, 'noSecretsPrinted': True}
        if args.diagnose:
            result.update(schema='ouf.semantic-target-acceptance-diagnostic.v1', diagnosticOnly=True, privateEvidenceOnly=False, evidencePublished=False)
            print('SEMANTIC_TARGET_ACCEPTANCE_DIAGNOSTIC='+json.dumps(result, sort_keys=True))
            print('SEMANTIC_TARGET_ACCEPTANCE_DIAGNOSTIC=PASS READ_ONLY_TARGET=true EVIDENCE_PUBLISHED=false START_AUTHORIZED=false NO_SECRETS_PRINTED=true')
            return 0
        phase = 'PRIVATE_EVIDENCE_PUBLICATION'
        publish(root, 'target-dossier.json', dossier_raw); publish(root, 'authority-plan.json', plan_raw)
        # Last receipt is the only completed-publication marker. No partial overwrite/replay.
        publish(root, 'inventory-receipt.json', encoded(result))
        print('SEMANTIC_TARGET_ACCEPTANCE_INVENTORY='+json.dumps(result, sort_keys=True))
        print('SEMANTIC_TARGET_ACCEPTANCE_INVENTORY=PASS READ_ONLY_TARGET=true PRIVATE_EVIDENCE_ONLY=true'
            ' AUTHORITY_PROVEN=false START_AUTHORIZED=false NO_SECRETS_PRINTED=true')
        return 0
    except (OSError, ValueError, KeyError, TypeError, AttributeError, RecursionError, subprocess.SubprocessError) as error:
        # Never serialize arbitrary exception text, paths, Docker output or field values.
        reason = str(error) if isinstance(error, Blocked) else type(error).__name__.upper()
        if not re.fullmatch('[A-Z_]{1,80}', reason):
            reason = 'TARGET_ACCEPTANCE_INVENTORY_UNPROVEN'
        marker = 'SEMANTIC_TARGET_ACCEPTANCE_DIAGNOSTIC' if args.diagnose else 'SEMANTIC_TARGET_ACCEPTANCE_INVENTORY'
        print(marker+'=BLOCKED CHECK='+phase+' REASON='+reason+' START_AUTHORIZED=false NO_SECRETS_PRINTED=true')
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
