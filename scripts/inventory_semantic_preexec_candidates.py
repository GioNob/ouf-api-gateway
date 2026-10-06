"""Read only stopped candidate runtime/network configuration, never live admission."""
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


def require(ok):
    if not ok: raise Blocked('CANDIDATE_BINDING_UNPROVEN')


def decode(raw):
    def pairs(items):
        result = {}
        for key, value in items:
            require(key not in result); result[key] = value
        return result
    return json.loads(raw, object_pairs_hook=pairs)


def digest(raw): return hashlib.sha256(raw).hexdigest()


def ancestors(path):
    require(path.is_absolute() and '..' not in path.parts)
    for parent in (path.parent, *path.parent.parents):
        info = parent.lstat()
        require(stat.S_ISDIR(info.st_mode) and info.st_uid == 0 and not info.st_mode & 0o022)


def private(path):
    ancestors(path)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        before = os.fstat(fd)
        require(stat.S_ISREG(before.st_mode) and before.st_uid == before.st_gid == 0
                and before.st_nlink == 1 and stat.S_IMODE(before.st_mode) == 0o600
                and before.st_size <= 131072)
        raw = os.read(fd, 131073); after = os.fstat(fd)
        stable = ('st_dev', 'st_ino', 'st_mode', 'st_uid', 'st_gid', 'st_nlink', 'st_size', 'st_mtime_ns', 'st_ctime_ns')
        require(len(raw) <= 131072 and all(getattr(before, k) == getattr(after, k) for k in stable))
        return raw
    finally: os.close(fd)


def bounded(argv, deadline, env):
    # Drain only stdout; never collect or disclose Docker stderr/credentials.
    child = subprocess.Popen(argv, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                             stdin=subprocess.DEVNULL, env=env)
    try:
        with selectors.DefaultSelector() as selector:
            selector.register(child.stdout, selectors.EVENT_READ)
            chunks = []; size = 0
            while True:
                remaining = deadline - time.monotonic(); require(remaining > 0)
                require(selector.select(remaining))
                raw = os.read(child.stdout.fileno(), 16384)
                if not raw: break
                size += len(raw); require(size <= 131072); chunks.append(raw)
            require(child.wait(timeout=max(0.001, deadline-time.monotonic())) == 0)
            return b''.join(chunks)
    finally:
        if child.poll() is None: child.kill()
        child.wait(); child.stdout.close()


CONTAINER = ('{"id":{{json .Id}},"name":{{json .Name}},"image":{{json .Image}},'
    '"status":{{json .State.Status}},"running":{{json .State.Running}},'
    '"restarting":{{json .State.Restarting}},"started":{{json .State.StartedAt}},'
    '"pid":{{json .State.Pid}},"runtime":{{json .HostConfig.Runtime}},'
    '"restart":{{json .HostConfig.RestartPolicy.Name}},"mode":{{json .HostConfig.NetworkMode}},'
    '"transaction":{{json (index .Config.Labels "ouf.semantic.candidate.transaction")}},'
    '"manifest":{{json (index .Config.Labels "ouf.semantic.candidate.manifest")}},'
    '"sandbox":{{json .NetworkSettings.SandboxKey}},"networks":{{json .NetworkSettings.Networks}}}')
NETWORK = ('{"id":{{json .Id}},"name":{{json .Name}},"driver":{{json .Driver}},'
    '"ipv6":{{json .EnableIPv6}},"internal":{{json .Internal}},'
    '"bridge":{{json (index .Options "com.docker.network.bridge.name")}},'
    '"owner":{{json (index .Labels "ouf.cold-network.owner")}},'
    '"members":{{json .Containers}}}')


def collect(manifest, journal, cold, query):
    specs = manifest['containers']; ids = journal['candidateIds']
    require(len(specs) == 2 and len(ids) == 2 and len(set(ids.values())) == 2)
    require(set(ids) == {s['name'] for s in specs})
    require(all(re.fullmatch('[0-9a-f]{64}', v) for v in ids.values()))
    require(re.fullmatch('[0-9a-f]{32}', journal['transaction']))
    rows = []; facts = {}
    for spec in specs:
        name = spec['name']; require(re.fullmatch('[A-Za-z0-9][A-Za-z0-9_.-]{0,127}', name))
        row = query('container', ids[name])
        require(row['id'] == ids[name] and row['name'] == '/'+name and row['image'] == spec['image'])
        require(row['status'] == 'created' and row['running'] is False and row['restarting'] is False
                and row['pid'] == 0 and row['started'].startswith('0001-01-01T') and row['restart'] == 'no')
        require(row['transaction'] == journal['transaction'] and row['manifest'] == journal['manifestHash'])
        require(re.fullmatch('[A-Za-z0-9][A-Za-z0-9_.-]{0,127}', row['runtime']))
        planned = {n['name']: n for n in spec['networks']}
        require(1 <= len(planned) <= 32 and len(planned) == len(spec['networks']))
        require(set(row['networks']) == set(planned))
        require(row['mode'] in (spec['networks'][0]['name'], spec['networks'][0]['id']))
        for net_name, net in planned.items():
            require(re.fullmatch('[0-9a-f]{64}', net['id']))
            ipaddress.IPv4Address(net['ipv4'])
            attachment = row['networks'][net_name]
            require(attachment['NetworkID'] in ('', None, net['id'])
                    and (attachment.get('IPAMConfig') or {}).get('IPv4Address') == net['ipv4']
                    and not attachment.get('GlobalIPv6Address') and name in (attachment.get('Aliases') or []))
            if net['id'] not in facts: facts[net['id']] = query('network', net['id'])
            fact = facts[net['id']]
            require(fact['id'] == net['id'] and fact['name'] == net_name
                    and fact['driver'] == 'bridge' and fact['ipv6'] is False)
            if net['id'] in cold['networkIds'].values():
                role = next(k for k, v in cold['networkIds'].items() if v == net['id'])
                require(fact['internal'] is (role == 'internal')
                        and fact['bridge'] == cold['binding'][role+'_bridge']
                        and fact['owner'] == manifest['installation']
                        and not set(fact['members'] or {}) - set(ids.values()))
        rows.append(row)
    return {'candidates': sorted(rows, key=lambda r: r['id']), 'networks': facts}


def inventory(manifest, journal, cold, query):
    first = collect(manifest, journal, cold, query)
    require(first == collect(manifest, journal, cold, query))
    rows = first['candidates']
    return {'schema': 'ouf.semantic-preexec-candidate-inventory.v1',
        'candidateCount': len(rows), 'candidateRuntimes': sorted({r['runtime'] for r in rows}),
        'configuredNetworkCount': len(first['networks']), 'configuredBindingsMatchManifest': True,
        'sandboxKeyPresentCount': sum(bool(r['sandbox']) for r in rows),
        'candidatesNeverStarted': True, 'liveNamespaceBindingProven': False,
        'bindingHash': digest(json.dumps(first, sort_keys=True, separators=(',', ':')).encode()),
        'readOnly': True, 'stableAcrossReads': True, 'atomicSnapshotProven': False,
        'fullCreationAcceptanceProven': False, 'ociHookIntegrationProven': False,
        'runtimeRegistrationAuthorized': False, 'startAuthorized': False,
        'providerCalls': 0, 'notReleaseAcceptance': True, 'noSecretsPrinted': True}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('manifest-root', 'creation-root', 'network-root'): parser.add_argument('--'+name, type=Path, required=True)
    for name in ('expected-manifest-hash', 'expected-creation-journal-hash', 'creation-source-commit', 'docker-path'):
        parser.add_argument('--'+name, required=True)
    args = parser.parse_args()
    try:
        require(os.geteuid() == 0)
        paths = [args.manifest_root/'stopped-manifest.json', args.creation_root/'creation-journal.json', args.network_root/'network-receipt.json']
        raw = [private(p) for p in paths]; manifest, journal, cold = map(decode, raw)
        require(digest(raw[0]) == args.expected_manifest_hash and digest(raw[1]) == args.expected_creation_journal_hash)
        require(manifest['schema'] == 'ouf.semantic-provider-stopped-manifest.v1' and manifest['startAuthorized'] is False)
        require(journal['schema'] == 'ouf.semantic-provider-stopped-create.v1' and journal['state'] == 'CREATED_STOPPED'
                and journal['startAuthorized'] is False and journal['sourceCommit'] == args.creation_source_commit
                and journal['manifestHash'] == digest(raw[0]) and manifest['networkReceiptHash'] == digest(raw[2]))
        docker = Path(args.docker_path); ancestors(docker); info = docker.lstat()
        require(stat.S_ISREG(info.st_mode) and info.st_uid == 0 and not info.st_mode & 0o022 and info.st_mode & 0o111)
        socket = Path('/run/docker.sock'); ancestors(socket); sock = socket.lstat()
        require(stat.S_ISSOCK(sock.st_mode) and sock.st_uid == 0 and not sock.st_mode & 0o002)
        source = Path(__file__).absolute().parent; ancestors(source/'config.json')
        require(not source.stat().st_mode & 0o077 and not os.path.lexists(source/'config.json'))
        deadline = time.monotonic()+30
        def query(kind, identity):
            verb = ['inspect', '--type', 'container'] if kind == 'container' else ['network', 'inspect']
            return decode(bounded([str(docker), '--config', str(source), '--host', 'unix:///run/docker.sock',
                *verb, '--format', CONTAINER if kind == 'container' else NETWORK, identity], deadline,
                {'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LC_ALL': 'C'}))
        result = inventory(manifest, journal, cold, query)
        require(raw == [private(p) for p in paths])
        current = socket.lstat()
        require(tuple(getattr(sock, k) for k in ('st_dev','st_ino','st_mode','st_uid','st_gid','st_nlink'))
                == tuple(getattr(current, k) for k in ('st_dev','st_ino','st_mode','st_uid','st_gid','st_nlink')))
        result.update(manifestHash=digest(raw[0]), creationJournalHash=digest(raw[1]))
        print('SEMANTIC_PREEXEC_CANDIDATE_INVENTORY='+json.dumps(result, sort_keys=True))
        print('SEMANTIC_PREEXEC_CANDIDATE_INVENTORY=PASS READ_ONLY=true START_AUTHORIZED=false NO_RULE_UNIT_CONTAINER_CHANGED=true NO_SECRETS_PRINTED=true')
        return 0
    except (OSError, ValueError, KeyError, TypeError, AttributeError, StopIteration, subprocess.SubprocessError):
        print('SEMANTIC_PREEXEC_CANDIDATE_INVENTORY=BLOCKED READ_ONLY=true START_AUTHORIZED=false NO_SECRETS_PRINTED=true')
        return 1


if __name__ == '__main__': raise SystemExit(main())
