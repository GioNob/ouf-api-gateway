"""Owned nft and prepared Linux namespace/bundle bindings for the preexec core.

No runtime registration, namespace creation, bundle modification or process
start. Prepared root-private configuration and authority come from the driver.
"""
import copy
import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess
import tempfile
import time

from tools.semantic_provider_lease_coordination import PrivateJournal, _ancestors
from tools.semantic_provider_lease_nft import structure_hash
from tools.semantic_provider_preexec import PreexecDenied, digest, rules


def footprint(value):
    def clean(item):
        if isinstance(item, list):
            return [clean(v) for v in item if not (isinstance(v, dict) and 'metainfo' in v)]
        if isinstance(item, dict):
            return {k: clean(v) for k, v in item.items() if k not in ('handle', 'packets', 'bytes')}
        return item
    return digest(clean(value))


class NativeBackend:
    def __init__(self, profile, commands, budget):
        if set(commands) != {'nft', 'ip', 'nsenter'} or type(budget) is not int or not 1 <= budget <= 5:
            raise ValueError('explicit bounded native commands required')
        for command in commands.values():
            path = Path(command); _ancestors(path); value = path.lstat()
            if not stat.S_ISREG(value.st_mode) or value.st_uid != 0 or value.st_mode & 0o022 \
                    or not value.st_mode & 0o111:
                raise PreexecDenied('TRUSTED_EXECUTABLE_REQUIRED')
        self.profile = copy.deepcopy(profile); self.seal = digest(profile)
        self.commands = dict(commands); self.command_seal = digest(commands); self.budget = budget
        self.deadline = time.monotonic()+budget
        self.table = profile['policy']['tableName']; self.raw = rules(profile)

    def run(self, name, args, raw=None):
        if digest(self.commands) != self.command_seal or digest(self.profile) != self.seal:
            raise PreexecDenied('NATIVE_CONFIGURATION_DRIFT')
        if raw is not None and len(raw.encode()) > 1_000_000:
            raise PreexecDenied('NATIVE_INPUT_UNBOUNDED')
        # File-backed capture bounds RAM even if a native read is unexpectedly
        # large. Trusted commands have a five-second maximum; stderr is discarded.
        with tempfile.TemporaryFile() as output:
            remaining = self.deadline-time.monotonic()
            if remaining <= 0: raise PreexecDenied('NATIVE_DRIVER_DEADLINE_MISSED')
            result = subprocess.run([self.commands[name], *args], input=raw, text=True,
                stdout=output, stderr=subprocess.DEVNULL, timeout=remaining,
                env={'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LC_ALL': 'C'})
            if result.returncode: raise PreexecDenied('NATIVE_OPERATION_UNPROVEN')
            output.seek(0); value = output.read(2_000_001)
            if len(value) > 2_000_000: raise PreexecDenied('NATIVE_OUTPUT_UNBOUNDED')
            return value.decode('utf-8')

    def tables(self):
        entries = json.loads(self.run('nft', ['-j', '-n', 'list', 'tables']))['nftables']
        present = {v['table']['family'] for v in entries if 'table' in v
            and v['table']['name'] == self.table and v['table']['family'] in ('inet', 'bridge')}
        if not present: return None
        if present != {'inet', 'bridge'}: raise PreexecDenied('PARTIAL_TABLE_PAIR')
        return {f: json.loads(self.run('nft', ['-j', '-n', 'list', 'table', f, self.table]))
                for f in sorted(present)}

    footprint = staticmethod(footprint)
    structure_hash = staticmethod(structure_hash)

    def create(self, raw):
        if raw != self.raw: raise PreexecDenied('SEALED_NATIVE_RULES_REQUIRED')
        self.run('nft', ['-f', '-'], 'create table inet '+self.table+'\ncreate table bridge '+self.table+'\n'+raw)

    def remove(self):
        self.run('nft', ['-f', '-'], 'delete table inet '+self.table+'\ndelete table bridge '+self.table+'\n')

    def generation(self, pid):
        if type(pid) is not int or not 1 < pid < 2147483647: raise PreexecDenied('PID_REQUIRED')
        path = Path('/proc')/str(pid)
        before = (path/'stat').read_text()
        inode = (path/'ns/net').stat().st_ino
        after = (path/'stat').read_text()
        # stat CPU/accounting fields may change while the identity stays stable.
        def ticks(raw): return int(raw.rsplit(')', 1)[1].split()[19])
        if ticks(before) != ticks(after): raise PreexecDenied('PID_GENERATION_CHANGED')
        return {'pid': pid, 'startTicks': ticks(after), 'namespaceInode': inode}

    def generation_alive(self, expected):
        try: current = self.generation(expected['pid'])
        except FileNotFoundError: return False
        # Other errors (including access denied/malformed proc) propagate.
        # Reused PID/start ticks prove the recorded generation is no longer live.
        if current['startTicks'] != expected['startTicks']: return False
        if current['namespaceInode'] != expected['namespaceInode']:
            raise PreexecDenied('LIVE_PROCESS_NAMESPACE_DRIFT')
        return True

    def bindings(self, profile, state):
        if digest(profile) != self.seal: raise PreexecDenied('PROFILE_BACKEND_BINDING_DRIFT')
        bundle = PrivateJournal(Path(profile['bundlePath'])/'config.json').read()
        if digest(bundle) != profile['bundleHash']: raise PreexecDenied('OCI_BUNDLE_DRIFT')
        networks = [v for v in bundle['linux']['namespaces'] if v.get('type') == 'network']
        if networks != [{'type': 'network', 'path': profile['namespacePath']}] \
                or set(bundle.get('hooks', {})) - {'prestart', 'createRuntime'}:
            raise PreexecDenied('PREPARED_NAMESPACE_AND_HOOK_ORDER_REQUIRED')
        namespace = Path(profile['namespacePath']); _ancestors(namespace)
        value = namespace.lstat()
        if not stat.S_ISREG(value.st_mode) or value.st_uid != 0 or value.st_mode & 0o022 \
                or value.st_ino != profile['namespaceInode']:
            raise PreexecDenied('PREPARED_NAMESPACE_DRIFT')
        host = json.loads(self.run('ip', ['-j', 'link', 'show']))
        indexed = {v['ifindex']: v for v in host}
        for attachment, child in zip(profile['policy']['attachments'], profile['namespaceLinks']):
            link = indexed.get(attachment['ifindex'])
            if link is None or link['ifname'] != attachment['interface'] or link.get('master') != attachment['bridge'] \
                    or link.get('link_index') != child['ifindex']:
                raise PreexecDenied('HOST_PORT_BINDING_DRIFT')
            peers = json.loads(self.run('nsenter', ['--net='+str(namespace), self.commands['ip'],
                '-j', 'addr', 'show', 'dev', child['interface']]))
            if len(peers) != 1: raise PreexecDenied('NAMESPACE_PORT_REQUIRED')
            peer = peers[0]
            addresses = [v['local'] for v in peer['addr_info'] if v['family'] == 'inet']
            if peer['ifindex'] != child['ifindex'] or peer.get('link_index') != attachment['ifindex'] \
                    or peer['address'] != attachment['mac'] or addresses != [attachment['ipv4']]:
                raise PreexecDenied('NAMESPACE_PORT_BINDING_DRIFT')
        for flow in profile['policy']['flows']:
            ingress = flow['peerIngress']
            if ingress['kind'] == 'HOST': continue
            peer = indexed.get(ingress['ifindex'])
            if peer is None: raise PreexecDenied('LIVE_PEER_INTERFACE_REQUIRED')
            if ingress['kind'] == 'BRIDGE_PORT':
                protected = next(v for v in profile['policy']['attachments']
                    if v['ipv4'] in (flow['source'], flow['destination']))
                if peer.get('master') != protected['bridge']:
                    raise PreexecDenied('LIVE_PEER_BRIDGE_DRIFT')
        if state is None: return None
        generation = self.generation(state['pid'])
        if generation['namespaceInode'] != profile['namespaceInode']:
            raise PreexecDenied('OCI_PROCESS_NAMESPACE_DRIFT')
        return generation

    def runtime(self, binding, operation):
        if set(binding) != {'path', 'sha256', 'root'} or operation not in ('state', 'start'):
            raise PreexecDenied('SEALED_RUNTIME_BINDING_REQUIRED')
        runtime = Path(binding['path']); _ancestors(runtime); before = runtime.lstat()
        if not stat.S_ISREG(before.st_mode) or before.st_uid != 0 or before.st_mode & 0o022 or not before.st_mode & 0o111:
            raise PreexecDenied('TRUSTED_RUNTIME_REQUIRED')
        fd = os.open(runtime, os.O_RDONLY | os.O_NOFOLLOW)
        try:
            value = hashlib.sha256(); size = 0
            while True:
                raw = os.read(fd, 65536)
                if not raw: break
                size += len(raw)
                if size > 64000000: raise PreexecDenied('RUNTIME_SIZE_UNBOUNDED')
                value.update(raw)
            info = os.fstat(fd)
            if value.hexdigest() != binding['sha256'] or any(getattr(before, k) != getattr(info, k)
                    for k in ('st_dev', 'st_ino', 'st_mode', 'st_uid', 'st_size', 'st_mtime_ns', 'st_ctime_ns')):
                raise PreexecDenied('RUNTIME_BINARY_DRIFT')
        finally: os.close(fd)
        root = Path(binding['root']); _ancestors(root/'state')
        # The runtime state root must already exist; this gate creates none.
        with tempfile.TemporaryFile() as output:
            remaining = self.deadline-time.monotonic()
            if remaining <= 0: raise PreexecDenied('NATIVE_DRIVER_DEADLINE_MISSED')
            result = subprocess.run([str(runtime), '--root', str(root), operation, self.profile['containerId']],
                stdin=subprocess.DEVNULL, stdout=output, stderr=subprocess.DEVNULL, timeout=remaining,
                env={'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LC_ALL': 'C'})
            if result.returncode: raise PreexecDenied('RUNTIME_OPERATION_UNPROVEN')
            output.seek(0); raw = output.read(16385)
            if len(raw) > 16384: raise PreexecDenied('RUNTIME_STATE_UNBOUNDED')
        if operation == 'start': return None
        def unique(pairs):
            value = {}
            for key, item in pairs:
                if key in value: raise PreexecDenied('DUPLICATE_RUNTIME_STATE_KEY')
                value[key] = item
            return value
        return json.loads(raw, object_pairs_hook=unique)
