"""Readiness must reject custody drift without promoting startup authority."""
import copy
import hashlib
import io
import json
import os
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from scripts import inventory_semantic_runtime_readiness as inventory
from scripts import restore_semantic_runtime_boot_guard as g


class ReadinessTest(unittest.TestCase):
    def setUp(self):
        self.args = SimpleNamespace(stage_root=Path('/sealed/prepared'),
                                    stage_source_commit='a'*40, installer_sha256='b'*64)
        self.kernel = {'staticFlows': [{'purpose': 'DNS'}, {'purpose': 'GATEWAY_ADAPTER'}],
            'providerFlows': [{}], 'guardedInterfaces': ['inside', 'outside'],
            'existingInterfaces': ['shared']}
        self.tables = {f: {'nftables': [{'table': {'family': f, 'name': 'owned', 'handle': 1}},
            {'set': {'family': f, 'table': 'owned', 'name': 'provider_0', 'handle': 2}}]}
            for f in ('inet', 'bridge')}
        self.conf = {'journalFile': '/sealed/prepared/transition-journal.json',
            'transactionId': 'transaction', 'expectedFootprint': g.footprint(self.tables),
            'lockFile': '/run/owned/guard.lock', 'kernel': self.kernel}
        self.receipt = {'configurationHash': 'configuration'}
        self.journal = {'schema': 'ouf.semantic-runtime-transition.v1', 'state': 'RUNTIME_EMPTY',
            'transactionId': 'transaction', 'configurationHash': 'configuration',
            'stageReceiptHash': g.digest(b'receipt'), 'startAuthorized': False,
            'leaseStructureHash': g.digest(g.encoded(g.stable(self.tables, True)))}
        self.events = []
        self.fd = os.open('/dev/null', os.O_RDONLY)
        self.addCleanup(lambda: os.close(self.fd))
        def read(path):
            if path.name == 'transition-journal.json': return copy.deepcopy(self.journal)
            if path.name == 'stopped-manifest.json': return {'containers': [{}, {}]}
            raise AssertionError('unexpected read')
        def private(path):
            return {'runtime-stage-receipt.json': b'receipt', 'transition-journal.json': g.encoded(self.journal),
                    'unit': b'unit', 'drop': b'drop'}[path.name]
        self.guard = SimpleNamespace(read=read, private=private, digest=g.digest, encoded=g.encoded,
            stable=g.stable, footprint=g.footprint, sets_empty=g.sets_empty,
            tables=lambda conf: copy.deepcopy(self.tables), lock=lambda path: os.dup(self.fd))
        self.prepared = (self.guard, self.receipt, {'guard.service': b'unit', 'docker-drop-in.conf': b'drop'},
            self.conf, {}, {'manifest_root': Path('/manifest')}, {}, 'guard', Path('/unit'), Path('/drop'), {})
        self.installation = SimpleNamespace(stage=lambda args: self.prepared,
            independent=lambda *a: self.events.append('independent'),
            loaded=lambda *a: self.events.append('loaded'))
        self.root = patch.object(inventory.os, 'geteuid', return_value=0)
        self.root.start(); self.addCleanup(self.root.stop)

    def test_pass_is_read_only_custody_and_never_authorizes_startup(self):
        result = inventory.collect(self.args, self.installation)
        self.assertTrue(result['stableAcrossReads']); self.assertTrue(result['readOnly'])
        self.assertFalse(result['startupReady']); self.assertFalse(result['startAuthorized'])
        self.assertFalse(result['activeLeaseLifecycleReady']); self.assertFalse(result['atomicSnapshotProven'])
        self.assertEqual(result['staticPurposes'], ['DNS', 'GATEWAY_ADAPTER'])
        self.assertEqual(self.events, ['independent', 'loaded', 'independent', 'loaded'])

    def test_incomplete_foreign_journal_and_changed_handles_block(self):
        for key, value in [('state', 'PREPARING'), ('startAuthorized', True), ('transactionId', 'foreign'),
                           ('stageReceiptHash', 'foreign'), ('configurationHash', 'foreign')]:
            old = self.journal[key]; self.journal[key] = value
            with self.assertRaises(ValueError): inventory.collect(self.args, self.installation)
            self.journal[key] = old
        self.tables['inet']['nftables'][0]['table']['handle'] = 9
        with self.assertRaises(ValueError): inventory.collect(self.args, self.installation)

    def test_active_lease_blocks_without_flush_and_second_read_drift_blocks(self):
        self.tables['bridge']['nftables'][1]['set']['elem'] = ['198.51.100.8']
        with self.assertRaises(ValueError): inventory.collect(self.args, self.installation)
        del self.tables['bridge']['nftables'][1]['set']['elem']
        def changed(*args):
            self.events.append('loaded')
            if len(self.events) == 4: self.journal['unexpected'] = 'changed'
        self.installation.loaded = changed; self.events.clear()
        with self.assertRaises(ValueError): inventory.collect(self.args, self.installation)

    def test_cli_error_is_redacted_and_has_no_partial_json_success(self):
        with patch.object(inventory, 'installer', side_effect=ValueError('PRIVATE_SECRET')), \
                patch('sys.stdout', new_callable=io.StringIO) as output:
            status = inventory.main(['--stage-root', '/sealed/prepared', '--stage-source-commit', 'a'*40,
                                     '--installer-sha256', 'b'*64])
        self.assertEqual(status, 1); self.assertNotIn('PRIVATE_SECRET', output.getvalue())
        self.assertNotIn('SEMANTIC_RUNTIME_READINESS=', output.getvalue())


@unittest.skipUnless(os.geteuid() == 0, 'private root source loader')
class SourceBindingTest(unittest.TestCase):
    def test_hash_mode_symlink_and_hardlink_are_checked_before_execution(self):
        with tempfile.TemporaryDirectory(dir=os.environ.get('OUF_RUNTIME_TRANSITION_TEST_PARENT', str(Path.cwd()))) as tmp:
            root = Path(tmp).resolve(); root.chmod(0o700)
            scripts = root/'source/scripts'; scripts.mkdir(parents=True, mode=0o700)
            source = scripts/'transition_semantic_runtime_guard.py'
            raw = b'VALUE = 17\n'; source.write_bytes(raw); source.chmod(0o600)
            args = SimpleNamespace(stage_root=root/'prepared', installer_sha256=hashlib.sha256(raw).hexdigest())
            self.assertEqual(inventory.installer(args).VALUE, 17)
            source.chmod(0o644)
            with self.assertRaises(ValueError): inventory.installer(args)
            source.chmod(0o600); args.installer_sha256 = '0'*64
            with self.assertRaises(ValueError): inventory.installer(args)
            args.installer_sha256 = hashlib.sha256(raw).hexdigest()
            os.link(source, scripts/'alias')
            with self.assertRaises(ValueError): inventory.installer(args)
            (scripts/'alias').unlink(); source.unlink(); source.symlink_to(scripts/'missing')
            with self.assertRaises(OSError): inventory.installer(args)
