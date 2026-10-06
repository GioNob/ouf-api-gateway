import copy
import unittest

from tools.materialize_southbound_lease_refresh import compile_refresh as compiler
from tests.test_southbound_kernel import configuration


def resolution(config, start=100, end=120):
    return [dict(endpointRef=f['endpointRef'], endpoint=f['endpoint'], resolutionEvidenceRef=f['resolutionEvidenceRef'],
        addresses=f['addresses'], observedMonotonic=start, expiresMonotonic=end, historicalEvidenceOnly=False)
        for f in config['providerFlows']]


def compile_refresh(config, values, now):
    return compiler(config, values, now, apply_budget_seconds=1)


class LeaseRefreshTest(unittest.TestCase):
    def test_one_batch_both_families_no_chain_or_shared_table_write(self):
        cfg = configuration(); cfg['providerFlows'][0]['leaseSeconds'] = 7
        value = compile_refresh(cfg, resolution(cfg), 110.4)
        self.assertFalse(value['denyOnly']); self.assertFalse(value['installed'])
        self.assertTrue(value['atomicBatchRequired']); self.assertFalse(value['resolutionProvenanceProven'])
        lines = value['nftTransaction'].splitlines()
        self.assertEqual(len(lines), 4); self.assertTrue(all(s.startswith('flush set ') for s in lines[:2]))
        self.assertIn('10.90.0.2 timeout 7s', lines[2]); self.assertIn('10.90.0.2 timeout 7s', lines[3])
        self.assertEqual(value['mustApplyByMonotonic'], 111.4)
        self.assertFalse(any(s in value['nftTransaction'] for s in ('delete table', 'add chain', 'flush ruleset', 'add rule')))

    def test_stale_missing_historical_failed_and_future_resolution_empty_sets(self):
        cfg = configuration()
        inputs = [[], resolution(cfg, end=109), resolution(cfg, start=111, end=120)]
        historic = resolution(cfg); historic[0]['historicalEvidenceOnly'] = True; inputs.append(historic)
        for values in inputs:
            value = compile_refresh(cfg, values, 110)
            self.assertTrue(value['denyOnly']); self.assertNotIn('add element', value['nftTransaction'])
            self.assertIn('flush set inet ouf_test provider_0', value['nftTransaction'])
            self.assertIn('flush set bridge ouf_test provider_0', value['nftTransaction'])

    def test_one_invalid_resolution_revokes_all_providers_no_partial_refresh(self):
        cfg = configuration(); other = copy.deepcopy(cfg['providerFlows'][0]); other['endpointRef'] = 'other-provider'
        cfg['providerFlows'].append(other); values = resolution(cfg); values[1]['endpoint'] = 'https://foreign.invalid/'
        value = compile_refresh(cfg, values, 110); self.assertTrue(value['denyOnly'])
        self.assertEqual(len(value['nftTransaction'].splitlines()), 4); self.assertNotIn('add element', value['nftTransaction'])

    def test_unsafe_addresses_privilege_expansion_and_clock_values_rejected(self):
        cfg = configuration()
        for address in ('127.0.0.1', '10.90.0.3', '169.254.169.254', '0.0.0.0/0', 'x;flush ruleset', '::1'):
            values = resolution(cfg); values[0]['addresses'] = [address]
            self.assertTrue(compile_refresh(cfg, values, 110)['denyOnly'])
        for clock in (True, float('nan'), float('inf'), -1):
            with self.assertRaises(ValueError): compile_refresh(cfg, resolution(cfg), clock)
        for clock in (True, float('nan'), float('inf'), -1, 3701):
            values = resolution(cfg); values[0]['expiresMonotonic'] = clock
            self.assertTrue(compile_refresh(cfg, values, 110)['denyOnly'])

    def test_fractional_remaining_time_and_configuration_ownership_fail_closed(self):
        cfg = configuration(); value = compile_refresh(cfg, resolution(cfg, end=110.9), 110)
        self.assertTrue(value['denyOnly'])
        cfg['guardedInterfaces'] = ['existing0']
        with self.assertRaises(ValueError): compile_refresh(cfg, [], 110)


if __name__ == '__main__': unittest.main()
