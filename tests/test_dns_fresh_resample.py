"""Deterministic TTL expiry and budget regressions; no public DNS/provider calls."""
import importlib.util
from pathlib import Path
import unittest
from unittest.mock import patch

from tools import semantic_provider_dns as dns

class Clock:
    def __init__(self): self.now = 100.0
    def monotonic(self): return self.now
    def sleep(self, seconds): self.now += seconds


def answer(host, kind, ttl, address=None):
    return {'transport': 'UDP', 'responseHash': 'a' * 64, 'authenticatedDataFlag': False,
        'records': [{'owner': host, 'type': kind, 'class': 1, 'ttl': ttl,
            'value': address or ('93.184.216.34' if kind == 1 else '2001:4860:4860::8888'), 'section': 'answer'}]}


class FreshResampleTest(unittest.TestCase):
    def observe(self, query, clock, resolvers=None):
        with patch.object(dns.time, 'monotonic', clock.monotonic), patch.object(dns.time, 'sleep', clock.sleep):
            return dns.observe('https://provider.fixture.example/sparql', resolvers or ['127.0.0.1'],
                53, 4, [], 2, 30, query)

    def test_almost_expired_response_requeries_all_data_and_drops_prior_addresses(self):
        clock = Clock(); calls = []
        def query(resolver, port, host, kind, deadline):
            calls.append((kind, deadline)); clock.now += .01
            first = len(calls) <= 2
            return answer(host, kind, 1 if first else 30,
                '1.1.1.1' if first and kind == 1 else None)
        value = self.observe(query, clock)
        self.assertEqual(value['freshObservationAttempts'], 2)
        self.assertEqual([k for k, _ in calls], [1, 28, 1, 28])
        self.assertEqual({deadline for _, deadline in calls}, {102.0})
        self.assertEqual(value['usableAddresses'], ['93.184.216.34'])
        self.assertNotIn('1.1.1.1', value['allAddresses'])
        self.assertLess(clock.now, 102.0)
        self.assertLessEqual(value['remainingLeaseSecondsAtObservation'], 30)

    def test_persistently_noncacheable_data_stops_after_three_independent_observations(self):
        clock = Clock(); calls = []
        def query(resolver, port, host, kind, deadline):
            calls.append((resolver, kind)); clock.now += .001
            return answer(host, kind, 0)
        with self.assertRaisesRegex(dns.DNSDenied, 'DNS_OBSERVATION_EXPIRED_OR_NONCACHEABLE') as raised:
            self.observe(query, clock, ['127.0.0.1', '127.0.0.2'])
        self.assertEqual(len(calls), 12)
        self.assertEqual(raised.exception.fresh_observation_attempts, 3)
        self.assertTrue(raised.exception.observation_window['ttlNoncacheable'])
        self.assertLess(clock.now, 102.0)

    def test_slow_query_cannot_reset_total_budget_or_install_a_late_answer(self):
        clock = Clock(); calls = []
        def query(resolver, port, host, kind, deadline):
            calls.append(deadline); clock.now += 2.01
            return answer(host, kind, 30)
        with self.assertRaisesRegex(dns.DNSDenied, 'DNS_DEADLINE_EXPIRED'):
            self.observe(query, clock)
        self.assertEqual(calls, [102.0])

    def test_bad_address_and_transport_failure_are_not_retried(self):
        for mode in ('policy', 'transport'):
            clock = Clock(); calls = []
            def query(resolver, port, host, kind, deadline):
                calls.append(kind); clock.now += .001
                if mode == 'transport': raise dns.DNSDenied('DNS_RESOLVER_TRANSPORT_FAILED')
                return answer(host, kind, 30, '10.1.2.3' if kind == 1 else None)
            with self.assertRaises(dns.DNSDenied): self.observe(query, clock)
            self.assertEqual(len(calls), 1 if mode == 'transport' else 2)

    def test_negative_other_family_ttl_remains_a_binding_minimum(self):
        clock = Clock()
        def query(resolver, port, host, kind, deadline):
            clock.now += .001
            if kind == 1: return answer(host, kind, 30)
            response = answer('fixture.example', 6, 20, 11)
            response['records'][0]['section'] = 'authority'
            return response
        value = self.observe(query, clock)
        self.assertEqual(value['minimumObservedTtlSeconds'], 11)
        self.assertLessEqual(value['remainingLeaseSecondsAtObservation'], 11)
        self.assertEqual(value['freshObservationAttempts'], 1)

    def test_one_second_profile_does_not_wait_beyond_its_original_budget(self):
        clock = Clock(); calls = []
        def query(resolver, port, host, kind, deadline):
            calls.append(deadline); clock.now += .01
            return answer(host, kind, 1)
        with patch.object(dns.time, 'monotonic', clock.monotonic), patch.object(dns.time, 'sleep', clock.sleep):
            with self.assertRaises(dns.DNSDenied):
                dns.observe('https://provider.fixture.example/sparql', ['127.0.0.1'], 53, 4, [], 1, 30, query)
        self.assertEqual(calls, [101.0, 101.0])
        self.assertLess(clock.now, 101.0)


if __name__ == '__main__': unittest.main()
