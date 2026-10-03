"""Fresh DNS lease lifecycle core, with a bounded owned-kernel backend contract.

No snapshot/resolution import, daemon, registration or host installation. The
backend must verify exclusive ownership, apply atomically with the supplied
deadline, and read remaining TTLs from both owned kernel sets. A deployment must
provide that backend, root-owned governed configuration and restart supervision.
"""
import ipaddress
import copy
import time

from tools import semantic_provider_dns as dns
from tools.materialize_southbound_kernel import materialize, fields
from tools.materialize_southbound_lease_refresh import compile_refresh


class LeaseDenied(RuntimeError):
    pass


class LeaseOwner:
    def __init__(self, configuration, profile, backend, *, clock=time.monotonic):
        materialize(configuration)
        if not configuration['providerFlows']: raise ValueError('explicit provider flows required')
        fields(profile, ('resolvers', 'resolverPort', 'timeoutSeconds', 'maxLeaseSeconds', 'applyBudgetSeconds'))
        for key, maximum in (('timeoutSeconds', 30), ('maxLeaseSeconds', 3600), ('applyBudgetSeconds', 30)):
            if type(profile[key]) is not int or not 1 <= profile[key] <= maximum:
                raise ValueError('bounded explicit owner timing required')
        # The DNS module also validates the selected numeric resolver profile.
        self.configuration = copy.deepcopy(configuration)
        self.profile = copy.deepcopy(profile)
        self.backend = backend
        self.clock = clock

    def revoke(self):
        """Never write an unknown table; failed revocation is reported, not PASS."""
        self.backend.verify_ownership(self.configuration)
        plan = compile_refresh(self.configuration, [], self.clock(),
                               apply_budget_seconds=self.profile['applyBudgetSeconds'])
        self.backend.apply(plan['nftTransaction'], plan['mustApplyByMonotonic'])
        sets = self.backend.read_sets(self.configuration)
        expected = {(family, i) for family in ('inet', 'bridge')
                    for i in range(len(self.configuration['providerFlows']))}
        if set(sets) != expected or any(sets.values()): raise LeaseDenied('REVOCATION_READBACK_FAILED')

    def refresh(self):
        """One cycle: query now, subtract all elapsed time, apply once, read back."""
        self.backend.verify_ownership(self.configuration)
        values = []
        try:
            for flow in self.configuration['providerFlows']:
                before = self.clock()
                value = dns.observe(flow['endpoint'], self.profile['resolvers'], self.profile['resolverPort'],
                    ipaddress.ip_address(flow['source']).version,
                    [address+'/'+str(ipaddress.ip_address(address).max_prefixlen)
                     for address in flow['allowedPrivateAddresses']],
                    self.profile['timeoutSeconds'], self.profile['maxLeaseSeconds'])
                # Deliberately use the time BEFORE the DNS call. Its remaining
                # TTL already subtracts query time; double subtraction is safe
                # and never extends the DNS deadline after delays/preemption.
                expires = before + value['remainingLeaseSecondsAtObservation']
                values.append(dict(endpointRef=flow['endpointRef'], endpoint=flow['endpoint'],
                    resolutionEvidenceRef=flow['resolutionEvidenceRef'], addresses=value['usableAddresses'],
                    observedMonotonic=before, expiresMonotonic=expires, historicalEvidenceOnly=False))
            plan = compile_refresh(self.configuration, values, self.clock(),
                                   apply_budget_seconds=self.profile['applyBudgetSeconds'])
            if plan['denyOnly']: raise LeaseDenied('FRESH_RESOLUTION_UNUSABLE')
            self.backend.verify_ownership(self.configuration)
            if self.clock() >= plan['mustApplyByMonotonic']: raise LeaseDenied('APPLY_DEADLINE_MISSED')
            # No retry with the same relative TTL: a subsequent cycle must query
            # again, even after an atomic transaction/transport failure.
            self.backend.apply(plan['nftTransaction'], plan['mustApplyByMonotonic'])
            sets = self.backend.read_sets(self.configuration)
            now = self.clock()
            if now >= plan['mustApplyByMonotonic']: raise LeaseDenied('READBACK_DEADLINE_MISSED')
            self.backend.verify_ownership(self.configuration)
            expected = {(family, i) for family in ('inet', 'bridge') for i in range(len(values))}
            if set(sets) != expected: raise LeaseDenied('KERNEL_SET_BINDING_MISMATCH')
            for (family, index), actual in sets.items():
                if set(actual) != set(values[index]['addresses']): raise LeaseDenied('KERNEL_ADDRESS_MISMATCH')
                for ttl in actual.values():
                    if type(ttl) not in (int, float) or not 0 < ttl <= self.configuration['providerFlows'][index]['leaseSeconds'] \
                            or now+ttl > values[index]['expiresMonotonic']:
                        raise LeaseDenied('KERNEL_EXPIRY_MISMATCH')
            return {'freshDnsQueried': True, 'bothFamiliesReadBack': True,
                    'providerCalls': 0, 'notReleaseAcceptance': True}
        except Exception:
            try: self.revoke()
            except Exception: raise LeaseDenied('REFRESH_FAILED_REVOCATION_UNPROVEN_FINITE_EXPIRY_REQUIRED') from None
            raise LeaseDenied('REFRESH_FAILED_SETS_REVOKED') from None
