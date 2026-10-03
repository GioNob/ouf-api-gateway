"""Compile one atomic owned-set refresh; never read snapshots or execute nft.

Fresh in-process resolution and monotonic timestamps must come from the trusted
owner worker. This pure compiler is not provenance/authentication enforcement.
Historical observations, failed/missing resolutions or any invalid update empty
all provider sets. Infrastructure chains and shared tables are never rewritten.
"""
import copy
import math

from tools.materialize_southbound_kernel import materialize, fields


def compile_refresh(configuration, resolutions, now_monotonic, *, apply_budget_seconds):
    # A malformed ownership/configuration cannot safely identify tables to empty.
    # Reject it; the future worker must let existing finite leases expire.
    baseline = materialize(configuration)
    table = baseline['tableName']; flows = configuration['providerFlows']
    if type(now_monotonic) not in (int, float) or not math.isfinite(now_monotonic) or now_monotonic < 0:
        raise ValueError('finite monotonic clock required')
    if type(apply_budget_seconds) is not int or not 1 <= apply_budget_seconds <= 30:
        raise ValueError('explicit bounded installation budget required')
    clear = [f'flush set {family} {table} provider_{i}' for family in ('inet', 'bridge') for i in range(len(flows))]
    updates = []; reason = None
    try:
        if not isinstance(resolutions, list) or len(resolutions) != len(flows):
            raise ValueError('missing resolution')
        seen = set()
        for index, flow in enumerate(flows):
            value = resolutions[index]
            fields(value, ('endpointRef', 'endpoint', 'resolutionEvidenceRef', 'addresses',
                           'observedMonotonic', 'expiresMonotonic', 'historicalEvidenceOnly'))
            if value['endpointRef'] != flow['endpointRef'] or value['endpoint'] != flow['endpoint'] \
                    or value['resolutionEvidenceRef'] != flow['resolutionEvidenceRef'] \
                    or value['historicalEvidenceOnly'] is not False or flow['endpointRef'] in seen:
                raise ValueError('resolution binding or historical evidence invalid')
            seen.add(flow['endpointRef'])
            start, end = value['observedMonotonic'], value['expiresMonotonic']
            if any(type(t) not in (int, float) or not math.isfinite(t) for t in (start, end)) \
                    or not 0 <= start <= now_monotonic < end or not 0 < end-start <= 3600:
                raise ValueError('expired or invalid resolution clock')
            seconds = min(math.floor(end-now_monotonic-apply_budget_seconds), flow['leaseSeconds'])
            if seconds < 1: raise ValueError('expired resolution')
            candidate = copy.deepcopy(configuration)
            candidate_flow = candidate['providerFlows'][index]
            candidate_flow['addresses'] = value['addresses']; candidate_flow['leaseSeconds'] = seconds
            candidate_flow['allowedPrivateAddresses'] = [p for p in flow['allowedPrivateAddresses'] if p in value['addresses']]
            materialize(candidate)  # exact address/family/private-exception/bounds checks
            for family in ('inet', 'bridge'):
                updates.append(f'add element {family} {table} provider_{index} {{ '+
                    ', '.join(f'{address} timeout {seconds}s' for address in value['addresses'])+' }')
    except (ValueError, TypeError, KeyError):
        reason = 'RESOLUTION_MISSING_STALE_HISTORICAL_OR_INVALID'; updates = []
    return {'schema': 'ouf.southbound-lease-refresh-plan.v1', 'tableName': table,
        'tableFamilies': ['inet', 'bridge'], 'nftTransaction': '\n'.join(clear+updates)+'\n' if clear else '',
        'denyOnly': reason is not None, 'denialReason': reason, 'atomicBatchRequired': True,
        'mustApplyByMonotonic': now_monotonic+apply_budget_seconds,
        'readbackRequired': True, 'installed': False, 'resolutionProvenanceProven': False,
        'notReleaseAcceptance': True}
