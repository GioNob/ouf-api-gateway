"""D-090 installation envelope for each independent provider route."""
import re


def provider_quota(inventory, rates):
    """Validate actual limit-count settings; Redis shares replicas, not remote_addr keys."""
    if not isinstance(inventory, dict) or not {'instances', 'egressKeys'} <= inventory.keys() \
            or inventory.keys() - {'instances', 'egressKeys', 'ceiling', 'redisBackend'}:
        raise ValueError('complete provider quota inventory required')
    instances = inventory['instances']
    keys = inventory['egressKeys']
    ceiling = inventory.get('ceiling', 20)
    for n in (instances, keys, ceiling):
        if type(n) is not int or n < 1:
            raise ValueError('positive installation inventory and ceiling required')
    if ceiling > 20 or not isinstance(rates, dict) or set(rates) != {'search', 'fetch'}:
        raise ValueError('D-090 per-route ceiling exceeded or missing route')
    backend = inventory.get('redisBackend')
    if 'redisBackend' in inventory and (not isinstance(backend, dict)
            or set(backend) != {'redis_host', 'redis_port'}
            or not isinstance(backend['redis_host'], str)
            or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9.-]{0,252}', backend['redis_host'])
            or type(backend['redis_port']) is not int or not 1 <= backend['redis_port'] <= 65535):
        raise ValueError('explicit shared Redis backend required')
    plan = {}
    for name in ('search', 'fetch'):
        rate = rates[name]
        fields = {'count', 'time_window', 'key_type', 'key', 'policy', 'rejected_code'}
        if not isinstance(rate, dict):
            raise ValueError('limit-count configuration required')
        shared = rate.get('policy') == 'redis'
        if shared:
            fields.update(('redis_host', 'redis_port', 'group'))
            if not backend or any(rate.get(k) != v for k, v in backend.items()) or type(rate.get('redis_port')) is not int \
                    or not isinstance(rate.get('group'), str) or not rate['group']:
                raise ValueError('shared route counter must match declared backend and group')
        if set(rate) != fields or rate['policy'] not in ('local', 'redis') \
                or rate['key_type'] != 'var' or rate['key'] != 'remote_addr' \
                or type(rate['time_window']) is not int or rate['time_window'] != 60 \
                or type(rate['rejected_code']) is not int or rate['rejected_code'] != 429 \
                or type(rate['count']) is not int or rate['count'] < 1:
            raise ValueError('invalid provider limit-count configuration')
        total = rate['count'] * keys * (1 if shared else instances)
        if total > ceiling:
            raise ValueError(f'{name}: count={rate["count"]}, instances={instances}, egressKeys={keys}, '
                             f'policy={rate["policy"]}, total={total} exceeds {ceiling}/60s')
        plan[name] = dict(instances=instances, egressKeys=keys, count=rate['count'],
                          policy=rate['policy'], total=total, ceiling=ceiling, windowSeconds=60)
    if rates['search'].get('group') and rates['search']['group'] == rates['fetch'].get('group'):
        raise ValueError('distinct shared counter groups required')
    return plan
