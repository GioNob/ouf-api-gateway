"""Installation fields owned by the internal R2B data-plane routes."""

ROUTE_CLASSES = {
    'r4a-udp-runtime-lake-write': 'r2bLakeWrite',
    'r4a-udp-runtime-handoff-write': 'r2bHandoffWrite',
    'r2b-semantic-reference': 'r2bSemanticGet',
    'r2b-semantic-reference-batch': 'r2bSemanticBatch',
    'r4a-onboarding-runtime-publications-list': 'r2bPublication',
    'r2b-publication-resolution': 'r2bPublication',
}


def limit_count(route_id, settings=None):
    return rate_limit_profile(ROUTE_CLASSES[route_id], settings)


def rate_limit_profile(route_class, settings=None):
    if settings is None:
        prefix = f'gateway.rateLimits.{route_class}.'
        values = {name: {'$installation': prefix + name}
                  for name in ('count', 'timeWindowSeconds', 'key')}
    else:
        values = settings.get(route_class)
        if not isinstance(values, dict):
            raise ValueError(f'missing gateway.rateLimits.{route_class}')
        for name in ('count', 'timeWindowSeconds'):
            if type(values.get(name)) is not int or values[name] < 1:
                raise ValueError(f'invalid gateway.rateLimits.{route_class}.{name}')
        if not isinstance(values.get('key'), str) or not values['key'].strip():
            raise ValueError(f'invalid gateway.rateLimits.{route_class}.key')
    return {'count': values['count'], 'time_window': values['timeWindowSeconds'],
            'key': values['key'], 'rejected_code': 429, 'show_limit_quota_header': True}
