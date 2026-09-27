#!/usr/bin/env python3
"""Read-only authenticated Gateway acceptance for Semantic HUMAN routing."""
import argparse
import base64
import json
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

ISSUER = 'https://auth.ouf-lab.it/realms/ouf'
API = 'https://api.ouf-lab.it'
CLIENT = 'ouf-human-admin'
SUBJECT = 'b93d8cf6-cd14-4ee6-91d7-84cd76c4f500'
SCOPES = {'ouf.semantic.search', 'ouf.semantic.propose'}


def request(url, method='GET', data=None, token=None):
    headers = {'Accept': 'application/json'}
    if token:
        headers['Authorization'] = 'Bearer ' + token
    if data is not None:
        headers['Content-Type'] = 'application/json'
    req = urllib.request.Request(url, method=method, data=data, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=20) as response:
            return response.status, response.read(1048576)
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read(1048576)


def post_form(url, values):
    req = urllib.request.Request(url, method='POST',
        data=urllib.parse.urlencode(values).encode(),
        headers={'Content-Type': 'application/x-www-form-urlencoded'})
    try:
        with urllib.request.urlopen(req, timeout=20) as response:
            return response.status, json.load(response)
    except urllib.error.HTTPError as exc:
        try:
            return exc.code, json.load(exc)
        except (ValueError, UnicodeError):
            return exc.code, {}


def login():
    status, raw = request(ISSUER + '/.well-known/openid-configuration')
    if status != 200:
        raise ValueError('DISCOVERY_UNAVAILABLE')
    doc = json.loads(raw)
    device = doc.get('device_authorization_endpoint', '')
    endpoint = doc.get('token_endpoint', '')
    if (doc.get('issuer') != ISSUER or not device.startswith(ISSUER + '/protocol/openid-connect/')
            or not endpoint.startswith(ISSUER + '/protocol/openid-connect/')):
        raise ValueError('OIDC_DISCOVERY_MISMATCH')
    status, start = post_form(device, {'client_id': CLIENT,
                                      'scope': 'openid ' + ' '.join(sorted(SCOPES))})
    if status != 200 or not all(start.get(k) for k in
            ('device_code', 'user_code', 'verification_uri', 'expires_in')):
        raise ValueError('DEVICE_AUTHORIZATION_FAILED')
    if not start['verification_uri'].startswith('https://auth.ouf-lab.it/'):
        raise ValueError('DEVICE_VERIFICATION_URI_INVALID')
    print('OPEN_IN_BROWSER=' + start['verification_uri'], flush=True)
    print('ENTER_DEVICE_CODE=' + start['user_code'], flush=True)
    interval = max(5, min(30, int(start.get('interval', 5))))
    until = time.monotonic() + min(600, int(start['expires_in']))
    while time.monotonic() < until:
        time.sleep(interval)
        status, result = post_form(endpoint, {'grant_type': 'urn:ietf:params:oauth:grant-type:device_code',
                                             'client_id': CLIENT, 'device_code': start['device_code']})
        if status == 200:
            token = result.get('access_token')
            break
        if result.get('error') == 'slow_down':
            interval = min(30, interval + 5)
        elif result.get('error') != 'authorization_pending':
            raise ValueError('DEVICE_LOGIN_FAILED')
    else:
        raise ValueError('DEVICE_LOGIN_EXPIRED')
    if not isinstance(token, str) or len(token) > 16384:
        raise ValueError('ACCESS_TOKEN_INVALID')
    part = token.split('.')[1]
    claims = json.loads(base64.urlsafe_b64decode(part + '=' * (-len(part) % 4)))
    aud = claims.get('aud', [])
    if isinstance(aud, str):
        aud = [aud]
    if not (claims.get('iss') == ISSUER and claims.get('azp') == CLIENT
            and claims.get('sub') == SUBJECT and claims.get('preferred_username') == 'ouf-admin'
            and claims.get('ouf_actor_type') in ('HUMAN', 'HUMAN_USER')
            and claims.get('tenant_id') == 'ouf-lab' and 'ouf-api-gateway' in aud
            and SCOPES <= set(str(claims.get('scope', '')).split())
            and isinstance(claims.get('exp'), int) and claims['exp'] > time.time() + 30):
        raise ValueError('HUMAN_TOKEN_SCOPE_OR_IDENTITY_MISMATCH')
    return token


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.parse_args()
    token = login()
    status, payload = request(API + '/api/semantic/v1/search?q=cinema&status=ACTIVE&limit=1', token=token)
    if status != 200 or not isinstance(json.loads(payload), list):
        raise ValueError('SEMANTIC_SEARCH_GATEWAY_HTTP_' + str(status))
    print('SEMANTIC_SEARCH_GATEWAY=PASS HTTP=200')
    # The invalid command has no identifiers and cannot create an artifact.
    status, _ = request(API + '/api/semantic/v1/artifacts', 'POST', b'{}', token)
    if status != 400:
        raise ValueError('SEMANTIC_PROPOSE_INVALID_BODY_HTTP_' + str(status))
    print('SEMANTIC_PROPOSE_OWNER_VALIDATION=PASS HTTP=400')
    print('SEMANTIC_HUMAN_GATEWAY_ACCEPTANCE=PASS NO_SEMANTIC_WRITES=true TOKEN_NOT_PRINTED=true')


if __name__ == '__main__':
    try:
        main()
    except (OSError, ValueError, TypeError, IndexError, KeyError, json.JSONDecodeError) as exc:
        code = str(exc) if isinstance(exc, ValueError) else type(exc).__name__
        print('SEMANTIC_HUMAN_GATEWAY_BLOCKED=' + code, file=sys.stderr)
        raise SystemExit(1)
