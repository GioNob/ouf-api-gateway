#!/usr/bin/env python3
"""Privately observe selected DNS resolvers; no provider HTTP or admission."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import time

from scripts import prepare_semantic_provider_trust as trust
from tools import semantic_provider_dns as dns


def private_json(path):
    trust.ancestors(path.parent)
    raw = trust.read_file(path, 0, 0, limit=131072)
    def unique(pairs):
        value = {}
        for key, item in pairs:
            if key in value: raise trust.Blocked('DUPLICATE_INPUT_KEY')
            value[key] = item
        return value
    return json.loads(raw, object_pairs_hook=unique), raw


def digest(raw): return hashlib.sha256(raw).hexdigest()


def binding(args):
    value, raw = private_json(args.runtime_stage_root/'binding.json')
    stage, stage_raw = private_json(args.runtime_stage_root/'stage-receipt.json')
    if stage.get('bindingHash') != digest(raw) or stage.get('runtimeFilesMounted') is not False \
            or stage.get('notReleaseAcceptance') is not True:
        raise trust.Blocked('RUNTIME_DNS_BINDING_DRIFT')
    source = Path(__file__).resolve().parents[1]
    return {'stageReceiptHash': digest(stage_raw), 'bindingHash': digest(raw), 'sourceCommit': args.source_commit,
        'sourceHashes': {p: digest((source/p).read_bytes()) for p in (
            'scripts/inventory_semantic_provider_dns.py', 'scripts/prepare_semantic_provider_trust.py', 'tools/semantic_provider_dns.py')},
        'endpoint': value['adapter']['provider']['endpoint'], 'allowedCidrs': value['adapter']['provider']['allowed_cidrs'],
        'dns': value['dns'], 'timeoutSeconds': args.timeout_seconds, 'maxLeaseSeconds': args.max_lease_seconds}


def operate(args):
    if os.geteuid() != 0: raise trust.Blocked('ROOT_REQUIRED')
    if not re.fullmatch('[a-f0-9]{40}', args.source_commit): raise trust.Blocked('IMMUTABLE_SOURCE_REQUIRED')
    for root in (args.runtime_stage_root, args.snapshot_root):
        if not root.is_absolute() or '..' in root.parts: raise trust.Blocked('ABSOLUTE_SAFE_PATH_REQUIRED')
        trust.ancestors(root.parent)
    desired = binding(args)
    if not 1 <= args.timeout_seconds <= 30 or not 1 <= args.max_lease_seconds <= 3600:
        raise trust.Blocked('BOUNDED_DNS_TIMING_REQUIRED')
    if args.mode == 'verify':
        saved, _ = private_json(args.snapshot_root/'dns-receipt.json')
        observation, raw = private_json(args.snapshot_root/'dns-observation.json')
        if saved.get('intent') != desired or saved.get('observationHash') != digest(raw) \
                or saved.get('notReleaseAcceptance') is not True or observation.get('historicalEvidenceOnly') is not True \
                or observation.get('kernelLeaseInstalled') is not False or observation.get('endpoint') != desired['endpoint']:
            raise trust.Blocked('HISTORICAL_DNS_OBSERVATION_DRIFT')
        return observation
    if args.snapshot_root.exists() or args.snapshot_root.is_symlink(): raise trust.Blocked('DNS_SNAPSHOT_EXISTS_RECONCILE')
    if args.mode == 'plan': return None
    args.snapshot_root.mkdir(mode=0o700)
    trust.write(args.snapshot_root/'dns-intent.json', json.dumps(desired, sort_keys=True).encode())
    profile = desired['dns']
    observation = dns.observe(desired['endpoint'], profile['resolvers'], profile['resolverPort'],
        profile['networkIPVersion'], desired['allowedCidrs'], args.timeout_seconds, args.max_lease_seconds)
    if binding(args) != desired: raise trust.Blocked('DNS_INPUT_CHANGED_DURING_OBSERVATION')
    raw = json.dumps(observation, sort_keys=True).encode()
    trust.write(args.snapshot_root/'dns-observation.json', raw)
    if trust.read_file(args.snapshot_root/'dns-observation.json', 0, 0, limit=131072) != raw:
        raise trust.Blocked('DNS_OBSERVATION_READBACK_DRIFT')
    trust.write(args.snapshot_root/'dns-receipt.json', json.dumps({'intent': desired, 'observationHash': digest(raw),
        'dnsOnly': True, 'providerCalls': 0, 'kernelLeaseInstalled': False, 'notReleaseAcceptance': True}, sort_keys=True).encode())
    return observation


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--mode', required=True, choices=('plan', 'apply', 'verify'))
    parser.add_argument('--runtime-stage-root', type=Path, required=True)
    parser.add_argument('--snapshot-root', type=Path, required=True)
    parser.add_argument('--source-commit', required=True)
    parser.add_argument('--timeout-seconds', type=int, required=True)
    parser.add_argument('--max-lease-seconds', type=int, required=True)
    args = parser.parse_args(argv)
    try:
        value = operate(args)
        print('SEMANTIC_PROVIDER_DNS='+json.dumps({'mode': args.mode, 'dnsCallsRequested': args.mode=='apply',
            'allAddressCount': len(value['allAddresses']) if value else 0,
            'usableAddressCount': len(value['usableAddresses']) if value else 0,
            'historicalEvidenceOnly': True, 'kernelLeaseInstalled': False,
            'leaseStillCurrentAtReadback': value['expiresAtUnixSeconds'] > time.time() if value else False,
            'noSecretsPrinted': True}, sort_keys=True))
        print('SEMANTIC_PROVIDER_DNS_INVENTORY=PASS NO_CONTAINER_CHANGED=true NO_NETWORK_OR_RULE_CHANGED=true '
            'NO_ROUTE_OR_IAM_WRITES=true NO_POLICY_PUBLICATION=true NO_PROVIDER_CALL=true '
            'NOT_RELEASE_ACCEPTANCE=true NO_SECRETS_PRINTED=true')
        if args.mode != 'plan': print('SEMANTIC_PROVIDER_DNS_RECEIPT='+str(args.snapshot_root/'dns-receipt.json')+' PRIVATE=true')
    except Exception as error:
        code = str(error) if isinstance(error, (trust.Blocked, dns.DNSDenied)) and re.fullmatch('[A-Z_]{1,100}', str(error)) else 'DNS_INVENTORY_FAILED'
        print('SEMANTIC_PROVIDER_DNS_INVENTORY=BLOCKED CODE='+code+' DO_NOT_RERUN_BLINDLY=true NO_SECRETS_PRINTED=true')
        raise SystemExit(1) from None


if __name__ == '__main__': main()
