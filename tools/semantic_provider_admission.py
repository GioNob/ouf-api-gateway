"""Admission intent checks and isolated native footprint construction.

Approval files are externally issued deployment artefacts, not IAM decisions.
The caller must source-seal this module and supply a verified private reader.
"""
import copy
import re
import time

from tools.semantic_provider_preexec import PreexecDenied, digest, rules
from tools.semantic_provider_preexec_native import footprint
from tools.materialize_semantic_shared_faces import materialize


def check(value, reason):
    if not value: raise PreexecDenied(reason)


def application_hash(bundle):
    # Bind the entire OCI document, including Linux devices/seccomp/sysctls,
    # namespaces and annotations. argv alone is not creation acceptance.
    return digest(bundle)


def live_profile(candidate, bundle, namespace, inode, children, hosts):
    check(application_hash(bundle) == candidate['applicationHash'], 'APPLICATION_ACCEPTANCE_DRIFT')
    networks = [v for v in bundle['linux']['namespaces'] if v.get('type') == 'network']
    check(len(networks) == 1 and set(networks[0]) in ({'type'},{'type','path'}), 'EXACT_NETWORK_NAMESPACE_REQUIRED')
    check(not set(bundle.get('hooks',{}))-{'prestart','createRuntime'}, 'LATE_MUTATING_HOOK_DENIED')
    if networks[0].get('path'): check(networks[0]['path'] == namespace, 'PREPARED_NAMESPACE_PATH_DRIFT')
    approved = candidate['networkBindings']
    check(isinstance(approved,list) and 1 <= len(approved) <= 32, 'BOUNDED_NETWORK_APPROVAL_REQUIRED')
    check(len(children) == len(approved), 'UNAPPROVED_NAMESPACE_INTERFACE')
    attachments, links = [], []
    for binding in approved:
        check(set(binding) == {'interface','bridge','mac','ipv4','workloadRef','bindingRef'}, 'EXACT_NETWORK_APPROVAL_REQUIRED')
        matches = [v for v in children if v['ifname'] == binding['interface']]
        check(len(matches) == 1, 'LIVE_CHILD_INTERFACE_REQUIRED'); child = matches[0]
        check(child['address'] == binding['mac'] and
              [v['local'] for v in child['addr_info'] if v['family'] == 'inet'] == [binding['ipv4']],
              'APPROVED_MAC_IP_BINDING_DRIFT')
        peers = [v for v in hosts if v['ifindex'] == child.get('link_index')]
        check(len(peers) == 1, 'LIVE_HOST_PEER_REQUIRED'); host = peers[0]
        check(host.get('link_index') == child['ifindex'] and host.get('master') == binding['bridge'],
              'APPROVED_HOST_BRIDGE_BINDING_DRIFT')
        attachments.append({k:binding[k] for k in ('bridge','mac','ipv4','workloadRef','bindingRef')}
                           | {'interface':host['ifname'],'ifindex':host['ifindex']})
        links.append({'interface':child['ifname'],'ifindex':child['ifindex'],'hostIfindex':host['ifindex']})
    policy = {'schema':'ouf.semantic-shared-faces.v1','tableName':candidate['tableName'],
              'attachments':attachments,'flows':copy.deepcopy(candidate['transport'])}
    materialize(policy)
    return {'schema':'ouf.semantic-preexec-profile.v2','namespaceOrigin':'PREPARED' if networks[0].get('path') else 'OCI_CREATED',
            'transactionId':candidate['transactionId'],'containerId':candidate['containerId'],
            'bundlePath':candidate['bundlePath'],'bundleHash':digest(bundle),
            'namespacePath':namespace,'namespaceInode':inode,'namespaceLinks':links,'policy':policy,
            'expectedFootprint':'0'*64,'applicationStartAuthorized':True,'infrastructureAuthorityComplete':True}


def transport_hash(candidate):
    return digest({k:candidate[k] for k in ('networkBindings','transport','tableName')})


def authority(binding, expected, reader, clock=time.time):
    check(set(binding) == {'path','sha256','issuedAt','expiresAt'}, 'EXACT_AUTHORITY_BINDING_REQUIRED')
    check(set(expected) == {'issuerRef','installationRef','entityRef','approvalRef','containerId',
          'transactionId','applicationHash','transportHash','creationAcceptanceHash'}, 'EXACT_AUTHORITY_SCOPE_REQUIRED')
    check(all(isinstance(expected[k],str) and re.fullmatch('[0-9a-f]{64}',expected[k])
          for k in ('containerId','transactionId','applicationHash','transportHash','creationAcceptanceHash')),
          'AUTHORITY_SCOPE_HASH_REQUIRED')
    now = clock()
    check(type(binding['issuedAt']) is int and type(binding['expiresAt']) is int
          and binding['issuedAt'] <= now < binding['expiresAt']
          and 0 < binding['expiresAt']-binding['issuedAt'] <= 300, 'AUTHORITY_EXPIRED_OR_NOT_YET_VALID')
    import hashlib
    import json
    raw = reader(binding['path'])
    check(hashlib.sha256(raw).hexdigest() == binding['sha256'], 'AUTHORITY_REVOKED_OR_CHANGED')
    def unique(pairs):
        result = {}
        for key, item in pairs:
            check(key not in result, 'DUPLICATE_AUTHORITY_KEY'); result[key] = item
        return result
    value = json.loads(raw, object_pairs_hook=unique)
    check(set(value) == {'schema','issuerRef','installationRef','entityRef','approvalRef',
          'containerId','transactionId','applicationHash','transportHash','creationAcceptanceHash',
          'issuedAt','expiresAt','state','infrastructureAuthorized','applicationStartAuthorized'},
          'EXACT_AUTHORITY_RECEIPT_REQUIRED')
    check(value['schema'] == 'ouf.semantic-deployment-admission-approval.v1'
          and value['state'] == 'ACTIVE' and value['infrastructureAuthorized'] is True
          and value['applicationStartAuthorized'] is True, 'DEPLOYMENT_AUTHORITY_REQUIRED')
    check(all(value[k] == v for k,v in expected.items())
          and value['issuedAt'] == binding['issuedAt'] and value['expiresAt'] == binding['expiresAt'],
          'AUTHORITY_SCOPE_BINDING_DRIFT')
    for key in ('issuerRef','installationRef','entityRef','approvalRef'):
        check(isinstance(value[key], str) and re.fullmatch('[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}', value[key]),
              'AUTHORITY_IDENTITY_REQUIRED')
    return value


def mirrors(profile, host_links):
    materialize(profile['policy'])
    indexes = {v['ifindex']:v['interface'] for v in profile['policy']['attachments']}
    for flow in profile['policy']['flows']:
        peer = flow['peerIngress']
        if peer['kind'] == 'HOST': continue
        found = [v for v in host_links if v['ifindex'] == peer['ifindex']]
        check(len(found) == 1, 'TEMPLATE_PEER_INDEX_UNPROVEN')
        indexes[peer['ifindex']] = found[0]['ifname']
    result = [{'ifindex':k,'interface':v} for k,v in sorted(indexes.items())]
    validate_mirrors(profile, result)
    return result


def validate_mirrors(profile, links):
    selected = {v['ifindex']:v['interface'] for v in profile['policy']['attachments']}
    peers = {f['peerIngress']['ifindex'] for f in profile['policy']['flows'] if f['peerIngress']['kind'] != 'HOST'}
    check(isinstance(links,list) and len(links) <= 160, 'TEMPLATE_LINKS_UNBOUNDED')
    indexed = {}
    for link in links:
        check(set(link) == {'ifindex','interface'} and type(link['ifindex']) is int
              and 1 < link['ifindex'] <= 2147483647 and isinstance(link['interface'],str)
              and re.fullmatch('[A-Za-z][A-Za-z0-9_-]{0,14}',link['interface'])
              and link['interface'] != 'lo' and link['ifindex'] not in indexed,
              'EXACT_TEMPLATE_INTERFACE_REQUIRED')
        indexed[link['ifindex']] = link['interface']
    check(set(indexed) == set(selected)|peers and len(set(indexed.values())) == len(indexed)
          and all(indexed[k] == v for k,v in selected.items()), 'TEMPLATE_INTERFACE_BINDING_DRIFT')


def isolated_template(profile, links, parent_inode, current_inode, run):
    # This assertion precedes every native write. No host readback is accepted
    # as the expected template. The whole namespace dies with the worker.
    check(type(parent_inode) is int and parent_inode > 0 and current_inode != parent_inode,
          'ISOLATED_TEMPLATE_NAMESPACE_REQUIRED')
    profile = copy.deepcopy(profile)
    check(isinstance(profile['transactionId'],str) and re.fullmatch('[0-9a-f]{64}',profile['transactionId']),
          'EXACT_TEMPLATE_TRANSACTION_REQUIRED')
    materialize(profile['policy']); validate_mirrors(profile, links)
    for link in links:
        run('ip',['link','add','name',link['interface'],'index',str(link['ifindex']),'type','dummy'])
    table = profile['policy']['tableName']
    run('nft',['-f','-'], 'create table inet '+table+'\ncreate table bridge '+table+'\n'+rules(profile))
    import json
    tables = {f:json.loads(run('nft',['-j','-n','list','table',f,table])) for f in ('bridge','inet')}
    return {'schema':'ouf.semantic-shared-native-template.v1','footprint':footprint(tables),
            'rulesHash':digest(rules(profile)), 'profileHash':digest(profile),
            'isolated':True,'hostRulesChanged':False,'startAuthorized':False}
