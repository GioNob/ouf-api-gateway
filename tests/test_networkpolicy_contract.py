from pathlib import Path
import yaml

ROOT=Path(__file__).resolve().parents[1]

def docs(name):return list(yaml.safe_load_all((ROOT/'helm'/'networkpolicy'/name).read_text()))

def test_southbound_has_default_deny_ingress_and_egress():
    policy=docs('southbound-default-deny.yaml')[0]
    assert policy['spec']['policyTypes']==['Ingress','Egress']
    assert 'ingress' not in policy['spec'] and 'egress' not in policy['spec']

def test_southbound_is_not_publicly_ingressible():
    allow=docs('southbound-default-deny.yaml')[1]
    peer=allow['spec']['ingress'][0]['from'][0]
    assert peer['namespaceSelector']['matchLabels']['ouf.southbound-client']=='true'

def test_ingestion_egress_only_targets_southbound_gateway_baseline():
    policy=docs('ingestion-no-direct-egress.yaml')[0]
    rules=policy['spec']['egress'];assert len(rules)==1
    peer=rules[0]['to'][0]
    assert peer['namespaceSelector']['matchLabels']['kubernetes.io/metadata.name']=='ouf-gateway'
    assert peer['podSelector']['matchLabels']['ouf.component']=='apisix-southbound'
