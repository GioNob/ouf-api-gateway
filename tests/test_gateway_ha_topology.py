from pathlib import Path
import yaml


DOCS=list(yaml.safe_load_all(Path('helm/topology/gateway-ha.yaml').read_text()))

def by(kind,name):
    for d in DOCS:
        if d['kind']==kind and d['metadata']['name']==name:return d
    raise AssertionError(f'missing {kind}/{name}')

def test_northbound_replicas_hpa_and_pdb():
    dep=by('Deployment','apisix-northbound');hpa=by('HorizontalPodAutoscaler','apisix-northbound');pdb=by('PodDisruptionBudget','apisix-northbound')
    assert dep['spec']['replicas']>=3
    assert hpa['spec']['minReplicas']==3 and hpa['spec']['maxReplicas']==10
    assert pdb['spec']['minAvailable']>=2

def test_southbound_has_two_replicas_and_pdb():
    dep=by('Deployment','apisix-southbound');pdb=by('PodDisruptionBudget','apisix-southbound')
    assert dep['spec']['replicas']>=2 and pdb['spec']['minAvailable']>=1

def test_control_plane_and_etcd_quorum():
    assert by('Deployment','apisix-control-plane')['spec']['replicas']>=2
    assert by('StatefulSet','etcd')['spec']['replicas']==3

def test_runtime_workloads_are_nonroot_spread_and_graceful():
    for kind,name in [('Deployment','apisix-northbound'),('Deployment','apisix-southbound'),('StatefulSet','etcd')]:
        pod=by(kind,name)['spec']['template']['spec']
        assert pod['securityContext']['runAsNonRoot'] is True
        assert pod['terminationGracePeriodSeconds']>=30
        assert pod['topologySpreadConstraints'][0]['whenUnsatisfiable']=='DoNotSchedule'
        c=pod['containers'][0]
        assert 'readinessProbe' in c and 'livenessProbe' in c
        assert c['resources']['requests'] and c['resources']['limits']
