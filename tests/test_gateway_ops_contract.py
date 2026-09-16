from pathlib import Path
import yaml

ROOT=Path(__file__).resolve().parents[1]

def load(rel):
    return yaml.safe_load((ROOT/rel).read_text())

def test_capacity_fixture_is_reproducible_and_bounded():
    f=load('ops/capacity-fixture-v1.yaml')['profile']
    assert f['routes']>0 and f['capabilities']>0 and f['sources']>0
    assert sum(f['requestMix'].values())==100
    assert f['payloadBytes']['p50']<=f['payloadBytes']['p95']<=f['payloadBytes']['p99']
    assert f['backendLatencyMs']['p50']<=f['backendLatencyMs']['p95']<=f['backendLatencyMs']['p99']

def test_observability_contract_covers_pet_signals_and_slos():
    c=load('ops/observability-contract-v1.yaml')
    etcd=set(c['metrics']['etcd'])
    assert {'etcd_server_wal_fsync_duration_seconds','etcd_disk_backend_commit_duration_seconds','etcd_server_leader_changes_seen_total','etcd_server_proposals_pending','etcd_mvcc_db_total_size_in_bytes'}<=etcd
    assert c['slos']['northboundAvailability']>0
    assert c['slos']['publicationConvergenceP95Seconds']<=30
    assert {'EtcdQuorumUnavailable','EtcdStorageSlow','PublicationConvergenceSlow'}<=set(c['alerts'])
