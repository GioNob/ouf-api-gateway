from pathlib import Path
import yaml


def test_runtime_catalog_has_pet_required_metadata_and_operational_keys():
    catalog = yaml.safe_load(Path('config/runtime-catalog-v1.yaml').read_text())['entries']
    required_fields = {'type','unit','default','minimum','maximum','scope','environmentScope','secretClassification','reload'}
    for name, entry in catalog.items():
        missing = required_fields - set(entry)
        assert not missing, f'{name} missing {sorted(missing)}'

    required_keys = {
        'publication.batchSize','publication.convergenceTimeout',
        'request.maxBytesCeiling','request.timeoutCeiling','rateLimit.defaultPerMinute',
        'ha.northbound.replicas','ha.northbound.hpaMinReplicas','ha.northbound.hpaMaxReplicas',
        'ha.northbound.cpuTargetUtilization','ha.northbound.pdbMinAvailable',
        'ha.southbound.replicas','ha.southbound.pdbMinAvailable','ha.controlPlane.replicas',
        'ha.etcd.members','ha.terminationGracePeriod','ha.preStopDrainDelay',
        'etcd.maxPendingProposals','etcd.storageSlowBlocksPublication','etcd.quorumRequiredForPublication',
        'restore.requireExactActiveRevision','restore.rejectWildcardRoutes',
    }
    assert required_keys <= set(catalog)


def test_catalog_matches_current_ha_and_resilience_defaults():
    catalog = yaml.safe_load(Path('config/runtime-catalog-v1.yaml').read_text())['entries']
    assert catalog['ha.northbound.replicas']['default'] == 3
    assert catalog['ha.northbound.hpaMaxReplicas']['default'] == 10
    assert catalog['ha.southbound.replicas']['default'] == 2
    assert catalog['ha.controlPlane.replicas']['default'] == 2
    assert catalog['ha.etcd.members']['default'] == 3
    assert catalog['ha.terminationGracePeriod']['default'] == 60
    assert catalog['ha.preStopDrainDelay']['default'] == 15
    assert catalog['etcd.maxPendingProposals']['default'] == 64
