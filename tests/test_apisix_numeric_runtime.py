import copy

import pytest

from tools.prepare_apisix_numeric_runtime import IMAGE_DIGEST, prepare


def test_profile_preserves_two_distinct_installation_topologies():
    for domain, port, peers in [('ente-a.example', 9080, ['https://etcd-a.example:2379']),
                                ('ente-b.example', 9443, ['https://store.example:32379'])]:
        config = {'apisix': {'node_listen': port},
                  'deployment': {'etcd': {'host': peers}},
                  'nginx_config': {'envs': ['OWNER_KEY']}, 'installation': {'domain': domain}}
        before = copy.deepcopy(config)
        result = prepare(config, IMAGE_DIGEST)
        assert config == before
        restored = copy.deepcopy(result['config'])
        del restored['apisix']['lua_module_hook']
        del restored['apisix']['extra_lua_path']
        assert restored == before
        assert all(a['readOnly'] for a in result['assets'])
        assert not result['installationApplied'] and not result['runtimeAuthorityIssued']


@pytest.mark.parametrize('key', ['lua_module_hook', 'extra_lua_path'])
def test_existing_extension_is_not_overwritten(key):
    with pytest.raises(ValueError, match='COMPOSITION_REVIEW'):
        prepare({'apisix': {key: 'existing'}}, IMAGE_DIGEST)


def test_unqualified_image_and_modified_asset_fail_closed(tmp_path):
    with pytest.raises(ValueError, match='IMAGE_NOT_QUALIFIED'):
        prepare({'apisix': {}}, 'sha256:'+'a'*64)
    (tmp_path/'jsonschema.lua').write_text('return {}')
    with pytest.raises(ValueError, match='ASSET_HASH_DRIFT'):
        prepare({'apisix': {}}, IMAGE_DIGEST, tmp_path)
