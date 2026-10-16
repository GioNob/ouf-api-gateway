"""Offline, version-bound APISIX compatibility assets; no deployment effects.

The installation owner stages these bytes, binds their custody and reviews the
mount/config changes with the normal runtime authority. This is not an apply API.
"""
import copy
import hashlib
from pathlib import Path

PROFILE = 'ouf.apisix-json-numeric-contract.v1'
IMAGE_DIGEST = 'sha256:84e6b5e787e9f889ebff88161cb9a16599bafcffa236c6b54c7f779a0655940d'
ASSETS = {
    'jsonschema.lua': ('f8c1fa8f9e8535467d4e8880312d769cdbf5e047d32593ab73d2fefb71e44364',
                       '/usr/local/apisix/deps/share/lua/5.1/jsonschema.lua'),
    'ouf_json_precision.lua': ('0444d8b4d6cab03ccc4b6cf47364d606b81ec11a843f7ab4714208d79dfb1eaa',
                               '/usr/local/apisix/conf/ouf_json_precision.lua'),
}


def prepare(config, image_digest, asset_root=None):
    """Return a new config and hash-checked assets; preserve installation values."""
    if image_digest != IMAGE_DIGEST:
        raise ValueError('APISIX_IMAGE_NOT_QUALIFIED_FOR_NUMERIC_PROFILE')
    if type(config) is not dict or type(config.get('apisix')) is not dict:
        raise ValueError('EXPLICIT_APISIX_CONFIGURATION_REQUIRED')
    following = copy.deepcopy(config)
    options = following['apisix']
    if options.get('lua_module_hook') is not None or options.get('extra_lua_path') is not None:
        raise ValueError('EXISTING_LUA_EXTENSION_REQUIRES_EXPLICIT_COMPOSITION_REVIEW')
    options.update(lua_module_hook='ouf_json_precision',
                   extra_lua_path='/usr/local/apisix/conf/?.lua')
    root = Path(asset_root) if asset_root is not None else Path(__file__).resolve().parents[1]/'runtime/apisix'
    assets = []
    for name, (expected, destination) in ASSETS.items():
        raw = (root/name).read_bytes()
        if len(raw) > 131072 or hashlib.sha256(raw).hexdigest() != expected:
            raise ValueError('NUMERIC_COMPATIBILITY_ASSET_HASH_DRIFT')
        assets.append({'name': name, 'sha256': expected, 'destination': destination,
                       'readOnly': True, 'bytes': raw})
    return {'profile': PROFILE, 'imageDigest': image_digest, 'config': following,
            'assets': assets, 'runtimeAuthorityIssued': False, 'installationApplied': False}
