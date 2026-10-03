"""Compile a systemd service only; never install, enable or start it."""
import re

from tools.materialize_southbound_kernel import fields


def compile_service(value):
    fields(value, ('unitName', 'pythonPath', 'sourceRoot', 'configurationFile', 'configurationHash',
                   'runtimeDirectory', 'restartSeconds', 'stopSeconds', 'dependencyUnits'))
    for key in ('unitName', 'runtimeDirectory'):
        if not re.fullmatch('[A-Za-z][A-Za-z0-9_-]{0,63}', value[key]): raise ValueError('explicit safe service binding required')
    for key in ('pythonPath', 'sourceRoot', 'configurationFile'):
        path = value[key]
        if not isinstance(path, str) or not re.fullmatch('/[A-Za-z0-9_./-]+', path) \
                or any(v in ('', '.', '..') for v in path.split('/')[1:]): raise ValueError('safe absolute unit path required')
    if not re.fullmatch('[0-9a-f]{64}', value['configurationHash']): raise ValueError('sealed configuration hash required')
    for key, low, high in (('restartSeconds', 1, 300), ('stopSeconds', 5, 600)):
        if type(value[key]) is not int or not low <= value[key] <= high: raise ValueError('explicit bounded service timing required')
    deps = value['dependencyUnits']
    if not isinstance(deps, list) or not 1 <= len(deps) <= 8 or len(set(deps)) != len(deps) \
            or any(not re.fullmatch(r'[A-Za-z0-9_-]+\.(service|target)', v) for v in deps):
        raise ValueError('explicit service dependencies required')
    unit = '\n'.join([
        '[Unit]', 'Description=Semantic provider DNS lease owner',
        'After='+' '.join(deps), 'Requires='+' '.join(deps),
        '[Service]', 'Type=simple', 'User=root', 'Group=root', 'UMask=0077',
        'WorkingDirectory='+value['sourceRoot'],
        'ExecStart='+value['pythonPath']+' -B -m scripts.run_semantic_provider_lease_owner'+
        ' --configuration '+value['configurationFile']+' --configuration-sha256 '+value['configurationHash']+
        ' --lock-file /run/'+value['runtimeDirectory']+'/owner.lock',
        'RuntimeDirectory='+value['runtimeDirectory'], 'RuntimeDirectoryMode=0700',
        'Restart=on-failure', 'RestartSec='+str(value['restartSeconds']), 'TimeoutStopSec='+str(value['stopSeconds']),
        'KillSignal=SIGTERM', 'KillMode=control-group', 'NoNewPrivileges=yes',
        'CapabilityBoundingSet=CAP_NET_ADMIN', 'AmbientCapabilities=CAP_NET_ADMIN',
        'ProtectSystem=strict', 'ProtectHome=yes', 'PrivateTmp=yes',
        'ProtectKernelTunables=yes', 'ProtectKernelModules=yes', 'ProtectControlGroups=yes',
        'RestrictNamespaces=yes', 'RestrictSUIDSGID=yes', 'LockPersonality=yes',
        'RestrictAddressFamilies=AF_INET AF_INET6 AF_NETLINK AF_UNIX',
        'ReadWritePaths=/run/'+value['runtimeDirectory'], '[Install]', 'WantedBy=multi-user.target', ''])
    return {'unitName': value['unitName']+'.service', 'unit': unit,
            'installed': False, 'enabled': False, 'started': False, 'notReleaseAcceptance': True}
