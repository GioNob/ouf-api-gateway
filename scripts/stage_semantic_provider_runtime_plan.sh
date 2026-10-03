#!/usr/bin/env bash
# Stage configuration metadata only. Downloaded Python runs without sudo.
set -euo pipefail
if [ "$#" -ne 5 ]; then
  printf '%s\n' 'usage: stage_semantic_provider_runtime_plan.sh OWNER/REPO COMMIT PROFILE_PATH SNAPSHOT_ROOT TRUST_RECEIPT_REF' >&2
  exit 2
fi
stage_repository=$1
stage_commit=$2
stage_profile=$3
stage_root=$4
stage_trust_ref=$5
[[ "$stage_repository" =~ ^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}/[A-Za-z0-9][A-Za-z0-9_.-]{0,99}$ ]]
[[ "$stage_commit" =~ ^[a-f0-9]{40}$ ]]
[[ "$stage_profile" =~ ^[A-Za-z0-9_./-]+\.json$ ]]
[[ "$stage_profile" != /* && "/$stage_profile/" != *'/../'* && "/$stage_profile/" != *'/./'* ]]
[[ "$stage_root" == /* && "$stage_trust_ref" == /* ]]
stage_tmp=$(mktemp -d "${OUF_RUNTIME_STAGE_TEMP_PARENT:-/tmp}/ouf-runtime-plan.XXXXXXXXXX")
trap 'rm -rf -- "$stage_tmp"' EXIT
umask 077
stage_files=(
  tools/materialize_semantic_provider_runtime.py
  tools/materialize_semantic_provider.py
  tools/semantic_provider_adapter.py
  tools/semantic_provider_admission.py
  tools/semantic_provider_relay.py
  tools/semantic_provider_boundary.py
  tools/southbound_security.py
  tools/lua/admit_semantic_provider.lua
)
for stage_file in "${stage_files[@]}" "$stage_profile"; do
  mkdir -p -- "$stage_tmp/$(dirname -- "$stage_file")"
  stage_status=$(curl --fail --silent --show-error --proto '=https' --tlsv1.2 \
    --max-time 30 --max-filesize 131072 --output "$stage_tmp/$stage_file" \
    --write-out '%{http_code}' \
    "https://raw.githubusercontent.com/$stage_repository/$stage_commit/$stage_file")
  # Do not follow redirects or accept a redirect/HTML page as pinned source.
  [[ "$stage_status" == 200 ]]
done
(
  cd -- "$stage_tmp"
  python3 -B -m tools.materialize_semantic_provider_runtime \
    --configuration "$stage_profile" > runtime-plan.json
)
# This fixed stdlib program creates only new root-private metadata files.
# It never imports or executes downloaded code with elevated privileges.
sudo python3 -B - "$stage_tmp" "$stage_profile" "$stage_repository" "$stage_commit" \
  "$stage_root" "$stage_trust_ref" <<'PY'
import hashlib
import json
import os
from pathlib import Path
import stat
import sys

def read(path, limit):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_size > limit:
            raise ValueError()
        raw = os.read(fd, limit + 1)
        if len(raw) > limit:
            raise ValueError()
        return raw
    finally:
        os.close(fd)

def write(path, raw):
    fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, 0o600)
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, 'wb', closefd=False) as stream:
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
    finally:
        os.close(fd)

created = False
try:
    if os.geteuid() != 0:
        raise ValueError()
    source, profile, repository, commit, destination, trust_reference = sys.argv[1:]
    source = Path(source)
    root = Path(destination)
    for path in (root, Path(trust_reference)):
        if not path.is_absolute() or '..' in path.parts or str(path) != str(path.resolve(strict=False)):
            raise ValueError()
    for ancestor in (root.parent, *root.parent.parents):
        info = ancestor.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or stat.S_IMODE(info.st_mode) & 0o022:
            raise ValueError()
    raw = read(source/'runtime-plan.json', 131072)
    plan = json.loads(raw)
    if plan.get('schema') != 'ouf.semantic-provider-runtime-plan.v1' or plan.get('installed') is not False \
            or plan.get('providerCalls') != 0 or plan.get('notReleaseAcceptance') is not True:
        raise ValueError()
    binding = read(source/profile, 65536)
    files = ('tools/materialize_semantic_provider_runtime.py', 'tools/materialize_semantic_provider.py',
             'tools/semantic_provider_adapter.py', 'tools/semantic_provider_admission.py',
             'tools/semantic_provider_relay.py', 'tools/semantic_provider_boundary.py',
             'tools/southbound_security.py', 'tools/lua/admit_semantic_provider.lua')
    hashes = {p: hashlib.sha256(read(source/p, 131072)).hexdigest() for p in files}
    manifest = {'schema': 'ouf.semantic-provider-runtime-stage.v1', 'repository': repository,
        'sourceCommit': commit, 'profilePath': profile, 'sourceHashes': hashes,
        'bindingHash': hashlib.sha256(binding).hexdigest(), 'planHash': hashlib.sha256(raw).hexdigest(),
        'trustReceiptReference': trust_reference, 'trustArtifactsRevalidated': False,
        'liveConfigurationRevalidated': False, 'runtimeFilesMounted': False,
        'providerCalls': 0, 'notReleaseAcceptance': True}
    # mkdir is exclusive: an existing or failed snapshot is never overwritten.
    root.mkdir(mode=0o700)
    created = True
    write(root/'binding.json', binding)
    write(root/'runtime-plan.json', raw)
    for name, expected in (('binding.json', manifest['bindingHash']), ('runtime-plan.json', manifest['planHash'])):
        info = (root/name).lstat()
        if info.st_uid != 0 or stat.S_IMODE(info.st_mode) != 0o600 \
                or hashlib.sha256(read(root/name, 131072)).hexdigest() != expected:
            raise ValueError()
    info = root.lstat()
    if info.st_uid != 0 or stat.S_IMODE(info.st_mode) != 0o700:
        raise ValueError()
    write(root/'stage-receipt.json', json.dumps(manifest, sort_keys=True).encode())
    print('SEMANTIC_PROVIDER_RUNTIME_STAGE=PASS CONFIGURATION_COMPILED=true PRIVATE=true '
          'NO_CONTAINER_CREATED=true NO_NETWORK_OR_RULE_CHANGED=true NO_ROUTE_OR_IAM_WRITES=true '
          'NO_POLICY_PUBLICATION=true NO_PROVIDER_CALL=true NOT_RELEASE_ACCEPTANCE=true NO_SECRETS_PRINTED=true')
    print('SEMANTIC_PROVIDER_RUNTIME_STAGE_RECEIPT='+str(root/'stage-receipt.json')+' PRIVATE=true')
except Exception:
    print('SEMANTIC_PROVIDER_RUNTIME_STAGE=BLOCKED DO_NOT_RERUN_BLINDLY=true '
          'PARTIAL_SNAPSHOT_RETAINED='+str(created).lower()+' NO_SECRETS_PRINTED=true')
    raise SystemExit(1) from None
PY
