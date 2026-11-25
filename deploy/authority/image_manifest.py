"""Publish the common tested-image manifest alongside the Docker save archive."""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys


def publish(directory, *, repository, source_commit, tested_commit, tree, run_id, attempt, image_id):
    archive = directory / 'image.tar.gz'
    with archive.open('rb') as stream:
        checksum = hashlib.file_digest(stream, 'sha256').hexdigest()
    manifest = dict(schema='ouf.gateway-authority-tested-image.v1', repository=repository,
                    reviewedSourceCommit=source_commit, testedCommit=tested_commit, testedTree=tree,
                    workflowRunId=run_id, workflowRunAttempt=attempt, imageRevisionLabel=tested_commit,
                    imageTag='gateway-authority:' + tested_commit, imageId=image_id, archiveName=archive.name,
                    archiveBytes=archive.stat().st_size, archiveSha256=checksum)
    (directory / 'manifest.json').write_bytes(json.dumps(manifest, indent=2).encode() + b'\n')
    (directory / 'SHA256SUMS').write_bytes(f'{checksum}  {archive.name}\n'.encode('ascii'))


if __name__ == '__main__':
    directory, image_id = sys.argv[1:]
    commit = subprocess.check_output(['git', 'rev-parse', 'HEAD'], text=True).strip()
    if commit != os.environ['REVIEWED_SOURCE_COMMIT']:
        raise SystemExit('reviewed source differs from tested checkout')
    tree = subprocess.check_output(['git', 'rev-parse', 'HEAD^{tree}'], text=True).strip()
    publish(Path(directory), repository=os.environ['GITHUB_REPOSITORY'], source_commit=os.environ['REVIEWED_SOURCE_COMMIT'],
            tested_commit=commit, tree=tree, run_id=os.environ['GITHUB_RUN_ID'],
            attempt=os.environ['GITHUB_RUN_ATTEMPT'], image_id=image_id)
