"""Regression for preserved public-root bundles and unchanged private limits."""
import os
from pathlib import Path
import tempfile
import unittest
from scripts import inventory_semantic_provider_candidate_inputs as inputs


@unittest.skipUnless(os.geteuid()==0,'root-owned metadata fixtures require root')
class CandidateMetadataTest(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(prefix='ouf-candidate-metadata-',
            dir=os.environ.get('OUF_CANDIDATE_METADATA_TEST_PARENT',str(Path.cwd())))
        self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name)
    def create(self,name,size,mode):
        path=self.root/name
        path.write_bytes(b'x'*size);path.chmod(mode)
        return path
    def test_real_target_sized_public_bundle_accepted(self):
        path=self.create('trust-bundle.pem',225117,0o644)
        inputs.file_metadata(path,0,0,0o644,limit=1048576)
    def test_private_metadata_and_json_keep_original_limit(self):
        path=self.create('private.json',225117,0o600)
        with self.assertRaisesRegex(inputs.Blocked,'ARTIFACT_METADATA_DRIFT'):
            inputs.file_metadata(path,0,0,0o600)
        with self.assertRaisesRegex(inputs.Blocked,'ARTIFACT_METADATA_DRIFT'):
            inputs.private_json(path)
    def test_public_limit_and_owner_mode_link_guards_remain(self):
        too_big=self.create('oversized.pem',1048577,0o644)
        with self.assertRaises(inputs.Blocked): inputs.file_metadata(too_big,0,0,0o644,limit=1048576)
        path=self.create('public.pem',225117,0o644)
        with self.assertRaises(inputs.Blocked): inputs.file_metadata(path,10006,10006,0o644,limit=1048576)
        path.chmod(0o666)
        with self.assertRaises(inputs.Blocked): inputs.file_metadata(path,0,0,0o644,limit=1048576)
        path.chmod(0o644)
        linked=self.root/'linked.pem';os.link(path,linked)
        with self.assertRaises(inputs.Blocked): inputs.file_metadata(path,0,0,0o644,limit=1048576)
        linked.unlink();linked.symlink_to(path)
        with self.assertRaises(inputs.Blocked): inputs.file_metadata(linked,0,0,0o644,limit=1048576)


if __name__=='__main__': unittest.main()
