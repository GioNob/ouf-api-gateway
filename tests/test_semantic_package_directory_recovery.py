"""Real GNU install reproduction and narrow, receipt-aware directory recovery."""
import hashlib
import os
from pathlib import Path
import stat
import subprocess
import sys
import unittest
from tests import test_semantic_local_producers_package as fixture
from scripts import repair_semantic_local_producers_package_directory as recovery


@unittest.skipUnless(os.geteuid()==0,'root-private GNU directory regression')
class DirectoryRecoveryTest(unittest.TestCase):
    def setUp(self):
        f=fixture.LocalProducersPackageTest();f.setUp();self.addCleanup(f.doCleanups);self.f=f
        self.root=f.root/'native-package';self.root.mkdir(mode=0o700)
        subprocess.run(['install','-d','-m','0700','-o','root','-g','root',str(self.root/'source/scripts'),
            str(self.root/'source/tools')],check=True,timeout=5)
        for name in fixture.NAMES:
            path=self.root/'source'/name;path.write_bytes((f.root/'source'/name).read_bytes());path.chmod(0o600)
        self.manifest=self.root/'sources.sha256';self.manifest.write_bytes(f.manifest.read_bytes());self.manifest.chmod(0o600)
        self.sha=f.manifest_hash
    def run_stage(self,mode):
        return subprocess.run([sys.executable,'-I','-B',str(self.root/'source'/fixture.NAMES[0]),
            '--mode',mode,'--package-root',str(self.root),'--source-commit','a'*40,
            '--source-manifest-sha256',self.sha],capture_output=True,text=True,timeout=10)
    def test_actual_install_bug_recovery_then_original_plan_apply_verify(self):
        self.assertEqual(stat.S_IMODE((self.root/'source').stat().st_mode),0o755)
        failed=self.run_stage('plan');self.assertNotEqual(failed.returncode,0);self.assertIn('PRIVATE_PACKAGE_DIRECTORY_REQUIRED',failed.stdout)
        before={p:p.read_bytes() for p in self.root.rglob('*') if p.is_file()}
        planned=recovery.operate('inspect',self.root,self.sha);self.assertFalse(planned['sourceModeCorrected'])
        self.assertEqual(planned['directoriesBefore'],planned['directoriesAfter'])
        result=recovery.operate('repair',self.root,self.sha);self.assertTrue(result['sourceModeCorrected'])
        self.assertFalse(result['receiptCreated']);self.assertFalse(result['ownershipChanged'])
        self.assertEqual(before,{p:p.read_bytes() for p in before})
        for mode in ('plan','apply','verify'):
            value=self.run_stage(mode);self.assertEqual(value.returncode,0,value.stdout)
        with self.assertRaisesRegex(RuntimeError,'RECEIPT_EXISTS_DO_NOT_REPLAY'):recovery.operate('repair',self.root,self.sha)
    def test_fixed_install_explicit_intermediate_directory_is_private(self):
        for mask in (0o022,0o077):
            root=self.f.root/('fixed-'+oct(mask));root.mkdir(mode=0o700)
            def umask():os.umask(mask)
            subprocess.run(['install','-d','-m','0700','-o','root','-g','root',str(root),str(root/'source'),
                str(root/'source/scripts'),str(root/'source/tools')],check=True,timeout=5,preexec_fn=umask)
            for p in (root,root/'source',root/'source/scripts',root/'source/tools'):
                info=p.stat();self.assertEqual((stat.S_IMODE(info.st_mode),info.st_uid,info.st_gid),(0o700,0,0))
    def test_existing_unknown_or_symlink_receipt_blocks_without_chmod(self):
        path=self.root/'source-package-receipt.json'
        for symlink in (False,True):
            if symlink:path.symlink_to(self.root/'missing')
            else:path.write_bytes(b'uncertain partial receipt')
            with self.assertRaisesRegex(RuntimeError,'RECEIPT_EXISTS_DO_NOT_REPLAY'):recovery.operate('repair',self.root,self.sha)
            self.assertEqual(stat.S_IMODE((self.root/'source').stat().st_mode),0o755);path.unlink()
    def test_source_or_manifest_drift_blocks_before_chmod(self):
        path=self.root/'source'/fixture.NAMES[1];path.write_bytes(path.read_bytes()+b'\n')
        with self.assertRaisesRegex(RuntimeError,'ORIGINAL_SOURCE_HASH_DRIFT'):recovery.operate('repair',self.root,self.sha)
        self.assertEqual(stat.S_IMODE((self.root/'source').stat().st_mode),0o755)
        self.manifest.write_bytes(self.manifest.read_bytes()+b'\n')
        with self.assertRaisesRegex(RuntimeError,'ORIGINAL_MANIFEST_PIN_REQUIRED'):recovery.operate('repair',self.root,self.sha)
    def test_unexpected_mode_owner_or_symlink_is_not_repaired(self):
        path=self.root/'source';path.chmod(0o750)
        with self.assertRaisesRegex(RuntimeError,'UNEXPECTED_DIRECTORY_METADATA'):recovery.operate('repair',self.root,self.sha)
        self.assertEqual(stat.S_IMODE(path.stat().st_mode),0o750);path.chmod(0o755)
        # Scratch supports only root IDs; test a foreign group in metadata.
        from unittest.mock import patch
        from types import SimpleNamespace
        original_lstat=Path.lstat
        def foreign(p):
            info=original_lstat(p)
            return SimpleNamespace(st_mode=info.st_mode,st_uid=0,st_gid=1000) if p==path else info
        with patch.object(Path,'lstat',foreign):
            with self.assertRaisesRegex(RuntimeError,'UNEXPECTED_DIRECTORY_METADATA'):recovery.operate('repair',self.root,self.sha)
        original=self.root/'original-source';path.rename(original);path.symlink_to(original)
        with self.assertRaisesRegex(RuntimeError,'UNEXPECTED_DIRECTORY_METADATA'):recovery.operate('repair',self.root,self.sha)
    def test_private_source_hardlink_is_refused(self):
        source=self.root/'source'/fixture.NAMES[1];os.link(source,self.root/'hardlink.py')
        with self.assertRaisesRegex(RuntimeError,'PRIVATE_ORIGINAL_SOURCE_REQUIRED'):recovery.operate('repair',self.root,self.sha)
        self.assertEqual(stat.S_IMODE((self.root/'source').stat().st_mode),0o755)
    def test_already_private_source_is_noop_without_receipt(self):
        (self.root/'source').chmod(0o700)
        before=(self.root/'source').stat().st_ctime_ns
        value=recovery.operate('repair',self.root,self.sha);self.assertFalse(value['sourceModeCorrected'])
        self.assertEqual((self.root/'source').stat().st_ctime_ns,before)
    def test_repair_fsync_failure_does_not_create_receipt_or_touch_sources(self):
        from unittest.mock import patch
        before=self.manifest.read_bytes()
        with patch.object(recovery.os,'fsync',side_effect=OSError('fixture fsync failure')):
            with self.assertRaises(OSError):recovery.operate('repair',self.root,self.sha)
        self.assertFalse((self.root/'source-package-receipt.json').exists());self.assertEqual(before,self.manifest.read_bytes())


if __name__=='__main__':unittest.main()
