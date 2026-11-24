"""Issued replay joins only. Inert structures never issue, sign, persist or execute a grant."""
from contextlib import ExitStack
import unittest
from pathlib import Path
from unittest.mock import patch

from scripts import verify_pi_core_b114_boot_evidence as subject
from scripts.build_pi_core_linux import BuildError, canonical, sha256
from test_pi_core_b113_replay import UID, inert


class B114IssueReplay(unittest.TestCase):
    approval, artifact, signer = '1'*40, '2'*40, 'SHA256:'+'a'*43
    release_path, nomination, archive = (Path('/inert/'+p) for p in ('release/release', 'observer/nomination', 'archive'))

    @classmethod
    def setUpClass(cls):
        pred = subject.predecessor
        cls.blobs = {subject.ROOT / p: (subject.ROOT / p).read_bytes() for p in pred.PATHS.values()}
        cls.held = pred.joined({k: cls.blobs[subject.ROOT / p] for k, p in pred.PATHS.items()})
        # Exercise the real builder -> published receipt -> reader contract, without
        # supplying a slot, a Mach-O file, a Git signature or a writable destination.
        spec = dict(media=cls.held['media'], approval_commit=cls.approval,
                    build_seal_sha256=sha256(b'inert seal'), release_sha256='5'*64)
        props = dict(identifier=subject.owner.ID, runner_sha256='3'*64, cdhash='4'*40)
        cls.pin = subject.owner._pin(spec, props)
        cls.ctx = cls.held | {'runner': cls.pin, 'runner_catalog_sha256': sha256(canonical(cls.pin))}

    def replay(self, *, host_loss=False):
        return subject.replay(self.approval, self.artifact, self.signer, self.release_path, self.nomination,
                              '6'*64, self.archive, UID, '7'*64, host_loss=host_loss)

    def test_held_and_loss_refuse_without_private_read_or_archive(self):
        with patch.object(subject.seal, 'approved_source', side_effect=BuildError('held')) as verified, \
                patch.object(subject.seal, 'read_private') as material, patch.object(subject, 'read_owner_archive') as read:
            self.assertEqual(self.replay(host_loss=True)['host'], 'unresolved-host-loss')
            verified.assert_not_called()
            with self.assertRaisesRegex(BuildError, 'held'):
                self.replay()
            read.assert_not_called()
            material.assert_not_called()

    def test_signed_artifact_ancestry_and_source_join_precede_private_release(self):
        src = subject.ROOT / 'scripts/verify_pi_core_b114_boot_evidence.py'
        sources = self.blobs | {subject.seal.SEAL: b'inert seal', src: src.read_bytes()}
        blobs = sources | {subject.ARTIFACT: canonical(self.pin)}
        with patch.object(subject.seal, 'REVIEWED_SOURCES', frozenset(sources)), \
             patch.object(subject.seal, 'approved_source', return_value=({'release_sha256':'5'*64},
                          sha256(b'inert seal'), sources)), \
             patch.object(subject.seal, 'verify_commit') as sig, patch.object(subject.seal, 'require_ancestor') as ancestry, \
             patch.object(subject.seal, 'signed_blob', side_effect=lambda commit,path: blobs[path]) as read:
            public = lambda: subject.public_issue(self.approval,self.artifact,self.signer)
            self.assertEqual(public()[-1], self.ctx)
            sig.assert_called_once_with(self.artifact, self.signer)
            ancestry.assert_called_once_with(self.approval, self.artifact)
            read.reset_mock()
            with self.assertRaisesRegex(BuildError, 'distinct'):
                subject.public_issue(self.approval, self.approval, self.signer)
            read.assert_not_called()
            with patch.object(subject.seal,'require_ancestor',side_effect=BuildError('unrelated')), self.assertRaises(BuildError):
                public()
            read.assert_not_called()
            with patch.object(subject,'regular_bytes',return_value=b'other checkout'), self.assertRaisesRegex(BuildError,'checkout'):
                public()
            for path, foreign in ((src,b'changed verifier'), (subject.seal.SEAL,b'changed seal'),
                                  (subject.ARTIFACT,canonical(self.held['runner'])),
                                  (subject.ARTIFACT,canonical(self.pin | {'request_sha256':'f'*64})),
                                  (subject.ARTIFACT,canonical(self.pin | {'runner_sha256':self.held['runner']['runner_sha256']}))):
                with self.subTest(path=path), patch.dict(blobs,{path:foreign}), self.assertRaises(BuildError):
                    public()

    def test_external_pre_attempt_requires_exact_artifact_entry_and_different_custody(self):
        entry = {'test': 'deliberately not a release'}
        doc = dict(schema='aragorn/b114-independent-pre-attempt/v1', approval_commit=self.approval,
                   artifact_commit=self.artifact, runner_catalog_sha256=self.ctx['runner_catalog_sha256'],
                   release_sha256=self.pin['release_sha256'], entry=entry)
        for update, good in (({},True), ({'artifact_commit':self.approval},False),
                             ({'runner_catalog_sha256':self.held['runner_catalog_sha256']},False),
                             ({'entry':{}},False)):
            raw = canonical(doc | update)
            with patch.object(subject,'identity'), patch.object(subject,'retained',return_value=raw):
                args = (self.nomination,sha256(raw),self.ctx,entry,self.approval,self.artifact)
                if good:
                    subject._pre_attempt(*args)
                    with self.assertRaises(BuildError):
                        subject._pre_attempt(args[0],'a'*64,*args[2:])
                else:
                    with self.assertRaises(BuildError):
                        subject._pre_attempt(*args)
        with patch.object(subject,'public_issue',return_value=({},'a',{},self.ctx)), \
                patch.object(subject.seal,'read_private') as private, self.assertRaisesRegex(BuildError,'overlapping'):
            subject.replay(self.approval,self.artifact,self.signer,self.release_path,self.release_path,'a',
                           self.archive,UID,'b',host_loss=False)
        private.assert_not_called()

    def test_issued_host_join_compares_attempt_media_recorder_and_window(self):
        manifest, files, facts, wrapper = inert(self.ctx)
        entry = facts | {'disk_sha256': self.ctx['media']['disk_sha256']}
        self.assertEqual(subject._capture(manifest,files,self.ctx,entry)[0], files['serial.raw'])
        for altered, nom, archive in [
            ({'serial.raw':files['serial.raw']+b'changed'},entry,manifest),
            ({'owner-terminal.json':canonical(wrapper | {'media': self.ctx['media'] | {'uki_sha256':'9'*64}})},entry,manifest),
            ({'owner-terminal.json':canonical(wrapper | {'start_check_raw_ns': 1007})},entry,manifest),
            ({},entry | {'expires_utc':120},manifest), ({},entry | {'host_identity_sha256':'9'*64},manifest),
            ({},entry,manifest | {'ledger_attempt_identity':None})]:
            with self.subTest(keys=list(altered), end=nom['expires_utc']), self.assertRaises(BuildError):
                subject._capture(archive, files | altered, self.ctx, nom)

    def test_verified_binary_and_external_bindings_required_before_raw_archive(self):
        manifest, files, facts, _ = inert(self.ctx)
        # Not a parseable private release: this isolated orchestration test replaces the issuer trust boundary.
        entry = facts | {'disk_sha256':self.ctx['media']['disk_sha256']}
        fake = {'approved_attempts': [entry]}
        with ExitStack() as s:
            s.enter_context(patch.object(subject,'public_issue',return_value=({},'digest',{},self.ctx)))
            s.enter_context(patch.object(subject.seal,'read_private',return_value=fake))
            s.enter_context(patch.object(subject.seal,'release_digest',return_value=self.pin['release_sha256']))
            binary=s.enter_context(patch.object(subject.owner,'verify_artifact'))
            external=s.enter_context(patch.object(subject,'_pre_attempt'))
            read=s.enter_context(patch.object(subject,'read_owner_archive',return_value=(manifest,files)))
            binary.side_effect=BuildError('binary')
            with self.assertRaisesRegex(BuildError,'binary'):
                self.replay()
            external.assert_not_called()
            read.assert_not_called()
            binary.side_effect=None
            external.side_effect=BuildError('independent')
            with self.assertRaisesRegex(BuildError,'independent'):
                self.replay()
            read.assert_not_called()
            external.side_effect=None
            self.assertEqual(self.replay()['guest']['status'],'matching_candidate_record_only')
            with patch.object(subject.predecessor,'compare_serial',side_effect=BuildError('invalid console record')):
                report=self.replay()
            self.assertEqual((report['host'], report['guest']['status']), ('consistent-issued-transcript','indeterminate'))
            self.assertFalse(report['boot_verified'] or report['retry_authorized'] or report['phase3_exit_eligible'])
