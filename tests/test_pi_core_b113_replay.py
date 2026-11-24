"""Only inert wire examples. No issued release, actual capture, VM or enrollment."""
from contextlib import redirect_stdout
from io import StringIO
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from scripts import verify_pi_core_b113_boot_evidence as v
from scripts.build_pi_core_linux import BuildError, canonical, sha256
from scripts.pi_core_owner_archive import export_owner_archive
from test_pi_core_owner_records import UID, owner_fixture
from test_pi_core_owner_watchdog_records import watchdog_files


def line(m):
    return (f'other console text\nARAGORN_B44_V1 boot={UID} disk_ro=1 part_ro=1 sector=512 '
            f'part_bytes={(m["root_size"]+511)//512*512} root_ro=1 lib_ro=1 lib_same=1 pid=1 '
            f'manager_sha256={m["manager_sha256"]} root_sha256={m["root_sha256"]}\r\n').encode()


def inert(ctx):
    r, m = ctx['runner'], ctx['catalog']
    raw = line(m)
    nodes = [dict(dev=1, ino=i) for i in range(11, 16)]
    facts = dict(attempt_uuid=UID, release_sha256=r['release_sha256'], host_identity_sha256='c'*64,
                 fixture_identity=nodes[0], disk_identity=nodes[2], store_identity=nodes[3],
                 store_sha256='d'*64, policy_sha256='e'*64, not_before_utc=100, expires_utc=400)
    expected = {k: facts[k] for k in ('fixture_identity', 'disk_identity', 'store_identity')} | {
        'runner_sha256': r['runner_sha256'], 'runner_cdhash': r['cdhash'], 'disk_sha256': m['disk_sha256'],
        'store_sha256_before': facts['store_sha256'], 'policy_sha256_before': facts['policy_sha256'],
        'attempt_identity': nodes[1]}
    files, _ = owner_fixture(UID, expected)
    terminal = json.loads(files['owner-terminal.json'])
    terminal['owner']['capture'].update(capture_bytes=len(raw), capture_sha256=sha256(raw))
    wrapper = dict(schema='aragorn/b113-owner-terminal/v1', release_sha256=r['release_sha256'],
                   host_identity_sha256=facts['host_identity_sha256'], consumed_identity=nodes[1],
                   start_check_raw_ns=1005, start_check_utc_s=120, terminal=terminal, media=ctx['media'])
    files.update({'owner-terminal.json': canonical(wrapper), 'serial.raw': raw})
    files.update(watchdog_files(UID, dict(attempt_start_ns=1000, recorder_armed_ns=1003, start_issued_ns=1006, record_end_ns=1012)))
    manifest = dict(attempt_uuid=UID, fixture_identity=nodes[0], attempt_identity=nodes[1],
                    ledger_attempt_identity=nodes[4], files={n: {'source': {'mode': 0o400}} for n in files})
    return manifest, files, facts, wrapper


class B113Replay(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.blobs = {k: (v.ROOT / p).read_bytes() for k, p in v.PATHS.items()}
        cls.ctx = v.joined(cls.blobs)

    def test_exact_join_refuses_any_other_candidate_release_or_recorder(self):
        for key in self.blobs:
            with self.subTest(key=key), self.assertRaises(BuildError):
                v.joined(self.blobs | {key: self.blobs[key] + b' '})
        with self.assertRaises(BuildError):
            v.joined(self.blobs | {'release': canonical(v.HELD | {'approved_attempts': [{}]}) + b'\n'})

    def test_authentication_precedes_all_blob_reads_and_has_no_checkout_fallback(self):
        commit, signer = '1'*40, 'SHA256:'+'a'*43
        by_path = {commit + ':' + p: self.blobs[k] for k, p in v.PATHS.items()}
        def git(*args):
            if args[0] == 'log':
                return f'{commit}\nG\n{signer}\n'.encode()
            value = by_path[args[-1]]
            return {'-t': b'blob\n', '-s': str(len(value)).encode(), 'blob': value}[args[1]]
        with patch.object(v, '_git', side_effect=git):
            self.assertEqual(v.signed_catalogs(commit, signer), self.ctx)
            with self.assertRaisesRegex(BuildError, 'signature'):
                v.signed_catalogs(commit, 'SHA256:'+'b'*43)
            del by_path[commit + ':' + v.PATHS['proposal']]
            with self.assertRaises(KeyError):
                v.signed_catalogs(commit, signer)

    def test_unchanged_wire_format_distinguishes_b112_root_and_never_authenticates_efi(self):
        m = self.ctx['catalog']
        raw = line(m)
        finding = v.compare_serial(raw, self.ctx, sha256(raw))
        self.assertEqual((finding['status'], finding['candidate_uki_sha256'], finding['capture_sha256']),
                         ('matching_candidate_record_only', m['uki_sha256'], sha256(raw)))
        self.assertFalse(finding['boot_verified'] or finding['external_boot_id_compared'] or finding['host_custody_verified'])
        old = line(m | {'root_size': 3406943909, 'root_sha256': '42f38fc97f01248623fb69f2720d24a42b7e6a405a50124bc7cbe9542601409a'})
        for wrong, pin in [(old, sha256(old)), (raw, '0'*64), (raw+raw, sha256(raw+raw))]:
            with self.subTest(pin=pin), self.assertRaises(BuildError):
                v.compare_serial(wrong, self.ctx, pin)

    def test_archive_consumer_joins_b113_envelope_and_original_bytes_before_reading_guest(self):
        # Deliberately impossible/unpublished issue, different from the *actual* B113
        # runner, catalog and release; only unit-test the future wire join.
        ctx = self.ctx | {'runner_catalog_sha256': '3'*64, 'runner': self.ctx['runner'] | {
            'schema': 'aragorn/b113-single-use-owner/v1', 'boot_authorized': True, 'approval_commit': '1'*40,
            'runner_sha256': 'a'*64, 'cdhash': 'b'*40, 'release_sha256': '2'*64}}
        manifest, files, facts, wrapper = inert(ctx)
        data = v.archive_serial(manifest, files, ctx, host_loss=False, authenticate_issue=lambda *_: facts)
        self.assertEqual(data['record_offset'], len(b'other console text\n'))
        for changed, expected, lost in [
            ({'serial.raw': files['serial.raw'] + b'\n'}, facts, False),
            ({'owner-terminal.json': canonical(wrapper | {'media': self.ctx['media'] | {'esl_sha256': 'f'*64}})}, facts, False),
            ({'owner-terminal.json': canonical(wrapper | {'start_check_raw_ns': 1007})}, facts, False),
            ({'owner-events.jsonl': files['owner-events.jsonl'][:-1]}, facts, False),
            ({v.watchdog.ARM: b'{}'}, facts, False), ({}, facts | {'host_identity_sha256': 'f'*64}, False),
            ({}, facts, True)]:
            with self.subTest(changed=list(changed), loss=lost), patch.object(v, 'compare_serial') as guest:
                with self.assertRaises(BuildError):
                    v.archive_serial(manifest, files | changed, ctx, host_loss=lost, authenticate_issue=lambda *_: expected)
                guest.assert_not_called()
        with self.assertRaisesRegex(BuildError, 'unauthenticated'):
            v.archive_serial(manifest, files, ctx, host_loss=False)

    def test_even_consistent_target_bytes_conflict_with_held_release(self):
        manifest, files, facts, wrapper = inert(self.ctx)
        with patch.object(v, 'compare_serial') as parse, self.assertRaisesRegex(BuildError, 'held'):
            v.archive_serial(manifest, files, self.ctx, host_loss=False, authenticate_issue=lambda *_: self.fail('issue gate bypassed'))
        parse.assert_not_called()
        with patch.object(v, 'archive_serial') as inspect:
            for loss, expected in [(False, 'transcript-conflicts-with-held-release'), (True, 'unresolved-host-loss')]:
                result = v.assess(manifest, files, self.ctx, loss)
                self.assertEqual((result['disposition'], result['guest']['status']), (expected, 'not-evaluated'))
                self.assertFalse(result['boot_authorized'] or result['retry_authorized'] or result['restoration_verified'])
            inspect.assert_not_called()

    def test_real_archive_reader_requires_nominated_digest_and_b113_refusal(self):
        with tempfile.TemporaryDirectory() as temp:
            base = Path(temp).resolve()
            ledger, archive = base/'ledger', base/'archive'
            for p in (ledger, ledger/UID, archive):
                p.mkdir(mode=0o700)
            files = watchdog_files(UID) | {v.watchdog.REFUSAL: v.REFUSAL}
            for name, raw in files.items():
                target = ledger/UID/name
                target.write_bytes(raw)
                target.chmod(0o400)
            digest = export_owner_archive(None, ledger, archive, UID)
            args = ['1'*40, 'SHA256:'+'a'*43, 'replay', str(archive), UID, digest]
            with patch.object(v, 'signed_catalogs', return_value=self.ctx), redirect_stdout(StringIO()) as out:
                self.assertEqual(v.main(args), 0)
                self.assertEqual(json.loads(out.getvalue())['guest'], {'status': 'not-evaluated'})
                self.assertEqual(v.main(args + ['--host-loss']), 2)
                with self.assertRaises(BuildError):
                    v.main(args[:-1] + ['f'*64])
            for wrong in (b'B50 held: no approved boot attempt\n', b''):
                with self.assertRaises(BuildError):
                    v._held(UID, files | {v.watchdog.REFUSAL: wrong})
