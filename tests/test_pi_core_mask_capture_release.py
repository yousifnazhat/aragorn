"""One-use release tests with inert kernel, clock and storage stand-ins only."""
from contextlib import nullcontext
from pathlib import Path
from types import SimpleNamespace
import os
import stat
import unittest
from unittest.mock import Mock, call, patch

from aragorn import pi_core_mask_capture_release as release
from aragorn.pi_core_coordinator_entry import _Inputs
from aragorn.pi_core_stopped_mask_capture import StoppedMaskCapture


def pin(c):
    return "sha256:" + c * 64


class MaskRelease(unittest.TestCase):
    def setUp(self):
        self.cfg = StoppedMaskCapture(Path("/evidence/raw"), Path("/evidence/receipts"), "1"*32,
                                      pin("d"), pin("4"), pin("5"), "253:7", ("259:0",), "ext4")
        self.inputs = _Inputs(23.0)
        self.inputs.rows = [dict(path=Path("/approved/plan.json"), pin=pin("a"))]
        device = os.makedev(8, 2)
        self.ledger = dict(dev="8:2", ino=5, mnt_id=21)
        self.doc = dict(schema="aragorn/pi-core-stopped-mask-release/v1", scope=release.SCOPE,
                        plan_digest=pin("a"), host_profile_digest=pin("b"), deployment_digest=pin("d"),
                        attempt_id=self.cfg.attempt_id, max_starts=1, boot_id="d25532ed-0952-44bf-90fa-0d72dd1773da",
                        claim_directory=self.ledger, not_before_unix_ns=10**12, expires_unix_ns=10**12 + 4*10**9)
        self.inputs.read = Mock(return_value=self.doc)
        self.inputs.guard = Mock()
        m = dict(mount_id=1, dev="8:1", root="/", options={"ro"}, fs_type="ext4")
        self.mounts = {"/":m, str(release.CLAIM_ROOT):dict(m, mount_id=21, root="/ledger", dev="8:2", options={"rw"}),
                       "/evidence":dict(m, mount_id=22, root="/evidence", dev="8:2", options={"rw"})}
        self.evidence_roots = ((device, 6), (device, 7))
        self.enterContext(patch.object(release.time, "monotonic_ns", return_value=20*10**9))
        self.wall = self.enterContext(patch.object(release.time, "time_ns", return_value=10**12))
        self.enterContext(patch.object(release.view, "_platform"))
        self.enterContext(patch.object(release.view, "_stat", return_value=self.ledger))
        self.kernel = self.enterContext(patch.object(release, "_kernel_inputs", return_value=(self.doc["boot_id"], b"fixture")))
        self.enterContext(patch.object(release, "verify_mounts", side_effect=lambda *a, **kw:
            kw["mount_details"].update(self.mounts)))
        self.roots = self.enterContext(patch.object(release.custody, "_roots", side_effect=lambda a,b,d:
            nullcontext((8, Mock(), self.evidence_roots))))
        self.spend = self.enterContext(patch.object(release, "_spend"))

    def claim(self):
        return release.claim_capture_release(self.inputs, release_digest=pin("c"), plan_digest=pin("a"),
            host_profile_digest=pin("b"), capture=self.cfg, deadline=23.0)

    def test_nominated_boot_plan_window_and_claim_precede_return(self):
        self.assertRegex(self.claim(), "^sha256:[0-9a-f]{64}$")
        self.inputs.read.assert_called_once_with(release.RELEASE_PATH, pin("c"), 8192)
        self.assertEqual(self.spend.call_args.args[:2], (8, "spent-" + self.cfg.attempt_id + ".json"))
        self.assertIn(b'"status":"SPENT"', self.spend.call_args.args[2])
        self.assertEqual(self.kernel.call_count, 2)

    def test_release_must_match_external_scope_boot_host_deployment_attempt_and_original_deadline(self):
        for k,v in (("scope","PILOT"),("max_starts",True),("max_starts",2),("plan_digest",pin("9")),
                    ("host_profile_digest",pin("8")),("deployment_digest",pin("7")),("attempt_id","3"*32),
                    ("expires_unix_ns",10**12+2*10**9),("expires_unix_ns",10**12+301*10**9),
                    ("not_before_unix_ns",10**12+1),("boot_id","2949cc6e-a894-4330-8441-53b3d70f7e8f"),
                    ("claim_directory",dict(self.ledger, ino=7)), ("another_authority", True)):
            with self.subTest(k=k,v=v), patch.dict(self.doc,{k:v}), self.assertRaises(ValueError):
                self.claim()
        self.inputs.rows.clear()
        with self.assertRaises(ValueError):
            self.claim()
        self.spend.assert_not_called()

    def test_no_dispatch_if_boot_changed_or_window_expired_after_spend(self):
        self.kernel.side_effect = [(self.doc["boot_id"],b"fixture"),("d111394a-d648-4368-9f17-b233306b7f76", b"fixture")]
        with self.assertRaisesRegex(ValueError, "another guest boot"):
            self.claim()
        self.spend.assert_called_once()
        self.kernel.side_effect = None
        self.wall.side_effect = [10**12, 10**12, 10**12+4*10**9]
        with self.assertRaisesRegex(ValueError, "insufficient"):
            self.claim()
        self.assertEqual(self.spend.call_count, 2)

    def test_volatile_shared_subtrees_readonly_mount_or_changed_target_refuse(self):
        for extra in ({"root":"/evidence/raw"},{"fs_type":"tmpfs"},{"options":{"ro"}},
                      {"dev":"253:7"},{"mount_id":34}):
            bad = dict(self.mounts[str(release.CLAIM_ROOT)], **extra)
            with self.subTest(extra=extra), patch.dict(self.mounts,{str(release.CLAIM_ROOT):bad}), self.assertRaises(ValueError):
                self.claim()
        with patch.dict(self.mounts,{"/approved/export": self.mounts[str(release.CLAIM_ROOT)]}), self.assertRaises(ValueError):
            self.claim()
        self.spend.assert_not_called()

    def arm(self):
        raw = release.canonical_json(self.doc)
        self.inputs.rows.append(dict(path=release.RELEASE_PATH, pin=pin("c"), raw=raw, fd=42))
        pread = self.enterContext(patch.object(release.os, "pread", return_value=raw))
        read = self.enterContext(patch.object(release, "_read_claim"))
        claim_digest = self.claim()
        def guard():
            return release.guard_capture_start(self.inputs, release_digest=pin("c"),
                                               claim_digest=claim_digest, capture=self.cfg, deadline=23.0)
        return guard, pread, read

    def test_final_guard_rereads_original_claim_and_release_without_spending_and_cannot_retry(self):
        guard, pread, read = self.arm()
        self.assertIsNone(guard())
        pread.assert_called_once_with(42, 8193, 0)
        read.assert_called_once_with(*self.spend.call_args.args, self.spend.return_value)
        with self.assertRaisesRegex(ValueError, "already used"):
            guard()
        self.spend.assert_called_once()

    def test_expired_final_guard_never_reclaims(self):
        guard, _, read = self.arm()
        self.wall.return_value += 4*10**9
        with self.assertRaisesRegex(ValueError, "insufficient"):
            guard()
        read.assert_not_called()
        self.spend.assert_called_once()

    def test_withdrawn_final_release_never_reclaims(self):
        guard, pread, read = self.arm()
        pread.return_value = b""
        with self.assertRaisesRegex(ValueError, "withdrawn"):
            guard()
        read.assert_not_called()
        self.spend.assert_called_once()

    def test_final_guard_refuses_changed_evidence_roots(self):
        guard, pread, _ = self.arm()
        self.evidence_roots = (self.evidence_roots[0], (self.evidence_roots[1][0], 99))
        with self.assertRaisesRegex(ValueError, "custody roots changed"):
            guard()
        pread.assert_not_called()
        self.spend.assert_called_once()


class ExactClaim(unittest.TestCase):
    def test_replaced_claim_identity_refused_before_read_even_with_same_bytes(self):
        out = SimpleNamespace(st_uid=0, st_gid=0, st_mode=stat.S_IFREG|0o400, st_size=2, st_nlink=1)
        with patch.object(release.os, "stat", return_value=out), \
             patch.object(release.custody.files, "_file_identity", return_value=(8,2)), \
             patch.object(release.custody.files, "_read_owned_bytes_at", return_value=b"ok") as read:
            with self.assertRaisesRegex(ValueError, "identity changed"):
                release._read_claim(8, "spent", b"ok", (8,1))
            read.assert_not_called()

    def test_create_is_exclusive_with_full_fsync_readback_no_retry_or_unlink(self):
        fd = 5
        h = Mock(wraps=os)
        for k in ("O_WRONLY","O_CREAT","O_EXCL","O_NOFOLLOW","O_CLOEXEC"):
            setattr(h,k,getattr(os,k))
        h.open.return_value = fd
        out = dict(st_uid=0, st_gid=0, st_mode=stat.S_IFREG|0o400, st_nlink=1, st_size=0)
        first = SimpleNamespace(**out)
        last = SimpleNamespace(**(out | {"st_size":2}))
        h.fstat.side_effect = [first, last, first]
        h.stat.return_value = last
        h.close = Mock()
        h.fsync = Mock()
        with patch.object(release,"os",h), patch.object(release.custody.files,"_file_identity",side_effect=id), \
             patch.object(release.custody.files,"write_all") as write, \
             patch.object(release.custody.files,"_read_owned_bytes_at",return_value=b"ok"):
            release._spend(9, "spent", b"ok")
            h.open.assert_called_once_with("spent",os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,
                                           0o400,dir_fd=9)
            self.assertEqual(h.fsync.call_args_list,[call(fd),call(9)])
            write.side_effect = OSError("uncertain write")
            with self.assertRaises(OSError):
                release._spend(9, "spent", b"ok")
            h.open.side_effect = FileExistsError("spent")
            with self.assertRaises(FileExistsError):
                release._spend(9,"spent",b"ok")
            self.assertEqual(write.call_count,2)
            self.assertEqual(h.close.call_count,2)
            h.unlink.assert_not_called()
