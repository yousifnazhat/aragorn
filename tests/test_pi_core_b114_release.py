"""Offline B114 seal/shape controls only. No slot is signed, compiled, saved or issued."""
import unittest
from pathlib import Path
from unittest.mock import patch

from scripts import pi_core_b114_release as s
from scripts.build_pi_core_linux import BuildError, canonical, sha256


def example():
    # Nonexistent fixture/host and an expired window; these values live only in memory.
    e = {k: sha256(("inert " + k).encode()) for k in s.HASHES}
    e.update(disk_sha256=s.DISK, attempt_uuid="00000000-0000-4000-8000-000000000001",
             fixture="/nonexistent/b114-unit-fixture", not_before_utc=1, expires_utc=2)
    e.update({k: {"dev": 2, "ino": n+1} for n, k in enumerate(s.IDENTITIES)})
    release = {"schema": s.owner.HELD["schema"], "approved_attempts": [e]}
    pins = {"release_sha256": sha256(canonical(release)), **{k: e[k] for k in s.APPROVALS}}
    return e, release, pins


class B114Release(unittest.TestCase):
    def test_shipped_seal_refuses_before_any_private_file_or_closure_read(self):
        raw = s.SEAL.read_bytes()
        self.assertEqual(s._object(raw), s.HELD_SEAL)
        with patch.object(s, "verify_commit") as auth, patch.object(s, "signed_blob", return_value=raw) as blob, \
                patch.object(s, "read_private") as private:
            with self.assertRaisesRegex(BuildError, "held B114 seal"):
                s.authorized_material(s.BASELINE, "unused", None)
        auth.assert_called_once_with(s.BASELINE, "unused")
        blob.assert_called_once_with(s.BASELINE, s.SEAL)
        private.assert_not_called()

    def test_seal_binds_exact_candidate_and_distinct_original_approval_digests(self):
        _, _, pins = example()
        doc = s.HELD_SEAL | {"approved": pins}
        self.assertEqual(s.approved_digest(canonical(doc)), pins)
        for change in ({"schema": "aragorn/b50-private-build-seal/v1"},
                       {"candidate": doc["candidate"] | {"proposal": "f"*64}},
                       {"enabled": True}, {"approved": pins | {"extra": "a"*64}},
                       {"approved": pins | {"boot_approval_sha256": pins["nomination_sha256"]}},
                       {"approved": {k: v for k, v in pins.items() if k != "enrollment_sha256"}}):
            with self.subTest(change=change), self.assertRaises(BuildError):
                s.approved_digest(canonical(doc | change))
        with self.assertRaisesRegex(BuildError, "duplicate"):
            s.approved_digest(canonical(doc).replace(b'{"approved":', b'{"approved":null,"approved":', 1))

    def test_only_exact_one_slot_content_matches_out_of_band_seal(self):
        entry, release, pins = example()
        self.assertEqual(s.match_private(pins, canonical(release)), release)
        for wrong in (release | {"schema": "aragorn/b50-single-use-release/v1"}, s.owner.HELD,
                      release | {"approved_attempts": [entry, entry]},
                      release | {"approved_attempts": [entry | {"disk_sha256": "a"*64}]},
                      release | {"approved_attempts": [entry | {"fixture_identity": entry["disk_identity"]}]},
                      release | {"approved_attempts": [entry | {"expires_utc": True}]},
                      release | {"approved_attempts": [entry | {"nonce": "unreviewed"}]}):
            with self.subTest(wrong=wrong), self.assertRaises(BuildError):
                s.match_private(pins, canonical(wrong))
        for field in s.PIN_KEYS:
            with self.subTest(field=field), self.assertRaises(BuildError):
                s.match_private(pins | {field: "f"*64}, canonical(release))
        with self.assertRaisesRegex(BuildError, "duplicate"):
            s.match_private(pins, canonical(release).replace(b'"fixture":', b'"fixture":null,"fixture":', 1))

    def test_git_restricts_commit_signer_paths_and_rejects_symlink_blob(self):
        signer, commit = "SHA256:" + "b"*43, "a"*40
        with patch.object(s.b113, "_git", return_value=f"{commit}\nG\nSHA256:{'c'*43}\n".encode()):
            with self.assertRaisesRegex(BuildError, "wrong source or signer"):
                s.verify_commit(commit, signer)
        with patch.object(s.b113, "_git") as git:
            for op in (lambda: s.verify_commit("HEAD", signer), lambda: s.require_ancestor(commit, commit),
                       lambda: s.signed_blob(commit, Path("/tmp/unreviewed"))):
                with self.assertRaises(BuildError):
                    op()
            git.assert_not_called()
        with patch.object(s.b113, "_git", return_value=b"120000 blob " + b"a"*40 + b"\t" +
                          s.SEAL.relative_to(s.ROOT).as_posix().encode() + b"\0") as git:
            with self.assertRaisesRegex(BuildError, "nonregular"):
                s.signed_blob(commit, s.SEAL)
            self.assertEqual(git.call_count, 1)

    def test_changed_frozen_source_and_unreviewed_worktree_refuse_before_private_read(self):
        _, _, pins = example()
        signed_seal = canonical(s.HELD_SEAL | {"approved": pins})
        def blob(commit, path):
            if path == s.SEAL:
                return signed_seal
            return b"previous" if commit == s.BASELINE else b"wrong"
        with patch.object(s, "verify_commit"), patch.object(s, "signed_blob", side_effect=blob), \
                patch.object(s, "require_ancestor"), patch.object(s, "read_private") as private:
            with self.assertRaisesRegex(BuildError, "frozen"):
                s.authorized_material("a"*40, "unused", None)
            private.assert_not_called()
        data = {p: b"expected" for p in s.REVIEWED_SOURCES}
        self.assertNotIn(s.ARTIFACT, data)
        for sources in ({s.SEAL: b"x"}, data):
            with patch.object(s, "approved_source", return_value=(pins, "unused", sources)), \
                    patch.object(s.owner.host, "source_bytes", return_value=b"changed"), patch.object(s, "read_private") as private:
                with self.assertRaisesRegex(BuildError, "working sources"):
                    s.authorized_material("a"*40, "unused", None)
                private.assert_not_called()

    def test_real_time_build_refuses_expired_window_without_invalidating_historical_release(self):
        _, release, pins = example()
        data = {p: b"example" for p in s.REVIEWED_SOURCES}
        with patch.object(s, "approved_source", return_value=(pins, "unused", data)), \
                patch.object(s.owner.host, "source_bytes", return_value=b"example"), \
                patch.object(s, "read_private", return_value=release), patch.object(s.time, "time_ns", return_value=2*10**9):
            with self.assertRaisesRegex(BuildError, "expired"):
                s.authorized_material("a"*40, "unused", None)
        self.assertEqual(s.release_digest(release), pins["release_sha256"])
