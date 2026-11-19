"""Inert review records; test build selection, not allocation, signed authority or a VM start."""
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

from scripts import pi_core_boot_build_seal as seal
from scripts.build_pi_core_linux import BuildError, canonical, sha256
from scripts.pi_core_single_use_release import release_digest
from tests.test_pi_core_single_use_release import entry, envelope


def slip(approved):
    return {"schema": "aragorn/b50-private-build-seal/v1", "purpose": "prepare-single-use-build-only",
            "approved": approved}


class PrivateBootBuildSeal(unittest.TestCase):
    def setUp(self):
        e = entry()
        self.release = envelope(e)
        self.fields = {k: e[k] for k in ("nomination_sha256", "enrollment_sha256", "boot_approval_sha256")}
        self.fields["release_sha256"] = release_digest(self.release)

    def test_signed_build_scope_selects_only_matching_singleton(self):
        expected = seal.approved_digest(canonical(slip(self.fields)))
        self.assertEqual(expected, self.fields)
        self.assertEqual(seal.match_private(expected, canonical(self.release)), self.release)
        for bad in (envelope(), envelope(entry(), entry()), envelope(entry() | {"expires_utc": 421})):
            with self.subTest(count=len(bad["approved_attempts"])), self.assertRaises(BuildError):
                seal.match_private(expected, canonical(bad))
        for k in self.fields:
            with self.subTest(k=k), self.assertRaises(BuildError):
                seal.match_private(expected | {k: "9" * 64}, canonical(self.release))

    def test_rejects_incomplete_ambiguous_or_overbroad_signoff(self):
        d = slip(self.fields)
        for bad in (slip(None), d | {"schema": "future"}, d | {"purpose": "boot-now"}, d | {"boot": True},
                    slip(self.fields | {"release_sha256": False}), slip(self.fields | {"also_approve_cleanup": True}),
                    slip(self.fields | {"boot_approval_sha256": self.fields["nomination_sha256"]}),
                    *(slip({k: v for k, v in self.fields.items() if k != omit}) for omit in self.fields)):
            with self.subTest(keys=str(bad)[:100]), self.assertRaises(BuildError):
                seal.approved_digest(canonical(bad))
        good = canonical(d)
        duplicate = good.replace(b'"purpose":', b'"purpose":"wrong","purpose":')
        for raw in (duplicate, b"\xff", b"[", b" " * 32769):
            with self.subTest(size=len(raw)), self.assertRaises(BuildError):
                seal.approved_digest(raw)

    def test_held_signed_seal_never_reads_target_or_private_release(self):
        commit, signer = "b" * 40, "fixture-signer-not-authority"
        with patch.object(seal.binding, "signed_pin") as signed, \
             patch.object(seal, "_blob", return_value=canonical(slip(None))) as blobs, \
             patch.object(seal.binding, "retained", side_effect=AssertionError("must not open a private file")) as opened:
            with self.assertRaises(BuildError):
                seal.reviewed_release(commit, signer, Path("/nonexistent/private-release"), {})
            signed.assert_called_once_with(commit, signer)
            blobs.assert_called_once_with(commit, seal.SEAL)
            opened.assert_not_called()

    def test_exact_signed_sources_then_sealed_private_input_only(self):
        raw_seal = canonical(slip(self.fields)) + b"\n"
        commit = "b" * 40
        def blob(commit, p):
            return raw_seal if p == seal.SEAL else p.relative_to(seal.ROOT).as_posix().encode()
        good = {p: sha256(blob(commit, p)) for p in seal.REVIEWED_SOURCES}
        first = min(p for p in good if p != seal.SEAL)
        for bad in (good | {first: "f" * 64}, {p: h for p, h in good.items() if p != first}):
            with self.subTest(count=len(bad)), patch.object(seal.binding, "signed_pin"), \
                 patch.object(seal, "_blob", side_effect=blob), \
                 patch.object(seal.binding, "retained", side_effect=AssertionError("unreviewed input")) as opened:
                with self.assertRaises(BuildError):
                    seal.reviewed_release(commit, "fixture-signer", Path("/nonexistent/private-release"), bad)
                opened.assert_not_called()
        with TemporaryDirectory() as tmp, patch.object(seal.binding, "signed_pin") as signed, \
             patch.object(seal, "_blob", side_effect=blob):
            private = Path(tmp).resolve(strict=True) / "inert-fixture.json"
            private.write_bytes(canonical(self.release))
            private.chmod(0o400)
            got = seal.reviewed_release(commit, "fixture-signer", private, good)
            self.assertEqual(got, (self.release, sha256(raw_seal)))
            signed.assert_called_once_with(commit, "fixture-signer")
