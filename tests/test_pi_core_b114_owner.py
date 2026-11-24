"""Inert builder controls only. Never issue a grant or invoke compiler, signer, runner or VM."""
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest import TestCase, mock

from scripts import prepare_pi_core_b114_owner as owner
from scripts.build_pi_core_linux import BuildError, canonical


class B114IssueBuilder(TestCase):
    def test_denied_seal_never_reaches_render_tools_or_private_output(self):
        # The signed-seal implementation has separate authentication tests; check its builder boundary here.
        with mock.patch.object(owner.seal, "authorized_material", side_effect=BuildError("hold")) as authenticate, \
             mock.patch.object(owner, "_materials") as render, mock.patch.object(owner, "_tools") as tools, \
             mock.patch.object(owner, "_reserve") as reserve, mock.patch.object(owner, "_compile") as compiler:
            with self.assertRaisesRegex(BuildError, "hold"):
                owner.build("1"*40, "untrusted", Path("/not-opened"))
            authenticate.assert_called_once()
            for operation in (render, tools, reserve, compiler):
                operation.assert_not_called()

    def test_only_exact_two_native_input_changes_start_from_frozen_b113(self):
        prior = {owner.old.PIN: owner.old.host.source_bytes(owner.old.PIN)}
        files, media = owner._template(prior)
        # NOT even syntactically a release. The pure renderer returns bytes only, not an artifact or slot.
        inert = b"NOT A GRANT"
        rendered = owner._render(files, inert)
        self.assertEqual({k for k in files if files[k] != rendered[k]}, {"b45-binding.inc", "b50-embedded-release.h"})
        self.assertEqual(rendered["b45-binding.inc"].replace(owner.ID.encode(), owner.old.ID.encode()),
                         files["b45-binding.inc"])
        self.assertEqual(rendered["b50-embedded-release.h"],
                         owner.old.arrays("B50ReleaseBytes", inert) + owner.old.arrays("B113Media", canonical(media)))
        self.assertEqual(files["supervised-owner.m"].count(b"B50PreStart()"), 1)
        self.assertIn(b"B50Consume(r,session)", rendered["owner-runner.m"])

    def test_mutated_source_cannot_reuse_matching_ingredient_record(self):
        prior = {owner.old.PIN: owner.old.host.source_bytes(owner.old.PIN)}
        files, spec = owner.old.snapshots()
        for mapped, summary in ((files | {"owner-runner.m": b"unreviewed"}, spec),
                                (files, spec | {"release_sha256": "0"*64})):
            with self.subTest(), mock.patch.object(owner.old, "snapshots", return_value=(mapped, summary)), \
                 self.assertRaisesRegex(BuildError, "generated source/tool/media"):
                owner._template(prior)

    def test_changed_grant_does_not_bypass_existing_attempt_or_recover_partial_build(self):
        # No fresh reservation is issued: the fixture supplies the spent claim and partial directory.
        uid = "00000000-0000-4000-8000-000000000001"
        with TemporaryDirectory() as tmp:
            root = Path(tmp).resolve() / "custody"
            root.mkdir(mode=0o700)
            with mock.patch.object(owner, "WORK", root):
                claim = root / owner._claim_name(uid)
                claim.mkdir(mode=0o700)
                old = owner._issued_dir("1"*64)
                old.mkdir(mode=0o700)
                marker = old / "partial"
                marker.write_bytes(b"original")
                for digest in ("1"*64, "2"*64):
                    with self.subTest(digest=digest), self.assertRaises(FileExistsError):
                        owner._reserve(uid, digest)
                self.assertEqual(set(root.iterdir()), {old, claim})
                self.assertEqual(marker.read_bytes(), b"original")

    def test_held_or_substituted_bytes_refuse_before_codesign(self):
        media, private = {"test": "media"}, b"not a slot"
        with TemporaryDirectory() as temp, mock.patch.object(owner.host, "run") as external_tool:
            exe = Path(temp).resolve() / "not-executable-code"
            exe.write_bytes(canonical(media) + private + owner.old.RELEASE)
            exe.chmod(0o500)
            with self.assertRaisesRegex(BuildError, "held or substituted"):
                owner._properties(exe, media, private)
            external_tool.assert_not_called()
