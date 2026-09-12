from __future__ import annotations

import fcntl
import os
import unittest
from io import BytesIO
from unittest.mock import Mock, patch

from aragorn import protected_install, protected_install_v2
from aragorn.acquire import ingest_local
from aragorn.oci_worker_protocol import canonical_json
from aragorn.protected_install import ProtectedInstallTransactionError
from aragorn.protected_install_context import VerifiedInstallContextV2
from aragorn.protected_install_v2 import _publish_protected_install_transaction
from aragorn.protected_skill_quarantine import publish_quarantine_at
from tests import test_protected_install as baseline

_digest = baseline._digest
_retain_manifest = baseline._retain_manifest


class ProtectedInstallV2Tests(unittest.TestCase):
    setUp = baseline.ProtectedInstallTransactionTests.setUp
    _context = baseline.ProtectedInstallTransactionTests._context

    def _publish(self, context: VerifiedInstallContextV2, *, provider=None) -> dict:
        with patch(
            "aragorn.protected_install.verify_protected_install_context_v2",
            return_value=context,
        ):
            return _publish_protected_install_transaction(
                self.cas,
                {},
                self.root_fd,
                now_unix=100,
                claim_now_unix=100,
                expected_context_digest=context.context_digest,
                expected_target_name=context.target_name,
                expected_runtime_conformance_digest=(
                    context.runtime_conformance_digest
                ),
                measured_target_runtime_digest=context.target_runtime_digest,
                revoked_context_ids=(),
                expected_active_cas=(
                    self.cas if context.expected_active_context_id is not None else None
                ),
                claim_state_provider=provider,
            )

    def _quarantine(self, skill_digest: str) -> None:
        fcntl.flock(self.root_fd, fcntl.LOCK_EX)
        try:
            publish_quarantine_at(
                self.root_fd, skill_digest, _digest("9"), expected_uid=os.geteuid()
            )
        finally:
            fcntl.flock(self.root_fd, fcntl.LOCK_UN)

    @staticmethod
    def _version_path(context: VerifiedInstallContextV2) -> str:
        return (
            ".aragorn-versions/admitted-skill/"
            f"{context.context_id.removeprefix('sha256:')}-"
            f"{context.manifest_digest.removeprefix('sha256:')}"
        )

    def test_quarantined_bytes_reject_new_contexts_and_manifests_before_staging(
        self,
    ) -> None:
        _, same_bytes_manifest = _retain_manifest(
            self.cas, self.root, "source-a-again", b"A"
        )
        self.assertNotEqual(same_bytes_manifest, self.manifest_a_digest)
        skill_digest = self.manifest_a["files"][0]["digest"]
        self._quarantine(skill_digest)
        for character, manifest_digest in (
            ("1", self.manifest_a_digest),
            ("2", same_bytes_manifest),
        ):
            context = self._context(
                context_character=character,
                manifest_digest=manifest_digest,
                operation="install",
                expected_active=None,
            )
            with (
                self.subTest(context=character),
                patch.object(protected_install, "_create_staging_directory") as stage,
                self.assertRaisesRegex(
                    ProtectedInstallTransactionError, "before consuming"
                ),
            ):
                self._publish(context)
            stage.assert_not_called()
            self.assertFalse(
                os.path.lexists(self.protected / self._version_path(context))
            )
        self.assertEqual(
            list((self.protected / ".aragorn-install-claims").glob("*")), []
        )
        self.assertFalse(os.path.lexists(self.protected / "admitted-skill"))

    def test_quarantined_predecessor_allows_clean_update_but_not_rollback(self) -> None:
        installed = self._context(
            context_character="1",
            manifest_digest=self.manifest_a_digest,
            operation="install",
            expected_active=None,
        )
        self._publish(installed)
        active = self.protected / "admitted-skill"
        record = self.protected / ".aragorn-active-runtime.json"
        before_record = record.read_bytes()
        self._quarantine(self.manifest_a["files"][0]["digest"])
        self.assertEqual(record.read_bytes(), before_record)
        self.assertEqual(os.readlink(active), self._version_path(installed))
        self.assertEqual((active / "SKILL.md").read_bytes(), b"A")

        updated = self._context(
            context_character="2",
            manifest_digest=self.manifest_b_digest,
            operation="update",
            expected_active=(installed.context_id, installed.manifest_digest),
        )
        self._publish(updated)
        clean_record = record.read_bytes()
        rolled_back = self._context(
            context_character="3",
            manifest_digest=self.manifest_a_digest,
            operation="rollback",
            expected_active=(updated.context_id, updated.manifest_digest),
        )
        with self.assertRaisesRegex(
            ProtectedInstallTransactionError, "before consuming"
        ):
            self._publish(rolled_back)
        self.assertEqual(record.read_bytes(), clean_record)
        self.assertEqual(os.readlink(active), self._version_path(updated))
        self.assertEqual((active / "SKILL.md").read_bytes(), b"B")
        self.assertEqual(
            (self.protected / self._version_path(installed) / "SKILL.md").read_bytes(),
            b"A",
        )
        self.assertFalse(
            os.path.lexists(self.protected / self._version_path(rolled_back))
        )
        self.assertFalse(
            (
                self.protected
                / ".aragorn-install-claims"
                / f"{rolled_back.context_id[7:]}.json"
            ).exists()
        )

    def test_candidate_quarantine_rechecked_under_exclusive_lock_before_claim(
        self,
    ) -> None:
        context = self._context(
            context_character="1",
            manifest_digest=self.manifest_a_digest,
            operation="install",
            expected_active=None,
        )
        skill_digest = self.manifest_a["files"][0]["digest"]
        require = protected_install_v2.require_not_quarantined_at
        materialize = protected_install._materialize_verified_manifest
        checks = []

        def require_locked(fd, digest, *, expected_uid):
            other = os.open(self.protected, os.O_RDONLY | os.O_DIRECTORY)
            try:
                with self.assertRaises(BlockingIOError):
                    fcntl.flock(other, fcntl.LOCK_SH | fcntl.LOCK_NB)
            finally:
                os.close(other)
            checks.append(digest)
            return require(fd, digest, expected_uid=expected_uid)

        def quarantine_after_staging(*args):
            materialize(*args)
            # Inject newer trusted state while the transaction still owns root EX.
            publish_quarantine_at(
                self.root_fd, skill_digest, _digest("9"), expected_uid=os.geteuid()
            )

        with (
            patch.object(
                protected_install_v2,
                "require_not_quarantined_at",
                side_effect=require_locked,
            ),
            patch.object(
                protected_install,
                "_materialize_verified_manifest",
                side_effect=quarantine_after_staging,
            ),
            self.assertRaisesRegex(
                ProtectedInstallTransactionError, "before consuming"
            ),
        ):
            self._publish(context)
        self.assertEqual(checks, [skill_digest, skill_digest])
        self.assertEqual(
            list((self.protected / ".aragorn-install-claims").glob("*")), []
        )
        versions = self.protected / ".aragorn-versions" / context.target_name
        self.assertEqual(list(versions.iterdir()), [])
        self.assertFalse(os.path.lexists(self.protected / context.target_name))

    def test_malformed_present_quarantine_refuses_without_consuming_context(
        self,
    ) -> None:
        skill_digest = self.manifest_a["files"][0]["digest"]
        marker = self.protected / f".aragorn-quarantined-skill-{skill_digest[7:]}.json"
        marker.write_bytes(b"{")
        marker.chmod(0o444)
        context = self._context(
            context_character="1",
            manifest_digest=self.manifest_a_digest,
            operation="install",
            expected_active=None,
        )
        with self.assertRaisesRegex(
            ProtectedInstallTransactionError, "before consuming"
        ):
            self._publish(context)
        self.assertEqual(marker.read_bytes(), b"{")
        self.assertEqual(
            list((self.protected / ".aragorn-install-claims").glob("*")), []
        )
        self.assertFalse(os.path.lexists(self.protected / context.target_name))

    def test_generic_manifest_without_root_skill_keeps_existing_contract(self) -> None:
        source = self.root / "generic-source"
        source.mkdir()
        (source / "README.md").write_bytes(b"generic artifact")
        manifest = ingest_local(source, self.cas)
        raw = canonical_json(manifest)
        manifest_digest = self.cas.put(BytesIO(raw), max_bytes=len(raw))
        context = self._context(
            context_character="1",
            manifest_digest=manifest_digest,
            operation="install",
            expected_active=None,
        )
        with patch.object(
            protected_install_v2, "require_not_quarantined_at"
        ) as checked:
            self._publish(context)
        checked.assert_not_called()
        self.assertEqual(
            (self.protected / context.target_name / "README.md").read_bytes(),
            b"generic artifact",
        )

    def test_claim_provider_keeps_its_order_and_exact_fresh_state(self) -> None:
        context = self._context(
            context_character="1",
            manifest_digest=self.manifest_a_digest,
            operation="install",
            expected_active=None,
        )
        events = []
        revoked = []
        require = protected_install_v2.require_not_quarantined_at

        def require_traced(*args, **kwargs):
            events.append("deny-check")
            return require(*args, **kwargs)

        def provider():
            events.append("provider")
            versions = self.protected / ".aragorn-versions" / context.target_name
            staged = list(versions.glob(".aragorn-stage-*"))
            self.assertEqual(len(staged), 1)
            self.assertEqual((staged[0] / "SKILL.md").read_bytes(), b"A")
            return 111, revoked

        def verify(*args, **kwargs):
            events.append("verify")
            if kwargs["now_unix"] == 111:
                self.assertIs(kwargs["revoked_context_ids"], revoked)
            return context

        with (
            patch.object(
                protected_install_v2,
                "require_not_quarantined_at",
                side_effect=require_traced,
            ),
            patch.object(
                protected_install,
                "verify_protected_install_context_v2",
                side_effect=verify,
            ),
        ):
            # _publish's verifier mock would hide the callback trace here.
            result = _publish_protected_install_transaction(
                self.cas,
                {},
                self.root_fd,
                now_unix=100,
                claim_now_unix=100,
                expected_context_digest=context.context_digest,
                expected_target_name=context.target_name,
                expected_runtime_conformance_digest=context.runtime_conformance_digest,
                measured_target_runtime_digest=context.target_runtime_digest,
                revoked_context_ids=(),
                claim_state_provider=provider,
            )
        self.assertEqual(result["context_id"], context.context_id)
        self.assertEqual(
            events,
            ["verify", "deny-check", "verify", "provider", "deny-check", "verify"],
        )

    def test_delegated_result_and_recovery_error_are_preserved_exactly(self) -> None:
        context = self._context(
            context_character="1",
            manifest_digest=self.manifest_a_digest,
            operation="install",
            expected_active=None,
        )
        result = {"opaque": "legacy transaction result"}
        with patch.object(
            protected_install,
            "_publish_protected_install_transaction",
            return_value=result,
        ):
            self.assertIs(self._publish(context), result)
        error = ProtectedInstallTransactionError(
            "legacy failure after consuming its context",
            recovery={"context_id": "held"},
        )
        with (
            patch.object(
                protected_install,
                "_publish_protected_install_transaction",
                side_effect=error,
            ),
            self.assertRaises(ProtectedInstallTransactionError) as raised,
        ):
            self._publish(context)
        self.assertIs(raised.exception, error)
        self.assertEqual(raised.exception.recovery, {"context_id": "held"})
        other = os.open(self.protected, os.O_RDONLY | os.O_DIRECTORY)
        try:
            fcntl.flock(other, fcntl.LOCK_EX | fcntl.LOCK_NB)
            fcntl.flock(other, fcntl.LOCK_UN)
        finally:
            os.close(other)

    def test_post_claim_activation_failure_retains_recoverable_state(self) -> None:
        context = self._context(
            context_character="1",
            manifest_digest=self.manifest_a_digest,
            operation="install",
            expected_active=None,
        )
        with (
            patch.object(
                protected_install,
                "_rename_activation_link",
                side_effect=RuntimeError("injected activation failure"),
            ),
            self.assertRaisesRegex(
                ProtectedInstallTransactionError,
                "after consuming.*no rollback was attempted",
            ) as raised,
        ):
            self._publish(context)
        self.assertEqual(raised.exception.recovery["context_id"], context.context_id)
        self.assertEqual(
            raised.exception.recovery["version_path"], self._version_path(context)
        )
        claim = (
            self.protected
            / ".aragorn-install-claims"
            / f"{context.context_id[7:]}.json"
        )
        self.assertTrue(claim.is_file())
        self.assertTrue((self.protected / self._version_path(context)).is_dir())
        self.assertFalse(os.path.lexists(self.protected / context.target_name))

    def test_provider_failure_is_not_called_again_and_consumes_no_context(self) -> None:
        context = self._context(
            context_character="1",
            manifest_digest=self.manifest_a_digest,
            operation="install",
            expected_active=None,
        )
        provider = Mock(side_effect=RuntimeError("state unavailable"))
        with (
            patch.object(
                protected_install_v2,
                "require_not_quarantined_at",
                wraps=protected_install_v2.require_not_quarantined_at,
            ) as checked,
            self.assertRaisesRegex(
                ProtectedInstallTransactionError,
                "before consuming.*cannot obtain fresh protected install claim state: state unavailable",
            ),
        ):
            self._publish(context, provider=provider)
        provider.assert_called_once_with()
        checked.assert_called_once()
        self.assertEqual(
            list((self.protected / ".aragorn-install-claims").iterdir()), []
        )
        self.assertFalse(os.path.lexists(self.protected / context.target_name))


if __name__ == "__main__":
    unittest.main()
