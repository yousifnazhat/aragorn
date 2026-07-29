from __future__ import annotations

import os
import unittest
from copy import deepcopy
from dataclasses import replace
from io import BytesIO
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

from aragorn.acquire import ingest_local
from aragorn.artifact_closure import canonical_json
from aragorn.cas import CAS
from aragorn.oci_worker_protocol import canonical_digest
from aragorn.protected_install import (
    ProtectedInstallTransactionError,
    _publish_protected_install_transaction,
)
from aragorn.protected_install_context import (
    ProtectedInstallContextError,
    VerifiedInstallContextV2,
    verify_protected_install_context_v2,
)


def _digest(character: str) -> str:
    return "sha256:" + character * 64


def _retain_manifest(
    cas: CAS, root: Path, name: str, content: bytes
) -> tuple[dict, str]:
    source = root / name
    source.mkdir()
    (source / "SKILL.md").write_bytes(content)
    manifest = ingest_local(source, cas)
    raw = canonical_json(manifest)
    return manifest, cas.put(BytesIO(raw), max_bytes=len(raw))


class ProtectedInstallContextV2Tests(unittest.TestCase):
    def test_v2_binds_install_and_exact_update_predecessors(self) -> None:
        with TemporaryDirectory() as temporary:
            root = Path(temporary)
            cas = CAS(root / "state")
            protected = root / "protected"
            protected.mkdir(mode=0o700)
            root_fd = os.open(
                protected,
                os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
            )
            self.addCleanup(os.close, root_fd)
            root_state = os.fstat(root_fd)
            context = {
                "schema": "aragorn/protected-install-context/v2",
                "authority": "BROKER_CONTEXT_ONLY_NOT_INSTALLER_AUTHORITY",
                "context_id": _digest("1"),
                "status": "active",
                "expires_at_unix": 101,
                "operation": "install",
                "expected_active": None,
                "decision_digest": _digest("2"),
                "manifest_digest": _digest("3"),
                "artifact_graph_digest": _digest("4"),
                "policy_digest": _digest("5"),
                "analyzer_run_receipt_digests": [_digest("6")],
                "analyzer_verifier_digest": _digest("7"),
                "artifact_graph_verifier_digest": _digest("8"),
                "target_runtime_digest": _digest("9"),
                "runtime_conformance_digest": _digest("a"),
                "destination": {
                    "root_device": root_state.st_dev,
                    "root_inode": root_state.st_ino,
                    "target_name": "admitted-skill",
                },
            }

            def verify(candidate: dict[str, object]) -> VerifiedInstallContextV2:
                with patch(
                    "aragorn.protected_install_context.verify_decision_v3",
                    return_value={
                        "verdict": "ALLOW",
                        "manifest_digest": candidate["manifest_digest"],
                    },
                ) as decision_verifier:
                    verified = verify_protected_install_context_v2(
                        cas,
                        candidate,
                        root_fd,
                        now_unix=100,
                        expected_context_digest=canonical_digest(candidate),
                        expected_target_name="admitted-skill",
                        expected_runtime_conformance_digest=_digest("a"),
                        measured_target_runtime_digest=_digest("9"),
                        revoked_context_ids=(),
                    )
                self.assertEqual(
                    decision_verifier.call_args.kwargs[
                        "expected_quarantine_receipt_digest"
                    ],
                    candidate.get("quarantine_receipt_digest"),
                )
                self.assertEqual(
                    decision_verifier.call_args.kwargs[
                        "expected_gateway_profile_digest"
                    ],
                    candidate.get("gateway_profile_digest"),
                )
                return verified

            installed = verify(context)
            self.assertEqual(installed.operation, "install")
            self.assertIsNone(installed.expected_active_context_id)
            self.assertIsNone(installed.expected_active_manifest_digest)

            update = deepcopy(context)
            update.update(
                {
                    "context_id": _digest("b"),
                    "operation": "update",
                    "expected_active": {
                        "context_id": context["context_id"],
                        "manifest_digest": context["manifest_digest"],
                    },
                }
            )
            updated = verify(update)
            self.assertEqual(updated.operation, "update")
            self.assertEqual(
                updated.expected_active_context_id,
                context["context_id"],
            )
            self.assertEqual(
                updated.expected_active_manifest_digest,
                context["manifest_digest"],
            )

            invalid = deepcopy(context)
            invalid["expected_active"] = update["expected_active"]
            with self.assertRaisesRegex(
                ProtectedInstallContextError,
                "must not bind an active predecessor",
            ):
                verify(invalid)

            explicit_local = {
                **context,
                "quarantine_receipt_digest": None,
                "gateway_profile_digest": None,
            }
            verify(explicit_local)

            github_bound = {
                **context,
                "quarantine_receipt_digest": _digest("c"),
                "gateway_profile_digest": _digest("d"),
            }
            verify(github_bound)

            with self.assertRaisesRegex(
                ProtectedInstallContextError,
                "fields are invalid",
            ):
                verify(
                    {
                        **context,
                        "quarantine_receipt_digest": _digest("c"),
                    }
                )


class ProtectedInstallTransactionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.cas = CAS(self.root / "state")
        self.manifest_a, self.manifest_a_digest = _retain_manifest(
            self.cas,
            self.root,
            "source-a",
            b"A",
        )
        self.manifest_b, self.manifest_b_digest = _retain_manifest(
            self.cas,
            self.root,
            "source-b",
            b"B",
        )
        self.manifest_c, self.manifest_c_digest = _retain_manifest(
            self.cas,
            self.root,
            "source-c",
            b"C",
        )
        self.protected = self.root / "protected"
        self.protected.mkdir(mode=0o700)
        self.root_fd = os.open(
            self.protected,
            os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
        )
        self.addCleanup(os.close, self.root_fd)

    def _context(
        self,
        *,
        context_character: str,
        manifest_digest: str,
        operation: str,
        expected_active: tuple[str, str] | None,
    ) -> VerifiedInstallContextV2:
        root_state = os.fstat(self.root_fd)
        return VerifiedInstallContextV2(
            context_digest=_digest(context_character),
            context_id=_digest(context_character),
            decision_digest=_digest("d"),
            manifest_digest=manifest_digest,
            target_runtime_digest=_digest("e"),
            runtime_conformance_digest=_digest("f"),
            root_device=root_state.st_dev,
            root_inode=root_state.st_ino,
            target_name="admitted-skill",
            expires_at_unix=200,
            operation=operation,
            expected_active_context_id=(
                None if expected_active is None else expected_active[0]
            ),
            expected_active_manifest_digest=(
                None if expected_active is None else expected_active[1]
            ),
        )

    def _publish(self, context: VerifiedInstallContextV2) -> dict:
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
                    self.cas
                    if context.expected_active_context_id is not None
                    else None
                ),
            )

    @staticmethod
    def _version_path(context: VerifiedInstallContextV2) -> str:
        return (
            ".aragorn-versions/admitted-skill/"
            f"{context.context_id.removeprefix('sha256:')}-"
            f"{context.manifest_digest.removeprefix('sha256:')}"
        )

    def test_install_update_and_rollback_use_distinct_exact_cas_versions(
        self,
    ) -> None:
        installed = self._context(
            context_character="1",
            manifest_digest=self.manifest_a_digest,
            operation="install",
            expected_active=None,
        )
        install_record = self._publish(installed)
        active = self.protected / "admitted-skill"
        self.assertTrue(active.is_symlink())
        self.assertEqual(os.readlink(active), self._version_path(installed))
        self.assertEqual((active / "SKILL.md").read_bytes(), b"A")
        self.assertEqual(
            install_record["authority"],
            "BROKER_TRANSACTION_RECORD_ONLY_NOT_INSTALLER_AUTHORITY",
        )
        install_claim = (
            self.protected
            / ".aragorn-install-claims"
            / f"{installed.context_id.removeprefix('sha256:')}.json"
        )
        self.assertEqual(install_claim.read_bytes(), canonical_json(install_record))

        updated = self._context(
            context_character="2",
            manifest_digest=self.manifest_b_digest,
            operation="update",
            expected_active=(installed.context_id, installed.manifest_digest),
        )
        self._publish(updated)
        self.assertEqual(os.readlink(active), self._version_path(updated))
        self.assertEqual((active / "SKILL.md").read_bytes(), b"B")

        rolled_back = self._context(
            context_character="3",
            manifest_digest=self.manifest_a_digest,
            operation="rollback",
            expected_active=(updated.context_id, updated.manifest_digest),
        )
        self._publish(rolled_back)
        self.assertEqual(os.readlink(active), self._version_path(rolled_back))
        self.assertEqual((active / "SKILL.md").read_bytes(), b"A")
        self.assertNotEqual(
            self._version_path(installed),
            self._version_path(rolled_back),
        )
        self.assertTrue((self.protected / self._version_path(installed)).is_dir())
        self.assertTrue((self.protected / self._version_path(updated)).is_dir())
        self.assertTrue((self.protected / self._version_path(rolled_back)).is_dir())

    def test_replay_and_aba_contexts_fail_before_a_new_claim(self) -> None:
        installed = self._context(
            context_character="1",
            manifest_digest=self.manifest_a_digest,
            operation="install",
            expected_active=None,
        )
        self._publish(installed)
        with self.assertRaisesRegex(
            ProtectedInstallTransactionError,
            "context is consumed",
        ):
            self._publish(installed)

        updated = self._context(
            context_character="2",
            manifest_digest=self.manifest_b_digest,
            operation="update",
            expected_active=(installed.context_id, installed.manifest_digest),
        )
        self._publish(updated)
        rolled_back = self._context(
            context_character="3",
            manifest_digest=self.manifest_a_digest,
            operation="rollback",
            expected_active=(updated.context_id, updated.manifest_digest),
        )
        self._publish(rolled_back)

        stale = self._context(
            context_character="4",
            manifest_digest=self.manifest_c_digest,
            operation="update",
            expected_active=(installed.context_id, installed.manifest_digest),
        )
        with self.assertRaisesRegex(
            ProtectedInstallTransactionError,
            "active link does not match",
        ):
            self._publish(stale)
        self.assertEqual(
            os.readlink(self.protected / "admitted-skill"),
            self._version_path(rolled_back),
        )
        stale_claim = (
            self.protected
            / ".aragorn-install-claims"
            / f"{stale.context_id.removeprefix('sha256:')}.json"
        )
        self.assertFalse(os.path.lexists(stale_claim))

    def test_unexpected_active_symlink_fails_without_claim_or_version(self) -> None:
        installed = self._context(
            context_character="1",
            manifest_digest=self.manifest_a_digest,
            operation="install",
            expected_active=None,
        )
        self._publish(installed)
        active = self.protected / "admitted-skill"
        active.unlink()
        active.symlink_to("/tmp", target_is_directory=True)

        updated = self._context(
            context_character="2",
            manifest_digest=self.manifest_b_digest,
            operation="update",
            expected_active=(installed.context_id, installed.manifest_digest),
        )
        with self.assertRaisesRegex(
            ProtectedInstallTransactionError,
            "active link does not match",
        ):
            self._publish(updated)
        self.assertEqual(os.readlink(active), "/tmp")
        claim = (
            self.protected
            / ".aragorn-install-claims"
            / f"{updated.context_id.removeprefix('sha256:')}.json"
        )
        self.assertFalse(os.path.lexists(claim))
        self.assertFalse(os.path.lexists(self.protected / self._version_path(updated)))

    def test_claim_recheck_rejects_revocation_and_binding_drift(self) -> None:
        nested_source = self.root / "source-nested"
        (nested_source / "references").mkdir(parents=True)
        (nested_source / "SKILL.md").write_bytes(b"A")
        (nested_source / "references" / "note.md").write_bytes(b"nested")
        nested_manifest = ingest_local(nested_source, self.cas)
        nested_raw = canonical_json(nested_manifest)
        nested_manifest_digest = self.cas.put(
            BytesIO(nested_raw),
            max_bytes=len(nested_raw),
        )
        revoked = self._context(
            context_character="1",
            manifest_digest=nested_manifest_digest,
            operation="install",
            expected_active=None,
        )

        def fresh_claim_state() -> tuple[int, tuple[str, ...]]:
            staged = list(
                (
                    self.protected
                    / ".aragorn-versions"
                    / "admitted-skill"
                ).glob(".aragorn-stage-*/SKILL.md")
            )
            self.assertEqual(len(staged), 1)
            self.assertEqual(staged[0].read_bytes(), b"A")
            return 101, (revoked.context_id,)

        with (
            patch(
                "aragorn.protected_install.verify_protected_install_context_v2",
                side_effect=[
                    revoked,
                    ProtectedInstallContextError("context revoked during staging"),
                ],
            ) as verifier,
            self.assertRaisesRegex(
                ProtectedInstallTransactionError,
                "before consuming.*revoked during staging",
            ),
        ):
            _publish_protected_install_transaction(
                self.cas,
                {},
                self.root_fd,
                now_unix=100,
                claim_now_unix=101,
                expected_context_digest=revoked.context_digest,
                expected_target_name=revoked.target_name,
                expected_runtime_conformance_digest=(
                    revoked.runtime_conformance_digest
                ),
                measured_target_runtime_digest=revoked.target_runtime_digest,
                revoked_context_ids=(),
                claim_state_provider=fresh_claim_state,
            )
        self.assertEqual(verifier.call_count, 2)
        self.assertEqual(verifier.call_args_list[0].kwargs["now_unix"], 100)
        self.assertEqual(verifier.call_args_list[1].kwargs["now_unix"], 101)
        self.assertEqual(
            verifier.call_args_list[1].kwargs["revoked_context_ids"],
            (revoked.context_id,),
        )
        target_versions = (
            self.protected / ".aragorn-versions" / "admitted-skill"
        )
        self.assertEqual(list(target_versions.glob(".aragorn-stage-*")), [])

        changed = self._context(
            context_character="2",
            manifest_digest=self.manifest_a_digest,
            operation="install",
            expected_active=None,
        )
        with (
            patch(
                "aragorn.protected_install.verify_protected_install_context_v2",
                side_effect=[
                    changed,
                    replace(changed, manifest_digest=self.manifest_b_digest),
                ],
            ),
            self.assertRaisesRegex(
                ProtectedInstallTransactionError,
                "context changed before claim",
            ),
        ):
            _publish_protected_install_transaction(
                self.cas,
                {},
                self.root_fd,
                now_unix=100,
                claim_now_unix=101,
                expected_context_digest=changed.context_digest,
                expected_target_name=changed.target_name,
                expected_runtime_conformance_digest=(
                    changed.runtime_conformance_digest
                ),
                measured_target_runtime_digest=changed.target_runtime_digest,
                revoked_context_ids=(),
            )

        claims = self.protected / ".aragorn-install-claims"
        self.assertEqual(list(claims.glob("*.json")), [])
        self.assertEqual(list(target_versions.glob(".aragorn-stage-*")), [])
        self.assertFalse(os.path.lexists(self.protected / "admitted-skill"))

    def test_post_claim_activation_failure_retains_recoverable_state(self) -> None:
        installed = self._context(
            context_character="1",
            manifest_digest=self.manifest_a_digest,
            operation="install",
            expected_active=None,
        )

        with (
            patch(
                "aragorn.protected_install.verify_protected_install_context_v2",
                return_value=installed,
            ),
            patch(
                "aragorn.protected_install._rename_activation_link",
                side_effect=RuntimeError("injected activation failure"),
            ),
            self.assertRaisesRegex(
                ProtectedInstallTransactionError,
                "after consuming.*no rollback was attempted",
            ) as raised,
        ):
            _publish_protected_install_transaction(
                self.cas,
                {},
                self.root_fd,
                now_unix=100,
                claim_now_unix=100,
                expected_context_digest=installed.context_digest,
                expected_target_name=installed.target_name,
                expected_runtime_conformance_digest=(
                    installed.runtime_conformance_digest
                ),
                measured_target_runtime_digest=installed.target_runtime_digest,
                revoked_context_ids=(),
            )

        self.assertIsNotNone(raised.exception.recovery)
        assert raised.exception.recovery is not None
        self.assertEqual(
            raised.exception.recovery["context_id"],
            installed.context_id,
        )
        self.assertEqual(
            raised.exception.recovery["version_path"],
            self._version_path(installed),
        )
        claim = (
            self.protected
            / ".aragorn-install-claims"
            / f"{installed.context_id.removeprefix('sha256:')}.json"
        )
        self.assertTrue(claim.is_file())
        self.assertTrue((self.protected / self._version_path(installed)).is_dir())
        self.assertFalse(os.path.lexists(self.protected / installed.target_name))
        self.assertEqual(
            len(list(self.protected.glob(".aragorn-activate-*"))),
            1,
        )


if __name__ == "__main__":
    unittest.main()
