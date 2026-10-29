from __future__ import annotations

import fcntl
import os
import unittest
from pathlib import Path
from unittest import mock

from aragorn import runtime_active_skill_lineage, runtime_active_skill_lineage_v2
from aragorn.protected_skill_quarantine import publish_quarantine_at
from aragorn.runtime_action_observation_publisher import (
    RuntimeActionObservationPublisherError,
)
from aragorn.runtime_active_skill_lineage import ACTIVE_RUNTIME_RECORD
from aragorn.runtime_active_skill_lineage_v2 import (
    hold_runtime_active_skill_lineage,
    verify_runtime_active_skill_lineage,
)
from tests.test_runtime_active_skill_lineage import (
    _activate,
    _digest,
    _fixture,
    _materialize,
    _publish_record,
    _transaction,
)


def _verify(fixture: dict[str, object]) -> dict[str, object]:
    return verify_runtime_active_skill_lineage(
        os.getpid(),
        fixture["attribution"],  # type: ignore[arg-type]
        fixture["grant"],  # type: ignore[arg-type]
        protected_root=fixture["root"],  # type: ignore[arg-type]
        expected_install_uid=os.geteuid(),
    )


class RuntimeActiveSkillLineageV2Tests(unittest.TestCase):
    def test_digest_quarantine_rejects_lineage_without_mutating_installed_evidence(
        self,
    ) -> None:
        with _fixture() as fixture:
            root, skill, grant = fixture["root"], fixture["skill"], fixture["grant"]
            assert isinstance(root, Path)
            assert isinstance(skill, Path)
            assert isinstance(grant, dict)
            before = _verify(fixture)
            root_fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY)
            try:
                fcntl.flock(root_fd, fcntl.LOCK_EX)
                publish_quarantine_at(
                    root_fd, _digest("9"), _digest("8"), expected_uid=os.geteuid()
                )
                fcntl.flock(root_fd, fcntl.LOCK_UN)
                self.assertEqual(_verify(fixture), before)
                fcntl.flock(root_fd, fcntl.LOCK_EX)
                publish_quarantine_at(
                    root_fd,
                    grant["active_skill_digest"],
                    _digest("8"),
                    expected_uid=os.geteuid(),
                )
                fcntl.flock(root_fd, fcntl.LOCK_UN)
            finally:
                os.close(root_fd)
            with self.assertRaisesRegex(
                RuntimeActionObservationPublisherError,
                "^runtime active-skill lineage cannot be verified: installed skill digest is quarantined$",
            ):
                _verify(fixture)
            self.assertEqual(skill.read_bytes(), fixture["skill_raw"])
            self.assertEqual(
                (root / ACTIVE_RUNTIME_RECORD).read_bytes(), fixture["record_raw"]
            )
            self.assertEqual(skill.stat().st_mode & 0o777, 0o444)
            skill_raw = fixture["skill_raw"]
            assert isinstance(skill_raw, bytes)
            alternate = _transaction(
                root,
                context_id=_digest("d"),
                context_digest=_digest("e"),
                manifest_digest=_digest("f"),
                skill_raw=skill_raw,
            )
            version = _materialize(root, alternate, skill_raw)
            _activate(root, alternate)
            _publish_record(root, alternate)
            fixture["grant"] = {
                **grant,
                "install_context_digest": alternate["context_digest"],
                "source_manifest_digest": alternate["manifest_digest"],
            }
            fixture["attribution"] = {
                **fixture["attribution"],
                "skill_path": str(version / "SKILL.md"),
            }
            with mock.patch(
                "aragorn.protected_skill_quarantine.read_quarantine_at",
                return_value=None,
            ) as absent:
                coherent = _verify(fixture)
            absent.assert_called_once_with(
                mock.ANY, grant["active_skill_digest"], expected_uid=os.geteuid()
            )
            self.assertEqual(coherent["context_digest"], alternate["context_digest"])
            self.assertEqual(coherent["manifest_digest"], alternate["manifest_digest"])
            self.assertEqual(coherent["runtime_skill_path"], str(version / "SKILL.md"))
            # A new installation context/version containing the same bytes is still denied.
            with self.assertRaisesRegex(
                RuntimeActionObservationPublisherError,
                "^runtime active-skill lineage cannot be verified: installed skill digest is quarantined$",
            ):
                _verify(fixture)

    def test_malformed_quarantine_is_wrapped_and_releases_lineage_lock(self) -> None:
        with _fixture() as fixture:
            root, grant = fixture["root"], fixture["grant"]
            assert isinstance(root, Path)
            assert isinstance(grant, dict)
            digest = grant["active_skill_digest"]
            marker = root / f".aragorn-quarantined-skill-{digest[7:]}.json"
            marker.write_bytes(b"{")
            marker.chmod(0o444)
            with self.assertRaises(RuntimeActionObservationPublisherError):
                _verify(fixture)
            installer_fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY)
            try:
                fcntl.flock(installer_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                fcntl.flock(installer_fd, fcntl.LOCK_UN)
            finally:
                os.close(installer_fd)
            self.assertEqual(marker.read_bytes(), b"{")

    def test_quarantine_check_runs_under_shared_install_lock(self) -> None:
        with _fixture() as fixture:
            root = fixture["root"]
            assert isinstance(root, Path)
            require = runtime_active_skill_lineage_v2.require_not_quarantined_at

            def require_locked(fd, digest, *, expected_uid):
                installer_fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY)
                try:
                    with self.assertRaises(BlockingIOError):
                        fcntl.flock(installer_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                finally:
                    os.close(installer_fd)
                return require(fd, digest, expected_uid=expected_uid)

            with mock.patch.object(
                runtime_active_skill_lineage_v2,
                "require_not_quarantined_at",
                side_effect=require_locked,
            ) as checked:
                _verify(fixture)
            checked.assert_called_once()
            self.assertEqual(
                checked.call_args.args[1], fixture["grant"]["active_skill_digest"]
            )
            self.assertEqual(checked.call_args.kwargs, {"expected_uid": os.geteuid()})

    def test_wrapper_keeps_shared_lock_for_entire_action_and_releases_it(self) -> None:
        with _fixture() as fixture:
            root = fixture["root"]
            installer_fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY)
            try:
                with hold_runtime_active_skill_lineage(
                    os.getpid(),
                    fixture["attribution"],
                    fixture["grant"],
                    protected_root=root,
                    expected_install_uid=os.geteuid(),
                ) as lineage:
                    self.assertEqual(
                        lineage["active_skill_digest"],
                        fixture["grant"]["active_skill_digest"],
                    )
                    with self.assertRaises(BlockingIOError):
                        fcntl.flock(installer_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                fcntl.flock(installer_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                fcntl.flock(installer_fd, fcntl.LOCK_UN)
            finally:
                os.close(installer_fd)

    def test_action_error_is_not_reclassified_and_releases_lock(self) -> None:
        with _fixture() as fixture:
            error = ValueError("injected action failure")
            with (
                self.assertRaises(ValueError) as raised,
                hold_runtime_active_skill_lineage(
                    os.getpid(),
                    fixture["attribution"],
                    fixture["grant"],
                    protected_root=fixture["root"],
                    expected_install_uid=os.geteuid(),
                ),
            ):
                raise error
            self.assertIs(raised.exception, error)
            installer_fd = os.open(fixture["root"], os.O_RDONLY | os.O_DIRECTORY)
            try:
                fcntl.flock(installer_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                fcntl.flock(installer_fd, fcntl.LOCK_UN)
            finally:
                os.close(installer_fd)

    def test_reopened_marker_root_must_match_the_shared_locked_lineage(self) -> None:
        with _fixture() as fixture:
            root = fixture["root"]
            other = root.parent / "other-protected"
            other.mkdir(mode=0o700)
            open_root = runtime_active_skill_lineage._open_protected_root
            calls = []

            def reopen(path, expected_uid):
                calls.append(path)
                return open_root(root if len(calls) == 1 else other, expected_uid)

            with (
                mock.patch.object(
                    runtime_active_skill_lineage,
                    "_open_protected_root",
                    side_effect=reopen,
                ),
                mock.patch.object(
                    runtime_active_skill_lineage_v2, "require_not_quarantined_at"
                ) as checked,
                self.assertRaisesRegex(
                    RuntimeActionObservationPublisherError,
                    "protected install root identity changed",
                ),
            ):
                _verify(fixture)
            self.assertEqual(calls, [root, root])
            checked.assert_not_called()

    def test_no_marker_has_identical_lineage_result(self) -> None:
        with _fixture() as fixture:
            expected = runtime_active_skill_lineage.verify_runtime_active_skill_lineage(
                os.getpid(),
                fixture["attribution"],
                fixture["grant"],
                protected_root=fixture["root"],
                expected_install_uid=os.geteuid(),
            )
            self.assertEqual(_verify(fixture), expected)


if __name__ == "__main__":
    unittest.main()
