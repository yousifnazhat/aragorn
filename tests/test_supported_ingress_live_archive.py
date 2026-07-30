from __future__ import annotations

import json
import tarfile
import tempfile
import unittest
from collections.abc import Iterator
from pathlib import Path
from typing import Self
from unittest.mock import patch

from aragorn import decision_receipt, github_recursive_artifact_graph
from aragorn.github_quarantine_receipt import github_source_closure_digest
from aragorn.oci_worker_protocol import canonical_json
from aragorn.protected_install_transition_replay import _decision
from aragorn.supported_ingress_live_archive import (
    _EXPECTED_INVENTORY,
    ARCHIVE_DIGEST,
    SupportedIngressLiveArchiveError,
    _load,
    _transfer_inventory,
    verify_supported_ingress_live_archive,
)

_ROOT = Path(__file__).resolve().parents[1]
_ARCHIVE = (
    _ROOT
    / "benchmark"
    / "evidence"
    / "phase1-supported-ingress-live-c87b82b9b7a4-2026-07-29.tar.xz"
)
_RECEIPT = (
    _ROOT
    / "benchmark"
    / "receipts"
    / "phase1-supported-ingress-live-qualification-2026-07-29.json"
)


class SupportedIngressLiveArchiveTests(unittest.TestCase):
    def test_derives_supported_ingress_receipt_and_rejects_tampering(self) -> None:
        with (
            patch(
                "aragorn.supported_ingress_live_archive.github_source_closure_digest",
                wraps=github_source_closure_digest,
            ) as verify_closure,
            patch(
                "aragorn.supported_ingress_live_archive._replay_decision",
                wraps=_decision,
            ) as replay_decision,
            patch(
                "aragorn.supported_ingress_live_archive._transfer_inventory",
                wraps=_transfer_inventory,
            ) as transfer_inventory,
            patch(
                "aragorn.supported_ingress_live_archive."
                "decision_receipt.verify_decision_v3",
                wraps=decision_receipt.verify_decision_v3,
            ) as verify_decision,
            patch(
                "aragorn.github_recursive_artifact_graph."
                "verify_recursive_github_artifact_graph",
                wraps=(
                    github_recursive_artifact_graph.verify_recursive_github_artifact_graph
                ),
            ) as verify_graph,
        ):
            replay = verify_supported_ingress_live_archive(_ARCHIVE)
        self.assertEqual(verify_closure.call_count, 3)
        self.assertEqual(replay_decision.call_count, 2)
        self.assertEqual(transfer_inventory.call_count, 1)
        self.assertEqual(verify_decision.call_count, 3)
        self.assertEqual(verify_graph.call_count, 3)
        self.assertEqual(
            replay["evidence_coverage"],
            {
                "fully_replayed_cases": [
                    "byte-update-base",
                    "byte-update-next",
                    "recursive-metrics",
                ],
                "live_summary_only_cases": [
                    "install",
                    "release-error",
                    "update",
                ],
            },
        )
        receipt_raw = _RECEIPT.read_bytes()

        self.assertEqual(replay, json.loads(receipt_raw))
        self.assertEqual(receipt_raw, canonical_json(replay) + b"\n")
        self.assertEqual(replay["archive"]["digest"], ARCHIVE_DIGEST)
        self.assertEqual(replay["status"], "PASS")
        self.assertTrue(replay["qualification"]["supported_ingress_qualified"])
        self.assertFalse(replay["qualification"]["installer_work_eligible"])
        self.assertEqual(
            replay["cases"]["release-error"]["status"],
            "ERROR",
        )
        self.assertTrue(replay["cases"]["release-error"]["protected_state_unchanged"])
        self.assertTrue(replay["cases"]["update"]["active_tree_byte_identical"])
        self.assertEqual(
            replay["cases"]["recursive-metrics"]["static_references_resolved"],
            13,
        )
        self.assertEqual(
            replay["cases"]["recursive-metrics"]["unresolved_required_fail_closed"],
            18,
        )
        self.assertEqual(
            replay["cases"]["byte-update-next"]["changed_paths"],
            ["SKILL.md"],
        )
        self.assertEqual(
            replay["current_runtime_numerical_gate"]["installed_digest_mismatches"],
            0,
        )

        with tempfile.TemporaryDirectory() as temporary:
            forged = Path(temporary) / _ARCHIVE.name
            raw = bytearray(_ARCHIVE.read_bytes())
            raw[-1] ^= 1
            forged.write_bytes(raw)
            with self.assertRaisesRegex(
                SupportedIngressLiveArchiveError,
                "digest is not the retained identity",
            ):
                verify_supported_ingress_live_archive(forged)

    def test_fails_closed_when_source_closure_derivation_changes(self) -> None:
        with (
            patch(
                "aragorn.supported_ingress_live_archive.github_source_closure_digest",
                return_value="sha256:" + "0" * 64,
            ),
            self.assertRaisesRegex(
                SupportedIngressLiveArchiveError,
                "source closure digest changed",
            ),
        ):
            verify_supported_ingress_live_archive(_ARCHIVE)

    def test_fails_closed_when_analyzer_decision_replay_changes(self) -> None:
        with (
            patch(
                "aragorn.supported_ingress_live_archive._replay_decision",
                side_effect=ValueError("forged analyzer chain"),
            ),
            self.assertRaisesRegex(
                SupportedIngressLiveArchiveError,
                "analyzer and decision replay changed",
            ),
        ):
            verify_supported_ingress_live_archive(_ARCHIVE)

    def test_fails_closed_when_graph_derivation_changes(self) -> None:
        with (
            patch(
                "aragorn.github_recursive_artifact_graph."
                "verify_recursive_github_artifact_graph",
                side_effect=ValueError("forged graph"),
            ),
            self.assertRaisesRegex(
                SupportedIngressLiveArchiveError,
                "graph and decision replay changed",
            ),
        ):
            verify_supported_ingress_live_archive(_ARCHIVE)

    def test_rejects_unsafe_paths_and_member_overflow(self) -> None:
        unsafe = tarfile.TarInfo("../escape")
        unsafe.type = tarfile.DIRTYPE
        unsafe.mode = 0o700
        unsafe.uname = unsafe.gname = "root"

        class UnsafeStream:
            def __enter__(self) -> Self:
                return self

            def __exit__(self, *_args: object) -> None:
                return None

            def __iter__(self) -> Iterator[tarfile.TarInfo]:
                return iter([unsafe])

        with (
            patch(
                "aragorn.supported_ingress_live_archive.tarfile.open",
                return_value=UnsafeStream(),
            ),
            self.assertRaisesRegex(
                SupportedIngressLiveArchiveError,
                "non-canonical",
            ),
        ):
            _load(b"")

        root = "phase1-supported-ingress-live-c87b82b9b7a4-2026-07-29"
        members = []
        for index in range(_EXPECTED_INVENTORY["members"] + 1):
            member = tarfile.TarInfo(root if index == 0 else f"{root}/{index:03d}")
            member.type = tarfile.DIRTYPE
            member.mode = 0o700
            member.uname = member.gname = "root"
            members.append(member)

        class OverflowStream:
            def __enter__(self) -> Self:
                return self

            def __exit__(self, *_args: object) -> None:
                return None

            def __iter__(self) -> Iterator[tarfile.TarInfo]:
                return iter(members)

        with (
            patch(
                "aragorn.supported_ingress_live_archive.tarfile.open",
                return_value=OverflowStream(),
            ),
            self.assertRaisesRegex(
                SupportedIngressLiveArchiveError,
                "member count exceeds its limit",
            ),
        ):
            _load(b"")


if __name__ == "__main__":
    unittest.main()
