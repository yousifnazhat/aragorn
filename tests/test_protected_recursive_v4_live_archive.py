from __future__ import annotations

import copy
import json
import tarfile
import tempfile
import unittest
from collections.abc import Iterator
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Self
from unittest.mock import patch

import aragorn.protected_recursive_v4_live_archive as replay_module
from aragorn.artifact_closure import canonical_json
from aragorn.protected_install_transition_replay import _File
from aragorn.protected_recursive_v4_live_archive import (
    ARCHIVE_DIGEST,
    ProtectedRecursiveV4LiveArchiveError,
    _document,
    _historical_replay,
    _journal,
    _load,
    _request_v4,
    _verify_local_replay_closure,
    _verify_release_coordinator,
    _verify_v6_graph_binding,
    verify_protected_recursive_v4_live_archive,
)

_ROOT = Path(__file__).resolve().parents[1]
_ARCHIVE = (
    _ROOT
    / "benchmark"
    / "evidence"
    / "phase1-protected-recursive-v4-live-0307946e55d9-2026-07-29.tar.xz"
)
_RECEIPT = (
    _ROOT
    / "benchmark"
    / "receipts"
    / "phase1-protected-recursive-v4-live-qualification-2026-07-29.json"
)


class ProtectedRecursiveV4LiveArchiveTests(unittest.TestCase):
    def test_replays_request_v4_live_path(self) -> None:
        with (
            patch(
                "aragorn.protected_recursive_v3_live_archive.build_gateway_request",
                side_effect=AssertionError("current helper used"),
            ),
            patch(
                "aragorn.github_recursive_live_archive.validate_handoff_manifest",
                side_effect=AssertionError("current helper used"),
            ),
        ):
            replay = verify_protected_recursive_v4_live_archive(_ARCHIVE)
        receipt_raw = _RECEIPT.read_bytes()

        self.assertEqual(replay, json.loads(receipt_raw))
        self.assertEqual(receipt_raw, canonical_json(replay) + b"\n")
        self.assertEqual(replay["archive"]["digest"], ARCHIVE_DIGEST)
        self.assertEqual(replay["install"]["verdict"], "ALLOW")
        self.assertEqual(replay["install"]["release_pin_count"], 0)
        self.assertEqual(replay["update"]["verdict"], "ALLOW")
        self.assertEqual(replay["update"]["release_pin_count"], 0)
        self.assertEqual(replay["update"]["changed_paths"], [])
        self.assertEqual(replay["release_error"]["verdict"], "ERROR")
        self.assertEqual(
            replay["release_error"]["graph_schema"],
            "aragorn/admission-artifact-graph/v6",
        )
        self.assertEqual(replay["release_error"]["release_pin_count"], 1)
        self.assertEqual(replay["release_error"]["analyzer_run_receipts"], 0)
        self.assertFalse(replay["release_error"]["published"])
        self.assertFalse(replay["qualification"]["phase1_complete"])

        with tempfile.TemporaryDirectory() as temporary:
            forged = Path(temporary) / _ARCHIVE.name
            raw = bytearray(_ARCHIVE.read_bytes())
            raw[-1] ^= 1
            forged.write_bytes(raw)
            with self.assertRaisesRegex(
                ProtectedRecursiveV4LiveArchiveError,
                "digest is not the retained identity",
            ):
                verify_protected_recursive_v4_live_archive(forged)

    def test_concurrent_replays_restore_module_globals(self) -> None:
        before = vars(replay_module).copy()
        with ThreadPoolExecutor(max_workers=2) as executor:
            results = list(
                executor.map(
                    verify_protected_recursive_v4_live_archive,
                    (_ARCHIVE, _ARCHIVE),
                )
            )

        self.assertEqual([result["status"] for result in results], ["PASS", "PASS"])
        self.assertEqual(
            {
                name
                for name, value in before.items()
                if vars(replay_module).get(name) is not value
            },
            set(),
        )

    def test_rejects_null_or_mismatched_release_pin_binding(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            archive = _load(_ARCHIVE.read_bytes(), Path(temporary))
            evidence = _document(archive, "evidence/install-journal.json")
            evidence = _document_message(evidence)
            request_path = "requests/install.json"
            original = archive.files[request_path]
            request = _document(archive, request_path)
            request["recursive"]["release_pin_set_digest"] = None
            archive.files[request_path] = _File(
                _canonical(request),
                original.mode,
            )
            with _historical_replay(archive, Path(temporary)) as historical:
                self.assertFalse(
                    (Path(temporary) / "capture-source" / "aragorn" / "cli.py").exists()
                )
                with self.assertRaisesRegex(
                    ProtectedRecursiveV4LiveArchiveError,
                    "request-v4 schema or recursive binding changed",
                ):
                    _request_v4(
                        archive,
                        evidence,
                        "install",
                        1_785_373_707_946_461,
                        historical=historical,
                    )

                archive.files[request_path] = original
                changed = copy.deepcopy(evidence)
                changed["source"]["recursive"]["release_pin_set_digest"] = (
                    "sha256:" + "0" * 64
                )
                with self.assertRaisesRegex(
                    ProtectedRecursiveV4LiveArchiveError,
                    "canonical request-v4 does not replay",
                ):
                    _request_v4(
                        archive,
                        changed,
                        "install",
                        1_785_373_707_946_461,
                        historical=historical,
                    )

            _verify_local_replay_closure(archive)
            for module in ("github_recursive_artifact_graph_v4", "github_gateway"):
                dependency_path = f"runtime/package/src/aragorn/{module}.py"
                dependency = archive.files[dependency_path]
                archive.files[dependency_path] = _File(
                    dependency.raw + b"\n",
                    dependency.mode,
                )
                with self.assertRaisesRegex(
                    ProtectedRecursiveV4LiveArchiveError,
                    "local replay dependency differs from capture",
                ):
                    _verify_local_replay_closure(archive)
                archive.files[dependency_path] = dependency

            coordinator = _journal(
                archive,
                "evidence/release-error-coordinator-journal.json",
                "aragorn-protected-install-coordinator-evidence.service",
            )["message"]
            _verify_release_coordinator(coordinator)
            changed_coordinator = dict(coordinator)
            changed_coordinator["unknown"] = True
            with self.assertRaisesRegex(
                ProtectedRecursiveV4LiveArchiveError,
                "release-bearing coordinator result changed",
            ):
                _verify_release_coordinator(changed_coordinator)

    def test_rejects_v6_recursive_identity_mutation(self) -> None:
        digest = "sha256:" + "1" * 64
        source = {
            "manifest_digest": digest,
            "source_proof_digest": digest,
            "quarantine_receipt_digest": digest,
            "gateway_profile_digest": digest,
            "artifact_graph_verifier_implementation_digest": digest,
        }
        recursive = {
            "root_manifest_digest": digest,
            "expansion_digest": digest,
            "expansion_proof_digest": None,
        }
        graph = {
            "root_manifest_digest": digest,
            "root_github_manifest_digest": digest,
            "source_proof_digest": digest,
            "quarantine_receipt_digest": digest,
            "gateway_profile_digest": digest,
            "expansion_digest": digest,
            "expansion_proof_digest": None,
            "verifier": {"implementation_digest": digest},
        }
        _verify_v6_graph_binding(graph, source, recursive)
        graph["expansion_digest"] = "sha256:" + "2" * 64
        with self.assertRaisesRegex(
            ProtectedRecursiveV4LiveArchiveError,
            "v6 graph recursive binding changed",
        ):
            _verify_v6_graph_binding(graph, source, recursive)

    def test_rejects_member_overflow_before_processing(self) -> None:
        root = "phase1-protected-recursive-v4-live-0307946e55d9"
        members = []
        for index in range(2_860):
            member = tarfile.TarInfo(root if index == 0 else f"{root}/{index:04d}")
            member.type = tarfile.DIRTYPE
            member.mode = 0o755
            members.append(member)

        class ArchiveStream:
            def __enter__(self) -> Self:
                return self

            def __exit__(self, *_args: object) -> None:
                return None

            def __iter__(self) -> Iterator[tarfile.TarInfo]:
                return iter(members)

        with (
            tempfile.TemporaryDirectory() as temporary,
            patch(
                "aragorn.protected_recursive_v4_live_archive.tarfile.open",
                return_value=ArchiveStream(),
            ),
            self.assertRaisesRegex(
                ProtectedRecursiveV4LiveArchiveError,
                "member count exceeds its limit",
            ),
        ):
            _load(b"", Path(temporary))


def _document_message(wrapper: dict[str, object]) -> dict[str, object]:
    import json

    return json.loads(str(wrapper["MESSAGE"]))


def _canonical(value: object) -> bytes:
    from aragorn.artifact_closure import canonical_json

    return canonical_json(value)


if __name__ == "__main__":
    unittest.main()
