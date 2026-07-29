from __future__ import annotations

import copy
import hashlib
import json
import tempfile
import unittest
from io import BytesIO
from pathlib import Path

from aragorn.artifact_closure import canonical_json
from aragorn.cas import CAS
from aragorn.github_recursive_live_archive import _verify_cas_inventory
from aragorn.protected_recursive_v3_live_archive import (
    ARCHIVE_DIGEST,
    ProtectedRecursiveV3LiveArchiveError,
    _File,
    _capture_boundary,
    _document,
    _journal,
    _load,
    _package_tree_digest,
    _release_error,
    _request_v3,
    _systemd_boundary,
    verify_protected_recursive_v3_live_archive,
)

_ROOT = Path(__file__).resolve().parents[1]
_ARCHIVE = (
    _ROOT
    / "benchmark"
    / "evidence"
    / "phase1-protected-recursive-v3-live-dac34f2-2026-07-29.tar.gz"
)
_RECEIPT = (
    _ROOT
    / "benchmark"
    / "receipts"
    / "phase1-protected-recursive-v3-live-qualification-2026-07-29.json"
)


class ProtectedRecursiveV3LiveArchiveTests(unittest.TestCase):
    def test_replays_exact_live_path_and_rejects_tampering(self) -> None:
        replay = verify_protected_recursive_v3_live_archive(_ARCHIVE)
        receipt_raw = _RECEIPT.read_bytes()

        self.assertEqual(replay, json.loads(receipt_raw))
        self.assertEqual(receipt_raw, canonical_json(replay) + b"\n")
        self.assertEqual(replay["archive"]["digest"], ARCHIVE_DIGEST)
        self.assertEqual(replay["install"]["verdict"], "ALLOW")
        self.assertEqual(replay["update"]["verdict"], "ALLOW")
        self.assertEqual(replay["update"]["changed_paths"], [])
        self.assertEqual(replay["release_error"]["verdict"], "ERROR")
        self.assertEqual(replay["release_error"]["analyzer_run_receipts"], 0)
        self.assertTrue(
            replay["release_error"]["recorded_protected_state_unchanged"]
        )
        self.assertEqual(
            replay["runtime"]["systemd"]["effective_units_verified"],
            3,
        )
        self.assertIn("BYTE_IDENTICAL_UPDATE_ONLY", replay["limitations"])
        self.assertEqual(
            replay["qualification"],
            {
                "live_protected_path_qualified": True,
                "runtime_conformance_qualified": False,
                "installer_work_eligible": False,
                "phase1_complete": False,
                "public_release_eligible": False,
            },
        )

        with tempfile.TemporaryDirectory() as temporary:
            forged = Path(temporary) / _ARCHIVE.name
            raw = bytearray(_ARCHIVE.read_bytes())
            raw[-1] ^= 1
            forged.write_bytes(raw)
            with self.assertRaisesRegex(
                ProtectedRecursiveV3LiveArchiveError,
                "digest is not the retained identity",
            ):
                verify_protected_recursive_v3_live_archive(forged)

    def test_rejects_semantic_security_boundary_mutations(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            archive = _load(_ARCHIVE.read_bytes(), Path(temporary))
            install_wrapper = _journal(
                archive,
                "evidence/install-journal.json",
                "aragorn-protected-install.service",
            )
            evidence = copy.deepcopy(install_wrapper["message"])

            request_path = "requests/install.json"
            original_request = archive.files[request_path]
            request = _document(archive, request_path)
            request["expires_at_unix"] += 1
            raw = canonical_json(request)
            archive.files[request_path] = _File(raw, 0o400)
            evidence["request_authority"]["request_digest"] = (
                "sha256:" + hashlib.sha256(raw).hexdigest()
            )
            with self.assertRaisesRegex(
                ProtectedRecursiveV3LiveArchiveError,
                "request freshness changed",
            ):
                _request_v3(
                    archive,
                    evidence,
                    "install",
                    journal_timestamp=install_wrapper["timestamp"],
                )
            archive.files[request_path] = original_request

            capture = _document(archive, "capture.json")
            changed_capture = copy.deepcopy(capture)
            changed_capture["assurance"]["release_error"] = (
                "LIVE_PINNED_RELEASE_ASSET_FAIL_CLOSED_REPLAYABLE_OFFLINE"
            )
            with self.assertRaisesRegex(
                ProtectedRecursiveV3LiveArchiveError,
                "capture boundary changed",
            ):
                _capture_boundary(changed_capture)
            changed_capture = copy.deepcopy(capture)
            changed_capture["provenance"]["commit_signer_fingerprint"] = (
                "SHA256:" + "A" * 43
            )
            with self.assertRaisesRegex(
                ProtectedRecursiveV3LiveArchiveError,
                "capture provenance changed",
            ):
                _capture_boundary(changed_capture)

            protected_path = "evidence/release-error-protected-state.json"
            original_protected = archive.files[protected_path]
            protected = _document(archive, protected_path)
            protected["after"]["entry_count"] = 1
            archive.files[protected_path] = _File(
                canonical_json(protected),
                original_protected.mode,
            )
            release_wrapper = _journal(
                archive,
                "evidence/release-error-journal.json",
                "aragorn-protected-install.service",
            )
            coordinator_wrapper = _journal(
                archive,
                "evidence/release-error-coordinator-journal.json",
                "aragorn-protected-install-coordinator-evidence.service",
            )
            with self.assertRaisesRegex(
                ProtectedRecursiveV3LiveArchiveError,
                "failure changed protected state",
            ):
                _release_error(
                    archive,
                    capture,
                    release_wrapper["message"],
                    coordinator_wrapper["message"],
                    journal_timestamp=release_wrapper["timestamp"],
                    reference_request=_document(
                        archive,
                        "requests/install.json",
                    ),
                )
            archive.files[protected_path] = original_protected

            systemd_path = "runtime/systemd-show.txt"
            original = archive.files[systemd_path]
            archive.files[systemd_path] = _File(
                original.raw.replace(
                    b"Names=aragorn-protected-install.service\n",
                    (
                        b"Names=aragorn-protected-install.service\n"
                        b"DropInPaths=/etc/systemd/system/"
                        b"aragorn-protected-install.service.d/evil.conf\n"
                        b"ExecStartPre={ path=/bin/sh ; argv[]=/bin/sh "
                        b"-c evil ; ignore_errors=no }\n"
                    ),
                    1,
                ),
                original.mode,
            )
            with self.assertRaisesRegex(
                ProtectedRecursiveV3LiveArchiveError,
                "effective systemd command surface changed",
            ):
                _systemd_boundary(archive)
            archive.files[systemd_path] = original

            archive.directories["runtime/package"] = 0o777
            with self.assertRaisesRegex(
                ProtectedRecursiveV3LiveArchiveError,
                "package metadata is unsafe",
            ):
                _package_tree_digest(archive, "runtime/package")

            archive.cases["install"].put(BytesIO(b"unexplained"), max_bytes=11)
            with self.assertRaisesRegex(
                ValueError,
                "exact CAS inventory",
            ):
                _verify_cas_inventory(
                    CAS(archive.cases["install"].root, read_only=True),
                    archive.blobs["install"],
                )


if __name__ == "__main__":
    unittest.main()
