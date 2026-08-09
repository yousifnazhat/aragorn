from __future__ import annotations

import gzip
import json
import os
import shutil
import subprocess
import tarfile
import unittest
from copy import deepcopy
from io import BytesIO
from pathlib import Path
from tempfile import TemporaryDirectory

from aragorn import admission_protected_session_snapshot as protected
from aragorn.admission_evidence import AdmissionEvidenceError
from aragorn.admission_runtime_profile import load_runtime_profile
from aragorn.cas import CAS

_ROOT = Path(__file__).resolve().parents[1]
_ADMISSION = _ROOT / "benchmark/admission/openclaw-v2026.7.1"
_HELPER = _ADMISSION / "protected-observation-v1.mjs"
_PROBE = _ADMISSION / "protected-session-snapshot-probe.mjs"
_MANIFEST = (
    _ADMISSION / "protected-session-snapshot-compiled-closure-v1.manifest.json"
)
_ARCHIVE = _ADMISSION / "protected-session-snapshot-compiled-closure-v1.tar.gz"
_NODE = shutil.which("node")


class ProtectedSessionSnapshotTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.cas = CAS(self.temporary.name)
        self.profile_path = _ADMISSION / "protected-consumer-profile-v1.json"
        self.profile = load_runtime_profile(self.profile_path.read_bytes())
        self.inventory = json.loads(
            (_ADMISSION / "update-reload-route-inventory-v1.json").read_bytes()
        )
        self.candidates = json.loads(
            (
                _ROOT / "benchmark/admission-runtime-candidates-v1.lock.json"
            ).read_bytes()
        )
        self.receipt = json.loads(
            (
                _ROOT
                / "benchmark/receipts/"
                "phase3-openclaw-protected-session-snapshot-v1-2026-08-09.json"
            ).read_bytes()
        )
        self.evidence_path = (
            _ROOT
            / "benchmark/evidence/"
            "openclaw-v2026.7.1-protected-session-snapshot-2026-08-09.json"
        )
        self.evidence = json.loads(self.evidence_path.read_bytes())
        self.manifest_raw = _MANIFEST.read_bytes()
        self.manifest = json.loads(self.manifest_raw)
        self.archive_raw = _ARCHIVE.read_bytes()
        self.closure_files = protected._verify_compiled_closure(
            self.archive_raw,
            manifest_raw=self.manifest_raw,
            manifest=self.manifest,
        )

    def retain_inputs(self) -> None:
        for path in (
            self.evidence_path,
            self.profile_path,
            _HELPER,
            _PROBE,
            _ADMISSION / "protected-route-config-v1.json",
            _ROOT / "benchmark/fixtures/phase3-protected-archive-existing/SKILL.md",
            _MANIFEST,
            _ARCHIVE,
        ):
            raw = path.read_bytes()
            self.cas.put(BytesIO(raw), max_bytes=len(raw))

    def verify(self, receipt: dict[str, object] | None = None) -> dict[str, object]:
        return protected.verify_openclaw_protected_session_snapshot(
            self.receipt if receipt is None else receipt,
            evidence_cas=self.cas,
            route_profile=self.profile,
            route_inventory=self.inventory,
            runtime_candidates=self.candidates,
        )

    def test_exact_route_fail_keeps_all_aggregate_authority_false(self) -> None:
        self.retain_inputs()
        result = self.verify()
        expected = json.loads(
            (
                _ROOT
                / "benchmark/receipts/phase3-openclaw-protected-session-snapshot-route-qualification-v1-2026-08-09.json"
            ).read_bytes()
        )

        self.assertEqual(result, expected)
        self.assertEqual(
            result["route"],
            {
                "id": "ADM-02/reload/session-snapshot-consumer",
                "observed_outcome": (
                    "AGENT_WRITABLE_SESSION_PROMPT_ACCEPTED_BY_PINNED_COMPILED_"
                    "CONSUMER_REPLAY"
                ),
                "status": "FAIL",
            },
        )
        self.assertEqual(result["decision"]["status"], "ROUTE_FAIL")
        self.assertFalse(result["decision"]["admission_profile_eligible"])
        self.assertFalse(result["decision"]["installer_work_eligible"])
        self.assertFalse(result["decision"]["phase3_exit_eligible"])
        self.assertIn(
            "DIRECT_PINNED_FUNCTION_REPLAY_NOT_AGENT_COMMAND_EXECUTION",
            result["limitations"],
        )
        self.assertIn(
            "NATIVE_PROVIDER_REQUEST_NOT_OBSERVED", result["limitations"]
        )
        self.assertIn(
            "NATIVE_SYSTEM_PROMPT_REPORT_NOT_PERSISTED", result["limitations"]
        )
        self.assertEqual(self.receipt["results"]["fail"], [])

    def test_rejects_receipt_and_compiled_consumer_causality_drift(self) -> None:
        self.retain_inputs()
        changed_receipt = deepcopy(self.receipt)
        changed_receipt["containment"]["network_mode"] = "bridge"
        with self.assertRaisesRegex(AdmissionEvidenceError, "receipt changed"):
            self.verify(changed_receipt)

        mutations = (
            lambda value: value["action"]["observations"]["boundary_after"][
                "probe"
            ].__setitem__("read_only", False),
            lambda value: value["action"]["observations"]["mutation"][
                "changed_json_paths"
            ].append("other.path"),
            lambda value: value["action"]["observations"]["mutation"][
                "preserved_entry_without_prompt_ref"
            ].__setitem__("exact_equal", False),
            lambda value: value["action"]["observations"][
                "compiled_route_replay"
            ]["injected_render"].__setitem__("marker_count_in_system_prompt", 0),
            lambda value: value["action"]["observations"][
                "compiled_route_replay"
            ]["non_skill_render_inputs"]["config"]["plugins"].__setitem__(
                "enabled", True
            ),
            lambda value: value["action"]["observations"][
                "compiled_route_replay"
            ]["module_files"]["store"].__setitem__(
                "digest", "sha256:" + "0" * 64
            ),
            lambda value: value["action"]["observations"][
                "final_system_prompt_report"
            ].__setitem__("ready", True),
            lambda value: value["action"]["observations"][
                "compiled_route_replay"
            ]["consumer_chain"].pop(),
        )
        for mutate in mutations:
            with self.subTest(mutation=mutate.__code__.co_firstlineno):
                evidence = deepcopy(self.evidence)
                mutate(evidence)
                with self.assertRaises(AdmissionEvidenceError):
                    protected._verify_action(
                        evidence, self.receipt, self.closure_files
                    )

    def test_compiled_closure_rejects_unsafe_or_unbounded_archives(self) -> None:
        self.assertEqual(len(self.closure_files), 14)
        for name in ("/absolute", "../escape", "a/../escape", r"a\escape"):
            self.assertFalse(protected._safe_member_name(name))

        oversized = gzip.compress(b"x" * (protected._MAX_DECOMPRESSED_BYTES + 1))
        with self.assertRaisesRegex(AdmissionEvidenceError, "size limit"):
            protected._verify_archive_members(
                oversized, manifest_raw=self.manifest_raw
            )

        buffer = BytesIO()
        with tarfile.open(fileobj=buffer, mode="w:gz") as bundle:
            for _ in range(2):
                member = tarfile.TarInfo("manifest.json")
                member.mode = 0o444
                member.size = len(self.manifest_raw)
                bundle.addfile(member, BytesIO(self.manifest_raw))
        with self.assertRaisesRegex(AdmissionEvidenceError, "members changed"):
            protected._verify_archive_members(
                buffer.getvalue(), manifest_raw=self.manifest_raw
            )

        symlink = BytesIO()
        with tarfile.open(fileobj=symlink, mode="w:gz") as bundle:
            member = tarfile.TarInfo("manifest.json")
            member.type = tarfile.SYMTYPE
            member.linkname = "../outside"
            bundle.addfile(member)
        with self.assertRaises(AdmissionEvidenceError):
            protected._verify_archive_members(
                symlink.getvalue(), manifest_raw=self.manifest_raw
            )

    @unittest.skipUnless(_NODE, "Node.js is required for the probe checks")
    def test_missing_cas_and_local_probe_fail_closed(self) -> None:
        with self.assertRaises(AdmissionEvidenceError):
            self.verify()

        for path in (_HELPER, _PROBE):
            checked = subprocess.run(
                [_NODE, "--check", str(path)],
                capture_output=True,
                check=False,
                cwd=_ROOT,
                text=True,
                timeout=5,
            )
            self.assertEqual(checked.returncode, 0, checked.stderr)
            self.assertEqual(checked.stderr, "")

        environment = os.environ.copy()
        environment["OPENCLAW_GATEWAY_TOKEN"] = "aragorn-local-not-used"
        completed = subprocess.run(
            [_NODE, str(_PROBE)],
            capture_output=True,
            check=False,
            cwd=_ROOT,
            env=environment,
            text=True,
            timeout=5,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertEqual(completed.stderr, "")
        result = json.loads(completed.stdout)
        reason = ["EXACT_PROTECTED_SESSION_SNAPSHOT_PREREQUISITE_MISSING"]
        self.assertEqual(result["route"]["status"], "NOT_TESTED")
        self.assertEqual(result["route"]["reason_codes"], reason)
        self.assertEqual(result["action"]["status"], "NOT_TESTED")
        self.assertEqual(result["action"]["reason_codes"], reason)
        self.assertEqual(result["action"]["observations"], {})
        canonical = json.dumps(
            result,
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        )
        self.assertEqual(completed.stdout, f"{canonical}\n")


if __name__ == "__main__":
    unittest.main()
