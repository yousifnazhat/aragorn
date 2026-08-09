from __future__ import annotations

import json
import os
import shutil
import subprocess
import unittest
from copy import deepcopy
from io import BytesIO
from pathlib import Path
from tempfile import TemporaryDirectory

from aragorn import admission_protected_prompt as protected_prompt
from aragorn.admission_evidence import AdmissionEvidenceError
from aragorn.admission_runtime_profile import load_runtime_profile
from aragorn.cas import CAS

_ROOT = Path(__file__).resolve().parents[1]
_ADMISSION = _ROOT / "benchmark/admission/openclaw-v2026.7.1"
_HELPER = _ADMISSION / "protected-observation-v1.mjs"
_PROBE = _ADMISSION / "protected-prompt-rebuild-probe.mjs"
_NODE = shutil.which("node")


class ProtectedPromptRebuildTests(unittest.TestCase):
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
            (_ROOT / "benchmark/admission-runtime-candidates-v1.lock.json").read_bytes()
        )
        self.receipt = json.loads(
            (
                _ROOT
                / "benchmark/receipts/phase3-openclaw-protected-prompt-rebuild-v1-2026-08-09.json"
            ).read_bytes()
        )
        self.evidence_path = (
            _ROOT
            / "benchmark/evidence/openclaw-v2026.7.1-protected-prompt-rebuild-2026-08-09.json"
        )
        self.evidence = json.loads(self.evidence_path.read_bytes())

    def retain_inputs(self) -> None:
        for path in (
            self.evidence_path,
            self.profile_path,
            _HELPER,
            _PROBE,
            _ADMISSION / "protected-route-config-v1.json",
            _ROOT / "benchmark/fixtures/phase3-protected-archive-existing/SKILL.md",
        ):
            raw = path.read_bytes()
            self.cas.put(BytesIO(raw), max_bytes=len(raw))

    def verify(self, receipt: dict[str, object] | None = None) -> dict[str, object]:
        return protected_prompt.verify_openclaw_protected_prompt_rebuild(
            self.receipt if receipt is None else receipt,
            evidence_cas=self.cas,
            route_profile=self.profile,
            route_inventory=self.inventory,
            runtime_candidates=self.candidates,
        )

    def test_exact_qualification_keeps_aggregate_authority_false(self) -> None:
        self.retain_inputs()
        result = self.verify()
        expected = json.loads(
            (
                _ROOT
                / "benchmark/receipts/phase3-openclaw-protected-prompt-rebuild-route-qualification-v1-2026-08-09.json"
            ).read_bytes()
        )

        self.assertEqual(result, expected)
        self.assertEqual(
            result["route"],
            {
                "id": "ADM-02/reload/missing-prompt-blob-rebuild",
                "observed_outcome": "EXACT_PROTECTED_PROMPT_BLOB_REBUILT",
                "status": "PASS",
            },
        )
        self.assertFalse(result["decision"]["admission_profile_eligible"])
        self.assertFalse(result["decision"]["installer_work_eligible"])
        self.assertFalse(result["decision"]["phase3_exit_eligible"])
        self.assertEqual(self.receipt["results"]["pass"], [])

    def test_rejects_receipt_prompt_causality_and_boundary_drift(self) -> None:
        self.retain_inputs()
        changed_receipt = deepcopy(self.receipt)
        changed_receipt["containment"]["network_mode"] = "bridge"
        with self.assertRaisesRegex(AdmissionEvidenceError, "receipt changed"):
            self.verify(changed_receipt)

        mutations = (
            lambda value: value["action"]["observations"]["rebuilt_snapshot"][
                "prompt"
            ].__setitem__("exact_text", "forged"),
            lambda value: value["action"]["observations"]["rebuilt_snapshot"][
                "blob"
            ].__setitem__("mtime_ns", "1"),
            lambda value: value["action"]["observations"]["invalidation"][
                "store_after_rewrite"
            ].__setitem__("digest", "sha256:" + "0" * 64),
            lambda value: value["action"]["observations"][
                "runtime_tree_after"
            ].__setitem__("tree_digest", "sha256:" + "1" * 64),
            lambda value: value["action"]["observations"][
                "gateway_process_after"
            ].__setitem__("start_time_ticks", "changed"),
            lambda value: value["action"]["prerequisites"]["boundary_before"][
                "configuration"
            ]["mount"]["records"][0]["mount_options"].append("rw"),
            lambda value: value["action"]["observations"]["rebuild_turn"][
                "wait"
            ]["response"]["value"].__setitem__("status", "failed"),
        )
        for mutate in mutations:
            with self.subTest(mutation=mutate.__code__.co_firstlineno):
                evidence = deepcopy(self.evidence)
                mutate(evidence)
                with self.assertRaises(AdmissionEvidenceError):
                    protected_prompt._verify_action(evidence, self.receipt)

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
        reason = ["EXACT_PROTECTED_PROMPT_REBUILD_PREREQUISITE_MISSING"]
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
