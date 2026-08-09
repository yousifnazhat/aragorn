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

from aragorn import admission_protected_cron as protected
from aragorn.admission_evidence import AdmissionEvidenceError
from aragorn.admission_runtime_profile import load_runtime_profile
from aragorn.cas import CAS

_ROOT = Path(__file__).resolve().parents[1]
_ADMISSION = _ROOT / "benchmark/admission/openclaw-v2026.7.1"
_HELPER = _ADMISSION / "protected-observation-v1.mjs"
_PROBE = _ADMISSION / "protected-cron-rescan-probe.mjs"
_NODE = shutil.which("node")


class ProtectedCronRescanTests(unittest.TestCase):
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
                / "benchmark/receipts/"
                "phase3-openclaw-protected-cron-rescan-v1-2026-08-09.json"
            ).read_bytes()
        )
        self.evidence_path = (
            _ROOT
            / "benchmark/evidence/"
            "openclaw-v2026.7.1-protected-cron-rescan-2026-08-09.json"
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
        return protected.verify_openclaw_protected_cron_rescan(
            self.receipt if receipt is None else receipt,
            evidence_cas=self.cas,
            route_profile=self.profile,
            route_inventory=self.inventory,
            runtime_candidates=self.candidates,
        )

    def test_exact_route_pass_keeps_all_aggregate_authority_false(self) -> None:
        self.retain_inputs()
        result = self.verify()
        expected = json.loads(
            (
                _ROOT
                / "benchmark/receipts/phase3-openclaw-protected-cron-rescan-route-qualification-v1-2026-08-09.json"
            ).read_bytes()
        )

        self.assertEqual(result, expected)
        self.assertEqual(
            result["route"],
            {
                "id": "ADM-02/reload/cron-rescan",
                "observed_outcome": (
                    "EXACT_PROTECTED_ISOLATED_CRON_SNAPSHOT_BUILT_BEFORE_"
                    "MODEL_RESOLUTION"
                ),
                "status": "PASS",
            },
        )
        self.assertEqual(result["decision"]["status"], "ROUTE_PASS")
        self.assertFalse(result["decision"]["admission_profile_eligible"])
        self.assertFalse(result["decision"]["installer_work_eligible"])
        self.assertFalse(result["decision"]["phase3_exit_eligible"])
        self.assertIn("NATIVE_PROVIDER_REQUEST_NOT_OBSERVED", result["limitations"])
        self.assertIn(
            "PERSIST_BEFORE_MODEL_ORDER_DERIVED_FROM_DYNAMIC_TIMESTAMPS",
            result["limitations"],
        )
        self.assertEqual(self.receipt["results"]["pass"], [])

    def test_rejects_receipt_causality_snapshot_and_cleanup_drift(self) -> None:
        self.retain_inputs()
        changed_receipt = deepcopy(self.receipt)
        changed_receipt["containment"]["network_mode"] = "bridge"
        with self.assertRaisesRegex(AdmissionEvidenceError, "receipt changed"):
            self.verify(changed_receipt)

        mutations = (
            lambda value: value["action"]["observations"][
                "session_state_before_forced_run"
            ].__setitem__("base_entry_present", True),
            lambda value: value["action"]["observations"]["snapshot"][
                "entry"
            ].__setitem__("session_id_present", True),
            lambda value: value["action"]["observations"]["snapshot"][
                "blob"
            ].__setitem__("digest", "sha256:" + "0" * 64),
            lambda value: value["action"]["observations"][
                "terminal_result"
            ].__setitem__("provider", "changed"),
            lambda value: value["action"]["observations"]["terminal_result"][
                "diagnostics"
            ]["entries"][0].__setitem__("ts", 0),
            lambda value: value["action"]["observations"]["run"]["terminal_poll"][
                "response"
            ]["value"].__setitem__("total", 2),
            lambda value: value["action"]["observations"]["cleanup"][
                "response"
            ]["value"].__setitem__("removed", False),
            lambda value: value["action"]["prerequisites"]["module_files_before"][
                "isolated_agent"
            ]["observed"].__setitem__("digest", "sha256:" + "1" * 64),
            lambda value: value["action"]["observations"][
                "boundary_after"
            ].__setitem__("ignored", True),
        )
        for mutate in mutations:
            with self.subTest(mutation=mutate.__code__.co_firstlineno):
                evidence = deepcopy(self.evidence)
                mutate(evidence)
                with self.assertRaises(AdmissionEvidenceError):
                    protected._verify_action(evidence, self.receipt)

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
        reason = ["EXACT_PROTECTED_CRON_RESCAN_PREREQUISITE_MISSING"]
        self.assertEqual(result["route"]["status"], "NOT_TESTED")
        self.assertEqual(result["route"]["reason_codes"], reason)
        self.assertEqual(result["action"]["status"], "NOT_TESTED")
        self.assertEqual(result["action"]["reason_codes"], reason)
        canonical = json.dumps(
            result,
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        )
        self.assertEqual(completed.stdout, f"{canonical}\n")


if __name__ == "__main__":
    unittest.main()
