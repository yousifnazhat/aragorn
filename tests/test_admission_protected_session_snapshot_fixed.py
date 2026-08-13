from __future__ import annotations

import json
import unittest
from copy import deepcopy
from io import BytesIO
from pathlib import Path
from tempfile import TemporaryDirectory

from aragorn import admission_protected_session_snapshot_fixed as fixed
from aragorn.admission_evidence import AdmissionEvidenceError
from aragorn.cas import CAS

_ROOT = Path(__file__).resolve().parents[1]
_ADMISSION = _ROOT / "benchmark/admission/openclaw-v2026.7.1"
_EVIDENCE = (
    _ROOT
    / "benchmark/evidence/openclaw-v2026.7.1-protected-session-snapshot-fixed-2026-08-12.json"
)
_RECEIPT = (
    _ROOT
    / "benchmark/receipts/phase3-openclaw-protected-session-snapshot-fixed-v1-2026-08-12.json"
)
_SOURCES = (
    _EVIDENCE,
    _ADMISSION / "protected-session-snapshot-fixed-profile-v1.json",
    _ADMISSION / "protected-session-snapshot-fixed-runtime-v1.lock.json",
    _ADMISSION / "protected-observation-v1.mjs",
    _ADMISSION / "protected-session-snapshot-fixed-probe.mjs",
    _ADMISSION / "protected-route-config-v1.json",
    _ROOT / "benchmark/fixtures/phase3-protected-archive-existing/SKILL.md",
    _ADMISSION / "protected-session-snapshot-fixed-compiled-closure-v1.manifest.json",
    _ADMISSION / "protected-session-snapshot-fixed-compiled-closure-v1.tar.gz",
)


def _load(path: Path) -> dict[str, object]:
    return json.loads(path.read_bytes())


class ProtectedSessionSnapshotFixedTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.cas = CAS(self.temporary.name)
        for path in _SOURCES:
            raw = path.read_bytes()
            self.cas.put(BytesIO(raw), max_bytes=len(raw))
        self.receipt = _load(_RECEIPT)
        self.profile = _load(
            _ADMISSION / "protected-session-snapshot-fixed-profile-v1.json"
        )
        self.lock = _load(
            _ADMISSION / "protected-session-snapshot-fixed-runtime-v1.lock.json"
        )
        self.inventory = _load(_ADMISSION / "update-reload-route-inventory-v1.json")
        self.candidates = _load(
            _ROOT / "benchmark/admission-runtime-candidates-v1.lock.json"
        )
        self.closure_files = fixed._verify_archive(
            (
                _ADMISSION
                / "protected-session-snapshot-fixed-compiled-closure-v1.tar.gz"
            ).read_bytes(),
            (
                _ADMISSION
                / "protected-session-snapshot-fixed-compiled-closure-v1.manifest.json"
            ).read_bytes(),
        )

    def verify(self) -> dict[str, object]:
        return fixed.verify_openclaw_protected_session_snapshot_fixed(
            self.receipt,
            evidence_cas=self.cas,
            route_profile=self.profile,
            runtime_lock=self.lock,
            route_inventory=self.inventory,
            runtime_candidates=self.candidates,
        )

    def test_exact_route_pass_keeps_every_broad_authority_false(self) -> None:
        first = self.verify()
        self.assertEqual(first, self.verify())
        self.assertEqual(first["route"]["status"], "PASS")
        self.assertEqual(
            first["profile"]["counts"],
            {"fail": 0, "not_tested": 20, "pass": 1},
        )
        self.assertEqual(
            [item["status"] for item in first["profile"]["routes"]].count("PASS"),
            1,
        )
        for field in (
            "admission_profile_eligible",
            "aggregate_admission_eligible",
            "edr_eligible",
            "installer_work_eligible",
            "phase3_exit_eligible",
            "release_eligible",
            "run_01_eligible",
            "run_02_eligible",
        ):
            self.assertIs(first["decision"][field], False)

    def test_semantic_mutations_fail_closed(self) -> None:
        evidence = _load(_EVIDENCE)
        mutations = (
            lambda value: value["action"]["observations"]["compiled_route_replay"][
                "resolver"
            ].__setitem__("injected_should_refresh", False),
            lambda value: value["action"]["observations"]["compiled_route_replay"][
                "resolver"
            ]["injected_snapshot"]["skills"].clear(),
            lambda value: value["action"]["observations"]["compiled_route_replay"][
                "injected_render"
            ].__setitem__("marker_count_in_system_prompt", 1),
            lambda value: value["action"]["observations"]["final_snapshot"][
                "blob"
            ].__setitem__(
                "prompt_ref",
                value["action"]["observations"]["mutation"]["blob"]["prompt_ref"],
            ),
            lambda value: value["action"]["observations"][
                "native_recovery_timing"
            ].__setitem__("final_entry_updated_at", 0),
            lambda value: value["action"]["observations"][
                "native_recovery_timing"
            ].__setitem__("ready", 1),
            lambda value: (
                value["action"]["observations"]["mutated_snapshot"][
                    "entry"
                ].__setitem__("session_id", "22222222-2222-4222-8222-222222222222"),
                value["action"]["observations"]["pre_injected_snapshot"][
                    "entry"
                ].__setitem__("session_id", "22222222-2222-4222-8222-222222222222"),
            ),
            lambda value: value["action"]["observations"]["mutation"][
                "atomic_store_replacement"
            ].__setitem__("rename_completed", False),
            lambda value: (
                value["action"]["prerequisites"]["gateway_process_before"].__setitem__(
                    "effective_capabilities", "0000000000000001"
                ),
                value["action"]["observations"]["gateway_process_after"].__setitem__(
                    "effective_capabilities", "0000000000000001"
                ),
            ),
            lambda value: (
                value["action"]["prerequisites"]["boundary_before"]["probe"]["records"][
                    0
                ].__setitem__("root", "/docker/volumes/evil-probe/_data"),
                value["action"]["observations"]["boundary_after"]["probe"]["records"][
                    0
                ].__setitem__("root", "/docker/volumes/evil-probe/_data"),
            ),
            lambda value: value["action"]["observations"].__setitem__(
                "final_system_prompt_report",
                {"ready": True, "report": {"skills": {"hash": "attacker"}}},
            ),
            lambda value: value["action"].__setitem__("id", "other-action"),
            lambda value: value["runtime_binding"].__setitem__(
                "openclaw_path", "/attacker/openclaw.mjs"
            ),
        )
        for mutate in mutations:
            with self.subTest(line=mutate.__code__.co_firstlineno):
                changed = deepcopy(evidence)
                mutate(changed)
                with self.assertRaises(AdmissionEvidenceError):
                    fixed._verify_evidence(changed, self.receipt, self.closure_files)

        changed = deepcopy(evidence)
        resolver = changed["action"]["observations"]["compiled_route_replay"][
            "resolver"
        ]
        forged = deepcopy(resolver["baseline_snapshot"])
        forged["prompt"] = "COORDINATED_UNTRUSTED_PROMPT"
        forged["skills"] = [{"name": "coordinated-untrusted-catalog"}]
        resolver["baseline_snapshot"] = forged
        resolver["injected_snapshot"] = deepcopy(forged)
        resolver["baseline_snapshot_digest"] = fixed.canonical_digest(forged)
        resolver["injected_snapshot_digest"] = fixed.canonical_digest(forged)
        with self.assertRaises(AdmissionEvidenceError):
            fixed._verify_evidence(changed, self.receipt, self.closure_files)

        changed = deepcopy(evidence)
        replay = changed["action"]["observations"]["compiled_route_replay"]
        for name in ("baseline_render", "injected_render"):
            replay[name]["skills_prompt"] = "COORDINATED_UNTRUSTED_RENDER"
            replay[name]["system_prompt"] = "COORDINATED_UNTRUSTED_RENDER"
        with self.assertRaises(AdmissionEvidenceError):
            fixed._verify_evidence(changed, self.receipt, self.closure_files)

        changed = deepcopy(evidence)
        changed["action"]["commands"][0]["exit_code"] = 1
        changed["action"]["prerequisites"]["version"]["exit_code"] = 1
        with self.assertRaises(AdmissionEvidenceError):
            fixed._verify_evidence(changed, self.receipt, self.closure_files)

        changed = deepcopy(evidence)
        changed["action"]["observations"]["compiled_route_replay"]["module_files"][
            "session_snapshot_implementation"
        ]["digest"] = "sha256:" + "0" * 64
        with self.assertRaises(AdmissionEvidenceError):
            fixed._verify_evidence(changed, self.receipt, self.closure_files)

        changed = deepcopy(evidence)
        replay = changed["action"]["observations"]["compiled_route_replay"]
        replay["non_skill_render_inputs"]["runtimeInfo"]["model"] = "attacker/model"
        replay["non_skill_render_inputs"]["toolNames"] = ["attacker_tool"]
        replay["non_skill_render_inputs_digest"] = fixed.canonical_digest(
            replay["non_skill_render_inputs"]
        )
        with self.assertRaises(AdmissionEvidenceError):
            fixed._verify_evidence(changed, self.receipt, self.closure_files)

        changed = deepcopy(evidence)
        for name in ("initial_snapshot", "mutated_snapshot", "pre_injected_snapshot"):
            entry = changed["action"]["observations"][name]["entry"]
            entry["started_at"] = entry["ended_at"] = entry["updated_at"] = 1
        with self.assertRaises(AdmissionEvidenceError):
            fixed._verify_evidence(changed, self.receipt, self.closure_files)

        changed = deepcopy(evidence)
        changed["action"]["observations"]["native_recovery_timing"][
            "injected_send_started_at"
        ] = changed["action"]["observations"]["final_snapshot"]["entry"]["started_at"]
        for command in changed["action"]["commands"]:
            command["pid"] = 1
        with self.assertRaises(AdmissionEvidenceError):
            fixed._verify_evidence(changed, self.receipt, self.closure_files)

        forged_closure = {
            ("/absolute" if path == fixed._FIXED_CLOSURE_PATHS[2] else path): raw
            for path, raw in self.closure_files.items()
        }
        with self.assertRaises(AdmissionEvidenceError):
            fixed._verify_evidence(evidence, self.receipt, forged_closure)

        changed = deepcopy(evidence)
        for name in ("mutated_snapshot", "pre_injected_snapshot"):
            changed["action"]["observations"][name]["blob"]["mtime_ns"] = "1"
            changed["action"]["observations"][name]["store"]["mtime_ns"] = "1"
        changed["action"]["observations"]["mutation"]["blob"]["mtime_ns"] = "1"
        changed["action"]["observations"]["mutation"]["store_after_rewrite"][
            "mtime_ns"
        ] = "1"
        changed["action"]["observations"]["compiled_route_replay"][
            "baseline_store_copy"
        ]["mtime_ns"] = "1"
        with self.assertRaises(AdmissionEvidenceError):
            fixed._verify_evidence(changed, self.receipt, self.closure_files)

        changed = deepcopy(evidence)
        final = changed["action"]["observations"]["final_snapshot"]
        final["entry_digest"] = "sha256:" + "0" * 64
        final["store"]["bytes"] = 1
        final["store"]["digest"] = "sha256:" + "0" * 64
        final["blob"]["mtime_ns"] = "1"
        with self.assertRaises(AdmissionEvidenceError):
            fixed._verify_evidence(changed, self.receipt, self.closure_files)

        changed = deepcopy(evidence)
        zero = "sha256:" + "0" * 64
        initial = changed["action"]["observations"]["initial_snapshot"]
        mutated = changed["action"]["observations"]["mutated_snapshot"]
        pre = changed["action"]["observations"]["pre_injected_snapshot"]
        mutation = changed["action"]["observations"]["mutation"]
        initial["entry_digest"] = mutation["entry_before_digest"] = zero
        mutated["entry_digest"] = pre["entry_digest"] = mutation[
            "entry_after_digest"
        ] = zero
        initial["store"]["digest"] = mutation["store_before"]["digest"] = zero
        mutated["store"]["digest"] = pre["store"]["digest"] = mutation[
            "store_after_rewrite"
        ]["digest"] = zero
        mutation["preserved_entry_without_prompt_ref"]["before_digest"] = zero
        mutation["preserved_entry_without_prompt_ref"]["after_digest"] = zero
        with self.assertRaises(AdmissionEvidenceError):
            fixed._verify_evidence(changed, self.receipt, self.closure_files)

    def test_missing_source_and_changed_profile_fail_closed(self) -> None:
        with (
            TemporaryDirectory() as temporary,
            self.assertRaises(AdmissionEvidenceError),
        ):
            fixed.verify_openclaw_protected_session_snapshot_fixed(
                self.receipt,
                evidence_cas=CAS(temporary),
                route_profile=self.profile,
                runtime_lock=self.lock,
                route_inventory=self.inventory,
                runtime_candidates=self.candidates,
            )
        self.profile["routes"][0]["outcome"] = "PASS"
        with self.assertRaises(AdmissionEvidenceError):
            self.verify()


if __name__ == "__main__":
    unittest.main()
