from __future__ import annotations

import json
import unittest
from copy import deepcopy
from io import BytesIO
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

from aragorn import admission_protected_restore_authority_cron as cron
from aragorn.admission_evidence import AdmissionEvidenceError
from aragorn.cas import CAS
from scripts.materialize_fixed_admission_probes import (
    transformed_restore_authority_probe,
)

_ROOT = Path(__file__).resolve().parents[1]
_ADMISSION = _ROOT / "benchmark/admission/openclaw-v2026.7.1"
_EVIDENCE = _ROOT / cron._EVIDENCE["path"]
_RECEIPT = _ROOT / (
    "benchmark/receipts/phase3-openclaw-protected-restore-authority-cron-"
    "rescan-v1-2026-08-13.json"
)
_PARENT = _ROOT / (
    "benchmark/receipts/phase3-openclaw-protected-restore-authority-chat-"
    "route-coverage-v1-2026-08-13.json"
)
_PROFILE = _ADMISSION / "protected-restore-authority-profile-v1.json"
_LOCK = _ADMISSION / "protected-restore-authority-runtime-v1.lock.json"
_CONFIG = _ADMISSION / "protected-restore-authority-config-v1.json"
_SOURCE_HELPER = _ADMISSION / "protected-observation-v1.mjs"
_SOURCE_PROBE = _ADMISSION / "protected-cron-rescan-probe.mjs"
_TARGET = _ROOT / "benchmark/fixtures/phase3-protected-archive-existing/SKILL.md"
_INVENTORY = _ADMISSION / "update-reload-route-inventory-v1.json"
_CANDIDATES = _ROOT / "benchmark/admission-runtime-candidates-v1.lock.json"


def _load(path: Path) -> dict[str, object]:
    return json.loads(path.read_bytes())


class ProtectedRestoreAuthorityCronTests(unittest.TestCase):
    def test_nine_route_coverage_and_hostile_inputs_fail_closed(self) -> None:
        receipt = _load(_RECEIPT)
        parent = _load(_PARENT)
        profile = _load(_PROFILE)
        lock = _load(_LOCK)
        evidence = _load(_EVIDENCE)
        inventory = _load(_INVENTORY)
        candidates = _load(_CANDIDATES)
        retained = {
            cron._digest(raw): raw
            for raw in (
                _PROFILE.read_bytes(),
                _LOCK.read_bytes(),
                _CONFIG.read_bytes(),
                _SOURCE_HELPER.read_bytes(),
                transformed_restore_authority_probe("protected-observation-v1.mjs"),
                _SOURCE_PROBE.read_bytes(),
                transformed_restore_authority_probe("protected-cron-rescan-probe.mjs"),
                _TARGET.read_bytes(),
                _EVIDENCE.read_bytes(),
            )
        }
        self.assertEqual(
            set(retained),
            {
                cron._EVIDENCE["digest"],
                *(digest for digest, _size in cron._SOURCES.values()),
            },
        )

        with TemporaryDirectory() as temporary:
            cas = CAS(temporary)
            for raw in retained.values():
                cas.put(BytesIO(raw), max_bytes=len(raw))

            def verify(
                *,
                source: dict[str, object] = receipt,
                selected_parent: dict[str, object] = parent,
                selected_profile: dict[str, object] = profile,
                selected_lock: dict[str, object] = lock,
                selected_inventory: dict[str, object] = inventory,
                selected_candidates: dict[str, object] = candidates,
                selected_cas: CAS = cas,
            ) -> dict[str, object]:
                return cron.verify_openclaw_protected_restore_authority_cron_rescan(
                    source,
                    evidence_cas=selected_cas,
                    route_profile=selected_profile,
                    runtime_lock=selected_lock,
                    route_inventory=selected_inventory,
                    runtime_candidates=selected_candidates,
                    chat_qualification=selected_parent,
                )

            first = verify()
            self.assertEqual(first, verify())
            self.assertEqual(
                cron.canonical_digest(first),
                "sha256:48e635064f9158851a7680201905f4021991319527bd00df28197b8e7e4bacc5",
            )
            self.assertEqual(
                first["profile"]["counts"],
                {"fail": 0, "not_tested": 12, "pass": 9},
            )
            parent_statuses = {
                item["id"]: item["status"] for item in parent["profile"]["routes"]
            }
            statuses = {
                item["id"]: item["status"] for item in first["profile"]["routes"]
            }
            self.assertEqual(
                {
                    route
                    for route in statuses
                    if statuses[route] != parent_statuses[route]
                },
                {cron._ROUTE},
            )
            self.assertEqual(
                {route for route, status in statuses.items() if status == "PASS"},
                cron._PASS_ROUTES,
            )
            self.assertTrue(
                all(
                    value is False
                    for key, value in first["decision"].items()
                    if key != "status"
                )
            )
            self.assertEqual(first["decision"]["status"], "PARTIAL_ROUTE_COVERAGE")
            self.assertEqual(first["source_recorded_at"], "2026-08-13T12:08:12.139Z")
            for limitation in (
                "CHAT_ROUTE_REUSES_SHARED_PROMPT_REBUILD_CAPTURE_NOT_INDEPENDENT_EXECUTION",
                "BLACK_BOX_NATIVE_CHAT_PERSISTENCE_WITHOUT_DIRECT_SESSION_UPDATES_TRACE",
                "ONE_MISSING_PROMPT_BLOB_TRIGGER_NOT_GENERAL_CHAT_ROUTE_COVERAGE",
                "ONE_FRESH_CAPTURE_NO_REPEATABILITY_CLAIM",
                "BASE_SESSION_ABSENT_BEFORE_FORCED_RUN_SO_NO_EXISTING_SNAPSHOT_REUSE_OR_TAMPER_REPAIR_CLAIM",
                "NO_SUCCESSFUL_MODEL_REPLY_OR_DELIVERY_CLAIM",
                "TWELVE_OTHER_PROTECTED_PROFILE_ROUTES_NOT_TESTED",
            ):
                self.assertIn(limitation, first["limitations"])

            changed_receipt = deepcopy(receipt)
            changed_receipt["phase3_exit_eligible"] = True
            with self.assertRaises(AdmissionEvidenceError):
                verify(source=changed_receipt)

            changed_receipt = deepcopy(receipt)
            changed_evidence = deepcopy(evidence)
            changed_evidence["action"]["commands"].append(
                deepcopy(changed_evidence["action"]["commands"][-1])
            )
            changed_summary = changed_receipt["execution"]["action"]
            changed_summary["command_count"] = 10
            changed_summary["command_pids"].append(changed_summary["command_pids"][-1])
            changed_summary["command_projections"].append(
                deepcopy(changed_summary["command_projections"][-1])
            )
            with self.assertRaisesRegex(AdmissionEvidenceError, "execution join"):
                cron._verify_receipt_execution(changed_receipt, changed_evidence)

            changed_parent = deepcopy(parent)
            next(
                item
                for item in changed_parent["profile"]["routes"]
                if item["id"] == cron._ROUTE
            )["status"] = "PASS"
            with self.assertRaises(AdmissionEvidenceError):
                verify(selected_parent=changed_parent)

            changed_profile = deepcopy(profile)
            changed_profile["controls"]["curator_restore_authority"] = "local"
            with self.assertRaises(AdmissionEvidenceError):
                verify(selected_profile=changed_profile)

            changed_lock = deepcopy(lock)
            changed_lock["source"]["commit"] = "0" * 40
            with self.assertRaises(AdmissionEvidenceError):
                verify(selected_lock=changed_lock)

            changed_inventory = deepcopy(inventory)
            changed_inventory["schema"] += "X"
            with self.assertRaises(AdmissionEvidenceError):
                verify(selected_inventory=changed_inventory)

            changed_candidates = deepcopy(candidates)
            changed_candidates["schema"] += "X"
            with self.assertRaises(AdmissionEvidenceError):
                verify(selected_candidates=changed_candidates)

            for omitted in retained:
                with self.subTest(omitted_cas=omitted), TemporaryDirectory() as empty:
                    incomplete = CAS(empty)
                    for digest, raw in retained.items():
                        if digest != omitted:
                            incomplete.put(BytesIO(raw), max_bytes=len(raw))
                    with self.assertRaises(AdmissionEvidenceError):
                        verify(selected_cas=incomplete)

        for label, mutate in (
            (
                "route",
                lambda value: value["route"].__setitem__("status", "PASS"),
            ),
            (
                "boundary",
                lambda value: value["action"]["prerequisites"][
                    "boundary_before"
                ].__setitem__("ready", False),
            ),
            (
                "command",
                lambda value: value["action"]["commands"][0]["argv"].append(
                    "--changed"
                ),
            ),
            (
                "snapshot",
                lambda value: value["action"]["observations"]["snapshot"][
                    "prompt"
                ].__setitem__("digest", "sha256:" + "0" * 64),
            ),
            (
                "cleanup",
                lambda value: value["action"]["observations"]["cleanup"]["response"][
                    "value"
                ].__setitem__("removed", False),
            ),
        ):
            changed = deepcopy(evidence)
            mutate(changed)
            with (
                self.subTest(hostile_evidence=label),
                self.assertRaises(AdmissionEvidenceError),
            ):
                cron._verify_evidence(
                    changed, receipt, profile, lock, _CONFIG.read_bytes()
                )

        after = evidence["action"]["observations"]
        terminal_arguments = {
            "job": after["job"],
            "run_id": after["terminal_result"]["runId"],
            "job_id": after["job"]["response"]["value"]["id"],
            "snapshot": after["snapshot"],
            "terminal_poll": after["run"]["terminal_poll"],
            "force_command": after["run"]["request"]["command"],
        }
        changed_terminal = deepcopy(after["terminal_result"])
        changed_terminal["runAtMs"] = (
            cron._epoch_ms(terminal_arguments["force_command"]["completed_at"]) + 1
        )
        with self.assertRaisesRegex(AdmissionEvidenceError, "causality"):
            cron._verify_terminal(changed_terminal, **terminal_arguments)

        changed_terminal = deepcopy(after["terminal_result"])
        changed_terminal["runAtMs"] = (
            int(cron.cron._RUN_ID.fullmatch(terminal_arguments["run_id"]).group(2)) - 1
        )
        with self.assertRaisesRegex(AdmissionEvidenceError, "causality"):
            cron._verify_terminal(changed_terminal, **terminal_arguments)

        changed_action = deepcopy(evidence["action"])
        changed_action["prerequisites"]["config_before"]["file"]["inode"] += 1
        changed_action["observations"]["config_after"]["file"]["inode"] += 1
        with (
            patch.object(cron, "_ACTION_DIGEST", cron.canonical_digest(changed_action)),
            self.assertRaisesRegex(AdmissionEvidenceError, "boundary identity"),
        ):
            cron._verify_action(changed_action, receipt, lock, _CONFIG.read_bytes())

        changed_action = deepcopy(evidence["action"])
        changed_action["observations"]["session_state_before_forced_run"][
            "completed_at"
        ] = changed_action["observations"]["run"]["request"]["command"]["completed_at"]
        with (
            patch.object(cron, "_ACTION_DIGEST", cron.canonical_digest(changed_action)),
            self.assertRaisesRegex(AdmissionEvidenceError, "forced run"),
        ):
            cron._verify_action(changed_action, receipt, lock, _CONFIG.read_bytes())

        changed_action = deepcopy(evidence["action"])
        changed_run = changed_action["observations"]["run"]
        changed_run["poll_count"] = 2
        changed_run["polls"].append(deepcopy(changed_run["polls"][0]))
        with (
            patch.object(cron, "_ACTION_DIGEST", cron.canonical_digest(changed_action)),
            self.assertRaisesRegex(AdmissionEvidenceError, "forced run"),
        ):
            cron._verify_action(changed_action, receipt, lock, _CONFIG.read_bytes())

        for module in (cron.cron, cron.curator):
            with (
                patch.object(module, "__file__", __file__),
                TemporaryDirectory() as temporary,
                self.assertRaises(AdmissionEvidenceError),
            ):
                cron.verify_openclaw_protected_restore_authority_cron_rescan(
                    receipt,
                    evidence_cas=CAS(temporary),
                    route_profile=profile,
                    runtime_lock=lock,
                    route_inventory=inventory,
                    runtime_candidates=candidates,
                    chat_qualification=parent,
                )


if __name__ == "__main__":
    unittest.main()
