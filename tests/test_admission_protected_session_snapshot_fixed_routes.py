from __future__ import annotations

import json
import unittest
from copy import deepcopy
from io import BytesIO
from pathlib import Path
from tempfile import TemporaryDirectory

from aragorn import admission_protected_session_snapshot_fixed_routes as routes
from aragorn.admission_evidence import AdmissionEvidenceError
from aragorn.cas import CAS

_ROOT = Path(__file__).resolve().parents[1]
_ADMISSION = _ROOT / "benchmark/admission/openclaw-v2026.7.1"
_RECEIPT = (
    _ROOT
    / "benchmark/receipts/phase3-openclaw-protected-session-snapshot-fixed-additional-routes-v1-2026-08-13.json"
)
_SESSION = (
    _ROOT
    / "benchmark/receipts/phase3-openclaw-protected-session-snapshot-fixed-route-qualification-v1-2026-08-12.json"
)


def _load(path: Path) -> dict[str, object]:
    return json.loads(path.read_bytes())


class ProtectedSessionSnapshotFixedRoutesTests(unittest.TestCase):
    def test_exact_six_route_coverage_and_split_view_fail_closed(self) -> None:
        with TemporaryDirectory() as temporary:
            cas = CAS(temporary)
            evidence: dict[str, dict[str, object]] = {}
            for key, spec in routes._CAPTURES.items():
                path = _ROOT / spec["path"]
                raw = path.read_bytes()
                cas.put(BytesIO(raw), max_bytes=len(raw))
                evidence[key] = json.loads(raw)
            profile_path = (
                _ADMISSION / "protected-session-snapshot-fixed-profile-v1.json"
            )
            lock_path = (
                _ADMISSION / "protected-session-snapshot-fixed-runtime-v1.lock.json"
            )
            for path in (profile_path, lock_path):
                raw = path.read_bytes()
                cas.put(BytesIO(raw), max_bytes=len(raw))
            receipt = _load(_RECEIPT)
            session = _load(_SESSION)
            profile = _load(profile_path)
            lock = _load(lock_path)
            inventory = _load(_ADMISSION / "update-reload-route-inventory-v1.json")
            candidates = _load(
                _ROOT / "benchmark/admission-runtime-candidates-v1.lock.json"
            )

            def verify(
                *,
                source: dict[str, object] = receipt,
                qualified: dict[str, object] = session,
            ) -> dict[str, object]:
                return routes.verify_openclaw_protected_session_snapshot_fixed_routes(
                    source,
                    evidence_cas=cas,
                    route_profile=profile,
                    runtime_lock=lock,
                    route_inventory=inventory,
                    runtime_candidates=candidates,
                    session_qualification=qualified,
                )

            first = verify()
            self.assertEqual(first, verify())
            self.assertEqual(
                first["profile"]["counts"],
                {"fail": 0, "not_tested": 15, "pass": 6},
            )
            statuses = {
                item["id"]: item["status"] for item in first["profile"]["routes"]
            }
            self.assertEqual(list(statuses.values()).count("PASS"), 6)
            self.assertEqual(list(statuses.values()).count("NOT_TESTED"), 15)
            core_route = routes._CAPTURES["core_updater"]["route"]
            self.assertNotIn(core_route, routes._PASS_ROUTES)
            self.assertEqual(statuses[core_route], "NOT_TESTED")
            self.assertTrue(
                all(
                    value is False
                    for key, value in first["decision"].items()
                    if key != "status"
                )
            )

            changed_receipt = deepcopy(receipt)
            changed_receipt["evidence"]["cron_rescan"]["digest"] = "sha256:" + "0" * 64
            changed_session = deepcopy(session)
            changed_session["route"]["status"] = "NOT_TESTED"
            with self.assertRaises(AdmissionEvidenceError):
                verify(source=changed_receipt)
            with self.assertRaises(AdmissionEvidenceError):
                verify(qualified=changed_session)

            def mutate_cron(value: dict[str, object]) -> None:
                for modules in (
                    value["action"]["prerequisites"]["module_files_before"],
                    value["action"]["observations"]["module_files_after"],
                ):
                    observed = modules["session_snapshot"]["observed"]
                    expected = modules["session_snapshot"]["expected"]
                    observed["path"] = expected["path"] = "/runtime/attacker.js"
                    observed["digest"] = expected["digest"] = "sha256:" + "0" * 64

            def mutate_workshop(value: dict[str, object]) -> None:
                value["selected_route_ids"] = []
                workspace = value["protected_boundary"]["roots"]["workspace_skills"]
                workspace["records"][0]["root"] = "/attacker/workspace"
                workspace["entry"]["entries"] = []
                workspace["entry"]["entry_count"] = 0
                proposal = value["actions"][0]["prerequisites"]["draft"]["mount"]
                proposal["records"][0]["root"] = "/attacker/proposal"
                proposal["records"][0]["source"] = "/dev/evil"
                proposal["entry"]["mode"] = "750"

            mutations = {
                "config_activation": lambda value: value["runtime_binding"].__setitem__(
                    "commit", "0" * 40
                ),
                "archive_replacement": lambda value: value["action"]["observations"][
                    "boundary_after"
                ]["runtime"]["records"][0].__setitem__("root", "/attacker/runtime"),
                "prompt_rebuild": lambda value: value[
                    "implementation_digests"
                ].__setitem__("probe", "sha256:" + "0" * 64),
                "cron_rescan": mutate_cron,
                "workshop_proposal_apply": mutate_workshop,
                "core_updater": lambda value: value["actions"][0]["observations"][
                    "update_repair"
                ]["response"]["value"].__setitem__("restart", True),
            }
            for key, mutate in mutations.items():
                with self.subTest(capture=key):
                    changed = deepcopy(evidence[key])
                    mutate(changed)
                    with self.assertRaises(AdmissionEvidenceError):
                        routes._verify_fixed_capture(key, changed)

            changed_core = deepcopy(evidence["core_updater"])
            changed_core["selected_route_ids"] = []
            with self.assertRaises(AdmissionEvidenceError):
                routes._verify_fixed_capture("core_updater", changed_core)

            for key in (
                "config_activation",
                "archive_replacement",
                "prompt_rebuild",
                "cron_rescan",
            ):
                with self.subTest(unexpected_selected_route_ids=key):
                    changed = deepcopy(evidence[key])
                    changed["selected_route_ids"] = []
                    with self.assertRaises(AdmissionEvidenceError):
                        routes._verify_fixed_capture(key, changed)

            def legacy_probe(value: dict[str, object]) -> dict[str, object]:
                if "protected_boundary" in value:
                    return value["protected_boundary"]["inputs"]["probe"]
                return value["action"]["prerequisites"]["boundary_before"]["probe"]

            for key in (
                "config_activation",
                "archive_replacement",
                "prompt_rebuild",
                "cron_rescan",
            ):
                with self.subTest(probe_entry_count=key):
                    changed = deepcopy(evidence[key])
                    legacy_probe(changed)["entry"]["entry_count"] = 0
                    with self.assertRaises(AdmissionEvidenceError):
                        routes._verify_fixed_capture(key, changed)

            archive_probe_mutations = {
                "uid": lambda probe: probe["entry"].__setitem__("uid", 1000),
                "path": lambda probe: probe.__setitem__("path", "/attacker/probe"),
                "source": lambda probe: probe["records"][0].__setitem__(
                    "source", "/dev/evil"
                ),
                "extra_record": lambda probe: probe["records"].append(
                    deepcopy(probe["records"][0])
                ),
            }
            for label, mutate in archive_probe_mutations.items():
                with self.subTest(archive_probe=label):
                    changed = deepcopy(evidence["archive_replacement"])
                    mutate(legacy_probe(changed))
                    with self.assertRaises(AdmissionEvidenceError):
                        routes._verify_fixed_capture("archive_replacement", changed)

            changed_archive = deepcopy(evidence["archive_replacement"])
            changed_archive["protected_boundary"]["effective_identity"]["uid"] = 0
            changed_archive["action"]["observations"]["boundary_after"] = deepcopy(
                changed_archive["protected_boundary"]
            )
            with self.assertRaises(AdmissionEvidenceError):
                routes._verify_fixed_capture("archive_replacement", changed_archive)

            for key in ("workshop_proposal_apply", "core_updater"):
                with self.subTest(route_runtime_source=key):
                    changed = deepcopy(evidence[key])
                    changed["protected_boundary"]["runtime"]["records"][0]["source"] = (
                        "/dev/evil"
                    )
                    with self.assertRaises(AdmissionEvidenceError):
                        routes._verify_fixed_capture(key, changed)

                with self.subTest(route_config_path=key):
                    changed = deepcopy(evidence[key])
                    configuration = changed["protected_boundary"]["configuration"]
                    configuration["file"]["path"] = "/attacker/openclaw.json"
                    if key == "core_updater":
                        changed["actions"][0]["observations"]["configuration_after"] = (
                            deepcopy(configuration)
                        )
                    with self.assertRaises(AdmissionEvidenceError):
                        routes._verify_fixed_capture(key, changed)

            changed_workshop = deepcopy(evidence["workshop_proposal_apply"])
            changed_workshop["protected_boundary"]["configuration"]["file"]["size"] = 0
            with self.assertRaises(AdmissionEvidenceError):
                routes._verify_fixed_capture(
                    "workshop_proposal_apply", changed_workshop
                )

            changed_workshop = deepcopy(evidence["workshop_proposal_apply"])
            changed_workshop["protected_boundary"]["runtime"]["entry"][
                "entry_count"
            ] = 0
            with self.assertRaises(AdmissionEvidenceError):
                routes._verify_fixed_capture(
                    "workshop_proposal_apply", changed_workshop
                )

            for invalid_mtime in ("0", 0):
                changed_cron = deepcopy(evidence["cron_rescan"])
                changed_cron["action"]["observations"]["snapshot"]["store"][
                    "mtime_ns"
                ] = invalid_mtime
                with self.assertRaises(AdmissionEvidenceError):
                    routes._verify_fixed_capture("cron_rescan", changed_cron)

            def coordinate_command_pids(value: object) -> None:
                if isinstance(value, dict):
                    if "argv" in value and "pid" in value:
                        value["pid"] = 77
                    for item in value.values():
                        coordinate_command_pids(item)
                elif isinstance(value, list):
                    for item in value:
                        coordinate_command_pids(item)

            pass_captures = [
                key
                for key, spec in routes._CAPTURES.items()
                if spec["route"] in routes._PASS_ROUTES
            ]
            for key in pass_captures:
                with self.subTest(duplicate_command_pid=key):
                    changed = deepcopy(evidence[key])
                    coordinate_command_pids(changed)
                    with self.assertRaises(AdmissionEvidenceError):
                        routes._verify_fixed_capture(key, changed)


if __name__ == "__main__":
    unittest.main()
