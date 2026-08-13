from __future__ import annotations

import json
import unittest
from copy import deepcopy
from io import BytesIO
from pathlib import Path
from tempfile import TemporaryDirectory

from aragorn import admission_protected_curator_restore as curator
from aragorn.admission_evidence import AdmissionEvidenceError
from aragorn.cas import CAS

_ROOT = Path(__file__).resolve().parents[1]
_ADMISSION = _ROOT / "benchmark/admission/openclaw-v2026.7.1"
_EVIDENCE = (
    _ROOT
    / "benchmark/evidence/openclaw-v2026.7.1-protected-curator-restore-denial-2026-08-13.json"
)
_RECEIPT = (
    _ROOT
    / "benchmark/receipts/phase3-openclaw-protected-session-snapshot-restore-authority-curator-denial-v1-2026-08-13.json"
)
_PROFILE = _ADMISSION / "protected-restore-authority-profile-v1.json"
_LOCK = _ADMISSION / "protected-restore-authority-runtime-v1.lock.json"
_CONFIG = _ADMISSION / "protected-restore-authority-config-v1.json"
_SOURCES = (
    _PROFILE,
    _LOCK,
    _CONFIG,
    _ADMISSION / "protected-curator-restore-denial-probe.mjs",
    _ADMISSION / "protected-observation-v1.mjs",
    _EVIDENCE,
)


def _load(path: Path) -> dict[str, object]:
    return json.loads(path.read_bytes())


class ProtectedCuratorRestoreTests(unittest.TestCase):
    def test_exact_route_pass_and_hostile_inputs_fail_closed(self) -> None:
        receipt = _load(_RECEIPT)
        profile = _load(_PROFILE)
        lock = _load(_LOCK)
        evidence = _load(_EVIDENCE)
        config_raw = _CONFIG.read_bytes()
        inventory = _load(_ADMISSION / "update-reload-route-inventory-v1.json")
        candidates = _load(
            _ROOT / "benchmark/admission-runtime-candidates-v1.lock.json"
        )

        with TemporaryDirectory() as temporary:
            cas = CAS(temporary)
            for path in _SOURCES:
                raw = path.read_bytes()
                cas.put(BytesIO(raw), max_bytes=len(raw))

            def verify(
                *,
                source: dict[str, object] = receipt,
                selected_profile: dict[str, object] = profile,
                selected_lock: dict[str, object] = lock,
                selected_cas: CAS = cas,
            ) -> dict[str, object]:
                return curator.verify_openclaw_protected_curator_restore_denial(
                    source,
                    evidence_cas=selected_cas,
                    route_profile=selected_profile,
                    runtime_lock=selected_lock,
                    route_inventory=inventory,
                    runtime_candidates=candidates,
                )

            first = verify()
            self.assertEqual(first, verify())
            self.assertEqual(
                first["schema"],
                "aragorn/admission-protected-curator-restore-denial-route-qualification/v1",
            )
            self.assertEqual(
                first["assurance"],
                "SEMANTICALLY_VERIFIED_PRIVATE_RESTORE_AUTHORITY_CURATOR_ROUTE_ONLY",
            )
            self.assertEqual(
                first["route"],
                {
                    "id": curator._ROUTE,
                    "observed_outcome": curator._OUTCOME,
                    "status": "PASS",
                },
            )
            self.assertEqual(
                first["profile"]["counts"],
                {"fail": 0, "not_tested": 20, "pass": 1},
            )
            statuses = {
                item["id"]: item["status"] for item in first["profile"]["routes"]
            }
            self.assertEqual(list(statuses.values()).count("PASS"), 1)
            self.assertEqual(statuses[curator._ROUTE], "PASS")
            self.assertTrue(
                all(
                    value is False
                    for key, value in first["decision"].items()
                    if key != "status"
                )
            )

            def evidence_case(label: str) -> None:
                changed = deepcopy(evidence)
                action = changed["action"]
                before = action["prerequisites"]
                after = action["observations"]
                if label == "module digest":
                    before["modules_before"]["curator"]["observed"]["digest"] = (
                        "sha256:" + "0" * 64
                    )
                elif label == "gateway denial success":
                    after["gateway_restore"]["command"]["exit_code"] = 0
                elif label == "gateway denial error":
                    after["gateway_restore"]["response"]["value"]["error"][
                        "message"
                    ] = "restored"
                elif label == "cli denial line":
                    command = after["cli_fallback_restore"]["command"]
                    command["stderr_excerpt"] = command["stderr_excerpt"].replace(
                        "external authority", "local authority"
                    )
                elif label == "invalid token success":
                    after["invalid_token_gateway_control"]["command"]["exit_code"] = 0
                elif label == "coordinated active rows":
                    for database in (
                        after["database_before"],
                        after["database_after_gateway"],
                        after["database_after_cli"],
                    ):
                        database["row"]["state"] = "active"
                    for status in (
                        after["curator_status_before"],
                        after["curator_status_after"],
                    ):
                        value = status["response"]["value"]
                        value["counts"] = {"active": 1, "archived": 0, "stale": 0}
                        value["skills"][0]["state"] = "active"
                elif label == "one post row":
                    after["curator_status_after"]["response"]["value"]["skills"].append(
                        deepcopy(curator._STATUS_SKILL)
                    )
                elif label == "bad data version":
                    after["database_after_cli"]["data_version"] = 5
                elif label == "writable mount":
                    before["boundary_before"]["runtime"]["read_only"] = False
                elif label == "config file mode":
                    before["boundary_before"]["configuration"]["file"]["mode"] = "660"
                elif label == "source mount":
                    before["boundary_before"]["runtime"]["records"][0]["source"] = (
                        "/dev/evil"
                    )
                elif label == "runtime change":
                    after["runtime_tree_after"]["tree_digest"] = "sha256:" + "0" * 64
                elif label == "module change":
                    after["modules_after"]["curator"]["observed"]["size"] = 1
                elif label == "command reorder":
                    action["commands"][0], action["commands"][1] = (
                        action["commands"][1],
                        action["commands"][0],
                    )
                elif label == "duplicate pid":
                    action["commands"][1]["pid"] = action["commands"][0]["pid"]
                elif label == "target change":
                    after["target_after"]["tree_digest"] = "sha256:" + "0" * 64
                elif label == "target file digest":
                    before["target_before"]["entries"][0]["digest"] = (
                        "sha256:" + "0" * 64
                    )
                elif label == "discovery change":
                    after["discovery_after"]["target_matches"][0]["filePath"] = (
                        "/tmp/attacker/SKILL.md"
                    )
                elif label == "coordinated discovery model visibility":
                    for discovery in (
                        after["discovery_before"],
                        after["discovery_after"],
                    ):
                        discovery["target_matches"][0]["modelVisible"] = False
                        for skill in discovery["response"]["value"]["skills"]:
                            if skill["name"] == curator._TARGET:
                                skill["modelVisible"] = False
                elif label == "claim ceiling":
                    changed["limitations"][0] = "FORGED"
                elif label == "coordinated status argv":
                    argv = [curator._NODE, curator._OPENCLAW, "--version"]
                    action["commands"][3]["argv"] = argv
                    after["curator_status_before"]["command"]["argv"] = argv
                elif label == "pre-seed status":
                    before["curator_status_before_seed"]["response"]["value"]["counts"][
                        "active"
                    ] = 1
                else:  # pragma: no cover - test table is closed below
                    raise AssertionError(label)
                curator._verify_evidence(changed, profile, lock, config_raw)

            def profile_case() -> None:
                changed = deepcopy(profile)
                changed["controls"]["curator_restore_authority"] = "local"
                verify(selected_profile=changed)

            def receipt_case() -> None:
                changed = deepcopy(receipt)
                changed["results"]["pass"] = [curator._ROUTE]
                verify(source=changed)

            def cas_case() -> None:
                with TemporaryDirectory() as empty:
                    verify(selected_cas=CAS(empty))

            cases = [
                ("local authority", profile_case),
                *(
                    (label, lambda label=label: evidence_case(label))
                    for label in (
                        "module digest",
                        "gateway denial success",
                        "gateway denial error",
                        "cli denial line",
                        "invalid token success",
                        "coordinated active rows",
                        "one post row",
                        "bad data version",
                        "writable mount",
                        "config file mode",
                        "source mount",
                        "runtime change",
                        "module change",
                        "command reorder",
                        "duplicate pid",
                        "target change",
                        "target file digest",
                        "discovery change",
                        "coordinated discovery model visibility",
                        "claim ceiling",
                        "coordinated status argv",
                        "pre-seed status",
                    )
                ),
                ("receipt", receipt_case),
                ("CAS", cas_case),
            ]
            for label, case in cases:
                with (
                    self.subTest(hostile=label),
                    self.assertRaises(AdmissionEvidenceError),
                ):
                    case()


if __name__ == "__main__":
    unittest.main()
