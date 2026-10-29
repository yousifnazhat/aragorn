from __future__ import annotations

import json
import unittest
from copy import deepcopy
from io import BytesIO
from pathlib import Path
from tempfile import TemporaryDirectory

from aragorn import admission_protected_session_snapshot_fixed_fresh_session as fresh
from aragorn.admission_evidence import AdmissionEvidenceError
from aragorn.cas import CAS

_ROOT = Path(__file__).resolve().parents[1]
_ADMISSION = _ROOT / "benchmark/admission/openclaw-v2026.7.1"
_EVIDENCE = (
    _ROOT
    / "benchmark/evidence/openclaw-v2026.7.1-protected-fresh-session-fixed-2026-08-13.json"
)
_RECEIPT = (
    _ROOT
    / "benchmark/receipts/phase3-openclaw-protected-session-snapshot-fixed-fresh-session-reset-v1-2026-08-13.json"
)
_PARENT = (
    _ROOT
    / "benchmark/receipts/phase3-openclaw-protected-session-snapshot-fixed-route-coverage-v1-2026-08-13.json"
)


def _load(path: Path) -> dict[str, object]:
    return json.loads(path.read_bytes())


class FixedFreshSessionTests(unittest.TestCase):
    def test_exact_seven_route_result_and_hostile_transitions(self) -> None:
        with TemporaryDirectory() as temporary:
            cas = CAS(temporary)
            raw = _EVIDENCE.read_bytes()
            cas.put(BytesIO(raw), max_bytes=len(raw))
            profile = _load(
                _ADMISSION / "protected-session-snapshot-fixed-profile-v1.json"
            )
            lock = _load(
                _ADMISSION / "protected-session-snapshot-fixed-runtime-v1.lock.json"
            )
            receipt = _load(_RECEIPT)
            parent = _load(_PARENT)

            result = (
                fresh.verify_openclaw_protected_session_snapshot_fixed_fresh_session(
                    receipt,
                    evidence_cas=cas,
                    route_profile=profile,
                    runtime_lock=lock,
                    parent_qualification=parent,
                )
            )
            self.assertEqual(
                result["profile"]["counts"], {"fail": 0, "not_tested": 14, "pass": 7}
            )
            statuses = {
                item["id"]: item["status"] for item in result["profile"]["routes"]
            }
            self.assertEqual(statuses[fresh._ROUTE], "PASS")
            self.assertEqual(list(statuses.values()).count("PASS"), 7)
            self.assertTrue(
                all(
                    value is False
                    for key, value in result["decision"].items()
                    if key != "status"
                )
            )

            evidence = json.loads(raw)
            mutations = [
                lambda value: value["selected_route_ids"].clear(),
                lambda value: value["protected_boundary"]["roots"]["managed_skills"][
                    "entry"
                ].__setitem__("gid", 0),
                lambda value: value["actions"][0]["observations"].__setitem__(
                    "session_id_rotated", False
                ),
                lambda value: value["actions"][0]["observations"][
                    "session_after_rotation"
                ]["entry"].__setitem__("snapshot_present", True),
                lambda value: value["actions"][0]["observations"][
                    "session_after_reset"
                ]["entry"]["prompt"].__setitem__("digest", "sha256:" + "0" * 64),
                lambda value: value["actions"][0]["observations"][
                    "reset_turn"
                ].__setitem__("scopes", ["operator.write"]),
                lambda value: value["actions"][0]["commands"][3].__setitem__(
                    "pid", value["actions"][0]["commands"][0]["pid"]
                ),
                lambda value: value["protected_boundary"].__setitem__("ready", False),
                lambda value: value["actions"][0]["prerequisites"]["commands"].append(
                    deepcopy(value["actions"][0]["prerequisites"]["commands"][0])
                ),
                lambda value: value["actions"][0]["observations"][
                    "session_before_reset"
                ]["entry"].__setitem__("started_at", 1),
                lambda value: value["actions"][0]["observations"][
                    "session_after_rotation"
                ]["file"].__setitem__("path", "/tmp/forged-sessions.json"),
                lambda value: value.__setitem__(
                    "recorded_at", "2026-08-13T06:32:30.100Z"
                ),
            ]
            for mutate in mutations:
                changed = deepcopy(evidence)
                mutate(changed)
                with self.assertRaises(AdmissionEvidenceError):
                    fresh._verify_evidence(changed)

            changed_receipt = deepcopy(receipt)
            changed_receipt["results"]["pass"] = [fresh._ROUTE]
            with self.assertRaises(AdmissionEvidenceError):
                fresh.verify_openclaw_protected_session_snapshot_fixed_fresh_session(
                    changed_receipt,
                    evidence_cas=cas,
                    route_profile=profile,
                    runtime_lock=lock,
                    parent_qualification=parent,
                )


if __name__ == "__main__":
    unittest.main()
