from __future__ import annotations

import base64
import json
import unittest
from copy import deepcopy
from pathlib import Path

from aragorn import admission_openclaw_final_v3_core_updater_provenance as subject
from aragorn.admission_evidence import AdmissionEvidenceError

_ROOT = Path(__file__).resolve().parents[1]
_ACQUISITION = _ROOT / (
    "benchmark/evidence/openclaw-final-v3-core-updater-compiled-modules-2026-09-06.json"
)
_OBSERVATION = _ROOT / (
    "benchmark/evidence/runtime-action-worker-final-combined-v3-route-"
    "core-updater-plugin-replacement-systemd-p3-final-2026-09-03.json"
)


class NativeProvenanceInventoryTests(unittest.TestCase):
    def test_missing_inventory_fails_without_native_execution(self) -> None:
        for files in ({}, {_PATH: b"" for _PATH in subject._MODULES}):
            with self.subTest(files=len(files)), self.assertRaises(AdmissionEvidenceError):
                subject.verify_core_updater_native_provenance(files, {})


class RetainedNativeProvenanceTests(unittest.TestCase):
    def setUp(self) -> None:
        acquisition = json.loads(_ACQUISITION.read_bytes())
        self.files = {
            item["path"]: base64.b64decode(item["content_base64"], validate=True)
            for item in acquisition["acquisition"]["module_files"]
        }
        self.document = json.loads(_OBSERVATION.read_bytes())["route_observation"]["document"]

    def test_retained_source_path_has_no_standalone_pass_authority(self) -> None:
        result = subject.verify_core_updater_native_provenance(self.files, self.document)
        self.assertEqual(len(result["bindings"]["modules"]), 10)
        self.assertTrue(result["source_backed_semantics"]["audit_within_repair_interval"])
        self.assertFalse(result["source_backed_semantics"]["direct_policy_process_or_call_site_trace"])
        self.assertTrue(all(
            value is False for key, value in result["decision"].items()
            if key.endswith("_eligible")
        ))

    def test_missing_extra_changed_or_relocated_native_bytes_fail(self) -> None:
        path = next(iter(self.files))
        missing = dict(self.files)
        del missing[path]
        extra = {**self.files, "/runtime/unexpected.js": b""}
        changed = {**self.files, path: self.files[path][:-1] + b"!"}
        relocated = {**missing, path.removeprefix("/runtime/"): self.files[path]}
        for files in (missing, extra, changed, relocated):
            with self.subTest(paths=tuple(files)), self.assertRaises(AdmissionEvidenceError):
                subject.verify_core_updater_native_provenance(files, self.document)

    def test_alias_and_temporal_provenance_drift_fail(self) -> None:
        for change in ("writer_alias", "diagnostic_alias", "audit_time", "command_time"):
            document = deepcopy(self.document)
            preflight = document["core_updater_preflight"]
            if change == "writer_alias":
                preflight["installed_index"]["writer_module"]["alias"] = "wrong"
            elif change == "diagnostic_alias":
                preflight["trusted_policy_audit"]["diagnostic_module"]["alias"] = "wrong"
            elif change == "audit_time":
                preflight["trusted_policy_audit"]["event"]["ts"] += 60_000
            else:
                action = document["actions"][0]
                changed_start = "2026-09-03T19:49:00.000Z"
                action["commands"][1]["started_at"] = changed_start
                action["observations"]["update_repair"]["command"]["started_at"] = changed_start
            with self.subTest(change=change), self.assertRaises(AdmissionEvidenceError):
                subject.verify_core_updater_native_provenance(self.files, document)


if __name__ == "__main__":
    unittest.main()
