from __future__ import annotations

import json
import unittest
from copy import deepcopy
from pathlib import Path

from aragorn.admission_evidence import AdmissionEvidenceError
from aragorn.admission_evidence_shared_filesystem_update import (
    verify_openclaw_shared_filesystem_update_evidence,
)
from aragorn.oci_worker_protocol import canonical_json

_ROOT = Path(__file__).resolve().parents[1]
_EVIDENCE = (
    _ROOT
    / "benchmark"
    / "evidence"
    / "openclaw-v2026.7.1-shared-filesystem-update-2026-07-29.json"
)


class SharedFilesystemUpdateEvidenceTests(unittest.TestCase):
    def test_slice_is_canonical_bound_and_non_authoritative(self) -> None:
        raw = _EVIDENCE.read_bytes()
        document = json.loads(raw)
        self.assertEqual(raw, canonical_json(document) + b"\n")
        verify_openclaw_shared_filesystem_update_evidence(document)

        mutations = [
            lambda item: item["decision"].update(installer_work_eligible=True),
            lambda item: item["payload"]["composition"]["container"].update(
                id="0" * 64
            ),
            lambda item: item["payload"]["composition"]["mount"]["after"][
                "container"
            ].update(inode=1),
            lambda item: item["payload"]["broker_update"]["after"].update(
                skill_digest="sha256:" + "0" * 64
            ),
            lambda item: item["payload"]["broker_update"][
                "coordinator_state_after"
            ].update(version_path="wrong"),
            lambda item: item["payload"]["activation"]["skills_status_after"].update(
                eligible=False
            ),
            lambda item: item["payload"]["gateway"]["process"]["after"].update(
                start_time_ticks="686561"
            ),
            lambda item: item["payload"]["os_invariant"]["attempts"][0].update(
                blocked=False
            ),
        ]
        for mutate in mutations:
            changed = deepcopy(document)
            mutate(changed)
            with self.subTest(mutate=mutate), self.assertRaises(AdmissionEvidenceError):
                verify_openclaw_shared_filesystem_update_evidence(changed)


if __name__ == "__main__":
    unittest.main()
