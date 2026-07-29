from __future__ import annotations

import json
import unittest
from copy import deepcopy
from pathlib import Path

from aragorn.admission_evidence import AdmissionEvidenceError
from aragorn.admission_evidence_coordinator_activation import (
    verify_openclaw_coordinator_runtime_activation_evidence,
)
from aragorn.oci_worker_protocol import canonical_json

_ROOT = Path(__file__).resolve().parents[1]
_EVIDENCE = (
    _ROOT
    / "benchmark"
    / "evidence"
    / "openclaw-v2026.7.1-coordinator-runtime-activation-2026-07-29.json"
)


class CoordinatorRuntimeActivationTests(unittest.TestCase):
    def test_retained_slice_is_canonical_bound_and_non_authoritative(
        self,
    ) -> None:
        raw = _EVIDENCE.read_bytes()
        document = json.loads(raw)
        self.assertEqual(raw, canonical_json(document) + b"\n")
        verify_openclaw_coordinator_runtime_activation_evidence(document)

        mutations = [
            lambda item: item["decision"].update(status="PASS"),
            lambda item: item["payload"]["composition"].update(
                docker_context="colima-aragorn-bakeoff"
            ),
            lambda item: item["payload"]["composition"]["mounts"][
                "/profile/state/skills"
            ].update(read_only=False),
            lambda item: item["payload"]["activation"]["provider"].update(
                tool_content="different"
            ),
            lambda item: item["payload"]["target"].update(
                digest="sha256:" + "0" * 64
            ),
        ]
        for mutate in mutations:
            changed = deepcopy(document)
            mutate(changed)
            with self.subTest(mutate=mutate), self.assertRaises(
                AdmissionEvidenceError
            ):
                verify_openclaw_coordinator_runtime_activation_evidence(
                    changed
                )


if __name__ == "__main__":
    unittest.main()
