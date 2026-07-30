from __future__ import annotations

import json
import tempfile
import unittest
from copy import deepcopy
from io import BytesIO
from pathlib import Path

from aragorn.cas import CAS
from aragorn.oci_worker_protocol import canonical_json
from aragorn.phase1_acquisition_lock_completion import (
    Phase1AcquisitionLockCompletionError,
    derive_phase1_acquisition_lock_completion_v3,
    verify_phase1_acquisition_lock_completion_v3,
)
from aragorn.phase1_acquisition_lock_v2 import (
    phase1_acquisition_lock_workload_v2,
)

_ROOT = Path(__file__).resolve().parents[1]
_EVIDENCE = _ROOT / "benchmark" / "evidence"
_EVIDENCE_V2 = _EVIDENCE / "phase1-acquisition-lock-evidence-v2.json"
_MILESTONE_V2 = (
    _ROOT
    / "benchmark"
    / "receipts"
    / "phase1-acquisition-lock-milestone-v2-2026-07-29.json"
)
_INGRESS = _EVIDENCE / "phase1-supported-ingress-live-c87b82b9b7a4-2026-07-29.tar.xz"
_REQUEST_V4 = (
    _EVIDENCE / "phase1-protected-recursive-v4-live-0307946e55d9-2026-07-29.tar.xz"
)
_COMPLETION = (
    _ROOT
    / "benchmark"
    / "receipts"
    / "phase1-acquisition-lock-completion-v3-2026-07-29.json"
)
_V2_SOURCES = {
    "recursive_archive": (
        _EVIDENCE
        / (
            "phase1-github-recursive-anthropics-claude-plugins-"
            "hook-development-6b708ace-2026-07-29.tar.gz"
        )
    ),
    "recursive_inventory": (
        _EVIDENCE
        / (
            "phase1-github-recursive-anthropics-claude-plugins-"
            "hook-development-6b708ace-2026-07-29.inventory.json"
        )
    ),
    "transition_archive": (
        _EVIDENCE
        / (
            "phase1-protected-transition-obra-superpowers-"
            "requesting-code-review-2026-07-29.tar.gz"
        )
    ),
}


def _cas(root: Path) -> CAS:
    writable = CAS(root)
    leaves = phase1_acquisition_lock_workload_v2()["leaf_digests"]
    sources = {
        leaves["recursive"]["archive"]: _V2_SOURCES["recursive_archive"],
        leaves["recursive"]["inventory"]: _V2_SOURCES["recursive_inventory"],
        leaves["protected_transition"]["archive"]: (_V2_SOURCES["transition_archive"]),
    }
    for expected, source in sources.items():
        raw = source.read_bytes()
        writable.put_expected(
            BytesIO(raw),
            expected_digest=expected,
            max_bytes=len(raw),
        )
    return CAS(root, read_only=True)


class Phase1AcquisitionLockCompletionTests(unittest.TestCase):
    def test_reverifies_all_leaves_and_rejects_forged_completion(self) -> None:
        evidence = json.loads(_EVIDENCE_V2.read_bytes())
        milestone = json.loads(_MILESTONE_V2.read_bytes())
        with tempfile.TemporaryDirectory() as temporary:
            cas = _cas(Path(temporary))
            completion = derive_phase1_acquisition_lock_completion_v3(
                evidence,
                milestone,
                evidence_cas=cas,
                supported_ingress_archive=_INGRESS,
                request_v4_archive=_REQUEST_V4,
            )
            self.assertEqual(completion, json.loads(_COMPLETION.read_bytes()))
            self.assertEqual(
                _COMPLETION.read_bytes(),
                canonical_json(completion) + b"\n",
            )
            self.assertTrue(completion["decision"]["bounded_acquisition_lock_complete"])
            self.assertFalse(completion["decision"]["runtime_conformance_qualified"])
            self.assertEqual(
                completion["claims"]["supported_ingress"][
                    "fully_replayed_successful_cases"
                ],
                2,
            )
            self.assertEqual(
                completion["claims"]["supported_ingress"]["live_summary_only_cases"],
                3,
            )
            self.assertEqual(
                completion["claims"]["current_runtime_numerical_gate"][
                    "implementation"
                ]["source_commit"],
                "c87b82b9b7a4b8465b9958d33d997fd014f49257",
            )
            self.assertTrue(
                completion["claims"]["request_v4_release_pin_custody"][
                    "current_runtime_cross_bound"
                ]
            )
            self.assertIsNone(
                verify_phase1_acquisition_lock_completion_v3(
                    evidence,
                    milestone,
                    completion,
                    evidence_cas=cas,
                    supported_ingress_archive=_INGRESS,
                    request_v4_archive=_REQUEST_V4,
                )
            )

            forged = deepcopy(completion)
            forged["decision"]["public_release_eligible"] = True
            with self.assertRaisesRegex(
                Phase1AcquisitionLockCompletionError,
                "does not match its derived aggregate",
            ):
                verify_phase1_acquisition_lock_completion_v3(
                    evidence,
                    milestone,
                    forged,
                    evidence_cas=cas,
                    supported_ingress_archive=_INGRESS,
                    request_v4_archive=_REQUEST_V4,
                )


if __name__ == "__main__":
    unittest.main()
