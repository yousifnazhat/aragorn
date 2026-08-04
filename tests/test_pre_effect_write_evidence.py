from __future__ import annotations

import hashlib
import json
import unittest
from copy import deepcopy
from pathlib import Path

from aragorn.admission_evidence import AdmissionEvidenceError
from aragorn.admission_evidence_pre_effect_write import (
    verify_openclaw_pre_effect_write_evidence,
)

_ROOT = Path(__file__).resolve().parents[1]
_EVIDENCE = (
    _ROOT
    / "benchmark"
    / "evidence"
    / "openclaw-v2026.7.1-pre-effect-write-2026-08-03.json"
)
_PROBE = (
    _ROOT
    / "benchmark"
    / "admission"
    / "openclaw-v2026.7.1"
    / "pre-effect-write-probe.mjs"
)


class PreEffectWriteEvidenceTests(unittest.TestCase):
    def test_retained_slice_replays_and_rejects_boundary_mutations(self) -> None:
        raw = _EVIDENCE.read_bytes()
        self.assertEqual(
            hashlib.sha256(raw).hexdigest(),
            "b60039d2a1cd63b3853ac851a900d2157f1315908c054de8e2b2c34267a886c2",
        )
        document = json.loads(raw)
        verify_openclaw_pre_effect_write_evidence(document)
        self.assertEqual(
            "sha256:" + hashlib.sha256(_PROBE.read_bytes()).hexdigest(),
            document["adapter"]["implementation_digest"],
        )

        mutations = [
            lambda item: item["decision"].update(run_01_eligible=True),
            lambda item: item["inputs"]["skill"].update(digest="sha256:" + "0" * 64),
            lambda item: item["scenario"]["evidence"]["history"]["response"][
                "messages"
            ][3]["content"][0].update(id="unbound-write"),
            lambda item: item["scenario"]["evidence"]["denied_tool_result"].update(
                isError=False
            ),
            lambda item: item["mountinfo"]["before"]["protected"].update(
                mount_options=["rw"]
            ),
            lambda item: item["scenario"]["evidence"]["target_after"]["target"].update(
                exists=True
            ),
            lambda item: item["processes"].update(
                gateway_after={**item["processes"]["gateway_after"], "pid": 2}
            ),
        ]
        for mutate in mutations:
            changed = deepcopy(document)
            mutate(changed)
            with self.subTest(mutate=mutate), self.assertRaises(AdmissionEvidenceError):
                verify_openclaw_pre_effect_write_evidence(changed)


if __name__ == "__main__":
    unittest.main()
