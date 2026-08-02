from __future__ import annotations

import json
import unittest
from copy import deepcopy
from pathlib import Path

from aragorn.behavior_capability_diff import (
    AUTHORITY,
    CAPABILITY_KINDS,
    BehaviorCapabilityDiffError,
    derive_behavior_capability_diff,
    verify_behavior_capability_diff,
)
from aragorn.oci_worker_protocol import canonical_json

_SUBJECT = "sha256:" + "1" * 64
_DECLARED = ["network-connect", "file-read"]
_OBSERVED = ["process-exec", "file-read"]


class BehaviorCapabilityDiffTests(unittest.TestCase):
    def test_derives_canonical_sets_and_rejects_submitted_drift(self) -> None:
        document = derive_behavior_capability_diff(
            subject_digest=_SUBJECT,
            declared_capabilities=_DECLARED,
            observed_capabilities=_OBSERVED,
        )
        reordered = derive_behavior_capability_diff(
            subject_digest=_SUBJECT,
            declared_capabilities=["file-read", "network-connect"],
            observed_capabilities=["file-read", "process-exec"],
        )
        self.assertEqual(canonical_json(document), canonical_json(reordered))
        self.assertEqual(document["matched_capabilities"], ["file-read"])
        self.assertEqual(
            document["undeclared_observed_capabilities"],
            ["process-exec"],
        )
        self.assertEqual(
            document["declared_not_observed_capabilities"],
            ["network-connect"],
        )
        self.assertEqual(
            verify_behavior_capability_diff(
                document,
                expected_subject_digest=_SUBJECT,
                expected_declared_capabilities=_DECLARED,
                expected_observed_capabilities=_OBSERVED,
            ),
            document,
        )

        mutations = []
        changed = deepcopy(document)
        changed["undeclared_observed_capabilities"] = []
        mutations.append(("derived field", changed, _SUBJECT))
        changed = deepcopy(document)
        changed["observed_capabilities"] = ["socket-open"]
        mutations.append(("unknown category", changed, _SUBJECT))
        changed = deepcopy(document)
        changed["declared_capabilities"] = ["file-read", "file-read"]
        mutations.append(("duplicate category", changed, _SUBJECT))
        changed = deepcopy(document)
        changed["declared_capabilities"] = ["network-connect", "file-read"]
        mutations.append(("noncanonical order", changed, _SUBJECT))
        changed = deepcopy(document)
        changed["matched_capabilities"] = ("file-read",)
        mutations.append(("non-schema array", changed, _SUBJECT))
        changed = deepcopy(document)
        changed["matched_capabilities"] = ["file-read"] * 7
        mutations.append(("oversized derived field", changed, _SUBJECT))
        changed = {**document, "unexpected": []}
        mutations.append(("extra field", changed, _SUBJECT))
        changed = {**document, "authority": "INSTALLER_AUTHORITY"}
        mutations.append(("authority", changed, _SUBJECT))
        mutations.append(("subject", document, "sha256:" + "2" * 64))

        for label, changed, expected_subject in mutations:
            with (
                self.subTest(label=label),
                self.assertRaises(BehaviorCapabilityDiffError),
            ):
                verify_behavior_capability_diff(
                    changed,
                    expected_subject_digest=expected_subject,
                    expected_declared_capabilities=_DECLARED,
                    expected_observed_capabilities=_OBSERVED,
                )

        substituted = derive_behavior_capability_diff(
            subject_digest=_SUBJECT,
            declared_capabilities=["file-write"],
            observed_capabilities=["file-write"],
        )
        with self.assertRaises(BehaviorCapabilityDiffError):
            verify_behavior_capability_diff(
                substituted,
                expected_subject_digest=_SUBJECT,
                expected_declared_capabilities=_DECLARED,
                expected_observed_capabilities=_OBSERVED,
            )

        schema = json.loads(
            (
                Path(__file__).parents[1]
                / "schema"
                / "behavior-capability-diff-v1.schema.json"
            ).read_text()
        )
        self.assertEqual(
            schema["$defs"]["capability"]["enum"],
            sorted(CAPABILITY_KINDS),
        )
        self.assertEqual(document["authority"], AUTHORITY)


if __name__ == "__main__":
    unittest.main()
