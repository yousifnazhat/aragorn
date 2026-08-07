from __future__ import annotations

import hashlib
import json
import unittest
from copy import deepcopy
from pathlib import Path

from aragorn import runtime_revocation_openclaw_systemd_evidence as verifier
from aragorn.admission_evidence import AdmissionEvidenceError
from aragorn.oci_worker_protocol import canonical_digest, canonical_json

_ROOT = Path(__file__).resolve().parents[1]
_EVIDENCE = (
    _ROOT
    / "benchmark"
    / "evidence"
    / "runtime-revocation-openclaw-systemd-composition-p3-5b-2026-08-06.json"
)
_RAW_DIGEST = "e60d5cc364f9cf378ee832eaa955119733d92a7dafb0fb83365e85eb4f9225c4"
_CANONICAL_DIGEST = (
    "sha256:3751a1650b0f5caa49fa56ef412047f7965ecd06c659e46ca223715de5868e94"
)
_ZERO_DIGEST = "sha256:" + "0" * 64


def _set(*path: str, value: object):
    def mutate(document: dict) -> None:
        current = document
        for name in path[:-1]:
            current = current[name]
        current[path[-1]] = value

    return mutate


def _forge_source_install(document: dict) -> None:
    document["artifacts"][0]["installed_digest"] = _ZERO_DIGEST


def _non_revocation_policy_mismatch(document: dict) -> None:
    document["inputs"]["policy"]["allow"][0]["payload_digest"] = _ZERO_DIGEST


def _stale_revocation(document: dict) -> None:
    decision = document["scenario"]["profile_receipt"]["document"]["broker_result"][
        "decision"
    ]
    document["inputs"]["revocation_publication"]["document"]["expires_at_unix"] = (
        decision["evaluated_at_unix"]
    )


def _replace_gateway_process(document: dict) -> None:
    document["scenario"]["processes_after"]["gateway"]["pid"] += 1


def _no_op_publication(document: dict) -> None:
    before = document["publication"]["before"]["controls"]
    after = document["publication"]["after"]["controls"]
    after["revocations"] = deepcopy(before["revocations"])
    after["state"] = deepcopy(before["state"])


def _post_hoc_grant_receipt_reuse(document: dict) -> None:
    document["scenario"]["grant_state_before"] = deepcopy(
        document["scenario"]["grant_state_after"]
    )


def _forge_journal_authority(document: dict) -> None:
    result = document["publication"]["journal"]["result"]
    result["authority"] = "DURABLE_PROVENANCE_AUTHORITY"


def _forge_broker_reason(document: dict) -> None:
    result = document["scenario"]["driver"]["scenario"]["proof"][
        "retained_tool_result"
    ]["result"]
    result["reason_codes"] = ["ACTION_NOT_ALLOWED"]


def _forge_peer(document: dict) -> None:
    document["peer_trace"]["sensor"]["peer_credentials"][0]["uid"] = 0


def _reuse_receipt_submission(document: dict) -> None:
    document["scenario"]["profile_receipt"]["document"]["submission_digest"] = (
        _ZERO_DIGEST
    )


def _forge_consumed_request(document: dict) -> None:
    document["scenario"]["broker_state"]["document"]["consumed"][0][
        "request_digest"
    ] = _ZERO_DIGEST


def _replace_projected_skills(document: dict) -> None:
    records = document["scenario"]["driver"]["provider"]["records"]
    for record in records:
        for message in record["body"]["messages"]:
            if message.get("role") == "system":
                message["content"] = "No projected skills are present."
        raw = canonical_json(record["body"])
        record["body_raw"] = raw.decode("ascii")
        record["body_bytes"] = len(raw)
        record["body_digest"] = "sha256:" + hashlib.sha256(raw).hexdigest()


class RuntimeRevocationOpenClawSystemdEvidenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.raw = _EVIDENCE.read_bytes()
        cls.document = json.loads(cls.raw)

    def test_retained_artifact_is_pinned_canonical_and_verifies(self) -> None:
        self.assertEqual(hashlib.sha256(self.raw).hexdigest(), _RAW_DIGEST)
        self.assertEqual(self.raw, canonical_json(self.document) + b"\n")
        self.assertEqual(canonical_digest(self.document), _CANONICAL_DIGEST)
        self.assertEqual(verifier._RAW_DIGEST, _RAW_DIGEST)
        self.assertEqual(verifier._EVIDENCE_DIGEST, _CANONICAL_DIGEST)
        verifier.verify_runtime_revocation_openclaw_systemd_evidence(
            self.document,
            expected_digest=_CANONICAL_DIGEST,
        )

    def test_expected_digest_is_explicit_and_exact(self) -> None:
        with self.assertRaises(AdmissionEvidenceError):
            verifier.verify_runtime_revocation_openclaw_systemd_evidence(self.document)
        with self.assertRaises(AdmissionEvidenceError):
            verifier.verify_runtime_revocation_openclaw_systemd_evidence(
                self.document,
                expected_digest="sha256:" + "f" * 64,
            )

    def test_repinned_semantic_mutations_are_rejected(self) -> None:
        mutations = {
            "claim promotion": _set("decision", "run_02_eligible", value=True),
            "durable journal promotion": _set(
                "decision", "journal_result_is_durable_provenance", value=True
            ),
            "limitation removal": lambda document: document["limitations"].pop(),
            "collector closure": _set(
                "collector", "probe", "path", value="/src/scripts/forged.py"
            ),
            "source install closure": _forge_source_install,
            "parent image lineage": _set(
                "harness", "document", "parent_image_id", value=_ZERO_DIGEST
            ),
            "non-revocation policy mismatch": _non_revocation_policy_mismatch,
            "stale revocation": _stale_revocation,
            "replaced protected process": _replace_gateway_process,
            "no-op publication": _no_op_publication,
            "post-hoc grant receipt reuse": _post_hoc_grant_receipt_reuse,
            "publisher credential": _set(
                "deployment",
                "units",
                "publisher_after",
                "LoadCredential",
                value='a(ss) 1 "forged" "/tmp/forged"',
            ),
            "journal authority": _forge_journal_authority,
            "broker sole reason": _forge_broker_reason,
            "skill prompt projection": _replace_projected_skills,
            "receipt submission": _reuse_receipt_submission,
            "consumed request": _forge_consumed_request,
            "blocked effect": _set(
                "scenario", "effects_after", "target", "lexists", value=True
            ),
            "SO_PEERCRED chain": _forge_peer,
            "publication ordering": _set(
                "publication",
                "sequence",
                "publisher_start_monotonic_ns",
                value=0,
            ),
            "journal publication interval": _set(
                "publication",
                "journal",
                "record",
                "__MONOTONIC_TIMESTAMP",
                value="1",
            ),
            "runtime secret absence": _set(
                "scenario",
                "runtime_facing_grant_or_lease_absent",
                value=False,
            ),
        }
        for name, mutate in mutations.items():
            with self.subTest(name=name):
                changed = deepcopy(self.document)
                mutate(changed)
                with self.assertRaises(AdmissionEvidenceError):
                    verifier.verify_runtime_revocation_openclaw_systemd_evidence(
                        changed,
                        expected_digest=canonical_digest(changed),
                    )


if __name__ == "__main__":
    unittest.main()
