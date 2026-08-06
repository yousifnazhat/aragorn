from __future__ import annotations

import hashlib
import json
import unittest
from copy import deepcopy
from pathlib import Path
from unittest.mock import patch

from aragorn import runtime_process_profile_openclaw_systemd_evidence as verifier
from aragorn.admission_evidence import AdmissionEvidenceError
from aragorn.oci_worker_protocol import canonical_digest, canonical_json

_ROOT = Path(__file__).resolve().parents[1]
_EVIDENCE = (
    _ROOT
    / "benchmark"
    / "evidence"
    / "runtime-process-profile-openclaw-systemd-composition-p3-4b-2026-08-05.json"
)
_RAW_DIGEST = "a4769cfbcaf57956f974559d5e8c0d9d0ee04dee9b0a7502fce1f2db489d57ce"
_ZERO_DIGEST = "sha256:" + "0" * 64


def _set(*path: str, value: object):
    def mutate(document: dict) -> None:
        current = document
        for name in path[:-1]:
            current = current[name]
        current[path[-1]] = value

    return mutate


def _forge_prompt_projection(document: dict) -> None:
    record = document["scenario"]["driver"]["provider"]["records"][0]
    prompt = next(
        message
        for message in record["body"]["messages"]
        if message.get("role") == "system"
    )
    prompt["content"] = prompt["content"].replace(
        "<name>aragorn-runtime-composition</name>",
        "<name>forged-runtime-composition</name>",
    )
    document["scenario"]["provider_system_prompt"] = prompt["content"]
    raw = canonical_json(record["body"])
    record.update(
        body_raw=raw.decode("ascii"),
        body_bytes=len(raw),
        body_digest="sha256:" + hashlib.sha256(raw).hexdigest(),
    )


def _forge_gateway_peer(document: dict) -> None:
    trace = document["peer_trace"]["sensor"]
    old_pid = trace["peer_credentials"][0]["pid"]
    trace["peer_credentials"][0]["pid"] = 999999
    trace["raw"] = trace["raw"].replace(
        f"pid={old_pid},", "pid=999999,", 1
    )
    trace["raw_digest"] = "sha256:" + hashlib.sha256(
        trace["raw"].encode()
    ).hexdigest()


def _forge_submission(document: dict) -> None:
    scenario = document["scenario"]
    receipt = scenario["receipt"]
    receipt["document"]["submission_digest"] = _ZERO_DIGEST
    receipt["digest"] = canonical_digest(receipt["document"])
    raw = canonical_json(receipt["document"])
    scenario["receipt_file"].update(digest=receipt["digest"], bytes=len(raw))
    scenario["receipt_file"]["stat"]["size"] = len(raw)
    scenario["control_after"]["profile-receipt.json"] = receipt["digest"]


def _append_gateway_argument(document: dict) -> None:
    unit = document["deployment"]["units"]["gateway"]
    unit["ExecStart"] = unit["ExecStart"].replace(
        " ; ignore_errors=", " --inspect ; ignore_errors=", 1
    )


def _refresh_provider_body(record: dict) -> None:
    raw = canonical_json(record["body"])
    record.update(
        body_raw=raw.decode("ascii"),
        body_bytes=len(raw),
        body_digest="sha256:" + hashlib.sha256(raw).hexdigest(),
    )


def _erase_second_provider_body(document: dict) -> None:
    record = document["scenario"]["driver"]["provider"]["records"][1]
    record["body"] = {}
    _refresh_provider_body(record)


def _forge_provider_model(document: dict) -> None:
    record = document["scenario"]["driver"]["provider"]["records"][0]
    record["body"]["model"] = "other-model"
    _refresh_provider_body(record)


def _forge_provider_user_message(document: dict) -> None:
    records = document["scenario"]["driver"]["provider"]["records"]
    for record in records:
        message = record["body"]["messages"][1]
        prefix, separator, _text = message["content"].partition("] ")
        message["content"] = prefix + separator + "unrelated request"
        _refresh_provider_body(record)


def _insert_unpaired_accept(document: dict) -> None:
    trace = document["peer_trace"]["sensor"]
    pid = document["deployment"]["processes"]["sensor"]["pid"]
    extra = (
        f"{pid}   accept4(5, {{sa_family=AF_UNIX}}, "
        "[110 => 2], SOCK_CLOEXEC) = 99\n"
    )
    marker = f"{pid}   accept4(5,  <detached ...>"
    trace["raw"] = trace["raw"].replace(marker, extra + marker, 1)
    trace["raw_digest"] = "sha256:" + hashlib.sha256(
        trace["raw"].encode()
    ).hexdigest()


def _erase_history_assistant_call(document: dict) -> None:
    messages = document["scenario"]["driver"]["turn"]["history"]["response"][
        "messages"
    ]
    messages[1]["content"] = []


class RuntimeProcessProfileOpenClawSystemdEvidenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.raw = _EVIDENCE.read_bytes()
        cls.document = json.loads(cls.raw)

    def test_retained_artifact_is_canonical_and_verifies(self) -> None:
        self.assertEqual(hashlib.sha256(self.raw).hexdigest(), _RAW_DIGEST)
        self.assertEqual(self.raw, canonical_json(self.document) + b"\n")
        verifier.verify_runtime_process_profile_openclaw_systemd_evidence(
            self.document
        )

    def test_retained_digest_is_mandatory(self) -> None:
        with (
            patch.object(verifier, "_EVIDENCE_DIGEST", None),
            self.assertRaises(AdmissionEvidenceError),
        ):
            verifier.verify_runtime_process_profile_openclaw_systemd_evidence(
                self.document
            )

    def test_boundary_mutations_are_rejected_after_repin(self) -> None:
        mutations = {
            "claim promotion": _set("decision", "phase3_exit_eligible", value=True),
            "skill prompt projection": _forge_prompt_projection,
            "gateway MainPID peer": _forge_gateway_peer,
            "gateway appended argument": _append_gateway_argument,
            "provider second-body lineage": _erase_second_provider_body,
            "provider model identity": _forge_provider_model,
            "provider bounded user message": _forge_provider_user_message,
            "unpaired accepted socket": _insert_unpaired_accept,
            "retained assistant tool call": _erase_history_assistant_call,
            "profile digest": _set("profile", "digest", value=_ZERO_DIGEST),
            "submission receipt": _forge_submission,
            "runtime pin": _set(
                "runtime", "tree", "tree_digest", value=_ZERO_DIGEST
            ),
        }
        for name, mutate in mutations.items():
            with self.subTest(name=name):
                changed = deepcopy(self.document)
                mutate(changed)
                with self.assertRaises(AdmissionEvidenceError):
                    verifier.verify_runtime_process_profile_openclaw_systemd_evidence(
                        changed,
                        expected_digest=canonical_digest(changed),
                    )


if __name__ == "__main__":
    unittest.main()
