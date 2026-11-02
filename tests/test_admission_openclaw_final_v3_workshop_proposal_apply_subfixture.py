from __future__ import annotations

import hashlib
import json
import re
import unittest
from copy import deepcopy
from datetime import datetime, timedelta
from pathlib import Path

from aragorn import (
    admission_openclaw_final_v3_workshop_proposal_apply_subfixture as subject,
)
from aragorn.admission_evidence import AdmissionEvidenceError
from aragorn.oci_worker_protocol import canonical_digest

_ROOT = Path(__file__).resolve().parents[1]


def _document():
    return json.loads((_ROOT / subject.old._EVIDENCE["path"]).read_bytes())[
        "route_observation"
    ]["document"]


def _refresh_commands(document):
    """Repair only test-fixture output hashes and repeated command records."""
    before = document["actions"][0]["prerequisites"]
    after = document["actions"][0]["observations"]
    responses = [before["system_info"]]
    responses.extend(
        after[name]
        for name in (
            "catalog_before",
            "catalog_after_apply",
            "final_catalog",
            "native_proposal_result",
            "native_apply_result",
        )
    )
    for name in ("initial_turn", "next_same_session_turn"):
        responses.extend([after[name]["send"], after[name]["wait"]])
    for response in responses:
        command = response["command"]
        raw = (
            json.dumps(response["response"]["value"], ensure_ascii=False) + "\n"
        ).encode()
        command.update(
            stdout_excerpt=raw.decode(),
            stdout_bytes=len(raw),
            stdout_digest="sha256:" + hashlib.sha256(raw).hexdigest(),
        )
    before["commands"][1] = deepcopy(before["system_info"]["command"])
    for name in ("initial_turn", "next_same_session_turn"):
        after[name]["commands"] = deepcopy(
            [after[name]["send"]["command"], after[name]["wait"]["command"]]
        )
    document["actions"][0]["commands"] = deepcopy(
        [
            after["catalog_before"]["command"],
            *after["initial_turn"]["commands"],
            after["native_proposal_result"]["command"],
            after["native_apply_result"]["command"],
            after["catalog_after_apply"]["command"],
            *after["next_same_session_turn"]["commands"],
            after["final_catalog"]["command"],
        ]
    )


def _fresh_document():
    """Synthetic coherent identity mutation; this is never fresh-capture evidence."""
    original = _document()
    replacements = {
        original["run_nonce"]: "a" * 32,
        subject.old._SESSION_ID: "12345678-1234-4123-8123-123456789abc",
        subject.old._PROPOSAL_ID: "aragorn-protected-workshop-20260829-abcdef1234",
    }

    def shift(value):
        if isinstance(value, dict):
            return {key: shift(item) for key, item in value.items()}
        if isinstance(value, list):
            return [shift(item) for item in value]
        if type(value) is int and value > 1_000_000_000_000:
            return value + 86_400_000
        if type(value) is str:
            for old, new in replacements.items():
                value = value.replace(old, new)
            return re.sub(
                r"2026-08-28T[0-9:.]+Z",
                lambda match: (
                    (datetime.fromisoformat(match[0]) + timedelta(days=1))
                    .isoformat(timespec="milliseconds")
                    .replace("+00:00", "Z")
                ),
                value,
            )
        return value

    document = shift(original)
    before = document["actions"][0]["prerequisites"]
    after = document["actions"][0]["observations"]
    gateway = before["gateway_process"]
    gateway.update(pid=12345, hostname="abcdef123456", start_time_ticks="987654321")
    before["system_info"]["response"]["value"].update(
        pid=gateway["pid"],
        hostname=gateway["hostname"],
        machineName=gateway["hostname"],
        release="6.8.0-fixture-refresh",
        osLabel="Linux 6.8.0-fixture-refresh",
        memoryTotalBytes=32_000_000_000,
        diskTotalBytes=64_000_000_000,
    )
    before["draft"]["mount"]["records"][0]["root"] = (
        "/docker/volumes/aragorn-fresh-proposal-fixture/_data"
    )
    proposed = after["native_proposal_result"]["response"]["value"]
    new_hash = hashlib.sha256(proposed["content"].encode()).hexdigest()
    proposed["record"]["draftHash"] = new_hash
    after["native_apply_result"]["response"]["value"]["record"]["draftHash"] = new_hash
    for name, digest, inode in (
        ("initial_snapshot", "a", 1234),
        ("final_snapshot", "b", 5678),
    ):
        after[name]["file"].update(
            digest="sha256:" + digest * 64, inode=inode, size=6600
        )
    after["immediate_post_apply_snapshot"] = deepcopy(after["initial_snapshot"])
    _refresh_commands(document)
    commands = [*before["commands"], *document["actions"][0]["commands"]]
    pid_map = {command["pid"]: 20000 + index for index, command in enumerate(commands)}

    def change_pids(value):
        if isinstance(value, dict):
            if "argv" in value:
                value["pid"] = pid_map[value["pid"]]
            for item in value.values():
                change_pids(item)
        elif isinstance(value, list):
            for item in value:
                change_pids(item)

    change_pids(document)
    return document


class WorkshopProposalApplySemanticTests(unittest.TestCase):
    def test_retained_and_coherently_fresh_documents_are_semantic_only(self):
        for document in (_document(), _fresh_document()):
            with self.subTest(nonce=document["run_nonce"]):
                before = deepcopy(document)
                result = subject.verify_openclaw_final_v3_workshop_proposal_apply_semantic_compatibility(
                    document
                )
                self.assertEqual(document, before)
                self.assertEqual(
                    result["bindings"]["input_document_canonical_digest"],
                    canonical_digest(document),
                )
                self.assertIn("NOT_OBSERVED_OR_QUALIFIED", result["decision"]["status"])
                self.assertFalse(result["route_semantics"]["pass_authority"])
                for key in subject.shared._ELIGIBILITY_KEYS:
                    self.assertIs(result["decision"][key], False)

    def test_unjoined_identity_type_and_chronology_mutations_are_rejected(self):
        mutations = (
            (("run_nonce",), "b" * 32),
            (("implementation_digest",), "sha256:" + "0" * 64),
            (("recorded_at",), "2026-08-28T00:00:00.000Z"),
            (("runtime_binding", "commit"), "0" * 40),
            (("protected_boundary", "effective_identity", "uid"), True),
            (("actions", 0, "id"), "workshop-invalidation"),
            (("actions", 0, "prerequisites", "gateway_process", "pid"), 54321),
            (
                ("actions", 0, "prerequisites", "gateway_process", "start_time_ticks"),
                "0",
            ),
            (("actions", 0, "prerequisites", "draft", "mount", "read_only"), False),
            (
                ("actions", 0, "prerequisites", "draft", "mount", "entry", "uid"),
                992,
            ),
            (
                (
                    "actions",
                    0,
                    "prerequisites",
                    "draft",
                    "mount",
                    "records",
                    0,
                    "mount_options",
                ),
                ["ro", "rw"],
            ),
            (
                ("actions", 0, "prerequisites", "draft", "mount", "records", 0, "root"),
                "/docker/volumes/../_data",
            ),
            (
                ("actions", 0, "prerequisites", "draft", "observation", "digest"),
                "sha256:" + "0" * 64,
            ),
            (
                ("actions", 0, "observations", "final_snapshot", "entry", "session_id"),
                "12345678-1234-4123-8123-000000000000",
            ),
            (
                (
                    "actions",
                    0,
                    "observations",
                    "final_snapshot",
                    "entry",
                    "snapshot_version",
                ),
                1787946611772,
            ),
            (
                (
                    "actions",
                    0,
                    "observations",
                    "final_snapshot",
                    "entry",
                    "snapshot_version",
                ),
                True,
            ),
            (
                (
                    "actions",
                    0,
                    "observations",
                    "initial_snapshot",
                    "entry",
                    "runtime_ms",
                ),
                1,
            ),
            (
                (
                    "actions",
                    0,
                    "observations",
                    "final_snapshot",
                    "entry",
                    "prompt",
                    "digest",
                ),
                "sha256:" + "0" * 64,
            ),
            (("actions", 0, "observations", "final_snapshot", "file", "size"), 0),
            (
                ("actions", 0, "observations", "final_snapshot", "file", "digest"),
                subject.old._INITIAL_STORE_DIGEST,
            ),
            (("actions", 0, "observations", "final_snapshot", "file", "inode"), 0),
            (
                (
                    "actions",
                    0,
                    "observations",
                    "native_apply_result",
                    "response",
                    "value",
                    "record",
                    "id",
                ),
                "wrong-proposal",
            ),
            (
                ("actions", 0, "observations", "proposal_result", "proposal_id"),
                "wrong-proposal",
            ),
            (
                ("actions", 0, "observations", "target_after_proposal_observed_at"),
                "2026-08-28T19:50:11.000Z",
            ),
            (
                (
                    "actions",
                    0,
                    "observations",
                    "catalog_after_apply",
                    "response",
                    "value",
                    "ok",
                ),
                True,
            ),
            (
                ("actions", 0, "observations", "final_catalog", "command", "exit_code"),
                0,
            ),
            (("actions", 0, "commands", 0, "stdout_digest"), "sha256:" + "0" * 64),
            (("actions", 0, "observations", "initial_snapshot_check", "ready"), 1),
        )
        for path, value in mutations:
            with self.subTest(path=path, value=value):
                document = _document()
                target = document
                for key in path[:-1]:
                    target = target[key]
                target[path[-1]] = value
                with self.assertRaises(AdmissionEvidenceError):
                    subject.verify_openclaw_final_v3_workshop_proposal_apply_semantic_compatibility(
                        document
                    )

    def test_reencoded_commands_do_not_hide_broken_proposal_or_time_joins(self):
        for mutation in (
            "proposal",
            "scan",
            "command-order",
            "session-command",
            "nonfinite",
        ):
            with self.subTest(mutation=mutation):
                document = _document()
                after = document["actions"][0]["observations"]
                if mutation == "proposal":
                    after["native_apply_result"]["response"]["value"]["record"][
                        "id"
                    ] = "wrong-proposal"
                elif mutation == "scan":
                    after["native_apply_result"]["response"]["value"]["record"]["scan"][
                        "scannedAt"
                    ] = "2026-08-28T19:50:10.000Z"
                elif mutation == "command-order":
                    after["final_catalog"]["command"]["started_at"] = after[
                        "native_apply_result"
                    ]["command"]["started_at"]
                elif mutation == "session-command":
                    command = after["next_same_session_turn"]["send"]["command"]
                    params = json.loads(command["argv"][-1])
                    params["sessionKey"] = "agent:main:different-session"
                    command["argv"][-1] = json.dumps(
                        params, sort_keys=True, separators=(",", ":")
                    )
                else:
                    document["actions"][0]["prerequisites"]["system_info"]["response"][
                        "value"
                    ]["loadAverage"][0] = float("nan")
                _refresh_commands(document)
                with self.assertRaises(AdmissionEvidenceError):
                    subject.verify_openclaw_final_v3_workshop_proposal_apply_semantic_compatibility(
                        document
                    )

    def test_summary_booleans_cannot_substitute_for_observed_facts(self):
        document = _document()
        original = subject.verify_openclaw_final_v3_workshop_proposal_apply_semantic_compatibility(
            document
        )
        after = document["actions"][0]["observations"]
        for key, value in after.items():
            if type(value) is bool:
                after[key] = not value
        for key in (
            "initial_snapshot_check",
            "immediate_post_apply_snapshot_check",
            "final_snapshot_check",
            "final_snapshot_transition",
        ):
            after[key] = {name: not value for name, value in after[key].items()}
        after["initial_turn"]["confirmed"] = True
        after["next_same_session_turn"]["confirmed"] = True
        changed = subject.verify_openclaw_final_v3_workshop_proposal_apply_semantic_compatibility(
            document
        )
        self.assertEqual(changed["decision"], original["decision"])
        after["final_snapshot"]["entry"]["skill_names"].append("unapproved-workshop")
        with self.assertRaises(AdmissionEvidenceError):
            subject.verify_openclaw_final_v3_workshop_proposal_apply_semantic_compatibility(
                document
            )

    def test_malformed_document_is_an_evidence_error(self):
        for value in (None, [], {}, {"actions": []}):
            with self.subTest(value=value), self.assertRaises(AdmissionEvidenceError):
                subject.verify_openclaw_final_v3_workshop_proposal_apply_semantic_compatibility(
                    value
                )


if __name__ == "__main__":
    unittest.main()
