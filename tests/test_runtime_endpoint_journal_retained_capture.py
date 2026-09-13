"""Replay one pinned observation, never live capture or RUN qualification.

The upper monotonic bound below is artifact-reported (its latest row), not an
independent reconstruction of collection time, delivery latency, or completeness.
"""

from __future__ import annotations

import hashlib
import json
import unittest
from copy import deepcopy
from pathlib import Path
from unittest.mock import patch

from aragorn.oci_worker_protocol import canonical_digest, canonical_json
from scripts import capture_runtime_quarantine_systemd_check as capture
from scripts import runtime_endpoint_journal_systemd_check as checker

_ARTIFACT = (
    Path(capture.__file__).resolve().parents[1]
    / "benchmark/evidence/phase3-runtime-endpoint-journal-systemd-development-v1-2026-09-13.json"
)
_BYTES = 291238
_SHA256 = "31438babf6eb95b71ef7e8460a8d368375a0416941a89c44f5c8d3b661002bb0"
_COMMIT = "91c1debbf79200d04e195043541fa2ce0b3ac1c5"
_STAGE_FALSE = (
    "broker_response_drain_deployed",
    "durable_event_retention",
    "native_terminal_retention",
    "native_turn_completion",
    "phase3_qualification",
    "producer_release_included",
    "production_activation_eligible",
    "quarantine_response_deployed",
    "root_deployment",
    "run_qualification",
    "runtime_journal_deployed",
    "runtime_startup_enforcement",
)


def _decode_pinned(raw: bytes) -> dict:
    if len(raw) != _BYTES or hashlib.sha256(raw).hexdigest() != _SHA256:
        raise AssertionError("fixed endpoint journal artifact bytes changed")
    value = json.loads(raw, object_pairs_hook=checker._object)
    if canonical_json(value) != raw:
        raise AssertionError("fixed endpoint journal artifact is not canonical")
    return value


class RuntimeEndpointJournalRetainedCaptureTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        with _ARTIFACT.open("rb") as source:
            cls.raw = source.read(_BYTES + 1)
        cls.capture = _decode_pinned(cls.raw)

    def _assert_envelope(self, value):
        observation, stage = value["observation"], value["staged_profile"]
        self.assertEqual(value["source"]["commit"], _COMMIT)
        self.assertEqual(
            value["schema"], "aragorn/runtime-endpoint-journal-systemd-capture/v1"
        )
        self.assertEqual(
            value["authority"],
            "LOCAL_SUCCESSOR_FIXTURE_NOT_RUN_OR_PHASE3_QUALIFICATION",
        )
        self.assertEqual(
            observation["schema"],
            "aragorn/runtime-endpoint-journal-systemd-integration-observation/v1",
        )
        self.assertEqual(
            observation["authority"],
            "LOCAL_JOURNAL_DELIVERY_OBSERVATION_NOT_DURABILITY_COMPLETENESS_OR_RUN_AUTHORITY",
        )
        for item in (value, observation):
            self.assertEqual(item["status"], "OBSERVED")
            self.assertIs(item["phase3_eligible"], False)
            self.assertIs(item["run_conformance_eligible"], False)
        for key in ("durable_event_retention", "complete_event_coverage"):
            self.assertIs(observation[key], False)
        for key in _STAGE_FALSE:
            self.assertIs(stage[key], False)
        self.assertEqual(stage["schema"], capture.journal_stage._SCHEMA)
        self.assertEqual(stage["authority"], capture.journal_stage._AUTHORITY)
        for name, count, key in (
            ("files", 55, "path"),
            ("source_inputs", 63, "name"),
            ("base_inputs", 47, "name"),
            ("new_dependencies", 10, "name"),
        ):
            self.assertEqual(len(stage[name]), count)
            self.assertEqual(len({item[key] for item in stage[name]}), count)
        files = {item["path"]: item for item in stage["files"]}
        self.assertEqual(set(observation["installed_sources"]), set(checker._CODE))
        for path, item in observation["installed_sources"].items():
            size, digest, mode = checker._CODE[path]
            self.assertEqual(
                (item["bytes"], item["digest"]), (size, "sha256:" + digest)
            )
            self.assertEqual(files[path]["bytes"], size)
            self.assertEqual(files[path]["digest"], item["digest"])
            self.assertEqual(files[path]["mode"], f"{mode:04o}")
            identity = item["identity"]
            self.assertEqual(identity[2:7], [0o100000 | mode, 0, 0, 1, size])
        self.assertEqual(set(value["fixture_helpers"]), set(capture._JOURNAL_FILES))
        for path, destination in capture._JOURNAL_FILES.items():
            self.assertEqual(value["fixture_helpers"][path]["path"], path)
            self.assertEqual(
                value["fixture_helpers"][path]["installed_path"], destination
            )
            self.assertEqual(value["fixture_helpers"][path]["installed_mode"], "0444")
        self.assertTrue(
            capture._parent_unchanged(value["parent_before"], value["parent_after"])
        )

    def _assert_journal(self, observation):
        captured, processes = observation["journal"], observation["processes"]
        self.assertEqual(set(captured), set(checker._ROLES))
        # This only replays the recorded range; acquisition-time upper bounds
        # are not retained and are not independently proved by this test.
        reported_upper = max(
            int(row["journal"]["__MONOTONIC_TIMESTAMP"])
            for item in captured.values()
            for row in item["rows"]
        )
        for role, item in captured.items():
            rows = checker._rows(
                item["raw_jsonl"].encode("ascii"),
                role,
                processes[role],
                observation["boot_id"],
                observation["journal_lower_monotonic_us"],
                reported_upper,
            )
            self.assertEqual(rows, item["rows"])
            self.assertTrue(
                all(
                    row["journal"]["__CURSOR"] != observation["journal_after_cursor"]
                    for row in rows
                )
            )
        proof = observation["effect_proof"]
        receipt = proof["receipt"]
        self.assertEqual(canonical_digest(receipt), proof["receipt_digest"])
        self.assertEqual(
            canonical_digest(receipt["broker_result"]), receipt["broker_result_digest"]
        )
        self.assertEqual(
            canonical_digest(receipt["runtime_attribution"]),
            receipt["runtime_attribution_digest"],
        )
        checker._pairs(
            captured, processes, observation["unauthorized_peer_refusal"], proof
        )

    def _assert_cleanup(self, value):
        observation, cleanup = value["observation"], value["cleanup"]
        container = value["fixture_container"]
        self.assertEqual(observation["fixture_container"], container)
        states = observation["fixture_stack_cleanup"]
        self.assertEqual(set(states), set(checker.prior._ALL_UNITS))
        for unit, state in states.items():
            self.assertEqual(
                state,
                {
                    "Id": unit,
                    "ActiveState": "inactive",
                    "MainPID": "0",
                    "ControlPID": "0",
                },
            )
        for key in ("container_name_absent", "removed_id_absent", "daemon_reachable"):
            self.assertIs(cleanup[key], True)
        self.assertEqual(cleanup["removed_id"], container)
        self.assertEqual(cleanup["owned_container"]["id"], container)
        self.assertEqual(cleanup["owned_container"]["owner"], cleanup["owner"])
        self.assertEqual(cleanup["owned_container"]["image"], value["fixture_image"])
        self.assertEqual(cleanup["image"], value["fixture_image"])
        self.assertEqual(cleanup["owned_container"]["name"], "/" + cleanup["name"])
        commands = cleanup["commands"]
        self.assertEqual(len(commands), 6)
        self.assertTrue(
            all(
                type(item["exit_code"]) is int and item["exit_code"] == 0
                for item in commands
            )
        )
        prefix = ["docker", "--context", "colima-aragorn-bakeoff"]
        self.assertEqual(
            commands[2]["argv"], [*prefix, "container", "rm", "--force", container]
        )
        self.assertEqual(commands[2]["stdout"], container + "\n")
        for item, selector in zip(
            commands[-2:],
            ("name=^/" + cleanup["name"] + "$", "id=" + container),
            strict=True,
        ):
            self.assertEqual(
                item["argv"],
                [
                    *prefix,
                    "container",
                    "ls",
                    "--all",
                    "--no-trunc",
                    "--filter",
                    selector,
                    "--format",
                    "{{.ID}}",
                ],
            )
            self.assertEqual(item["stdout"], "")

    def test_exact_capture_replays_eight_records_without_qualification(self):
        self._assert_envelope(self.capture)
        self._assert_journal(self.capture["observation"])
        self._assert_cleanup(self.capture)

    def test_byte_pin_is_checked_before_parsing(self):
        for raw in (b"", self.raw + b" ", b"X" + self.raw[1:]):
            with self.subTest(size=len(raw)), patch.object(json, "loads") as loads:
                with self.assertRaisesRegex(AssertionError, "bytes changed"):
                    _decode_pinned(raw)
                loads.assert_not_called()

    def test_retained_aliases_and_ceilings_cannot_be_promoted(self):
        for name in (
            "raw-alias",
            "result-join",
            "qualification",
            "unit-cleanup",
            "container-removal",
        ):
            value = deepcopy(self.capture)
            observation = value["observation"]
            if name == "raw-alias":
                observation["journal"]["worker"]["rows"][0]["event"]["stage"] = "FRAME"
            elif name == "result-join":
                observation["effect_proof"]["worker_request_digest"] = (
                    "sha256:" + "0" * 64
                )
            elif name == "qualification":
                observation["complete_event_coverage"] = True
            elif name == "unit-cleanup":
                observation["fixture_stack_cleanup"][checker.prior._WORKER][
                    "MainPID"
                ] = "1"
            else:
                value["cleanup"]["commands"][-1]["stdout"] = (
                    value["fixture_container"] + "\n"
                )
            with (
                self.subTest(name=name),
                self.assertRaises((AssertionError, RuntimeError)),
            ):
                self._assert_envelope(value)
                self._assert_journal(observation)
                self._assert_cleanup(value)


if __name__ == "__main__":
    unittest.main()
