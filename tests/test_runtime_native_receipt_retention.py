"""Fixed live-artifact consistency replay, not independent acquisition or qualification."""

import copy
import hashlib
import json
import stat
import subprocess
import unittest
from pathlib import Path
from unittest.mock import mock_open, patch

from aragorn.oci_worker_protocol import canonical_digest, canonical_json
from scripts import runtime_native_receipt_systemd_check as subject
from tests.test_materialize_runtime_native_tool_receipts import _modules
from tests.test_runtime_native_tool_cache_build_retention import ARTIFACT as BUILD
from tests.test_runtime_native_tool_cache_build_retention import PIN as BUILD_PIN
from tests.test_runtime_native_tool_cache_build_retention import TREE

ROOT = Path(__file__).resolve().parents[1]
ARTIFACT = (
    "benchmark/evidence/phase3-native-receipt-systemd-development-v1-2026-09-13.json"
)
PIN = (402783, "8257d73125622c963f82a15fbfb1d992c05a30116e79e9c5a59524ec351dcc5b")
SOURCE = "29c5dc6d84e41f019497dacd3b07e09406117a85"
VOLUME = "aragorn-native-cache-runtime-79ed6eb-v1"
IMAGE = "sha256:1c75f0c37070aa5b702e134e6e6c830690f596891ce0f4fa389ea7515300ea17"


def _pin(raw, expected):
    if type(raw) is not bytes or len(raw) != expected[0]:
        raise ValueError("fixed retained byte length or type changed")
    if hashlib.sha256(raw).hexdigest() != expected[1]:
        raise ValueError("fixed retained digest changed")


def _read(path, expected):
    with (ROOT / path).open("rb") as stream:
        raw = stream.read(expected[0] + 1)
    _pin(raw, expected)
    return raw


def _load(raw):
    _pin(raw, PIN)
    document = json.loads(raw)
    if canonical_json(document) + b"\n" != raw:
        raise ValueError("fixed canonical JSON and final LF changed")
    return document


def _record_pin(record):
    return record["bytes"], record["digest"].removeprefix("sha256:")


class NativeReceiptRetentionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.raw = _read(ARTIFACT, PIN)
        cls.document = _load(cls.raw)

    def test_bounded_pin_before_parse_canonical_lf_and_false_ceilings(self):
        for raw in (bytearray(self.raw), self.raw[:-1], self.raw + b"\n"):
            with (
                patch.object(hashlib, "sha256") as digest,
                patch.object(json, "loads") as parser,
                self.assertRaises(ValueError),
            ):
                _load(raw)
            digest.assert_not_called()
            parser.assert_not_called()
        with patch.object(json, "loads") as parser, self.assertRaises(ValueError):
            _load(self.raw[:-1] + b" ")
        parser.assert_not_called()
        changed = self.raw[:-1] + b" "
        with (
            patch(
                __name__ + ".PIN", (len(changed), hashlib.sha256(changed).hexdigest())
            ),
            self.assertRaises(ValueError),
        ):
            _load(changed)
        with patch.object(Path, "open", mock_open(read_data=self.raw)) as opened:
            self.assertEqual(_read(ARTIFACT, PIN), self.raw)
            opened.return_value.read.assert_called_once_with(PIN[0] + 1)
        d, o = self.document, self.document["observation"]
        self.assertEqual(
            d["schema"], "aragorn/runtime-native-receipt-systemd-capture/v1"
        )
        self.assertEqual(
            d["authority"], "LOCAL_SUCCESSOR_FIXTURE_NOT_RUN_OR_PHASE3_QUALIFICATION"
        )
        self.assertEqual(
            o["schema"],
            "aragorn/runtime-native-receipt-systemd-integration-observation/v1",
        )
        self.assertEqual(
            o["authority"],
            "OWNED_LOCAL_READ_CREATE_OBSERVATION_NOT_COMPLETE_CAPTURE_OR_RUN_AUTHORITY",
        )
        for item in (d, o, o["read"]["output"], o["create"]["output"]):
            self.assertEqual(item["status"], "OBSERVED")
            for flag in ("phase3_eligible", "run_conformance_eligible"):
                self.assertIs(item[flag], False)
        self.assertIs(d["production_activation_eligible"], False)
        self.assertIs(o["complete_event_coverage"], False)
        for item in (o, o["read"]["output"], o["create"]["output"]):
            self.assertIs(item["native_ack_wire_capture"], False)
        self.assertEqual(
            o["limitations"],
            [
                "ONE_OWNED_INERT_READ_AND_NONEXECUTING_CREATE_NOT_GENERAL_TOOL_COMPATIBILITY",
                "GATEWAY_REPORTS_AND_PINNED_HOOK_PATH_NOT_HOSTILE_SAME_PROCESS_CAUSATION",
                "ACK_DIGEST_JOURNAL_JOIN_AND_CLIENT_PATH_NOT_WIRE_CAPTURE_OR_JOURNAL_DURABILITY",
                "NO_PROGRESS_TRANSCRIPT_POSTPROCESSING_OR_INTERMEDIATE_EFFECT_COVERAGE",
                "NO_HOSTILE_OWNER_ROLLBACK_LATENCY_EXTERNAL_COLLECTOR_HEALTH_OR_RUN_QUALIFICATION",
            ],
        )
        stage_flags = [v for v in d["staged_profile"].values() if type(v) is bool]
        self.assertEqual(len(stage_flags), 18)
        self.assertTrue(all(value is False for value in stage_flags))

    def test_receipt_ack_journal_effect_source_runtime_and_reported_cleanup_joins(self):
        d, eq = self.document, self.assertEqual
        o, setup = d["observation"], d["observation"]["setup"]
        snapshots = [
            setup["empty_store"],
            o["receipt_store_after_read"],
            o["receipt_store_after_create"],
        ]
        expected = setup["provisioning"]["genesis_digest"]
        for count, snapshot in zip((0, 2, 4), snapshots, strict=True):
            subject._chain(
                snapshot["genesis"],
                snapshot["state"],
                snapshot["receipts"],
                expected,
                count,
            )
            eq(snapshot["genesis"], snapshots[0]["genesis"])
            eq(snapshot["state_digest"], canonical_digest(snapshot["state"]))
            eq(snapshot["receipts"], snapshots[-1]["receipts"][:count])
        eq(setup["activation_exit_code"], 0)
        for key in ("runtime_digest", "policy_digest", "policy_version"):
            eq(setup["worker_binding"][key], snapshots[0]["genesis"][key])
            eq(setup["provisioning"][key], snapshots[0]["genesis"][key])
        eq(setup["runtime_digest"], TREE["tree_digest"])
        for unit, value in setup["startup"]["load_credentials"].items():
            subject._credentials(value, unit)
        drivers = [o[kind]["output"] for kind in ("read", "create")]
        acks = subject._receipt_proof(snapshots[-1], drivers)
        eq(acks, o["expected_acknowledgements"])
        for ack in acks:
            self.assertIs(ack["effect_authorized"], False)
            self.assertIs(ack["run_qualified"], False)
        for kind, driver in zip(("read", "create"), drivers, strict=True):
            eq(o[kind]["output_digest"], canonical_digest(driver))
            eq(driver["provider"]["request_count"], 2)
            eq(driver["provider"]["error_count"], 0)
            eq(
                driver["gateway"]["system_info"]["response"]["pid"],
                o["processes"]["gateway"]["process"]["pid"],
            )
            self.assertIs(driver["raw_callback_projection_is_source_derived"], True)
        self.assertIs(drivers[0]["read_transcript"]["exact_transcript_rpc_join"], True)
        self.assertIsNone(drivers[1]["read_transcript"])
        self.assertIsNone(drivers[0]["turn"]["identifiers"]["request_digest"])
        effect = o["effect_proof"]
        eq(
            drivers[1]["turn"]["identifiers"]["request_digest"],
            effect["worker_request_digest"],
        )
        receipt = effect["receipt"]
        eq(effect["receipt_digest"], canonical_digest(receipt))
        for key in ("broker_result", "runtime_attribution"):
            eq(receipt[key + "_digest"], canonical_digest(receipt[key]))
        eq(receipt["broker_result"]["verdict"], "ALLOW")
        eq(receipt["broker_result"]["effect_status"], "CREATED")
        eq(receipt["broker_result"]["target_name"], "runtime-worker-qualified.txt")
        eq(
            effect["target_digest"],
            "sha256:20c28aeafad659b2d49aa7b6b94980754eae950fa4338c53bb8b56772c59b24b",
        )
        for key in ("pid", "uid", "gid", "cgroup", "start_time_ticks"):
            eq(
                receipt["runtime_attribution"][key],
                o["processes"]["worker"]["process"][key],
            )
        # Reuse the checker's pinned v2 event contract, not checkout journal v1.
        # This is consistency replay; no collector, socket, or systemd call runs.
        with (
            _modules() as (_, _, journal),
            patch.object(subject.prior, "journal", journal),
        ):
            subject._journal_proof(o["journal"], o["processes"], acks, effect)
            eq(sum(len(item["rows"]) for item in o["journal"].values()), 14)
            for role, item in o["journal"].items():
                lines = item["raw_jsonl"].encode("ascii").splitlines(keepends=True)
                times = [
                    int(row["journal"]["__MONOTONIC_TIMESTAMP"]) for row in item["rows"]
                ]
                rows = []
                for offset in range(0, len(lines), 8):
                    rows.extend(
                        subject.prior._rows(
                            b"".join(lines[offset : offset + 8]),
                            role,
                            o["processes"][role],
                            o["boot_id"],
                            min(times),
                            max(times),
                        )
                    )
                eq(rows, item["rows"])
            changed = copy.deepcopy(o["journal"])
            changed["worker"]["rows"][1]["event"]["result_digest"] = (
                "sha256:" + "0" * 64
            )
            with self.assertRaises(RuntimeError):
                subject._journal_proof(changed, o["processes"], acks, effect)
        changed = copy.deepcopy(snapshots[-1])
        changed["receipts"][2]["event"]["params_digest"] = "sha256:" + "0" * 64
        with self.assertRaises(RuntimeError):
            subject._receipt_proof(changed, drivers)

        eq(d["source"]["commit"], SOURCE)
        eq(d["source"]["signature"]["status"], "GOOD_LOCAL_VERIFICATION")
        eq(d["build_observation"]["path"], BUILD)
        eq(_record_pin(d["build_observation"]), BUILD_PIN)
        build = json.loads(_read(BUILD, BUILD_PIN))
        eq(build["source"]["commit"], d["source"]["parent"])
        eq(build["final_runtime_measurement"]["tree"], TREE)
        stage = d["staged_profile"]
        eq(stage["required_runtime_not_included"]["tree"], TREE)
        files = {record["path"]: record for record in stage["files"]}
        eq(len(files), 60)
        eq(len(stage["source_inputs"]), 72)
        eq(len(stage["new_dependencies"]), 15)
        files.update(
            {
                record["installed_path"]: {**record, "mode": record["installed_mode"]}
                for record in d["fixture_helpers"].values()
            }
        )
        eq(len(o["installed_sources"]), 19)
        for path, installed in o["installed_sources"].items():
            eq(_record_pin(installed), _record_pin(files[path]))
            if path == "/opt/aragorn/native-receipt-read-create-driver-v1.mjs":
                # The driver observation retains bytes/digest, not file metadata.
                eq(set(installed), {"bytes", "digest"})
                continue
            identity = installed["identity"]
            eq(
                identity[2:7],
                [
                    stat.S_IFREG | int(files[path]["mode"], 8),
                    0,
                    0,
                    1,
                    installed["bytes"],
                ],
            )
        sources = {item["path"]: item for item in d["source"]["files"]}
        # Helpers and the stage/capture source may evolve after this capture.
        # Read their immutable Git objects, never today's mutable stage output.
        selected = [
            sources[name]
            for name in (
                "scripts/stage_runtime_native_receipt_profile.py",
                "scripts/capture_runtime_native_receipt_systemd_check.py",
            )
        ]
        selected.extend(d["fixture_helpers"].values())
        for record in selected:
            raw = subprocess.run(
                ["git", "--no-replace-objects", "show", SOURCE + ":" + record["path"]],
                cwd=ROOT,
                capture_output=True,
                check=True,
                timeout=10,
            ).stdout
            _pin(raw, _record_pin(record))
            eq(record["mode"], "100644")
        for snapshot in (d["runtime_before"], d["runtime_after"]):
            eq(snapshot["content"]["runtime_tree_before"], TREE)
            eq(snapshot["content"]["runtime_tree_after"], TREE)
            self.assertIs(snapshot["content"]["mount"]["read_only"], True)
            eq(snapshot["volume_inspect"]["Name"], VOLUME)
            eq(snapshot["running_users_before"], [])
            eq(snapshot["running_users_after"], [])
        eq(d["runtime_before"]["content"], d["runtime_after"]["content"])
        for key in ("content", "image_inspect", "volume_inspect", "parent"):
            eq(d["parent_before"][key], d["parent_after"][key])
        eq(d["parent_before"]["parent"], d["parent_identity"])
        container = d["fixture_container"]
        eq(o["fixture_container"], container)
        eq(d["fixture_image"]["Id"], IMAGE)
        eq(d["container_inspect"]["Id"], container)
        mount = [
            item
            for item in d["container_inspect"]["Mounts"]
            if item["Destination"] == "/runtime"
        ]
        eq(len(mount), 1)
        eq(mount[0]["Name"], VOLUME)
        self.assertIs(mount[0]["RW"], False)
        eq(
            d["invocation"]["argv"],
            [
                "docker",
                "--context",
                "colima-aragorn-bakeoff",
                "exec",
                container,
                "/usr/bin/python3.12",
                "-I",
                "-S",
                "-B",
                "/opt/aragorn/runtime-native-receipt-systemd-check.py",
                container,
            ],
        )
        cleanup = d["cleanup"]
        for key in ("container_name_absent", "removed_id_absent", "daemon_reachable"):
            self.assertIs(cleanup[key], True)
        eq(cleanup["removed_id"], container)
        eq(
            cleanup["owned_container"],
            {
                "id": container,
                "image": IMAGE,
                "name": "/" + cleanup["name"],
                "owner": cleanup["owner"],
            },
        )
        eq(
            d["container_inspect"]["Config"]["Labels"],
            {
                "dev.aragorn.snapshot-owner": cleanup["owner"],
                "dev.aragorn.source-commit": SOURCE,
            },
        )
        for unit, state in o["fixture_stack_cleanup"].items():
            eq(
                state,
                {
                    "Id": unit,
                    "ActiveState": "inactive",
                    "MainPID": "0",
                    "ControlPID": "0",
                },
            )


if __name__ == "__main__":
    unittest.main()
