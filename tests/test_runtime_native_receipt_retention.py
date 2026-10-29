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
from scripts import openclaw_final_v3_parent_snapshot as parent_snapshot
from scripts import runtime_native_config_denial_check as config_denial
from scripts import runtime_native_health_systemd_check as health
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
HEALTH_ARTIFACT = (
    "benchmark/evidence/phase3-native-health-systemd-development-v1-2026-09-13.json"
)
HEALTH_PIN = (
    446323,
    "d1cb54601571d036ea591c240ae6688b4722e3c710fb16d6efd06044f1dba2fc",
)
HEALTH_SOURCE = "94d788a87d765d9eecfc63ca407b0771c4acef0c"
CONFIG_ARTIFACT = "benchmark/evidence/phase3-native-config-denial-systemd-development-v1-2026-09-22.json"
CONFIG_PIN = (
    485205,
    "a66d351fb9599dfbea04f1645bcfd54934b0c07d9baa09932cb74abb6b9f7a7a",
)
CONFIG_SOURCE = "7dad4d495eb665b06c198361dda71f413fdce72b"


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


def _load(raw, expected=None):
    _pin(raw, PIN if expected is None else expected)
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

    def _native_joins(self, o):
        eq, setup = self.assertEqual, o["setup"]
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

    def test_receipt_ack_journal_effect_source_runtime_and_reported_cleanup_joins(self):
        d, eq = self.document, self.assertEqual
        o = d["observation"]
        self._native_joins(o)
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

    def test_retained_health_publications_preserve_native_receipts_and_stop_profile(
        self,
    ):
        raw = _read(HEALTH_ARTIFACT, HEALTH_PIN)
        with patch.object(json, "loads") as parser, self.assertRaises(ValueError):
            _load(raw[:-1] + b" ", HEALTH_PIN)
        parser.assert_not_called()
        self._health_joins(_load(raw, HEALTH_PIN), HEALTH_SOURCE)

    def test_retained_config_denial_joins_native_health_without_reload_authority(self):
        d = _load(_read(CONFIG_ARTIFACT, CONFIG_PIN), CONFIG_PIN)
        self._health_joins(d, CONFIG_SOURCE, with_config=True)
        o = d["observation"]
        config_denial.validate(o["config_denial"], o)
        helper = "scripts/runtime_native_config_denial_check.py"
        self.assertIn(helper, d["fixture_helpers"])
        self.assertIn(helper, {item["path"] for item in d["source"]["files"]})
        changed = copy.deepcopy(o["config_denial"])
        changed["after"]["effects"]["target_digest"] = "sha256:" + "0" * 64
        with self.assertRaises(config_denial.ConfigDenialError):
            config_denial.validate(changed, o)
        content = copy.deepcopy(d["parent_after"]["content"])
        next(iter(content["contract_files"].values()))["stat_after"]["device"] += 1
        with self.assertRaises(parent_snapshot.campaign.CampaignContractError):
            parent_snapshot._validate_content(content, d["parent_identity"])

    def _health_joins(self, d, source, *, with_config=False):
        eq = self.assertEqual
        o = d["observation"]
        h, setup = o["health_response"], o["setup"]
        self._native_joins(o)
        eq(
            d["schema"],
            "aragorn/runtime-native-config-denial-systemd-capture/v1"
            if with_config
            else "aragorn/runtime-native-health-systemd-capture/v1",
        )
        eq(h["schema"], "aragorn/native-health-systemd-observation/v1")
        eq(d["authority"], self.document["authority"])
        eq(o["authority"], self.document["observation"]["authority"])
        eq(o["limitations"], self.document["observation"]["limitations"])
        eq(
            h["authority"],
            "OWNED_ACCEPTED_HEALTH_RESPONSE_ONLY_NOT_SENSOR_LOSS_OR_RUN_QUALIFICATION",
        )
        for item in (d, o, h):
            eq(item["status"], "OBSERVED")
            for key in ("phase3_eligible", "run_conformance_eligible"):
                self.assertIs(item[key], False)
        for key in (
            "production_activation_eligible",
            "sensor_loss_detection",
            "watchdog_or_stale_health_coverage",
            "durable_dispatch_queue",
        ):
            self.assertIs(h[key], False)
        self.assertIs(d["production_activation_eligible"], False)
        self.assertIs(o["complete_event_coverage"], False)
        self.assertIs(o["native_ack_wire_capture"], False)
        health._check_hook_processes(o["processes"], h["processes_after_hook"])
        changed = copy.deepcopy(h["processes_after_hook"])
        changed["worker"]["process"]["pid"] += 1
        with self.assertRaises(health.HealthFixtureError):
            health._check_hook_processes(o["processes"], changed)
        eq(h["accepted_floor_before"], 3)
        eq(
            h["native_receipts_retained"],
            o["receipt_store_after_create"]["state_digest"],
        )
        self.assertIs(h["native_target_and_broker_receipt_unchanged"], True)
        eq(len(h["invocations"]), 2)
        before = h["invocations"][0]["response"]["result"]["response"]["before"]
        for role, record in zip(("gateway", "worker"), before, strict=True):
            native = o["processes"][role]
            for key in ("pid", "uid", "gid", "cgroup", "start_time_ticks"):
                eq(record["process"][key], native["process"][key])
            for key in ("Id", "MainPID", "ControlGroup", "InvocationID"):
                eq(record["unit"][key], native["unit"][key])
        invocations, cursors, times = set(), set(), []
        for epoch, status, record in zip(
            (4, 5), ("healthy", "unhealthy"), h["invocations"], strict=True
        ):
            document, envelope = record["document"], record["response"]["result"]
            eq(
                document,
                {
                    "schema": "aragorn/runtime-mediator-health/v1",
                    "runtime_digest": setup["runtime_digest"],
                    "sensor_digest": setup["policy"]["sensor_digest"],
                    "epoch": epoch,
                    "status": status,
                    "observed_at_unix": document["observed_at_unix"],
                    "expires_at_unix": document["observed_at_unix"] + 15,
                },
            )
            result = envelope["response"]
            evidence = {
                "cas_root": "/var/lib/aragorn-runtime-response",
                "digest": canonical_digest(result),
                "bytes": len(canonical_json(result)),
                "readback_verified": True,
                "blob_and_directory_chain_fsynced": True,
            }
            eq(
                envelope,
                {
                    "schema": "aragorn/retained-runtime-response/v1",
                    "authority": "LOCAL_ROOT_EVIDENCE_RETENTION_NOT_INDEPENDENT_QUALIFICATION",
                    "response": result,
                    "evidence": evidence,
                },
            )
            eq(
                record["retention"],
                {
                    **evidence,
                    "separate_process_readback": True,
                    "deduplication_checked": True,
                },
            )
            # Only replay embedded evidence. Never launch the acquisition helper,
            # read a host CAS, or claim a new readback/fsync occurred in this test.
            with patch.object(
                health.retained,
                "_retained_response",
                return_value=(result, record["retention"]),
            ) as replay:
                eq(
                    health._join(record, document, setup, before, unhealthy=epoch == 5),
                    record,
                )
                replay.assert_called_once_with(envelope)
            for part, unit in (
                ("publication", health._PUBLISHER),
                ("response", health._DISPATCH),
            ):
                item = record[part]
                journal = item["journal"]
                eq(journal["MESSAGE"].encode("ascii"), canonical_json(item["result"]))
                eq(journal["_SYSTEMD_INVOCATION_ID"], item["invocation_id"])
                eq(journal["_SYSTEMD_UNIT"], unit)
                eq(journal["_BOOT_ID"], o["boot_id"])
                times.append(int(journal["__MONOTONIC_TIMESTAMP"]))
                invocations.add(item["invocation_id"])
                cursors.add(journal["__CURSOR"])
                eq(
                    record["units"][unit],
                    {
                        "Id": unit,
                        "ActiveState": "inactive",
                        "SubState": "dead",
                        "MainPID": "0",
                        "ControlPID": "0",
                        "ExecMainStatus": "0",
                        "Result": "success",
                        "InvocationID": "",
                    },
                )
        eq(len(invocations), 4)
        eq(len(cursors), 4)
        self.assertTrue(all(value > 0 for value in times))
        eq(times, sorted(times))
        result = h["invocations"][1]["response"]["result"]["response"]
        for unit, mask in zip(
            health.response._UNITS, result["future_start_barrier"]["masks"], strict=True
        ):
            eq(
                mask,
                {
                    "path": "/etc/systemd/system/" + unit,
                    "target": "/dev/null",
                    "unit": {
                        "Id": unit,
                        "LoadState": "masked",
                        "UnitFileState": "masked",
                        "ActiveState": "inactive",
                        "SubState": "dead",
                        "MainPID": "0",
                        "ControlPID": "0",
                    },
                },
            )
        refusal = h["persistent_start_refusal"]
        eq(
            refusal["argv"],
            [
                "/usr/bin/systemctl",
                "--system",
                "--no-pager",
                "--no-ask-password",
                "start",
                *health.response._UNITS,
            ],
        )
        eq(refusal["exit_code"], 1)
        eq(refusal["stdout"], "")
        eq(
            refusal["stderr"],
            "".join(
                f"Failed to start {unit}: Unit {unit} is masked.\n"
                for unit in health.response._UNITS
            ),
        )
        hook = h["hook"]
        eq(hook["hook_digest"], health.canonical_digest_bytes(health._HOOK_RAW))
        eq(hook["before"]["units"][health._PUBLISHER]["OnSuccess"], "")
        eq(hook["after"]["units"][health._PUBLISHER]["OnSuccess"], health._DISPATCH)
        eq(hook["after"]["units"][health._PUBLISHER]["OnSuccessJobMode"], "fail")
        eq(hook["after"]["units"][health._PUBLISHER]["DropInPaths"], str(health._HOOK))

        eq(d["source"]["commit"], source)
        eq(d["source"]["signature"]["status"], "GOOD_LOCAL_VERIFICATION")
        eq(d["build_observation"], self.document["build_observation"])
        stage = d["staged_profile"]
        eq(stage["schema"], "aragorn/runtime-native-health-staged-profile/v1")
        eq(
            [len(stage[key]) for key in ("files", "source_inputs", "new_dependencies")],
            [66, 79, 21],
        )
        self.assertTrue(
            all(value is False for value in stage.values() if type(value) is bool)
        )
        eq(stage["required_runtime_not_included"]["tree"], TREE)
        files = {item["path"]: item for item in stage["files"]}
        files.update(
            {item["installed_path"]: item for item in d["fixture_helpers"].values()}
        )
        eq(len(h["installed_sources"]), 7)
        for sources in (o["installed_sources"], h["installed_sources"]):
            for path, record in sources.items():
                eq(_record_pin(record), _record_pin(files[path]))
        sources = {item["path"]: item for item in d["source"]["files"]}
        selected = [
            sources[name]
            for name in (
                "scripts/stage_runtime_native_health_profile.py",
                "scripts/capture_runtime_native_receipt_systemd_check.py",
            )
        ]
        selected.extend(d["fixture_helpers"].values())
        for record in selected:
            committed = subprocess.run(
                [
                    "git",
                    "--no-replace-objects",
                    "show",
                    source + ":" + record["path"],
                ],
                cwd=ROOT,
                capture_output=True,
                check=True,
                timeout=10,
            ).stdout
            _pin(committed, _record_pin(record))
        for key in ("image_inspect", "volume_inspect", "parent"):
            eq(d["parent_before"][key], d["parent_after"][key])
        contents = []
        for key in ("parent_before", "parent_after"):
            content = d[key]["content"]
            parent_snapshot._validate_content(content, d["parent_identity"])
            # Separate overlay mounts may have different st_dev. Each snapshot
            # must still hold its own exact before/after custody; all other
            # metadata and bytes remain equal across the two captures.
            projection = copy.deepcopy(content)
            for record in projection["contract_files"].values():
                for name in ("stat_before", "stat_after"):
                    record[name].pop("device")
            contents.append(projection)
        eq(*contents)
        eq(d["parent_identity"], self.document["parent_identity"])
        eq(d["runtime_before"]["content"], d["runtime_after"]["content"])
        for snapshot in (d["runtime_before"], d["runtime_after"]):
            eq(snapshot["content"]["runtime_tree_before"], TREE)
            eq(snapshot["content"]["runtime_tree_after"], TREE)
            eq(snapshot["volume_inspect"]["Name"], VOLUME)
            self.assertIs(snapshot["content"]["mount"]["read_only"], True)
        container, cleanup = d["fixture_container"], d["cleanup"]
        eq(o["fixture_container"], container)
        eq(h["fixture_container"], container)
        eq(d["fixture_image"]["Id"], IMAGE)
        eq(d["container_inspect"]["Id"], container)
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
                "--health",
                *(["--config-denial"] if with_config else []),
            ],
        )
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
                "dev.aragorn.source-commit": source,
            },
        )
        for key in ("container_name_absent", "removed_id_absent", "daemon_reachable"):
            self.assertIs(cleanup[key], True)
        eq(
            set(o["fixture_stack_cleanup"]),
            set(self.document["observation"]["fixture_stack_cleanup"])
            | set(health._UNITS),
        )
        for unit, state in o["fixture_stack_cleanup"].items():
            eq(state["Id"], unit)
            eq(state["ActiveState"], "inactive")
            eq(state["MainPID"], "0")
            eq(state["ControlPID"], "0")


if __name__ == "__main__":
    unittest.main()
