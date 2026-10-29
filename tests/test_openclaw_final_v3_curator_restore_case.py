from __future__ import annotations

import base64
import json
import stat
import subprocess
import unittest
from copy import deepcopy
from datetime import datetime, timedelta
from pathlib import Path
from tempfile import TemporaryDirectory

from aragorn import admission_openclaw_final_v3_campaign as campaign
from aragorn.admission_evidence import AdmissionEvidenceError
from aragorn.oci_worker_protocol import canonical_digest, canonical_json
from scripts import openclaw_final_v3_curator_restore_case as subject

_ROOT = Path(__file__).resolve().parents[1]


def _sync_route(native: dict) -> None:
    route = native["route_observation"]
    document = route["document"]
    raw = canonical_json(document) + b"\n"
    route["raw"] = {
        "base64": base64.b64encode(raw).decode(),
        "bytes": len(raw),
        "canonical_digest": canonical_digest(document),
        "digest": subject.old._digest(raw),
        "raw_is_canonical_json_lf": True,
    }
    route["route"] = deepcopy(document["route"])


def _sync_harness(native: dict) -> None:
    harness = native["harness"]
    raw = canonical_json(harness["document"])
    harness["digest"] = subject.old._digest(raw)
    harness["file"].update(
        base64=base64.b64encode(raw).decode(), bytes=len(raw), digest=harness["digest"]
    )
    harness["file"]["stat"]["size"] = len(raw)
    native["composition"]["action"]["harness"] = deepcopy(harness)


def _refresh_commands(document: dict) -> None:
    action = document["action"]
    commands = {item["pid"]: item for item in action["commands"]}

    def refresh(value):
        if type(value) is dict:
            if "command" in value and "response" in value:
                command, response = value["command"], value["response"]
                if (
                    response["parsed"] is True
                    and command["exit_code"] == 0
                    and command["argv"][2:5] == ["gateway", "call", "system.info"]
                ):
                    output = json.loads(command["stdout_excerpt"])
                    output.update(response["value"])
                    raw = (json.dumps(output, indent=2) + "\n").encode()
                    command.update(
                        stdout_bytes=len(raw),
                        stdout_digest=subject.old._digest(raw),
                        stdout_excerpt=raw.decode(),
                    )
                commands[command["pid"]] = command
            for child in value.values():
                refresh(child)
        elif type(value) is list:
            for child in value:
                refresh(child)

    refresh(action["prerequisites"])
    refresh(action["observations"])
    action["commands"] = [
        deepcopy(commands[item["pid"]]) for item in action["commands"]
    ]


class CuratorRestoreCaseTests(unittest.TestCase):
    def test_retained_fresh_development_capture_reverifies(self) -> None:
        raw = (
            _ROOT
            / "benchmark/evidence/phase3-openclaw-final-v3-curator-restore-development-case-v1-2026-09-11.json"
        ).read_bytes()
        self.assertEqual(
            subject.old._digest(raw),
            "sha256:405bd65cd927c3bb4cfaf64ee6b468f363e843c1aa7a559b8a341cf1746b70e6",
        )
        captured = json.loads(raw)
        verified = subject.verify_capture(
            base64.b64decode(captured["native_capture"]["base64"], validate=True),
            captured["request_binding"],
            source=captured["source"],
            invocation=captured["invocation"],
        )
        self.assertEqual(verified["proof"], captured["capture_checks"])
        self.assertIs(captured["cleanup"]["container_absent"], True)
        self.assertIs(captured["cleanup"]["volume_absent"], True)
        for field in ("image_inspect", "volume_inspect"):
            self.assertEqual(
                captured["parent_before"][field], captured["parent_after"][field]
            )
        self.assertEqual(
            captured["parent_before"]["content"]["runtime_tree_before"],
            captured["parent_after"]["content"]["runtime_tree_after"],
        )
        self.assertTrue(
            all(
                value is False
                for key, value in captured["decision"].items()
                if key.endswith("_eligible")
            )
        )

    @classmethod
    def setUpClass(cls) -> None:
        cls.temporary = TemporaryDirectory()
        cls.addClassCleanup(cls.temporary.cleanup)
        cls.directory = Path(cls.temporary.name).resolve()
        cls.contract = campaign.build_openclaw_final_v3_campaign_contract(
            campaign_nonce="a" * 64
        )
        cls.request = campaign.build_openclaw_final_v3_subfixture_request(
            cls.contract, subject._CASE
        )
        cls.prepared = subject.prepare_case(
            cls.contract, cls.request, directory=cls.directory
        )
        cls.source = {
            **subject.old._SOURCE,
            "files": subject.checks.historical_sources(
                subject.old._SOURCE, subject.SOURCE_PATHS
            ),
        }
        cls.raw = (_ROOT / subject.old._EVIDENCE["path"]).read_bytes()
        cls.native = json.loads(cls.raw)
        # Historical evidence is a regression input, not a new native capture.
        cls.invocation = {
            "argv": [
                "/bin/sh",
                str(_ROOT / subject._RECIPE),
                str(cls.directory / "native.json"),
            ],
            "exit_code": 0,
            "started_at": "2026-08-31T00:00:00Z",
            "completed_at": "2026-09-01T00:00:00Z",
        }

    def verify(self, native: dict) -> dict:
        return subject.verify_capture(
            canonical_json(native) + b"\n",
            self.prepared,
            source=self.source,
            invocation=self.invocation,
        )

    def test_preparation_binds_exact_bundle_source_and_native_argv(self) -> None:
        self.assertEqual(subject._CASE, "ADM-02/update/curator-restore-activation")
        self.assertEqual(self.prepared["request"], self.request)
        self.assertIsNone(self.prepared["descriptor"]["materializer"])
        self.assertEqual(self.prepared["bundle_files"], subject.old._PROBE_BUNDLE)
        self.assertEqual(
            set(subject.SOURCE_PATHS),
            {
                item[2]
                for item in (
                    *subject.old._SOURCE_ARTIFACTS.values(),
                    *subject.old._COLLECTOR_ARTIFACTS.values(),
                )
            },
        )
        self.assertEqual(self.prepared["source_files"], self.source["files"])
        mapping = self.prepared["path_mapping"]
        self.assertIs(mapping["literal_dispatch_argv_equality"], False)
        self.assertEqual(
            self.prepared["descriptor"]["argv"],
            ["/usr/local/bin/node", subject._PROVISIONAL_ROOT + "/" + subject._PROBE],
        )
        bundle = self.directory / "bundle"
        self.assertEqual(stat.S_IMODE(bundle.stat().st_mode), 0o555)
        self.assertEqual(
            {path.name for path in bundle.iterdir()},
            {item["name"] for item in subject.old._PROBE_BUNDLE},
        )
        self.assertEqual(len(mapping["files"]), 2)
        for item, mapped in zip(
            subject.old._PROBE_BUNDLE, mapping["files"], strict=True
        ):
            path = bundle / item["name"]
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o444)
            self.assertEqual(len(path.read_bytes()), item["bytes"])
            self.assertEqual(subject.old._digest(path.read_bytes()), item["digest"])
            self.assertEqual(
                mapped["native"], subject._NATIVE_ROOT + "/" + item["name"]
            )
            self.assertEqual(
                mapped["provisional"], subject._PROVISIONAL_ROOT + "/" + item["name"]
            )
            self.assertEqual(
                mapped["role"],
                "probe" if item["name"] == subject._PROBE else "probe-dependency",
            )
            self.assertEqual(
                (mapped["bytes"], mapped["digest"]), (item["bytes"], item["digest"])
            )

    def test_changed_request_fails_before_materialization(self) -> None:
        for value in (True, 99, "12"):
            with self.subTest(ordinal=value), TemporaryDirectory() as temporary:
                changed = deepcopy(self.request)
                changed["case"]["ordinal"] = value
                directory = Path(temporary).resolve()
                with self.assertRaises(AdmissionEvidenceError):
                    subject.prepare_case(self.contract, changed, directory=directory)
                self.assertEqual(list(directory.iterdir()), [])

    def test_retained_input_replays_without_granting_eligibility(self) -> None:
        self.assertEqual(subject.old._digest(self.raw), subject.old._EVIDENCE["digest"])
        result = subject.verify_capture(
            self.raw, self.prepared, source=self.source, invocation=self.invocation
        )
        self.assertEqual(result["native_capture"], self.native)
        self.assertEqual(result["harness"], self.native["harness"]["document"])
        self.assertEqual(
            result["proof"]["native_capture_digest"], subject.old._digest(self.raw)
        )
        self.assertEqual(
            result["proof"]["actual_native_argv"],
            self.native["route_observation"]["execution"]["argv"],
        )
        self.assertEqual(self.native["decision"]["route_pass_count"], 0)
        self.assertTrue(
            all(
                value is False
                for key, value in result["decision"].items()
                if key.endswith("_eligible")
            )
        )
        native = deepcopy(self.native)
        _sync_route(native)
        self.assertEqual(self.verify(native)["native_capture"], native)
        route = native["route_observation"]
        raw = (json.dumps(route["document"], indent=2) + "\n").encode()
        route["raw"].update(
            base64=base64.b64encode(raw).decode(),
            bytes=len(raw),
            digest=subject.old._digest(raw),
            raw_is_canonical_json_lf=False,
        )
        with self.assertRaises(AdmissionEvidenceError):
            self.verify(native)
        _sync_route(native)
        route["raw"]["raw_is_canonical_json_lf"] = False
        with self.assertRaises(AdmissionEvidenceError):
            self.verify(native)

    def test_rejects_source_preparation_and_raw_custody_drift(self) -> None:
        for mutation in (
            "mapping",
            "source",
            "duplicate_source",
            "bundle",
            "raw",
            "raw_format",
            "document",
            "route",
            "eligibility",
        ):
            with self.subTest(mutation=mutation):
                prepared, source, native = map(
                    deepcopy, (self.prepared, self.source, self.native)
                )
                route = native["route_observation"]
                if mutation == "mapping":
                    prepared["path_mapping"]["native_root"] = "/elsewhere"
                elif mutation == "source":
                    source["files"][0]["digest"] = "sha256:" + "0" * 64
                elif mutation == "duplicate_source":
                    source["files"].append(deepcopy(source["files"][0]))
                elif mutation == "bundle":
                    route["bundle"][0]["bytes"] += 1
                elif mutation == "raw":
                    route["raw"]["base64"] = base64.b64encode(b"{}").decode()
                elif mutation == "raw_format":
                    route["raw"]["raw_is_canonical_json_lf"] = False
                elif mutation == "document":
                    route["document"]["run_nonce"] = "0" * 32
                elif mutation == "route":
                    route["route"]["status"] = "PASS"
                else:
                    native["decision"]["phase3_exit_eligible"] = True
                with self.assertRaises(AdmissionEvidenceError):
                    subject.verify_capture(
                        canonical_json(native) + b"\n",
                        prepared,
                        source=source,
                        invocation=self.invocation,
                    )

    def test_rejects_coherently_reencoded_semantic_and_composition_drift(self) -> None:
        for mutation in (
            "database_row",
            "command_join",
            "command_service_pid",
            "probe_volume",
            "identity",
            "bindings",
            "profile",
            "artifact",
            "composition_decision",
        ):
            with self.subTest(mutation=mutation):
                native = deepcopy(self.native)
                composition = native["composition"]
                action = native["route_observation"]["document"]["action"]
                if mutation == "database_row":
                    action["observations"]["database_after_gateway"]["row"]["state"] = (
                        "active"
                    )
                elif mutation == "command_join":
                    action["commands"][0]["pid"] += 1
                elif mutation == "command_service_pid":
                    pid = native["route_observation"]["stack_before"]["pids"][
                        "aragorn-runtime-action-worker.service"
                    ]
                    action["commands"][1]["pid"] = pid
                    action["prerequisites"]["system_info_before"]["command"]["pid"] = (
                        pid
                    )
                elif mutation == "probe_volume":
                    for state, key in (
                        (action["prerequisites"], "boundary_before"),
                        (action["observations"], "boundary_after"),
                    ):
                        state[key]["probe"]["records"][0]["root"] = (
                            "/docker/volumes/aragorn-phase3-final-combined-v3-curator-restore-route-input-99999/_data"
                        )
                elif mutation == "identity":
                    composition["action"]["identities"]["gateway"]["uid"] = 991
                elif mutation == "bindings":
                    composition["bindings"]["sessions"] = "reused"
                elif mutation == "profile":
                    composition["profile"]["before"]["outcomes"]["PASS"] = 1
                    composition["profile"]["after"] = deepcopy(
                        composition["profile"]["before"]
                    )
                elif mutation == "artifact":
                    composition["action"]["artifacts"][
                        "final_combined_v3_curator_restore"
                    ]["curator_restore_probe"]["runtime_probe"]["stat"]["mode"] = "0666"
                else:
                    composition["decision"]["status"] = native["decision"]["status"]
                _sync_route(native)
                with self.assertRaises(AdmissionEvidenceError):
                    self.verify(native)

    def test_rejects_execution_and_shape_drift(self) -> None:
        for mutation in (
            "pid",
            "namespace",
            "environment_name",
            "environment_names",
            "argv",
            "extra_route",
            "extra_execution",
            "boolean_exit",
        ):
            with self.subTest(mutation=mutation):
                native = deepcopy(self.native)
                route = native["route_observation"]
                if mutation == "pid":
                    route["gateway_pid_binding"]["pid"] += 1
                elif mutation == "namespace":
                    route["gateway_pid_binding"]["mount_namespace"] = "/proc/1/ns/mnt"
                elif mutation == "environment_name":
                    route["gateway_pid_binding"]["environment_name"] = "OTHER_PID"
                elif mutation == "environment_names":
                    route["execution"]["environment_names"].append("OPENCLAW_TEST_FAST")
                elif mutation == "argv":
                    route["execution"]["argv"] += ["--route-id", subject._CASE]
                elif mutation == "extra_route":
                    route["unexpected"] = "unbound"
                elif mutation == "extra_execution":
                    route["execution"]["unexpected"] = "unbound"
                else:
                    route["execution"]["exit_code"] = False
                with self.assertRaises(AdmissionEvidenceError):
                    self.verify(native)

    def test_rejects_coherently_reencoded_host_and_mount_drift(self) -> None:
        for mutation in (
            "host_config",
            "binds",
            "mount_destination",
            "mount_mode",
            "volume_options",
            "volume_scope",
            "capture_owner",
        ):
            with self.subTest(mutation=mutation):
                native = deepcopy(self.native)
                host = native["harness"]["document"]
                if mutation == "host_config":
                    host["host_config"]["ipc_mode"] = "host"
                elif mutation == "binds":
                    host["host_config"]["binds"].append("/tmp:/extra:ro")
                elif mutation == "mount_destination":
                    host["route_input_mount"]["destination"] = "/elsewhere"
                elif mutation == "mount_mode":
                    host["openclaw_runtime_mount"]["mode"] = "rw"
                elif mutation == "volume_options":
                    host["route_input_volume_identity"]["options"] = {"device": "/tmp"}
                elif mutation == "volume_scope":
                    host["route_input_volume_identity"]["scope"] = "global"
                else:
                    host["route_input_volume_identity"]["labels"][
                        "dev.aragorn.capture-owner"
                    ] = subject.old._SOURCE["commit"] + ":1"
                _sync_harness(native)
                with self.assertRaises(AdmissionEvidenceError):
                    self.verify(native)

    def test_rejects_composition_and_invocation_chronology_drift(self) -> None:
        for mutation in (
            "composition_before_execution",
            "composition_after_outer",
            "outer_before_execution",
            "invocation",
        ):
            with self.subTest(mutation=mutation):
                native, invocation = map(deepcopy, (self.native, self.invocation))
                if mutation == "composition_before_execution":
                    native["composition"]["recorded_at"] = native["route_observation"][
                        "execution"
                    ]["started_at"]
                elif mutation == "composition_after_outer":
                    native["composition"]["recorded_at"] = "2026-08-31T00:13:46Z"
                elif mutation == "outer_before_execution":
                    native["recorded_at"] = native["route_observation"]["execution"][
                        "started_at"
                    ]
                else:
                    invocation["completed_at"] = invocation["started_at"]
                with self.assertRaises(AdmissionEvidenceError):
                    subject.verify_capture(
                        canonical_json(native) + b"\n",
                        self.prepared,
                        source=self.source,
                        invocation=invocation,
                    )

    def test_synthetic_fresh_identity_joins_are_not_capture_authority(self) -> None:
        old_host = self.native["harness"]["document"]
        old_gateway = self.native["route_observation"]["document"]["action"][
            "prerequisites"
        ]["gateway_process_before"]
        pid, hostname = 12345, "abcdef123456"
        ticks = str(int(old_gateway["start_time_ticks"]) + 1)
        container = hostname + "0" * 52
        volume = "aragorn-phase3-final-combined-v3-curator-restore-route-input-90001"
        replacements = {
            old_host["container_id"]: container,
            old_host["container_id"][:12]: hostname,
            old_host["route_input_volume_identity"]["name"]: volume,
            f"/proc/{old_gateway['pid']}/": f"/proc/{pid}/",
            f"pid={old_gateway['pid']} ;": f"pid={pid} ;",
        }

        def remap(value):
            if type(value) is dict:
                return {key: remap(item) for key, item in value.items()}
            if type(value) is list:
                return [remap(item) for item in value]
            if type(value) is int and value == old_gateway["pid"]:
                return pid
            if type(value) is str:
                if value == str(old_gateway["pid"]):
                    return str(pid)
                if value == old_gateway["start_time_ticks"]:
                    return ticks
                if value.startswith("2026-08-31T"):
                    return (
                        (datetime.fromisoformat(value) + timedelta(days=1))
                        .isoformat()
                        .replace("+00:00", "Z")
                    )
                for old, new in replacements.items():
                    value = value.replace(old, new)
            return value

        native = remap(self.native)
        route, host = native["route_observation"], native["harness"]["document"]
        route["document"]["run_nonce"] = "e" * 32
        _refresh_commands(route["document"])
        for state in (
            route["stack_before"]["service_state"],
            native["composition"]["action"]["boundaries"]["service_state"],
        ):
            properties = state["units"]["aragorn-agent-gateway.service"]["properties"]
            properties["ExecMainStartTimestampMonotonic"] = str(int(ticks) * 10_000)
            properties["ActiveEnterTimestampMonotonic"] = str(
                int(ticks) * 10_000 + 1_000
            )
            for entry in state["units"].values():
                raw = "".join(
                    f"{key}={value}\n" for key, value in entry["properties"].items()
                ).encode()
                entry["command"]["stdout"] = {
                    "base64": base64.b64encode(raw).decode(),
                    "bytes": len(raw),
                    "digest": subject.old._digest(raw),
                }
        git = subject.checks.old._git
        commit = git(["rev-parse", "HEAD"]).decode().strip()
        source = {
            "commit": commit,
            "parent": git(["rev-parse", commit + "^"]).decode().strip(),
            "tree": git(["rev-parse", commit + "^{tree}"]).decode().strip(),
            "files": self.source["files"],
        }
        host["source_commit"] = commit
        host["route_input_volume_identity"]["labels"].update(
            {
                "dev.aragorn.capture-owner": commit + ":90001",
                "dev.aragorn.source-commit": commit,
            }
        )
        signature = host["source_commit_verification"]
        signature["command"] = ["git", "verify-commit", "--raw", commit]
        verified = subprocess.run(
            signature["command"], cwd=_ROOT, check=True, capture_output=True
        )
        signature["exit_code"] = verified.returncode
        for key, raw in (
            ("commit_object", git(["cat-file", "commit", commit])),
            ("stdout", verified.stdout),
            ("stderr", verified.stderr),
        ):
            signature[key] = {
                "base64": base64.b64encode(raw).decode(),
                "bytes": len(raw),
                "digest": subject.old._digest(raw),
            }
        _sync_harness(native)
        _sync_route(native)
        result = subject.verify_capture(
            canonical_json(native) + b"\n",
            self.prepared,
            source=source,
            invocation={
                **self.invocation,
                "started_at": "2026-09-01T00:00:00Z",
                "completed_at": "2026-09-02T00:00:00Z",
            },
        )
        self.assertEqual(result["native_capture"], native)
        self.assertEqual(result["proof"]["current_source_commit"], commit)
        self.assertNotEqual(commit, subject.old._SOURCE["commit"])
        self.assertNotEqual(host["container_id"], old_host["container_id"])
        self.assertNotEqual(route["gateway_pid_binding"]["pid"], old_gateway["pid"])
        self.assertNotEqual(
            route["document"]["action"]["prerequisites"]["gateway_process_before"][
                "start_time_ticks"
            ],
            old_gateway["start_time_ticks"],
        )
        self.assertNotEqual(
            route["raw"]["digest"], self.native["route_observation"]["raw"]["digest"]
        )
        self.assertNotEqual(
            route["document"]["recorded_at"],
            self.native["route_observation"]["document"]["recorded_at"],
        )
        self.assertEqual(
            route["document"]["action"]["prerequisites"]["boundary_before"]["probe"][
                "records"
            ][0]["root"],
            f"/docker/volumes/{volume}/_data",
        )
        self.assertTrue(
            all(
                value is False
                for key, value in result["decision"].items()
                if key.endswith("_eligible")
            )
        )

    def test_malformed_inputs_fail_with_evidence_error(self) -> None:
        for mutation in (
            "raw",
            "prepared",
            "source",
            "invocation",
            "route_observation",
            "composition",
            "harness",
        ):
            with self.subTest(mutation=mutation):
                raw, prepared, source, invocation = (
                    self.raw,
                    self.prepared,
                    self.source,
                    self.invocation,
                )
                if mutation == "raw":
                    raw = b"[]\n"
                elif mutation == "prepared":
                    prepared = None
                elif mutation == "source":
                    source = None
                elif mutation == "invocation":
                    invocation = None
                else:
                    native = deepcopy(self.native)
                    native[mutation] = None
                    raw = canonical_json(native) + b"\n"
                with self.assertRaises(AdmissionEvidenceError):
                    subject.verify_capture(
                        raw, prepared, source=source, invocation=invocation
                    )


if __name__ == "__main__":
    unittest.main()
