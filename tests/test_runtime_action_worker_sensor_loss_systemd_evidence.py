from __future__ import annotations

import base64
import copy
import hashlib
import json
import unittest
from pathlib import Path
from unittest.mock import patch

from jsonschema.validators import validator_for

from aragorn import runtime_action_worker_sensor_loss_systemd_evidence as subject
from aragorn.admission_evidence import AdmissionEvidenceError
from aragorn.oci_worker_protocol import canonical_digest

_ROOT = Path(__file__).resolve().parents[1]
_EMPTY_DIGEST = "sha256:" + hashlib.sha256(b"").hexdigest()


def _raw(raw: bytes) -> dict:
    return {
        "base64": base64.b64encode(raw).decode("ascii"),
        "bytes": len(raw),
        "digest": "sha256:" + hashlib.sha256(raw).hexdigest(),
    }


def _metadata(*, inode: int, size: int, kind: str, mode: str) -> dict:
    return {
        "device": 45,
        "gid": 0,
        "inode": inode,
        "mode": mode,
        "nlink": 1,
        "size": size,
        "type": kind,
        "uid": 0,
    }


def _file(path: str, raw: bytes, inode: int, mode: str = "0444") -> dict:
    return {
        "path": path,
        **_raw(raw),
        "stat": _metadata(inode=inode, size=len(raw), kind="file", mode=mode),
    }


def _command(
    argv: list[str], stdout: bytes, tick: int, *, elapsed_ns: int = 100_000_000
) -> dict:
    completed_tick = tick + max(1, elapsed_ns // 1_000_000_000)
    return {
        "argv": argv,
        "caller": {"gid": 0, "uid": 0},
        "completed_at": f"2026-08-29T01:10:{completed_tick:02d}Z",
        "completed_monotonic_ns": tick * 1_000_000_000 + elapsed_ns,
        "elapsed_ns": elapsed_ns,
        "exit_code": 0,
        "signal": None,
        "started_at": f"2026-08-29T01:10:{tick:02d}Z",
        "started_monotonic_ns": tick * 1_000_000_000,
        "stderr": _raw(b""),
        "stdout": _raw(stdout),
    }


def _properties(name: str, pid: int, invocation: str, *, active: bool) -> dict:
    enabled = "static" if name == subject._GATEWAY_UNIT else "disabled"
    if not active:
        return {
            "ActiveEnterTimestampMonotonic": "0",
            "ActiveState": "inactive",
            "ControlGroup": "",
            "ExecMainCode": "0",
            "ExecMainExitTimestampMonotonic": "0",
            "ExecMainStartTimestampMonotonic": "0",
            "ExecMainStatus": "0",
            "InactiveEnterTimestampMonotonic": "0",
            "InvocationID": "",
            "MainPID": "0",
            "NRestarts": "0",
            "Result": "success",
            "SubState": "dead",
            "UnitFileState": enabled,
        }
    return {
        "ActiveEnterTimestampMonotonic": "1",
        "ActiveState": "active",
        "ControlGroup": f"/system.slice/{name}",
        "ExecMainCode": "0",
        "ExecMainExitTimestampMonotonic": "0",
        "ExecMainStartTimestampMonotonic": "1",
        "ExecMainStatus": "0",
        "InactiveEnterTimestampMonotonic": "0",
        "InvocationID": invocation,
        "MainPID": str(pid),
        "NRestarts": "0",
        "Result": "success",
        "SubState": "running",
        "UnitFileState": enabled,
    }


def _unit(name: str, pid: int, invocation: str, *, active: bool, tick: int) -> dict:
    properties = _properties(name, pid, invocation, active=active)
    stdout = "".join(f"{key}={properties[key]}\n" for key in subject._PROPERTIES)
    members = [str(pid)] if active else []
    cgroup_raw = ("\n".join(members) + "\n").encode() if members else b""
    return {
        "cgroup_members": members,
        "cgroup_procs": {
            "path": f"/sys/fs/cgroup/system.slice/{name}/cgroup.procs",
            "present": active,
            "raw": _raw(cgroup_raw),
        },
        "command": _command(
            ["systemctl", "show", name, *[f"-p{key}" for key in subject._PROPERTIES]],
            stdout.encode(),
            tick,
        ),
        "properties": properties,
    }


def _socket(path: str, inode: int, *, present: bool) -> dict:
    return {
        "metadata": (
            _metadata(inode=inode, size=0, kind="socket", mode="0660")
            if present
            else None
        ),
        "path": path,
        "present": present,
        "unix": [],
    }


def _service_snapshot(*, before: bool, tick: int) -> dict:
    pids = dict(zip(subject._UNITS, (101, 102, 103, 104), strict=True))
    invocations = {
        name: f"{index:x}" * 32 for index, name in enumerate(subject._UNITS, start=1)
    }
    units = {}
    for name in subject._UNITS:
        active = before or name == subject._BROKER_UNIT
        pid = pids[name]
        invocation = invocations[name]
        units[name] = _unit(
            name,
            pid,
            invocation,
            active=active,
            tick=tick,
        )
        if not before and name in {subject._GATEWAY_UNIT, subject._WORKER_UNIT}:
            properties = units[name]["properties"]
            properties.update(
                {
                    "ActiveEnterTimestampMonotonic": "1",
                    "ExecMainCode": "1",
                    "ExecMainExitTimestampMonotonic": "3500000",
                    "ExecMainStartTimestampMonotonic": "1",
                    "InactiveEnterTimestampMonotonic": "3600000",
                    "InvocationID": invocations[name],
                }
            )
            _rebind_properties(units[name])
        if not before and name == subject._SENSOR_UNIT:
            properties = units[name]["properties"]
            properties.update(
                {
                    "ActiveEnterTimestampMonotonic": "1",
                    "ActiveState": "failed",
                    "ExecMainCode": "2",
                    "ExecMainExitTimestampMonotonic": "3400000",
                    "ExecMainStartTimestampMonotonic": "1",
                    "ExecMainStatus": "9",
                    "InvocationID": invocations[name],
                    "Result": "signal",
                    "SubState": "failed",
                }
            )
            _rebind_properties(units[name])
    sockets = {
        path: _socket(path, 200 + index, present=before or index == 2)
        for index, path in enumerate(subject._SOCKETS)
    }
    return {"sockets": sockets, "units": units}


def _skill() -> dict:
    return {
        "file": {
            "bytes": 140,
            "digest": "sha256:" + "e" * 64,
            "path": "/opt/aragorn/runtime-profile/template-skill/SKILL.md",
            "stat": _metadata(inode=300, size=140, kind="file", mode="0444"),
        },
        "parents": [
            {"gid": 0, "mode": mode, "path": path, "uid": 0}
            for path, mode in (
                ("/", "0755"),
                ("/opt", "0555"),
                ("/opt/aragorn", "0555"),
                ("/opt/aragorn/runtime-profile", "0555"),
                ("/opt/aragorn/runtime-profile/template-skill", "0555"),
            )
        ],
    }


def _fixture() -> tuple[dict, dict]:
    artifacts = {
        name: _file(path, name.encode(), 400 + index, subject._ARTIFACT_MODES[name])
        for index, (name, path) in enumerate(subject._ARTIFACT_PATHS.items())
    }
    commit_object = b"tree " + b"0" * 40 + b"\ngpgsig test-signature\n"
    source_commit = hashlib.sha1(
        f"commit {len(commit_object)}\0".encode() + commit_object
    ).hexdigest()
    parent_image = "sha256:" + "a" * 64
    child_image = "sha256:" + "b" * 64
    parent_layer = "sha256:" + "c" * 64
    child_layer = "sha256:" + "d" * 64
    runtime_volume = "aragorn-openclaw-2026-7-1-phase3-final-7fa98d8-v1"
    bindings = {
        "artifacts": {name: value["digest"] for name, value in artifacts.items()},
        "child_image_id": child_image,
        "parent_image_id": parent_image,
        "source_commit": source_commit,
    }
    host_config = {
        "binds": [f"{runtime_volume}:/runtime:ro"],
        "cgroupns_mode": "private",
        "ipc_mode": "private",
        "network_mode": "none",
        "privileged": True,
        "readonly_rootfs": False,
        "runtime": "runc",
        "security_opt": ["label=disable"],
        "tmpfs": {
            "/run": "rw,nosuid,nodev,noexec,mode=755",
            "/run/lock": "rw,nosuid,nodev,noexec,mode=755",
        },
        "userns_mode": "",
    }
    runtime_identity = {
        "driver": "local",
        "labels": {
            "io.aragorn.phase": "phase3-final",
            "io.aragorn.role": "installed-runtime",
            "io.aragorn.source-commit": "7fa98d8e21b6d5937f25a7f19445ff683bb980bf",
            "io.aragorn.source-tree": "dd5ac3991f6dbce8b6e630e3e43644f64bc71d44",
        },
        "name": runtime_volume,
        "options": None,
        "scope": "local",
    }
    container_inspect = {
        "Config": {
            "Image": child_image,
            "Labels": {
                "dev.aragorn.profile": "phase3-runtime-action-worker-sensor-loss"
            },
        },
        "HostConfig": {
            "Binds": host_config["binds"],
            "CgroupnsMode": host_config["cgroupns_mode"],
            "IpcMode": host_config["ipc_mode"],
            "NetworkMode": host_config["network_mode"],
            "Privileged": host_config["privileged"],
            "ReadonlyRootfs": host_config["readonly_rootfs"],
            "Runtime": host_config["runtime"],
            "SecurityOpt": host_config["security_opt"],
            "Tmpfs": host_config["tmpfs"],
            "UsernsMode": host_config["userns_mode"],
        },
        "Id": "f" * 64,
        "Image": child_image,
        "Mounts": [
            {
                "Destination": "/runtime",
                "Driver": "local",
                "Mode": "ro",
                "Name": runtime_volume,
                "RW": False,
                "Type": "volume",
            }
        ],
        "Platform": "linux",
    }
    harness = {
        "capture_disposition": "EXPLICIT_OUTPUT_ONLY_NOT_RETAINED_EVIDENCE",
        "bindings": bindings,
        "container_id": "f" * 64,
        "host_config": host_config,
        "image_id": child_image,
        "image_lineage": {
            "added_layers": [child_layer],
            "child": {
                "id": child_image,
                "layers": [parent_layer, child_layer],
                "rootfs_type": "layers",
            },
            "parent": {
                "id": parent_image,
                "layers": [parent_layer],
                "rootfs_type": "layers",
            },
        },
        "image_reference": "aragorn-phase3-runtime-action-worker-sensor-loss-systemd",
        "openclaw_runtime_mount": {
            "destination": "/runtime",
            "driver": "local",
            "mode": "ro",
            "rw": False,
            "source": runtime_volume,
            "type": "volume",
        },
        "openclaw_runtime_volume": runtime_volume,
        "openclaw_runtime_volume_identity": runtime_identity,
        "parent_image_id": parent_image,
        "platform": "linux",
        "profile_label": "phase3-runtime-action-worker-sensor-loss",
        "raw_records": {
            "child_image_inspect": _raw(
                json.dumps(
                    [
                        {
                            "Id": child_image,
                            "RootFS": {
                                "Layers": [parent_layer, child_layer],
                                "Type": "layers",
                            },
                        }
                    ]
                ).encode()
            ),
            "container_inspect": _raw(json.dumps([container_inspect]).encode()),
            "parent_image_inspect": _raw(
                json.dumps(
                    [
                        {
                            "Id": parent_image,
                            "RootFS": {
                                "Layers": [parent_layer],
                                "Type": "layers",
                            },
                        }
                    ]
                ).encode()
            ),
            "runtime_volume_inspect": _raw(
                json.dumps(
                    [
                        {
                            "Driver": runtime_identity["driver"],
                            "Labels": runtime_identity["labels"],
                            "Name": runtime_identity["name"],
                            "Options": runtime_identity["options"],
                            "Scope": runtime_identity["scope"],
                        }
                    ]
                ).encode()
            ),
        },
        "run_image_reference": child_image,
        "schema": "aragorn/runtime-action-worker-sensor-loss-systemd-harness/v2",
        "source_artifacts": {
            name: _raw(name.encode()) for name in subject._ARTIFACT_PATHS
        },
        "source_commit_verification": {
            "command": ["git", "verify-commit", "--raw", source_commit],
            "commit_object": _raw(commit_object),
            "exit_code": 0,
            "stderr": _raw(subject._SOURCE_SIGNATURE),
            "stdout": _raw(b""),
        },
    }
    before = {
        "protected": {
            "entries": [],
            "root": _metadata(inode=350, size=0, kind="directory", mode="0750"),
            "target_exists": False,
        },
        "services": _service_snapshot(before=True, tick=1),
        "skill": _skill(),
    }
    after = {
        "protected": copy.deepcopy(before["protected"]),
        "services": _service_snapshot(before=False, tick=9),
        "skill": copy.deepcopy(before["skill"]),
    }
    document = {
        "after": after,
        "artifacts": artifacts,
        "authority": subject._AUTHORITY,
        "before": before,
        "bindings": bindings,
        "checks": copy.deepcopy(subject._CHECKS),
        "decision": copy.deepcopy(subject._SOURCE_DECISION),
        "harness": harness,
        "limitations": list(subject._LIMITATIONS),
        "recorded_at": "2026-08-29T01:10:12Z",
        "schema": subject._SCHEMA,
        "secret_checks": {"gateway_token_retained": False},
        "loss": _command(["kill", "-KILL", "103"], b"", tick=3),
        "stability": {
            "initial_services": _service_snapshot(before=False, tick=4),
            "wait": _command(
                ["sleep", "2"], b"", tick=6, elapsed_ns=2_000_000_000
            ),
        },
    }
    return document, bindings


def _rebind_properties(unit: dict) -> None:
    properties = unit["properties"]
    raw = "".join(f"{key}={properties[key]}\n" for key in subject._PROPERTIES).encode()
    unit["command"]["stdout"] = _raw(raw)


def _rebind_cgroup(unit: dict, members: list[str], *, present: bool = True) -> None:
    raw = ("\n".join(members) + "\n").encode() if members else b""
    unit["cgroup_members"] = members
    unit["cgroup_procs"]["present"] = present
    unit["cgroup_procs"]["raw"] = _raw(raw)


class RuntimeActionWorkerSensorLossSystemdEvidenceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.evidence, self.bindings = _fixture()

    def test_exact_observation_qualifies_only_the_bounded_status(self) -> None:
        digest = canonical_digest(self.evidence)
        with (
            patch.object(subject, "_RETAINED_EVIDENCE_DIGEST", digest),
            patch.object(subject, "_RETAINED_BINDINGS", self.bindings),
            patch.object(subject, "_RETAINED_PATH", "benchmark/evidence/test.json"),
            patch.object(subject, "_EVIDENCE_BYTES", 1),
            patch.object(subject, "_EVIDENCE_RAW_DIGEST", _EMPTY_DIGEST),
        ):
            qualification = (
                subject.runtime_action_worker_sensor_loss_systemd_qualification(
                    self.evidence,
                    expected_digest=digest,
                    expected_bindings=self.bindings,
                    implementation_digest=self._implementation_digest(),
                )
            )
        self.assertEqual(
            qualification["decision"]["status"],
            "SENSOR_PROCESS_LOSS_DURABLE_FAIL_STOP_OBSERVED",
        )
        self.assertTrue(
            qualification["decision"]["bounded_sensor_process_loss_evidence_eligible"]
        )
        for field in (
            "aggregate_gate_eligible",
            "run_01_eligible",
            "run_02_eligible",
            "phase3_exit_eligible",
            "edr_claim_eligible",
            "installer_authority_eligible",
            "public_release_eligible",
        ):
            self.assertIs(qualification["decision"][field], False)

        schema = json.loads(
            (
                _ROOT
                / "schema/runtime-action-worker-sensor-loss-systemd-qualification-v2.schema.json"
            ).read_bytes()
        )
        validator = validator_for(schema)
        validator.check_schema(schema)
        validator(schema).validate(qualification)

    def test_explicit_observation_binding_and_implementation_pins_are_required(
        self,
    ) -> None:
        digest = canonical_digest(self.evidence)
        for expected_digest, expected_bindings in (
            (None, self.bindings),
            (digest, None),
        ):
            with (
                self.subTest(expected_digest=expected_digest),
                self.assertRaises(AdmissionEvidenceError),
            ):
                subject.verify_runtime_action_worker_sensor_loss_systemd_evidence(
                    self.evidence,
                    expected_digest=expected_digest,
                    expected_bindings=expected_bindings,
                )
        with self.assertRaises(AdmissionEvidenceError):
            subject.runtime_action_worker_sensor_loss_systemd_qualification(
                self.evidence,
                expected_digest=digest,
                expected_bindings=self.bindings,
                implementation_digest=None,
            )
        with (
            patch.object(subject, "_RETAINED_EVIDENCE_DIGEST", digest),
            patch.object(subject, "_RETAINED_BINDINGS", self.bindings),
            patch.object(subject, "_RETAINED_PATH", "benchmark/evidence/test.json"),
            patch.object(subject, "_EVIDENCE_BYTES", 1),
            patch.object(subject, "_EVIDENCE_RAW_DIGEST", _EMPTY_DIGEST),
            self.assertRaises(AdmissionEvidenceError),
        ):
            subject.runtime_action_worker_sensor_loss_systemd_qualification(
                self.evidence,
                expected_digest=digest,
                expected_bindings=self.bindings,
                implementation_digest="sha256:" + "0" * 64,
            )

    def test_extra_or_missing_fields_are_rejected(self) -> None:
        for mutate in (
            lambda value: value.__setitem__("extra", None),
            lambda value: value.pop("secret_checks"),
            lambda value: value["before"]["services"]["units"][subject._GATEWAY_UNIT][
                "properties"
            ].__setitem__("LoadState", "loaded"),
        ):
            self._assert_rejected(mutate)

    def test_reported_checks_and_decision_cannot_override_raw_worker_state(
        self,
    ) -> None:
        def mutate(value: dict) -> None:
            worker = value["after"]["services"]["units"][subject._WORKER_UNIT]
            worker.update(
                copy.deepcopy(value["before"]["services"]["units"])[
                    subject._WORKER_UNIT
                ]
            )
            value["checks"] = copy.deepcopy(subject._CHECKS)
            value["decision"] = copy.deepcopy(subject._SOURCE_DECISION)

        self._assert_rejected(mutate)

    def test_broker_pid_and_invocation_must_survive_unchanged(self) -> None:
        def mutate(value: dict) -> None:
            broker = value["after"]["services"]["units"][subject._BROKER_UNIT]
            broker["properties"]["MainPID"] = "999"
            broker["properties"]["InvocationID"] = "a" * 32
            _rebind_cgroup(broker, ["999"])
            _rebind_properties(broker)

        self._assert_rejected(mutate)

    def test_sensor_cannot_restart_with_a_new_process(self) -> None:
        def mutate(value: dict) -> None:
            for services in (
                value["stability"]["initial_services"],
                value["after"]["services"],
            ):
                sensor = services["units"][subject._SENSOR_UNIT]
                sensor["properties"].update(
                    {
                        "ActiveState": "active",
                        "ControlGroup": f"/system.slice/{subject._SENSOR_UNIT}",
                        "ExecMainCode": "0",
                        "ExecMainExitTimestampMonotonic": "0",
                        "ExecMainStartTimestampMonotonic": "3800000",
                        "ExecMainStatus": "0",
                        "InvocationID": "a" * 32,
                        "MainPID": "203",
                        "Result": "success",
                        "SubState": "running",
                    }
                )
                _rebind_cgroup(sensor, ["203"])
                _rebind_properties(sensor)

        self._assert_rejected(mutate)

    def test_before_sensor_timestamps_must_precede_its_snapshot(self) -> None:
        def mutate(value: dict) -> None:
            sensor = value["before"]["services"]["units"][subject._SENSOR_UNIT]
            sensor["properties"]["ActiveEnterTimestampMonotonic"] = "2000000"
            _rebind_properties(sensor)

        self._assert_rejected(mutate)

    def test_sensor_failure_must_be_the_observed_sigkill(self) -> None:
        def mutate(value: dict) -> None:
            sensor = value["after"]["services"]["units"][subject._SENSOR_UNIT]
            sensor["properties"]["ExecMainStatus"] = "15"
            _rebind_properties(sensor)

        self._assert_rejected(mutate)

    def test_sensor_restart_counter_must_not_change(self) -> None:
        def mutate(value: dict) -> None:
            for services in (
                value["stability"]["initial_services"],
                value["after"]["services"],
            ):
                sensor = services["units"][subject._SENSOR_UNIT]
                sensor["properties"]["NRestarts"] = "1"
                _rebind_properties(sensor)

        self._assert_rejected(mutate)

    def test_initial_terminal_snapshot_is_required(self) -> None:
        self._assert_rejected(
            lambda value: value["stability"].pop("initial_services")
        )

    def test_stability_wait_is_exact_successful_root_sleep(self) -> None:
        for mutate in (
            lambda value: value["stability"]["wait"].__setitem__(
                "argv", ["sleep", "1"]
            ),
            lambda value: value["stability"]["wait"].update(
                {
                    "completed_monotonic_ns": 7_999_999_999,
                    "elapsed_ns": 1_999_999_999,
                }
            ),
            lambda value: value["stability"]["wait"].__setitem__("exit_code", 1),
            lambda value: value["stability"]["wait"]["caller"].__setitem__(
                "uid", 1000
            ),
        ):
            self._assert_rejected(mutate)

    def test_terminal_state_must_remain_exactly_stable(self) -> None:
        def mutate(value: dict) -> None:
            gateway = value["after"]["services"]["units"][subject._GATEWAY_UNIT]
            gateway["properties"]["InactiveEnterTimestampMonotonic"] = "3700000"
            _rebind_properties(gateway)

        self._assert_rejected(mutate)

    def test_fully_cleared_stopped_execution_state_is_accepted(self) -> None:
        cleared = copy.deepcopy(self.evidence)
        for services in (
            cleared["stability"]["initial_services"],
            cleared["after"]["services"],
        ):
            for name in subject._STOPPED_UNITS:
                unit = services["units"][name]
                unit["properties"].update(
                    {
                        "ActiveEnterTimestampMonotonic": "0",
                        "ExecMainCode": "0",
                        "ExecMainExitTimestampMonotonic": "0",
                        "ExecMainStartTimestampMonotonic": "0",
                        "InactiveEnterTimestampMonotonic": "0",
                        "InvocationID": "",
                    }
                )
                _rebind_properties(unit)
        subject.verify_runtime_action_worker_sensor_loss_systemd_evidence(
            cleared,
            expected_digest=canonical_digest(cleared),
            expected_bindings=self.bindings,
        )

    def test_mixed_cleared_and_retained_stopped_execution_is_rejected(self) -> None:
        def mutate(value: dict) -> None:
            for services in (
                value["stability"]["initial_services"],
                value["after"]["services"],
            ):
                gateway = services["units"][subject._GATEWAY_UNIT]
                gateway["properties"]["InvocationID"] = ""
                _rebind_properties(gateway)

        self._assert_rejected(mutate)

    def test_stability_snapshots_must_bracket_the_wait(self) -> None:
        def mutate(value: dict) -> None:
            wait = value["stability"]["wait"]
            wait["started_monotonic_ns"] = 3_900_000_000
            wait["completed_monotonic_ns"] = 5_900_000_000

        self._assert_rejected(mutate)

    def test_sensor_and_worker_sockets_cannot_reappear(self) -> None:
        def mutate(value: dict) -> None:
            for services in (
                value["stability"]["initial_services"],
                value["after"]["services"],
            ):
                for index, path in enumerate(subject._SOCKETS[:2], start=1):
                    services["sockets"][path] = _socket(
                        path, 998 + index, present=True
                    )

        self._assert_rejected(mutate)

    def test_reported_stability_check_cannot_be_tampered(self) -> None:
        self._assert_rejected(
            lambda value: value["checks"].__setitem__(
                "fail_stop_stable_for_two_seconds", False
            )
        )

    def test_skill_or_protected_target_change_is_rejected(self) -> None:
        for mutate in (
            lambda value: value["after"]["skill"]["file"].__setitem__(
                "digest", "sha256:" + "1" * 64
            ),
            lambda value: value["after"]["protected"].__setitem__(
                "target_exists", True
            ),
            lambda value: value["after"]["protected"]["entries"].append("target"),
        ):
            self._assert_rejected(mutate)

    def test_loss_must_be_one_successful_root_sensor_sigkill(self) -> None:
        for mutate in (
            lambda value: value["loss"].__setitem__("exit_code", 1),
            lambda value: value["loss"]["argv"].__setitem__(1, "-TERM"),
            lambda value: value["loss"]["caller"].__setitem__("uid", 1000),
        ):
            self._assert_rejected(mutate)

    def test_cgroup_members_must_derive_from_retained_raw_bytes(self) -> None:
        self._assert_rejected(
            lambda value: value["before"]["services"]["units"][
                subject._GATEWAY_UNIT
            ].__setitem__("cgroup_members", ["999"])
        )

    def test_broker_socket_inode_must_survive_unchanged(self) -> None:
        self._assert_rejected(
            lambda value: value["after"]["services"]["sockets"][subject._SOCKETS[2]][
                "metadata"
            ].__setitem__("inode", 999)
        )

    def test_raw_systemd_output_and_digest_are_recomputed(self) -> None:
        def mutate(value: dict) -> None:
            gateway = value["after"]["services"]["units"][subject._GATEWAY_UNIT]
            gateway["command"]["stdout"]["base64"] = base64.b64encode(
                b"ActiveState=inactive\n"
            ).decode()

        self._assert_rejected(mutate)

    def test_outer_artifact_image_and_source_substitutions_are_rejected(self) -> None:
        def artifact(value: dict) -> None:
            record = value["artifacts"]["probe"]
            replacement = _raw(b"hostile probe")
            record.update(replacement)
            record["stat"]["size"] = record["bytes"]
            value["bindings"]["artifacts"]["probe"] = record["digest"]

        def child(value: dict) -> None:
            replacement = "sha256:" + "8" * 64
            value["bindings"]["child_image_id"] = replacement
            value["harness"]["image_id"] = replacement
            value["harness"]["run_image_reference"] = replacement
            value["harness"]["image_lineage"]["child"]["id"] = replacement

        def source(value: dict) -> None:
            value["bindings"]["source_commit"] = "7" * 40

        for mutate in (artifact, child, source):
            self._assert_rejected(mutate)

    def test_raw_container_rejects_any_extra_mount(self) -> None:
        def mutate(value: dict) -> None:
            record = value["harness"]["raw_records"]["container_inspect"]
            retained = json.loads(base64.b64decode(record["base64"], validate=True))
            retained[0]["Mounts"].append(
                {
                    "Destination": "/host",
                    "Driver": "local",
                    "Mode": "rw",
                    "Name": "hostile",
                    "RW": True,
                    "Type": "volume",
                }
            )
            record.update(_raw(json.dumps(retained).encode()))

        self._assert_rejected(mutate)

    def test_caller_coordinated_rebind_cannot_create_qualification(self) -> None:
        hostile = copy.deepcopy(self.evidence)
        replacement = b"hostile but internally coherent probe"
        installed = hostile["artifacts"]["probe"]
        installed.update(_raw(replacement))
        installed["stat"]["size"] = len(replacement)
        source = hostile["harness"]["source_artifacts"]["probe"]
        source.update(_raw(replacement))
        hostile["bindings"]["artifacts"]["probe"] = installed["digest"]
        caller_bindings = copy.deepcopy(hostile["bindings"])
        hostile_digest = canonical_digest(hostile)
        subject.verify_runtime_action_worker_sensor_loss_systemd_evidence(
            hostile,
            expected_digest=hostile_digest,
            expected_bindings=caller_bindings,
        )
        with (
            patch.object(
                subject,
                "_RETAINED_EVIDENCE_DIGEST",
                canonical_digest(self.evidence),
            ),
            patch.object(subject, "_RETAINED_BINDINGS", self.bindings),
            self.assertRaises(AdmissionEvidenceError),
        ):
            subject.runtime_action_worker_sensor_loss_systemd_qualification(
                hostile,
                expected_digest=hostile_digest,
                expected_bindings=caller_bindings,
                implementation_digest=self._implementation_digest(),
            )

    def test_authority_flags_cannot_be_promoted(self) -> None:
        self._assert_rejected(
            lambda value: value["decision"].__setitem__("run_02_eligible", True)
        )

    def test_boolean_integer_substitution_is_rejected(self) -> None:
        self._assert_rejected(
            lambda value: value["loss"].__setitem__("exit_code", False)
        )

    def _assert_rejected(self, mutate) -> None:
        hostile = copy.deepcopy(self.evidence)
        mutate(hostile)
        with self.assertRaises(AdmissionEvidenceError):
            subject.verify_runtime_action_worker_sensor_loss_systemd_evidence(
                hostile,
                expected_digest=canonical_digest(hostile),
                expected_bindings=self.bindings,
            )

    @staticmethod
    def _implementation_digest() -> str:
        return (
            "sha256:" + hashlib.sha256(Path(subject.__file__).read_bytes()).hexdigest()
        )


if __name__ == "__main__":
    unittest.main()
