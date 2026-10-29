from __future__ import annotations

import base64
import hashlib
import json
import unittest
from collections.abc import Callable
from copy import deepcopy
from io import BytesIO
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

from aragorn import admission_protected_final_fresh_session_reset as subject
from aragorn.admission_evidence import AdmissionEvidenceError
from aragorn.cas import CAS

_ROOT = Path(__file__).resolve().parents[1]
_PATHS = {
    "composition": _ROOT
    / "benchmark/evidence/runtime-action-worker-final-combined-systemd-"
    "composition-p3-final-2026-08-13.json",
    "configuration": _ROOT / "benchmark/admission/openclaw-v2026.7.1/"
    "protected-final-combined-config-v1.json",
    "profile": _ROOT / "benchmark/admission/openclaw-v2026.7.1/"
    "protected-final-combined-profile-v1.json",
    "runtime_lock": _ROOT / "benchmark/admission/openclaw-v2026.7.1/"
    "protected-final-combined-runtime-v1.lock.json",
    "skill": _ROOT / "benchmark/runtime-action-worker-final-combined-systemd/SKILL.md",
    "plugin_index": _ROOT / "packaging/openclaw/aragorn-runtime-action-worker/index.js",
    "plugin_manifest": _ROOT
    / "packaging/openclaw/aragorn-runtime-action-worker/openclaw.plugin.json",
    "plugin_package": _ROOT
    / "packaging/openclaw/aragorn-runtime-action-worker/package.json",
    "evidence": _ROOT / subject._EVIDENCE["path"],
}
_RECEIPT = (
    _ROOT / "benchmark/receipts/phase3-openclaw-protected-final-fresh-session-reset-"
    "route-coverage-v1-2026-08-13.json"
)


def _digest(raw: bytes) -> str:
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def _put(store: CAS, retained: dict[str, bytes]) -> None:
    for raw in retained.values():
        store.put_expected(
            BytesIO(raw), expected_digest=_digest(raw), max_bytes=len(raw)
        )


def _route_raw(document: dict[str, object]) -> bytes:
    return (
        json.dumps(
            document,
            ensure_ascii=False,
            allow_nan=False,
            separators=(",", ":"),
        ).encode()
        + b"\n"
    )


def _repin(
    changed: dict[str, object], *, replace_nested_raw: bool = False
) -> tuple[dict[str, object], dict[str, object], dict[str, str]]:
    route = changed["route_observation"]
    if replace_nested_raw:
        nested = _route_raw(route["document"])
        canonical = subject.parent.oci_worker_protocol.canonical_json(route["document"])
        route["raw"] = {
            "base64": base64.b64encode(nested).decode(),
            "bytes": len(nested),
            "canonical_digest": _digest(canonical),
            "digest": _digest(nested),
            "raw_is_canonical_json_lf": nested == canonical + b"\n",
        }
        route["route"] = route["document"]["routes"][0]
    canonical = subject.parent.oci_worker_protocol.canonical_json(changed)
    evidence = {
        **subject._EVIDENCE,
        "bytes": len(canonical) + 1,
        "canonical_bytes": len(canonical),
        "canonical_digest": _digest(canonical),
        "digest": _digest(canonical + b"\n"),
    }
    nested_canonical = subject.parent.oci_worker_protocol.canonical_json(
        route["document"]
    )
    route_raw = {
        "bytes": route["raw"]["bytes"],
        "canonical_bytes": len(nested_canonical),
        "canonical_digest": _digest(nested_canonical),
        "digest": route["raw"]["digest"],
    }
    action = route["document"]["actions"][0]
    envelopes = {
        "composition": subject._canonical_digest(changed["composition"]),
        "composition_boundaries": subject._canonical_digest(
            changed["composition"]["action"]["boundaries"]
        ),
        "harness": subject._canonical_digest(changed["harness"]),
        "route_observation": subject._canonical_digest(route),
        "stack_before": subject._canonical_digest(route["stack_before"]),
        "boundary": subject._canonical_digest(route["document"]["protected_boundary"]),
        "action": subject._canonical_digest(action),
    }
    return evidence, route_raw, envelopes


def _repin_final_harness(changed: dict[str, object]) -> None:
    final = changed["harness"]["final_combined"]
    raw = subject.parent.oci_worker_protocol.canonical_json(final["document"])
    final["digest"] = final["file"]["digest"] = _digest(raw)
    final["file"]["bytes"] = final["file"]["stat"]["size"] = len(raw)
    final["file"]["base64"] = base64.b64encode(raw).decode()
    changed["harness"]["document"]["composition_harness_digest"] = final["digest"]
    changed["composition"]["action"]["harness"] = deepcopy(final)
    harness_raw = subject.parent.oci_worker_protocol.canonical_json(
        changed["harness"]["document"]
    )
    changed["harness"]["bytes"] = len(harness_raw)
    changed["harness"]["digest"] = _digest(harness_raw)


def _mutate_final_harness(
    changed: dict[str, object], mutate: Callable[[dict[str, object]], None]
) -> None:
    mutate(changed["harness"]["final_combined"]["document"])
    _repin_final_harness(changed)


def _mutate_final_harness_file(
    changed: dict[str, object], mutate: Callable[[dict[str, object]], None]
) -> None:
    mutate(changed["harness"]["final_combined"]["file"])
    changed["composition"]["action"]["harness"] = deepcopy(
        changed["harness"]["final_combined"]
    )


def _mutate_harness_bool_with_padding(changed: dict[str, object]) -> None:
    document = changed["harness"]["final_combined"]["document"]
    document["openclaw_runtime_mount"]["rw"] = 0
    document["host_config"]["binds"][2] = "xxxx" + document["host_config"]["binds"][2]
    _repin_final_harness(changed)


def _mutate_boundary_both(
    changed: dict[str, object], mutate: Callable[[dict[str, object]], None]
) -> None:
    mutate(changed["composition"]["action"]["boundaries"])
    mutate(changed["route_observation"]["stack_before"])


def _mutate_listener_port(boundary: dict[str, object]) -> None:
    listener = boundary["gateway_listener"]
    raw_record = listener["proc_net_tcp"]
    raw = base64.b64decode(raw_record["base64"], validate=True).replace(
        b"0100007F:4965", b"0100007F:4966"
    )
    raw_record.update(
        {"base64": base64.b64encode(raw).decode(), "digest": _digest(raw)}
    )
    listener["listener"]["line"] = listener["listener"]["line"].replace(
        "0100007F:4965", "0100007F:4966"
    )


def _mutate_listener_bool_inode(boundary: dict[str, object]) -> None:
    listener = boundary["gateway_listener"]
    raw_record = listener["proc_net_tcp"]
    raw = base64.b64decode(raw_record["base64"], validate=True).replace(
        b" 225705 1 ", b" 1 1 "
    )
    raw_record.update(
        {
            "base64": base64.b64encode(raw).decode(),
            "bytes": len(raw),
            "digest": _digest(raw),
        }
    )
    listener["listener"] = {
        "inode": True,
        "line": listener["listener"]["line"].replace(" 225705 1 ", " 1 1 "),
    }


def _mutate_socket_contract(boundary: dict[str, object]) -> None:
    path = "/run/aragorn-runtime-action-worker/worker.sock"
    boundary["sockets"][path]["metadata"]["mode"] = "0777"
    boundary["service_state"]["sockets"][path]["metadata"]["mode"] = "0777"


def _mutate_service_pid(
    changed: dict[str, object], service: str, old_pid: int, new_pid: int
) -> None:
    for boundary in (
        changed["composition"]["action"]["boundaries"],
        changed["route_observation"]["stack_before"],
    ):
        boundary["processes"][service]["pid"] = new_pid
        boundary["units"][service]["MainPID"] = str(new_pid)
        boundary["units"][service]["ExecStart"] = boundary["units"][service][
            "ExecStart"
        ].replace(f"pid={old_pid}", f"pid={new_pid}")
        state = boundary["service_state"]["units"][service]
        state["cgroup_members"] = [str(new_pid)]
        state["properties"]["MainPID"] = str(new_pid)
        stdout = base64.b64decode(state["command"]["stdout"]["base64"], validate=True)
        stdout = stdout.replace(
            f"MainPID={old_pid}\n".encode(), f"MainPID={new_pid}\n".encode()
        )
        state["command"]["stdout"].update(
            {
                "base64": base64.b64encode(stdout).decode(),
                "bytes": len(stdout),
                "digest": _digest(stdout),
            }
        )
    changed["route_observation"]["stack_before"]["pids"][service] = new_pid


def _mutate_service_property(
    changed: dict[str, object], service: str, key: str, value: str
) -> None:
    for boundary in (
        changed["composition"]["action"]["boundaries"],
        changed["route_observation"]["stack_before"],
    ):
        state = boundary["service_state"]["units"][service]
        previous = state["properties"][key]
        state["properties"][key] = value
        stdout = base64.b64decode(state["command"]["stdout"]["base64"], validate=True)
        stdout = stdout.replace(
            f"{key}={previous}\n".encode(), f"{key}={value}\n".encode()
        )
        state["command"]["stdout"].update(
            {
                "base64": base64.b64encode(stdout).decode(),
                "bytes": len(stdout),
                "digest": _digest(stdout),
            }
        )


def _mutate_container_and_cgroups(
    changed: dict[str, object], container_id: str
) -> None:
    _mutate_final_harness(
        changed, lambda document: document.__setitem__("container_id", container_id)
    )
    for boundary in (
        changed["composition"]["action"]["boundaries"],
        changed["route_observation"]["stack_before"],
    ):
        for service in boundary["units"]:
            cgroup = f"/docker/{container_id}/system.slice/{service}"
            boundary["units"][service]["ControlGroup"] = cgroup
            state = boundary["service_state"]["units"][service]
            previous = state["properties"]["ControlGroup"]
            state["properties"]["ControlGroup"] = cgroup
            stdout = base64.b64decode(
                state["command"]["stdout"]["base64"], validate=True
            ).replace(
                f"ControlGroup={previous}\n".encode(),
                f"ControlGroup={cgroup}\n".encode(),
            )
            state["command"]["stdout"].update(
                {
                    "base64": base64.b64encode(stdout).decode(),
                    "bytes": len(stdout),
                    "digest": _digest(stdout),
                }
            )


def _mutate_service_wall_time(changed: dict[str, object], service: str) -> None:
    for boundary in (
        changed["composition"]["action"]["boundaries"],
        changed["route_observation"]["stack_before"],
    ):
        command = boundary["service_state"]["units"][service]["command"]
        command["started_at"] = "2099-01-01T00:00:00.000000Z"
        command["completed_at"] = "2099-01-01T00:00:01.000000Z"


def _mutate_system_info_coherently(changed: dict[str, object]) -> None:
    prerequisites = changed["route_observation"]["document"]["actions"][0][
        "prerequisites"
    ]
    value = prerequisites["system_info"]["response"]["value"]
    value["cpuCount"] = 8
    stdout = json.dumps(value, indent=2) + "\n"
    for command in (
        prerequisites["system_info"]["command"],
        prerequisites["commands"][1],
    ):
        command["stdout_excerpt"] = stdout
        command["stdout_bytes"] = len(stdout.encode())
        command["stdout_digest"] = _digest(stdout.encode())


class FinalFreshSessionResetTests(unittest.TestCase):
    def test_exact_six_route_receipt_and_hostile_inputs_fail_closed(self) -> None:
        retained = {name: path.read_bytes() for name, path in _PATHS.items()}
        self.assertEqual(_digest(retained["evidence"]), subject._EVIDENCE["digest"])
        self.assertEqual(len(retained["evidence"]), subject._EVIDENCE["bytes"])
        self.assertEqual(
            {name: _digest(retained[name]) for name in subject.parent._SOURCES},
            {
                name: identity["digest"]
                for name, identity in subject.parent._SOURCES.items()
            },
        )

        with TemporaryDirectory() as temporary:
            store = CAS(temporary)
            _put(store, retained)
            first = subject.verify_openclaw_final_fresh_session_reset(
                evidence_cas=store
            )
            self.assertEqual(
                first,
                subject.verify_openclaw_final_fresh_session_reset(evidence_cas=store),
            )
        self.assertEqual(first["profile"]["counts"], {"PASS": 6, "NOT_TESTED": 15})
        statuses = {item["id"]: item["status"] for item in first["profile"]["routes"]}
        self.assertEqual(statuses[subject._ROUTE], "PASS")
        self.assertEqual(list(statuses.values()).count("PASS"), 6)
        self.assertTrue(
            all(
                first["decision"][key] is False
                for key in subject.parent._ELIGIBILITY_KEYS
            )
        )
        receipt_raw = _RECEIPT.read_bytes()

        for omitted in retained:
            with self.subTest(omitted=omitted), TemporaryDirectory() as temporary:
                store = CAS(temporary)
                _put(
                    store,
                    {name: raw for name, raw in retained.items() if name != omitted},
                )
                with self.assertRaises(AdmissionEvidenceError):
                    subject.verify_openclaw_final_fresh_session_reset(
                        evidence_cas=store
                    )

        original = json.loads(retained["evidence"])
        action = lambda value: value["route_observation"]["document"]["actions"][0]
        observed = lambda value: action(value)["observations"]
        mutations = [
            (False, lambda value: value["decision"].__setitem__("run_eligible", True)),
            (
                False,
                lambda value: value["composition"]["bindings"].__setitem__(
                    "network", "bridge"
                ),
            ),
            (
                False,
                lambda value: value["harness"]["document"]["collector"][
                    "materializer"
                ].__setitem__("bytes", 1),
            ),
            (
                False,
                lambda value: value["harness"]["document"][
                    "baseline_composition"
                ].__setitem__("digest", "sha256:" + "0" * 64),
            ),
            (
                False,
                lambda value: value["harness"]["document"].__setitem__(
                    "child_image_id", "sha256:" + "0" * 64
                ),
            ),
            (
                False,
                lambda value: _mutate_final_harness(
                    value,
                    lambda document: document["openclaw_runtime_mount"].__setitem__(
                        "rw", True
                    ),
                ),
            ),
            (False, _mutate_harness_bool_with_padding),
            (
                False,
                lambda value: _mutate_final_harness(
                    value,
                    lambda document: document["host_config"]["binds"].__setitem__(
                        2,
                        document["host_config"]["binds"][2][:-2] + "rw",
                    ),
                ),
            ),
            (
                False,
                lambda value: _mutate_final_harness(
                    value,
                    lambda document: document.__setitem__(
                        "image_id", "sha256:" + "0" * 64
                    ),
                ),
            ),
            (
                False,
                lambda value: _mutate_final_harness(
                    value,
                    lambda document: document.__setitem__(
                        "openclaw_runtime_volume", "forged-runtime"
                    ),
                ),
            ),
            (
                False,
                lambda value: _mutate_final_harness(
                    value,
                    lambda document: document.__setitem__("container_id", "evil"),
                ),
            ),
            (
                False,
                lambda value: _mutate_container_and_cgroups(value, "0" * 64),
            ),
            (
                False,
                lambda value: _mutate_final_harness_file(
                    value,
                    lambda file: file["stat"].__setitem__("mode", "0666"),
                ),
            ),
            (
                False,
                lambda value: _mutate_final_harness_file(
                    value,
                    lambda file: file.__setitem__("path", "/tmp/evil"),
                ),
            ),
            (
                False,
                lambda value: _mutate_final_harness_file(
                    value,
                    lambda file: file["stat"].__setitem__("uid", 992),
                ),
            ),
            (
                False,
                lambda value: _mutate_final_harness_file(
                    value,
                    lambda file: file["stat"].__setitem__("nlink", 2),
                ),
            ),
            (
                False,
                lambda value: _mutate_final_harness_file(
                    value,
                    lambda file: file["stat"].__setitem__("type", "symlink"),
                ),
            ),
            (
                False,
                lambda value: _mutate_final_harness_file(
                    value,
                    lambda file: file["stat"].__setitem__("nlink", True),
                ),
            ),
            (
                False,
                lambda value: value["route_observation"]["execution"][
                    "argv"
                ].__setitem__(6, "--reuid=0"),
            ),
            (
                False,
                lambda value: value["route_observation"]["execution"].__setitem__(
                    "extra", True
                ),
            ),
            (
                False,
                lambda value: value["route_observation"][
                    "gateway_pid_binding"
                ].__setitem__("pid", 1),
            ),
            (
                False,
                lambda value: value["route_observation"]["stack_before"]["processes"][
                    "aragorn-agent-gateway.service"
                ].__setitem__("no_new_privileges", 0),
            ),
            (
                False,
                lambda value: value["route_observation"]["stack_before"]["processes"][
                    "aragorn-runtime-action-worker.service"
                ].__setitem__("uids", [0, 0, 0, 0]),
            ),
            (
                False,
                lambda value: value["route_observation"]["stack_before"]["processes"][
                    "aragorn-runtime-action-worker.service"
                ].__setitem__("no_new_privileges", 0),
            ),
            (
                False,
                lambda value: value["composition"]["action"]["boundaries"]["processes"][
                    "aragorn-runtime-action-worker.service"
                ].__setitem__("uids", [0, 0, 0, 0]),
            ),
            (
                False,
                lambda value: value["route_observation"]["stack_before"][
                    "pids"
                ].__setitem__("aragorn-runtime-action-worker.service", 1),
            ),
            (
                False,
                lambda value: _mutate_service_pid(
                    value,
                    "aragorn-runtime-action-worker.service",
                    2_939,
                    2_833,
                ),
            ),
            (
                False,
                lambda value: _mutate_boundary_both(
                    value,
                    lambda boundary: boundary["processes"][
                        "aragorn-runtime-action-worker.service"
                    ].__setitem__("uids", [0, 0, 0, 0]),
                ),
            ),
            (
                False,
                lambda value: _mutate_boundary_both(
                    value,
                    lambda boundary: boundary["processes"][
                        "aragorn-runtime-action-worker.service"
                    ].__setitem__("no_new_privileges", 0),
                ),
            ),
            (
                False,
                lambda value: _mutate_boundary_both(
                    value,
                    lambda boundary: boundary["processes"][
                        "aragorn-runtime-action-worker.service"
                    ].__setitem__("no_new_privileges", True),
                ),
            ),
            (
                False,
                lambda value: _mutate_boundary_both(
                    value,
                    lambda boundary: boundary["processes"][
                        "aragorn-runtime-action-worker.service"
                    ].__setitem__("capabilities_effective", "0000000000000001"),
                ),
            ),
            (
                False,
                lambda value: _mutate_boundary_both(
                    value,
                    lambda boundary: boundary["units"][
                        "aragorn-runtime-action-worker.service"
                    ].__setitem__("User", "root"),
                ),
            ),
            (
                False,
                lambda value: _mutate_boundary_both(
                    value,
                    lambda boundary: boundary["units"][
                        "aragorn-agent-gateway.service"
                    ].__setitem__("NoNewPrivileges", "no"),
                ),
            ),
            (
                False,
                lambda value: _mutate_boundary_both(
                    value,
                    lambda boundary: boundary["units"][
                        "aragorn-agent-gateway.service"
                    ].__setitem__(
                        "ExecStart",
                        boundary["units"]["aragorn-agent-gateway.service"][
                            "ExecStart"
                        ].replace(
                            "start_time=[Thu 2026-08-13 21:44:26 UTC]",
                            "start_time=[evil]",
                        ),
                    ),
                ),
            ),
            (
                False,
                lambda value: _mutate_boundary_both(
                    value,
                    lambda boundary: boundary["units"][
                        "aragorn-runtime-action-worker.service"
                    ].__setitem__("NoNewPrivileges", "no"),
                ),
            ),
            (
                False,
                lambda value: _mutate_boundary_both(
                    value,
                    lambda boundary: boundary["units"][
                        "aragorn-agent-gateway.service"
                    ].__setitem__("User", "root"),
                ),
            ),
            (
                False,
                lambda value: _mutate_boundary_both(
                    value,
                    lambda boundary: boundary["enablement"].__setitem__(
                        "aragorn-runtime-action-worker.service", "enabled"
                    ),
                ),
            ),
            (
                False,
                lambda value: _mutate_boundary_both(
                    value,
                    _mutate_listener_port,
                ),
            ),
            (
                False,
                lambda value: _mutate_boundary_both(
                    value,
                    _mutate_listener_bool_inode,
                ),
            ),
            (
                False,
                lambda value: _mutate_boundary_both(
                    value,
                    _mutate_socket_contract,
                ),
            ),
            (
                False,
                lambda value: _mutate_service_property(
                    value,
                    "aragorn-runtime-action-worker.service",
                    "ExecMainCode",
                    "1",
                ),
            ),
            (
                False,
                lambda value: _mutate_service_wall_time(
                    value, "aragorn-runtime-action-worker.service"
                ),
            ),
            (
                True,
                lambda value: value["route_observation"]["document"][
                    "protected_boundary"
                ]["configuration"]["file"].__setitem__("mode", "600"),
            ),
            (
                True,
                lambda value: value["route_observation"]["document"][
                    "protected_boundary"
                ].__setitem__("extra", True),
            ),
            (
                True,
                lambda value: value["route_observation"]["document"][
                    "protected_boundary"
                ]["runtime"]["records"][0].__setitem__("mount_options", ["rw"]),
            ),
            (
                True,
                lambda value: value["route_observation"]["document"][
                    "protected_boundary"
                ]["configuration"]["mount"]["records"][0].__setitem__(
                    "mount_options", ["rw"]
                ),
            ),
            (
                True,
                lambda value: value["route_observation"]["document"][
                    "protected_boundary"
                ]["configuration"]["mount"]["entry"].__setitem__("exists", False),
            ),
            (
                True,
                lambda value: value["route_observation"]["document"][
                    "protected_boundary"
                ]["configuration"]["mount"].__setitem__("explicit", 1),
            ),
            (
                True,
                lambda value: value["route_observation"]["document"][
                    "protected_boundary"
                ]["configuration"]["mount"]["entry"]["entries"].append("evil"),
            ),
            (
                True,
                lambda value: value["route_observation"]["document"][
                    "protected_boundary"
                ]["configuration"]["mount"]["records"][0].__setitem__(
                    "filesystem", "overlay"
                ),
            ),
            (
                True,
                lambda value: value["route_observation"]["document"][
                    "protected_boundary"
                ]["configuration"]["mount"]["records"][0].__setitem__("source", "evil"),
            ),
            (
                True,
                lambda value: value["route_observation"]["document"][
                    "protected_boundary"
                ]["runtime"]["entry"].__setitem__("exists", False),
            ),
            (
                True,
                lambda value: value["route_observation"]["document"][
                    "protected_boundary"
                ]["runtime"].__setitem__("read_only", 1),
            ),
            (
                True,
                lambda value: value["route_observation"]["document"][
                    "protected_boundary"
                ]["runtime"]["entry"].__setitem__("type", "symlink"),
            ),
            (
                True,
                lambda value: value["route_observation"]["document"][
                    "protected_boundary"
                ]["runtime"].__setitem__("extra", True),
            ),
            (
                True,
                lambda value: value["route_observation"]["document"][
                    "protected_boundary"
                ]["roots"]["workspace_skills"].__setitem__("writable", False),
            ),
            (
                True,
                lambda value: action(value)["commands"][0]["argv"].__setitem__(
                    4, "forged.send"
                ),
            ),
            (
                True,
                lambda value: action(value)["prerequisites"]["runtime_files"]["node"][
                    "file"
                ].__setitem__("nlink", 2),
            ),
            (
                True,
                lambda value: action(value)["prerequisites"][
                    "runtime_files"
                ].__setitem__("extra", True),
            ),
            (
                True,
                lambda value: action(value)["prerequisites"]["runtime_files"]["node"][
                    "file"
                ].__setitem__("nlink", True),
            ),
            (
                True,
                lambda value: action(value)["prerequisites"]["runtime_files"][
                    "openclaw"
                ]["file"].__setitem__("nlink", 2),
            ),
            (
                True,
                lambda value: action(value)["prerequisites"]["runtime_files"][
                    "openclaw"
                ]["file"].__setitem__("nlink", True),
            ),
            (
                True,
                lambda value: action(value)["commands"][1].__setitem__(
                    "pid", action(value)["commands"][0]["pid"]
                ),
            ),
            (True, _mutate_system_info_coherently),
            (
                True,
                lambda value: action(value)["commands"][0].__setitem__(
                    "completed_at", "2026-08-13T21:44:50.000Z"
                ),
            ),
            (
                True,
                lambda value: action(value)["commands"][0].__setitem__(
                    "exit_code", False
                ),
            ),
            (
                True,
                lambda value: action(value)["commands"][0].__setitem__(
                    "stderr_bytes", False
                ),
            ),
            (
                True,
                lambda value: observed(value)["initialization_turn"]["wait"][
                    "response"
                ]["value"].__setitem__("error", "forged"),
            ),
            (
                True,
                lambda value: observed(value)["initialization_turn"]["send"][
                    "command"
                ].__setitem__("exit_code", False),
            ),
            (
                True,
                lambda value: observed(value)["initialization_turn"]["commands"][
                    0
                ].__setitem__("exit_code", False),
            ),
            (
                True,
                lambda value: observed(value)["initialization_turn"]["commands"][
                    0
                ].__setitem__("stderr_bytes", False),
            ),
            (
                True,
                lambda value: observed(value)["initialization_turn"]["send"][
                    "response"
                ].__setitem__("parsed", 1),
            ),
            (
                True,
                lambda value: observed(value)["initialization_turn"][
                    "send"
                ].__setitem__("extra", True),
            ),
            (
                True,
                lambda value: observed(value)["reset_turn"].__setitem__(
                    "scopes", ["operator.write"]
                ),
            ),
            (
                True,
                lambda value: (
                    observed(value)["reset_turn"].__setitem__("accepted", 1),
                    observed(value)["reset_turn"]["params"].__setitem__("deliver", 0),
                ),
            ),
            (
                True,
                lambda value: observed(value)["reset_turn"]["response"].__setitem__(
                    "status", "error"
                ),
            ),
            (
                True,
                lambda value: observed(value)["session_before_reset"][
                    "entry"
                ].__setitem__("session_id", "not-a-uuid"),
            ),
            (
                True,
                lambda value: observed(value)["session_before_reset"]["entry"][
                    "prompt"
                ].__setitem__("digest", "sha256:" + "0" * 64),
            ),
            (
                True,
                lambda value: observed(value)["session_after_rotation"][
                    "entry"
                ].__setitem__("snapshot_present", True),
            ),
            (
                True,
                lambda value: observed(value)["session_after_reset"]["entry"][
                    "prompt"
                ].__setitem__("bytes", 738),
            ),
            (
                True,
                lambda value: observed(value)["session_after_reset"][
                    "file"
                ].__setitem__(
                    "inode", observed(value)["session_before_reset"]["file"]["inode"]
                ),
            ),
            (
                True,
                lambda value: observed(value)["session_after_reset"][
                    "entry"
                ].__setitem__("updated_at", 1786657486000),
            ),
            (
                True,
                lambda value: observed(value)["session_before_reset_check"].__setitem__(
                    "ready", 1
                ),
            ),
        ]
        for index, (replace_nested, mutate) in enumerate(mutations):
            changed = deepcopy(original)
            mutate(changed)
            evidence_id, route_id, envelopes = _repin(
                changed, replace_nested_raw=replace_nested
            )
            raw = subject.parent.oci_worker_protocol.canonical_json(changed) + b"\n"
            changed_retained = {**retained, "evidence": raw}
            with (
                self.subTest(mutation=index),
                TemporaryDirectory() as temporary,
                patch.object(subject, "_EVIDENCE", evidence_id),
                patch.object(subject, "_ROUTE_RAW", route_id),
                patch.object(subject, "_ENVELOPES", envelopes),
                patch.object(subject, "_verify_retained_evidence", return_value=raw),
            ):
                store = CAS(temporary)
                _put(store, changed_retained)
                with self.assertRaises(AdmissionEvidenceError):
                    subject.verify_openclaw_final_fresh_session_reset(
                        evidence_cas=store
                    )

        for prefix in (b'{"schema":"duplicate",', b'{"nonfinite":NaN,'):
            invalid = prefix + retained["evidence"][1:]
            identity = {
                **subject._EVIDENCE,
                "bytes": len(invalid),
                "digest": _digest(invalid),
            }
            with (
                self.subTest(invalid_outer=prefix),
                TemporaryDirectory() as temporary,
                patch.object(subject, "_EVIDENCE", identity),
                patch.object(
                    subject, "_verify_retained_evidence", return_value=invalid
                ),
            ):
                store = CAS(temporary)
                _put(store, {**retained, "evidence": invalid})
                with self.assertRaises(AdmissionEvidenceError):
                    subject.verify_openclaw_final_fresh_session_reset(
                        evidence_cas=store
                    )

        nested_original = base64.b64decode(
            original["route_observation"]["raw"]["base64"], validate=True
        )
        for prefix in (b'{"schema":"duplicate",', b'{"nonfinite":NaN,'):
            changed = deepcopy(original)
            invalid = prefix + nested_original[1:]
            changed["route_observation"]["raw"].update(
                {
                    "base64": base64.b64encode(invalid).decode(),
                    "bytes": len(invalid),
                    "digest": _digest(invalid),
                }
            )
            outer_raw = (
                subject.parent.oci_worker_protocol.canonical_json(changed) + b"\n"
            )
            identity = {
                **subject._EVIDENCE,
                "bytes": len(outer_raw),
                "canonical_bytes": len(outer_raw) - 1,
                "canonical_digest": _digest(outer_raw[:-1]),
                "digest": _digest(outer_raw),
            }
            route_id = {
                **subject._ROUTE_RAW,
                "bytes": len(invalid),
                "digest": _digest(invalid),
            }
            with (
                self.subTest(invalid_nested=prefix),
                TemporaryDirectory() as temporary,
                patch.object(subject, "_EVIDENCE", identity),
                patch.object(subject, "_ROUTE_RAW", route_id),
                patch.object(
                    subject, "_verify_retained_evidence", return_value=outer_raw
                ),
                patch.object(
                    subject,
                    "_ENVELOPES",
                    {
                        **subject._ENVELOPES,
                        "route_observation": subject._canonical_digest(
                            changed["route_observation"]
                        ),
                    },
                ),
            ):
                store = CAS(temporary)
                _put(store, {**retained, "evidence": outer_raw})
                with self.assertRaises(AdmissionEvidenceError):
                    subject.verify_openclaw_final_fresh_session_reset(
                        evidence_cas=store
                    )

        with TemporaryDirectory() as temporary:
            duplicate = Path(temporary) / "admission_protected_final_disabled_routes.py"
            duplicate.write_bytes(Path(subject.parent.__file__).read_bytes())
            store = CAS(temporary)
            _put(store, retained)
            with (
                patch.object(subject.parent, "__file__", str(duplicate)),
                self.assertRaisesRegex(AdmissionEvidenceError, "parent dependency"),
            ):
                subject.verify_openclaw_final_fresh_session_reset(evidence_cas=store)

        self.assertEqual(
            receipt_raw,
            subject.parent.oci_worker_protocol.canonical_json(first) + b"\n",
        )
        self.assertEqual(json.loads(receipt_raw), first)

        with TemporaryDirectory() as temporary:
            store = CAS(temporary)
            _put(store, retained)
            parent_result = subject.parent.verify_openclaw_final_disabled_routes(
                evidence_cas=store
            )
            parent_result["profile"]["counts"] = {"PASS": 6, "NOT_TESTED": 15}
            with (
                patch.object(
                    subject.parent,
                    "verify_openclaw_final_disabled_routes",
                    return_value=parent_result,
                ),
                self.assertRaisesRegex(AdmissionEvidenceError, "parent qualification"),
            ):
                subject.verify_openclaw_final_fresh_session_reset(evidence_cas=store)

        for attribute, replacement in (
            ("_RETENTION", {**subject._RETENTION, "commit": "0" * 40}),
            ("_RETENTION_BLOB_OID", "0" * 40),
        ):
            with (
                self.subTest(signed_retention_mismatch=attribute),
                TemporaryDirectory() as temporary,
                patch.object(subject, attribute, replacement),
            ):
                store = CAS(temporary)
                _put(store, retained)
                with self.assertRaises(AdmissionEvidenceError):
                    subject.verify_openclaw_final_fresh_session_reset(
                        evidence_cas=store
                    )


if __name__ == "__main__":
    unittest.main()
