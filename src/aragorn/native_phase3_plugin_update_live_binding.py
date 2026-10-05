"""Read-only joins for the opt-in native plugin-update identity observation.

The original consumer still verifies the entire caller-pinned capture, without
projecting away its original evidence. This leaf then checks the local reader's
selected before/after records against the existing setup, process observations,
staged profile and operator-held static/source pins. It never imports or executes
the reader or a capture script. Retained source bytes prove content custody, not
that Python executed those bytes or that a local root observer is trustworthy.
No dimension becomes a complete live deployment attestation through this leaf.
"""

from __future__ import annotations

import hashlib
import json
import re
import stat
from typing import Any

from . import native_phase3_plugin_update_binding as reported
from .cas import CAS, CASError
from .oci_worker_protocol import canonical_json

SCHEMA = "aragorn/native-phase3-plugin-update-live-binding/v1"
AUTHORITY = "READ_ONLY_LOCAL_READBACK_JOINS_NOT_EXTERNAL_ATTESTATION_OR_QUALIFICATION"
SOURCE_PATHS = (
    "scripts/capture_runtime_native_plugin_update_identity_check.py",
    "scripts/runtime_native_plugin_update_identity_check.py",
    "src/aragorn/native_phase3_live_identity.py",
)
_INSTALLED_HELPERS = {
    SOURCE_PATHS[1]: "/opt/aragorn/runtime_native_plugin_update_identity_check.py",
    SOURCE_PATHS[2]: "/usr/lib/aragorn/aragorn/native_phase3_live_identity.py",
}
_UNITS = {
    "gateway": "aragorn-agent-gateway.service",
    "worker": "aragorn-runtime-action-worker.service",
    "sensor": "aragorn-runtime-lineage-capability-observation-publisher.service",
    "broker": "aragorn-runtime-lineage-capability-action-broker.service",
}
_ACCOUNTS = {
    "gateway": ("aragorn-agent-gateway", "aragorn-agent-gateway"),
    "worker": ("aragorn-runtime", "aragorn-runtime"),
    "sensor": ("aragorn-sensor", "aragorn-sensor"),
    "broker": ("aragorn-broker", "aragorn-runtime"),
}
_SHIMS = {
    "worker": "/usr/libexec/aragorn/aragorn-runtime-action-worker-service.py",
    "sensor": "/usr/libexec/aragorn/aragorn-runtime-observation-service-v4.py",
    "broker": "/usr/libexec/aragorn/aragorn-runtime-action-service-v5.py",
}
_CONFIG = "/etc/aragorn/agent-gateway/openclaw.json"
_WORKER = "/etc/aragorn/runtime-action-worker.json"
_RUNTIME = "/etc/aragorn/runtime-action-runtime.json"
_OBSERVATION = "/etc/aragorn/runtime-action-observation.json"
_GRANT = "/etc/aragorn/runtime-capability-grant.json"
_GENESIS = "/etc/aragorn/runtime-native-tool-genesis.json"
_POLICY = "/var/lib/aragorn-runtime-action/control/policy.json"
_ENTRY = "/runtime/lib/node_modules/openclaw/openclaw.mjs"
_WORKER_CODE = "/usr/lib/aragorn/aragorn/runtime_action_worker.py"
_PYTHON = "/usr/local/bin/python3.12"
_NODE = "/usr/local/bin/node"
_PROFILE_PATHS = (
    _WORKER_CODE,
    *_SHIMS.values(),
    *("/usr/lib/systemd/system/" + unit for unit in _UNITS.values()),
)
DYNAMIC_PATHS = (_CONFIG, _WORKER, _RUNTIME, _OBSERVATION, _GRANT, _GENESIS, _POLICY)
STATIC_PATHS = (*_PROFILE_PATHS, _ENTRY, _PYTHON, _NODE)
FILE_PATHS = (*STATIC_PATHS, *DYNAMIC_PATHS)
_CREDENTIALS = {
    "gateway": {"openclaw-config": _CONFIG, "native-tool-genesis": _GENESIS},
    "worker": {
        "worker-binding": _WORKER,
        "openclaw-config": _CONFIG,
        "native-tool-genesis": _GENESIS,
    },
    "sensor": {"observation-binding": _OBSERVATION, "capability-grant": _GRANT},
    "broker": {"runtime-binding": _RUNTIME, "capability-grant": _GRANT},
}
_BOUNDARIES = (
    "before_read_started_ns",
    "before_read_finished_ns",
    "invocation_started_ns",
    "invocation_finished_ns",
    "after_read_started_ns",
    "after_read_finished_ns",
)
_FLAGS = (
    "route_qualified",
    "phase3_eligible",
    "run_conformance_eligible",
    "production_activation_eligible",
    "common_deployment_fully_verified",
    "live_deployment_attested",
)
_READER_FLAGS = (
    "common_deployment_fully_verified",
    "route_qualified",
    "phase3_eligible",
    "live_deployment_attested",
)
_ENVELOPE_LIMITS = [
    "BEFORE_AFTER_UPDATE_ADAPTER_NOT_EACH_INTERNAL_COMMAND",
    "WRITER_INPUT_PINS_NOT_INDEPENDENT_HOST_ATTESTATION",
    "LOCAL_NATIVE_IDENTITY_LIMITATIONS_REMAIN",
    "NO_ROUTE_RUN_OR_PHASE3_QUALIFICATION",
]
_READER_LIMITS = [
    "POINT_IN_TIME_BEFORE_AFTER_READS_NOT_CONTINUOUS_IMMUTABILITY",
    "RUNTIME_ENTRYPOINT_BYTES_NOT_WHOLE_RUNTIME_TREE_OR_DOCKER_IMAGE",
    "GATEWAY_PROCESS_TITLE_AND_UNIT_LAUNCHER_NOT_LOADED_SCRIPT_PROVENANCE",
    "LOADED_CREDENTIAL_BYTES_NOT_PROOF_OF_APPLICATION_USE_OR_POLICY_SEMANTICS",
    "FIXED_WORKER_AND_UNIT_BYTES_NOT_FULL_IMPORTED_CODE_OR_70_FILE_PROFILE",
    "NO_ADAPTER_SOURCE_OR_SIGNED_ARAGORN_SOURCE_MEASUREMENT",
    "LOCAL_ROOT_OBSERVER_NOT_HOSTILE_ROOT_RESISTANT_OR_EXTERNAL_ATTESTATION",
    "NO_ROUTE_RUN_SENSOR_HEALTH_OR_PHASE3_QUALIFICATION",
]
_UNRESOLVED = {
    "runtime_commit_or_image": [
        "whole_runtime_tree",
        "image",
        "runtime_volume",
        "build_record",
    ],
    "adapter": ["capture_adapter_source_identity"],
    "configuration": ["application_use_of_measured_loaded_configuration"],
    "worker": ["complete_imported_worker_code_closure"],
    "os_profile": ["complete_installed_70_file_profile", "image_and_kernel_provenance"],
    "policy": ["independent_policy_semantics"],
    "aragorn_version": ["signed_source_commit_and_source_inventory"],
}
LIMITATIONS = (
    "RETAINED_LOCAL_READBACK_RECORDS_NOT_REEXECUTION_OR_HOST_ATTESTATION",
    "OPERATOR_SOURCE_PINS_NOT_PROOF_OF_EXECUTED_OR_LOADED_CODE",
    "PYTHON_AND_NODE_STATIC_PINS_REQUIRE_INDEPENDENT_OPERATOR_PROVENANCE",
    "OUTER_IMAGE_RUNTIME_TREE_PROFILE_AND_SOURCE_REMAIN_REPORTED_CUSTODY",
    "EQUAL_ENDPOINTS_NOT_CONTINUOUS_IMMUTABILITY_OR_EACH_COMMAND_ATTRIBUTION",
    "MONOTONIC_OBSERVER_BRACKETS_NOT_DECISION_OR_END_TO_END_LATENCY",
    "NO_INDEPENDENT_POLICY_SEMANTICS_LOGICAL_DATABASE_OR_ROUTE_COMPLETENESS",
    "NO_COMMON_LIVE_DEPLOYMENT_RUN_METRICS_OR_PHASE3_QUALIFICATION",
)


class NativePluginUpdateLiveBindingError(ValueError):
    """Retained local identity records do not satisfy the narrow binding."""


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise NativePluginUpdateLiveBindingError(message)


def _digest(raw: bytes) -> str:
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def _pin(value: object) -> str:
    _require(
        type(value) is str and re.fullmatch(r"sha256:[0-9a-f]{64}", value) is not None,
        "invalid caller-held content pin",
    )
    return value


def _integer(value: object, minimum: int = 0) -> bool:
    return type(value) is int and minimum <= value < 2**64


def _false(value: dict, names) -> None:
    _require(all(value[name] is False for name in names), "proof ceiling changed")


def _pins(value: object, paths) -> dict:
    _require(
        type(value) is dict and set(value) == set(paths), "fixed pin inventory changed"
    )
    return {name: _pin(item) for name, item in value.items()}


def _metadata(record: object, *, owners: set[tuple[int, int]], modes: set[int]) -> dict:
    _require(
        type(record) is dict and set(record) == {"bytes", "digest", "identity"},
        "file metadata inventory changed",
    )
    identity = record["identity"]
    _pin(record["digest"])
    _require(
        _integer(record["bytes"], 1)
        and record["bytes"] <= 256 * 1024 * 1024
        and type(identity) is list
        and len(identity) == 9
        and all(_integer(item) for item in identity)
        and stat.S_ISREG(identity[2])
        and stat.S_IMODE(identity[2]) in modes
        and (identity[3], identity[4]) in owners
        and identity[5] == 1
        and identity[6] == record["bytes"],
        "unsafe or inconsistent retained file metadata",
    )
    return record


def _aliases(snapshot: dict) -> None:
    def link(record: dict, path: str, target: str) -> None:
        identity = record["identity"]
        _require(
            record["path"] == path
            and record["target"] == target
            and type(identity) is list
            and len(identity) == 9
            and all(_integer(item) for item in identity)
            and stat.S_ISLNK(identity[2])
            and identity[3:6] == [0, 0, 1]
            and identity[6] == len(target),
            "fixed launcher/library link custody changed",
        )

    launcher = snapshot["fixed_python_launcher"]
    _require(
        type(launcher) is dict and set(launcher) == {"path", "target", "identity"},
        "Python launcher link inventory changed",
    )
    link(launcher, "/usr/bin/python3.12", _PYTHON)
    uses_alias = any(
        record["unit"]["FragmentPath"].startswith("/lib/")
        for record in snapshot["processes"].values()
    )
    _require(
        ("fixed_systemd_library_alias" in snapshot) is uses_alias,
        "systemd library alias evidence is missing or unexpected",
    )
    if uses_alias:
        alias = snapshot["fixed_systemd_library_alias"]
        _require(
            type(alias) is dict
            and set(alias)
            == {
                "path",
                "target",
                "identity",
                "canonical_unit_directory",
                "target_ancestry_identities",
            }
            and alias["canonical_unit_directory"] == "/usr/lib/systemd/system",
            "systemd alias evidence inventory changed",
        )
        link(alias, "/lib", "usr/lib")
        ancestry = alias["target_ancestry_identities"]
        _require(
            type(ancestry) is list and len(ancestry) == 4,
            "systemd alias ancestry inventory changed",
        )
        for identity in ancestry:
            _require(
                type(identity) is list
                and len(identity) == 5
                and all(_integer(item) for item in identity)
                and stat.S_ISDIR(identity[2])
                and not stat.S_IMODE(identity[2]) & 0o022
                and identity[3:] == [0, 0],
                "systemd alias target custody changed",
            )


def _raw_sources(capture: dict, expected: object, store: CAS) -> dict[str, bytes]:
    pins = _pins(expected, SOURCE_PATHS)
    records = capture["live_identity_sources"]
    _require(
        type(records) is dict and set(records) == set(SOURCE_PATHS),
        "live helper source inventory changed",
    )
    retained = {}
    for path, pin in pins.items():
        item = records[path]
        _require(
            type(item) is dict
            and set(item) == {"path", "bytes", "digest", "blob", "mode"}
            and item["path"] == path
            and item["mode"] == "100644"
            and item["digest"] == pin
            and _integer(item["bytes"], 1)
            and item["bytes"] <= 1024 * 1024,
            "helper source differs from operator pins",
        )
        raw = store.read(pin, max_bytes=1024 * 1024)
        git_blob = hashlib.sha1(
            b"blob " + str(len(raw)).encode("ascii") + b"\0" + raw
        ).hexdigest()
        _require(
            len(raw) == item["bytes"]
            and _digest(raw) == pin
            and item["blob"] == git_blob,
            "retained source bytes do not match source record",
        )
        retained[pin] = raw
        if path in _INSTALLED_HELPERS:
            installed = capture["fixture_helpers"][path]
            _require(
                installed
                == {
                    **item,
                    "installed_path": _INSTALLED_HELPERS[path],
                    "installed_mode": "0444",
                },
                "installed live helper source join changed",
            )
    return retained


def _envelope(value: dict, capture: dict, live_pin: str, static_pin: str) -> dict:
    _require(
        _digest(canonical_json(value)) == _pin(live_pin),
        "live envelope differs from caller pin",
    )
    _require(
        value["schema"]
        == "aragorn/runtime-native-plugin-update-identity-observation/v1"
        and value["authority"]
        == "OWNED_UPDATE_ADAPTER_WITH_LOCAL_LIVE_IDENTITY_NOT_ROUTE_OR_RUN_QUALIFICATION"
        and value["status"] == "OBSERVED"
        and value["route_id"] == reported.ROUTE
        and value["branch"] == reported.BRANCH
        and value["fixture_container"] == capture["fixture_container"]
        and value["provisioning_origin"]
        == "EXACT_EXISTING_WRITER_INPUT_BYTES_BEFORE_ACTIVATION"
        and value["pins_frozen_before_activation"] is True
        and type(value["activation_count"]) is int
        and value["activation_count"] == 1
        and type(value["invocation_count"]) is int
        and value["invocation_count"] == 1
        and value["refusal"] is None
        and value["limitations"] == _ENVELOPE_LIMITS,
        "not the bounded live-identity update observation",
    )
    _false(value, _FLAGS)
    timing = value["boundaries_monotonic_ns"]
    _require(
        type(timing) is dict
        and set(timing) == set(_BOUNDARIES)
        and all(_integer(timing[name], 1) for name in _BOUNDARIES)
        and all(
            timing[left] <= timing[right]
            for left, right in zip(_BOUNDARIES, _BOUNDARIES[1:])
        ),
        "observer read/invocation chronology changed",
    )
    manifest = value["static_pin_manifest"]
    _require(
        type(manifest) is dict
        and set(manifest) == {"schema", "file_digests"}
        and manifest["schema"] == "aragorn/native-plugin-update-identity-static-pins/v1"
        and _digest(canonical_json(manifest))
        == _pin(static_pin)
        == value["static_pin_manifest_digest"],
        "static manifest differs from caller pin",
    )
    static_pins = _pins(manifest["file_digests"], STATIC_PATHS)
    dynamic_pins = _pins(value["provisioning_file_digests"], DYNAMIC_PATHS)
    _require(
        _pins(value["expected_file_digests"], FILE_PATHS) == static_pins | dynamic_pins,
        "preactivation expected file pin inventory changed",
    )
    before = value["before"]
    _require(
        type(before) is dict
        and before == value["after"]
        and before["schema"] == "aragorn/native-phase3-live-identity/v1"
        and before["authority"]
        == "LOCAL_KERNEL_AND_PROTECTED_BYTES_NOT_HOST_ATTESTATION_OR_QUALIFICATION"
        and before["status"] == "LOCAL_NATIVE_IDENTITY_MEASURED"
        and before["container_id"] == capture["fixture_container"]
        and before["limitations"] == _READER_LIMITS
        and before["unresolved_dimensions"] == _UNRESOLVED,
        "before/after identity or reader claim ceiling changed",
    )
    _false(before, _READER_FLAGS)
    _require(
        value["comparison"]
        == {
            "status": "CALLER_MEASUREMENTS_EQUAL",
            "authority": "COMPARISON_ONLY_NOT_INDEPENDENT_LIVE_READBACK",
            "snapshot_digest": _digest(canonical_json(before)),
            "phase3_eligible": False,
            "route_qualified": False,
            "common_deployment_fully_verified": False,
        },
        "comparison is not the independently recomputed equality result",
    )
    boot = before["boot_id"]
    _require(
        type(boot) is str
        and re.fullmatch(r"[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}", boot)
        is not None
        and boot.replace("-", "") == capture["observation"]["boot_id"],
        "boot identity join changed",
    )
    return before


def _processes(snapshot: dict, observation: dict, container: str) -> dict:
    records = snapshot["processes"]
    _require(
        type(records) is dict and set(records) == set(_UNITS),
        "native process inventory changed",
    )
    accounts = {
        role: (
            observation["processes"][role]["process"]["uid"],
            observation["processes"][role]["process"]["gid"],
        )
        for role in _UNITS
    }
    _require(
        all(_integer(item, 1) for pair in accounts.values() for item in pair),
        "invalid process accounts",
    )
    _require(len({records[role]["pid"] for role in _UNITS}) == 4, "native PIDs overlap")
    for role, unit in _UNITS.items():
        record, outer = records[role], observation["processes"][role]
        state, uid_gid = record["unit"], accounts[role]
        uid, gid = uid_gid
        fsuid, fsgid = accounts["worker"] if role == "sensor" else uid_gid
        groups = (
            sorted({accounts["worker"][1], accounts["sensor"][1]})
            if role in {"sensor", "broker"}
            else (sorted({gid, accounts["gateway"][1]}) if role == "worker" else [gid])
        )
        cgroup = f"/docker/{container}/system.slice/{unit}"
        _require(
            _integer(record["pid"], 1)
            and _integer(record["start_time_ticks"], 1)
            and record["pid"] == outer["process"]["pid"]
            and record["start_time_ticks"] == outer["process"]["start_time_ticks"]
            and record["uids"] == [uid, uid, uid, fsuid]
            and record["gids"] == [gid, gid, gid, fsgid]
            and record["groups"] == groups
            and record["cgroup"] == outer["process"]["cgroup"] == cgroup,
            "kernel process does not join original observed epoch",
        )
        for name in ("cgroup_identity", "root_identity"):
            _require(
                type(record[name]) is list
                and len(record[name]) == 2
                and all(_integer(item, 1) for item in record[name]),
                "invalid process inode identity",
            )
        namespace = record["mount_namespace"]
        _require(
            type(namespace) is dict
            and set(namespace) == {"device", "inode"}
            and all(_integer(item, 1) for item in namespace.values()),
            "invalid mount namespace",
        )
        if role == "gateway":
            _require(
                record["cgroup_identity"]
                == [
                    outer["process"]["cgroup_device"],
                    outer["process"]["cgroup_inode"],
                ],
                "gateway cgroup inode join changed",
            )
            argv = [
                _NODE,
                _ENTRY,
                "gateway",
                "run",
                "--auth",
                "token",
                "--bind",
                "loopback",
                "--port",
                "18789",
                "--tailscale",
                "off",
            ]
            kernel_argv = ["openclaw-gateway"]
        else:
            credential = {
                "worker": "worker-binding",
                "sensor": "observation-binding",
                "broker": "runtime-binding",
            }[role]
            argv = [
                "/usr/bin/python3.12",
                "-I",
                "-S",
                "-B",
                _SHIMS[role],
                f"/run/credentials/{unit}/{credential}",
            ]
            if role in {"sensor", "broker"}:
                argv.append(f"/run/credentials/{unit}/capability-grant")
            kernel_argv = argv
        _require(
            record["argv"] == kernel_argv
            and state["Id"] == unit
            and state["MainPID"] == str(record["pid"])
            and state["ControlPID"] == "0"
            and state["ControlGroup"] == cgroup
            and state["ActiveState"] == "active"
            and state["SubState"] == "running"
            and state["User"] == _ACCOUNTS[role][0]
            and state["Group"] == _ACCOUNTS[role][1]
            and state["DropInPaths"] == ""
            and re.fullmatch(r"[0-9a-f]{32}", state["InvocationID"]) is not None
            and state["InvocationID"] != "0" * 32
            and state["FragmentPath"]
            in ("/lib/systemd/system/" + unit, "/usr/lib/systemd/system/" + unit)
            and state["ExecStart"].startswith(
                "{ path="
                + argv[0]
                + " ; argv[]="
                + " ".join(argv)
                + " ; ignore_errors=no ; "
            )
            and state["ExecStart"].count("argv[]=") == 1,
            "retained unit or command identity differs from fixed profile",
        )
        for name in state.keys() & outer["unit"].keys():
            _require(
                state[name] == outer["unit"][name],
                "unit readback differs from original process observation",
            )
    return accounts


def _files(snapshot: dict, envelope: dict, capture: dict, accounts: dict) -> None:
    files, observation = snapshot["files"], capture["observation"]
    setup, pins = observation["setup"], envelope["expected_file_digests"]
    _require(
        type(files) is dict and set(files) == set(FILE_PATHS),
        "measured file inventory changed",
    )
    for path, record in files.items():
        owner = (
            accounts["broker"]
            if path == _POLICY
            else (1000, 1000)
            if path == _ENTRY
            else (0, 0)
        )
        _metadata(
            record,
            owners={owner},
            modes={0o400}
            if path in DYNAMIC_PATHS
            else {0o755}
            if path == _ENTRY
            else {0o644, 0o755},
        )
        _require(
            record["digest"] == pins[path],
            "measured file differs from preactivation pin",
        )
    profile = {item["path"]: item for item in capture["staged_profile"]["files"]}
    for path in _PROFILE_PATHS:
        record = files[path]
        _require(
            record == observation["installed_sources"][path]
            and record["digest"] == profile[path]["digest"]
            and record["bytes"] == profile[path]["bytes"]
            and stat.S_IMODE(record["identity"][2]) == int(profile[path]["mode"], 8),
            "selected live code/unit bytes do not join staged and installed profile",
        )
    entry = capture["staged_profile"]["required_runtime_not_included"]
    _require(
        entry["entrypoint"] == _ENTRY
        and files[_ENTRY]["bytes"] == entry["entrypoint_bytes"] == 23463
        and files[_ENTRY]["digest"]
        == entry["entrypoint_digest"]
        == "sha256:f643b005d6db233a0b45204e8d8e943256874ccc6897b8a6e0cf42a9b376a188"
        and files[_PYTHON]["digest"] == setup["runtime_profile"]["executable_digest"],
        "runtime entrypoint or Python profile join changed",
    )
    documents = {
        _WORKER: setup["worker_binding"],
        _POLICY: setup["policy"],
        _GRANT: setup["grant"],
        _GENESIS: setup["empty_store"]["genesis"],
        _RUNTIME: {
            "schema": "aragorn/runtime-action-runtime-binding/v2",
            "runtime_digest": setup["runtime_digest"],
            "runtime_profile_digest": _digest(canonical_json(setup["runtime_profile"])),
        },
        _OBSERVATION: {
            "schema": "aragorn/runtime-observation-binding/v2",
            "sensor_digest": setup["policy"]["sensor_digest"],
            "runtime_profile": setup["runtime_profile"],
        },
    }
    worker, policy, grant, genesis = (
        setup["worker_binding"],
        setup["policy"],
        setup["grant"],
        setup["empty_store"]["genesis"],
    )
    policy_digest = _digest(canonical_json(policy))
    _require(
        worker["schema"] == "aragorn/runtime-action-worker-binding/v1"
        and policy["schema"] == "aragorn/runtime-action-policy/v1"
        and grant["schema"] == "aragorn/runtime-capability-grant/v1"
        and genesis["schema"] == "aragorn/native-tool-receipt-genesis/v1"
        and worker["runtime_digest"]
        == grant["runtime_digest"]
        == genesis["runtime_digest"]
        == setup["runtime_profile"]["runtime_digest"]
        == setup["runtime_digest"]
        and worker["policy_digest"]
        == grant["policy_digest"]
        == genesis["policy_digest"]
        == policy_digest
        and type(policy["version"]) is int
        and all(
            type(document["policy_version"]) is int
            and document["policy_version"] == policy["version"]
            for document in (worker, grant, genesis)
        )
        and grant["runtime_profile_digest"]
        == documents[_RUNTIME]["runtime_profile_digest"]
        and grant["sensor_digest"] == policy["sensor_digest"]
        and worker["active_skill_digest"]
        == grant["active_skill_digest"]
        == setup["skill_digest"]
        and [genesis["worker_uid"], genesis["worker_gid"]] == list(accounts["worker"])
        and setup["runtime_profile"]["cgroup"]
        == snapshot["processes"]["worker"]["cgroup"],
        "measured worker, grant, genesis, policy and process bindings disagree",
    )
    for path, document in documents.items():
        raw = canonical_json(document)
        _require(
            files[path]["digest"] == _digest(raw) and files[path]["bytes"] == len(raw),
            "provisioned bytes do not join original setup",
        )
    _require(
        files[_CONFIG]["digest"] == setup["configuration_digest"]
        and snapshot["measured_joins"]
        == {
            "configuration_digest": setup["configuration_digest"],
            "worker_binding_digest": _digest(canonical_json(setup["worker_binding"])),
            "policy_digest": _digest(canonical_json(setup["policy"])),
            "declared_runtime_digest_not_whole_tree_measurement": setup[
                "runtime_digest"
            ],
        },
        "measured binding document joins changed",
    )
    loaded = snapshot["loaded_process_views"]
    _require(
        type(loaded) is dict and set(loaded) == set(_UNITS),
        "loaded process-view inventory changed",
    )
    for role, credentials in _CREDENTIALS.items():
        views = loaded[role]
        _require(
            type(views) is dict and set(views) == {*credentials, "code_view"},
            "loaded credential inventory changed",
        )
        uid, gid = accounts[role]
        for name, source in credentials.items():
            view = _metadata(
                views[name], owners={(0, 0), (uid, 0), (uid, gid)}, modes={0o400, 0o440}
            )
            _require(
                (view["identity"][3] == 0 or stat.S_IMODE(view["identity"][2]) == 0o400)
                and view["bytes"] == files[source]["bytes"]
                and view["digest"] == files[source]["digest"],
                "loaded credential differs from measured provisioned source",
            )
        code = (
            _ENTRY
            if role == "gateway"
            else _WORKER_CODE
            if role == "worker"
            else _SHIMS[role]
        )
        view = _metadata(
            views["code_view"],
            owners={(1000, 1000)} if role == "gateway" else {(0, 0)},
            modes={0o755} if role == "gateway" else {0o644, 0o755},
        )
        _require(
            view["bytes"] == files[code]["bytes"]
            and view["digest"] == files[code]["digest"],
            "process code view differs from measured source",
        )
    # The fixed runtime volume is not root-owned. The original consumer already
    # checks its fixed volume root and read-only mount options on both sides;
    # join that reported custody to the selected source and service-view file.
    # This is not proof of whole-tree ownership or independently attested mounts.
    for side in ("runtime_before", "runtime_after"):
        mount = capture[side]["content"]["mount"]
        entry = mount["entry"]
        _require(
            mount["path"] == mount["records"][0]["mount_point"] == "/runtime"
            and mount["read_only"] is True
            and entry["path"] == "/runtime"
            and entry["exists"] is True
            and entry["type"] == "directory"
            and int(entry["mode"], 8) == 0o755
            and [entry["uid"], entry["gid"]]
            == files[_ENTRY]["identity"][3:5]
            == loaded["gateway"]["code_view"]["identity"][3:5]
            == [1000, 1000],
            "runtime mount custody differs from entrypoint source or gateway view",
        )
    # The adapter also measured the gateway credential independently while doing
    # its before/after protected-boundary snapshots. Join all overlapping fields.
    credential = loaded["gateway"]["openclaw-config"]
    for side in ("before", "after"):
        original = observation["plugin_update"]["document"]["action"][side]["boundary"][
            "config"
        ]["file"]
        identity = credential["identity"]
        _require(
            original["digest"] == credential["digest"]
            and original["size"] == credential["bytes"]
            and original["device"] == identity[0]
            and original["inode"] == identity[1]
            and int(original["mode"], 8) == stat.S_IMODE(identity[2])
            and [original["uid"], original["gid"], original["nlink"]] == identity[3:6],
            "gateway credential view differs from adapter boundary readback",
        )


def verify_native_plugin_update_live_binding(
    capture_raw: bytes,
    *,
    expected_capture_digest: str,
    expected_source_digest: str,
    expected_source_commit: str,
    deployment_raw: bytes,
    expected_deployment_digest: str,
    expected_live_identity_digest: str,
    expected_live_source_digests: dict[str, str],
    expected_static_pin_manifest_digest: str,
    evidence_cas: CAS,
) -> dict[str, Any]:
    """Replay local readback joins only; all pins must be independently held.

    The read-only CAS must contain the seven existing deployment artifacts,
    three exact helper source blobs, and canonical static-pin manifest. The
    latter two executable pins (Python/Node) are operator trust prerequisites,
    not identities learned from this capture. No live action is performed.
    """
    try:
        _require(
            type(evidence_cas) is CAS and evidence_cas.read_only is True,
            "read-only CAS required",
        )
        base = reported.verify_native_plugin_update_binding(
            capture_raw,
            expected_capture_digest=expected_capture_digest,
            expected_source_digest=expected_source_digest,
            expected_source_commit=expected_source_commit,
            deployment_raw=deployment_raw,
            expected_deployment_digest=expected_deployment_digest,
            evidence_cas=evidence_cas,
        )
        # The existing consumer already rejected duplicate/noncanonical/unbounded JSON.
        capture = json.loads(capture_raw)
        retained = _raw_sources(capture, expected_live_source_digests, evidence_cas)
        envelope = capture["live_identity"]
        snapshot = _envelope(
            envelope,
            capture,
            expected_live_identity_digest,
            expected_static_pin_manifest_digest,
        )
        static_raw = canonical_json(envelope["static_pin_manifest"])
        _require(
            evidence_cas.read(
                _pin(expected_static_pin_manifest_digest), max_bytes=16384
            )
            == static_raw,
            "static manifest is not retained at caller pin",
        )
        retained[expected_static_pin_manifest_digest] = static_raw
        accounts = _processes(
            snapshot, capture["observation"], capture["fixture_container"]
        )
        _aliases(snapshot)
        _files(snapshot, envelope, capture, accounts)
        # Recheck all CAS children used by this leaf, including the original seven.
        deployment = json.loads(deployment_raw)
        artifacts = reported.native_plugin_update_identity_artifacts(
            capture_raw,
            expected_capture_digest=expected_capture_digest,
            expected_source_digest=expected_source_digest,
            expected_source_commit=expected_source_commit,
        )
        retained.update(
            {deployment["bindings"][name]: raw for name, raw in artifacts.items()}
        )
        _require(
            all(
                evidence_cas.read(pin, max_bytes=1024 * 1024) == raw
                for pin, raw in retained.items()
            ),
            "retained evidence custody changed during verification",
        )
        return {
            "schema": SCHEMA,
            "authority": AUTHORITY,
            "status": "BOUNDED_LOCAL_READBACK_JOINS_VERIFIED",
            "context": {
                **base["context"],
                "live_identity_digest": expected_live_identity_digest,
                "live_source_digests": dict(expected_live_source_digests),
                "static_pin_manifest_digest": expected_static_pin_manifest_digest,
            },
            "reported_deployment_dimensions_verified": base[
                "reported_deployment_dimensions_verified"
            ],
            "live_deployment_dimensions_verified": [],
            "selected_local_readback_joins": {
                "runtime_commit_or_image": [
                    "fixed_entrypoint_bytes",
                    "python_profile_executable_pin",
                ],
                "adapter": ["retained_three_helper_source_blobs_and_install_records"],
                "configuration": [
                    "preactivation_source_digest",
                    "gateway_and_worker_loaded_credential_digests",
                ],
                "worker": ["worker_module_and_binding_bytes", "observed_process_epoch"],
                "os_profile": [
                    "eight_selected_staged_files",
                    "four_observed_process_epochs_and_unit_records",
                ],
                "policy": ["provisioned_policy_bytes_and_binding_digest_joins"],
                "aragorn_version": ["caller_pinned_source_record_only"],
            },
            "unresolved_dimensions": {
                name: list(parts) for name, parts in _UNRESOLVED.items()
            },
            "limitations": list(LIMITATIONS),
            "fresh_campaign_execution": False,
            "independent_policy_semantics_verified": False,
            "signature_verified": False,
            "metrics_eligible": False,
            **dict.fromkeys(_FLAGS, False),
        }
    except NativePluginUpdateLiveBindingError:
        raise
    except (
        KeyError,
        TypeError,
        ValueError,
        IndexError,
        OverflowError,
        OSError,
        CASError,
    ) as exc:
        raise NativePluginUpdateLiveBindingError(
            "native plugin-update live binding refused"
        ) from exc
