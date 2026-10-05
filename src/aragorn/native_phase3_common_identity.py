"""Fixed common-profile identity reads, not deployment or Python-load attestation.

The caller supplies exact installed-file pins from its reviewed common profile
and fresh provisioning. No stage renderer, input CAS, clock or service operation
is invoked here. The frozen reader's protected-read and kernel primitives are
reused without changing its global contracts or manufacturing old observations.
"""

from __future__ import annotations

import os
import re
import stat
import subprocess
import sys
from contextlib import ExitStack
from pathlib import Path
from typing import Any

from . import native_phase3_live_identity as prior
from . import runtime_broker_decision_measurement_verify as measurement
from .oci_worker_protocol import canonical_digest, canonical_json
from .runtime_capability_grant import parse_runtime_capability_grant

SCHEMA = "aragorn/native-phase3-common-live-identity/v1"
AUTHORITY = "LOCAL_COMMON_KERNEL_AND_PROTECTED_BYTES_NOT_DEPLOYMENT_ATTESTATION"
MEASUREMENT_BINDING = "/etc/aragorn/runtime-broker-decision-measurement.json"
MEASUREMENT_SOURCES = {
    name: "/usr/lib/aragorn/aragorn/" + name
    for name in (
        "runtime_action_broker.py",
        "runtime_action_broker_v4.py",
        "runtime_action_broker_v5.py",
        "runtime_action_service_v5.py",
        "runtime_broker_decision_measurement.py",
        "phase3_deployment.py",
        "phase3_quantitative_metrics.py",
    )
}
FILE_PATHS = (*prior.FILE_PATHS, MEASUREMENT_BINDING, *MEASUREMENT_SOURCES.values())
CREDENTIALS = {role: dict(values) for role, values in prior._CREDENTIALS.items()}
CREDENTIALS["broker"]["decision-measurement-binding"] = MEASUREMENT_BINDING
LIMITATIONS = (
    "POINT_IN_TIME_BEFORE_AFTER_READS_NOT_CONTINUOUS_IMMUTABILITY",
    "CALLER_FILE_PINS_REQUIRE_OUTER_COMMON_STAGED_PROFILE_BINDING",
    "SELECTED_MODULE_AND_UNIT_BYTES_NOT_WHOLE_73_FILE_PROFILE_OR_RUNTIME_TREE",
    "BROKER_ROOT_MODULE_BYTES_NOT_LOADED_PYTHON_MODULE_PROVENANCE",
    "LOADED_CREDENTIAL_BYTES_NOT_APPLICATION_ACK_OR_POLICY_SEMANTICS",
    "MEASUREMENT_BINDING_DIGESTS_NOT_INPUT_CAS_OR_DEPLOYMENT_CLOSURE_READBACK",
    "GRANT_STRUCTURE_AND_BINDING_JOINS_NOT_CURRENT_LIVENESS_OR_AUTHORIZATION",
    "LOCAL_ROOT_OBSERVER_NOT_HOSTILE_ROOT_RESISTANT_OR_EXTERNAL_ATTESTATION",
    "NO_ADMISSION_RUN_METRICS_OR_PHASE3_QUALIFICATION",
)
UNRESOLVED_DIMENSIONS = {
    **{key: list(value) for key, value in prior.UNRESOLVED_DIMENSIONS.items()},
    "os_profile": ["complete_installed_73_file_profile", "image_and_kernel_provenance"],
    "configuration": [
        "application_use_of_measured_loaded_configuration",
        "measurement_input_cas_and_deployment_closure",
    ],
}
_FALSE = (
    "common_deployment_fully_verified",
    "route_qualified",
    "phase3_eligible",
    "live_deployment_attested",
    "metrics_eligible",
    "application_acknowledged",
)


class NativeCommonIdentityError(ValueError):
    """The fixed common-profile observation could not be safely established."""


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise NativeCommonIdentityError(message)


def _broker_argv() -> list[str]:
    unit = prior._UNITS["broker"]
    return [
        "/usr/bin/python3.12",
        "-I",
        "-S",
        "-B",
        "/usr/libexec/aragorn/" + prior._SHIMS["broker"],
        *(f"/run/credentials/{unit}/{name}" for name in CREDENTIALS["broker"]),
    ]


def _broker_process(container: str, accounts: dict, fragment_alias_guard=None) -> dict:
    """New exact three-credential process contract; all kernel checks remain real."""
    unit, argv = prior._UNITS["broker"], _broker_argv()
    state = prior._show(unit)
    uid, gid = accounts["broker"]
    cgroup = f"/docker/{container}/system.slice/{unit}"
    _require(
        re.fullmatch(r"[1-9][0-9]*", state["MainPID"]) is not None,
        "broker has no active PID",
    )
    pid = int(state["MainPID"])
    _require(
        state["Id"] == unit
        and state["ActiveState"] == "active"
        and state["SubState"] == "running"
        and state["ControlPID"] == "0"
        and state["ControlGroup"] == cgroup
        and state["User"] == prior._ACCOUNTS["broker"][0]
        and state["Group"] == prior._ACCOUNTS["broker"][1]
        and re.fullmatch(r"[0-9a-f]{32}", state["InvocationID"]) is not None
        and state["InvocationID"] != "0" * 32
        and state["DropInPaths"] == ""
        and (
            state["FragmentPath"] == "/usr/lib/systemd/system/" + unit
            or (
                state["FragmentPath"] == "/lib/systemd/system/" + unit
                and fragment_alias_guard is not None
            )
        )
        and state["ExecStart"].startswith(
            "{ path="
            + argv[0]
            + " ; argv[]="
            + " ".join(argv)
            + " ; ignore_errors=no ; "
        )
        and state["ExecStart"].count("argv[]=") == 1,
        "common broker unit or credential arguments changed",
    )
    if state["FragmentPath"] == "/lib/systemd/system/" + unit:
        fragment_alias_guard()
    process = prior.process
    started = process._process_start_time(pid)
    fields = prior._pairs(
        [
            line.split(":", 1)
            for line in process._read_virtual_file(Path(f"/proc/{pid}/status"), 16384)
            .decode("ascii")
            .splitlines()
            if ":" in line
        ]
    )
    uids = [int(value) for value in fields["Uid"].split()]
    gids = [int(value) for value in fields["Gid"].split()]
    groups = [int(value) for value in fields["Groups"].split()]
    command = process._read_virtual_file(Path(f"/proc/{pid}/cmdline"), 8192)
    _require(
        uids == [uid] * 4
        and gids == [gid] * 4
        and sorted(groups) == prior._groups("broker", accounts)
        and command.endswith(b"\0")
        and command.rstrip(b"\0").split(b"\0")
        == [item.encode("ascii") for item in argv]
        and os.readlink(f"/proc/{pid}/exe") == prior._executable_path("broker")
        and process._process_cgroup(pid) == cgroup
        and pid in process._cgroup_processes(cgroup)
        and process._process_start_time(pid) == started,
        "common broker kernel process identity changed",
    )
    group, root = os.lstat("/sys/fs/cgroup" + cgroup), os.stat(f"/proc/{pid}/root")
    _require(
        stat.S_ISDIR(group.st_mode)
        and group.st_uid == 0
        and stat.S_ISDIR(root.st_mode)
        and root.st_uid == 0,
        "broker root or cgroup custody changed",
    )
    return {
        "unit": state,
        "pid": pid,
        "start_time_ticks": started,
        "uids": uids,
        "gids": gids,
        "groups": sorted(groups),
        "cgroup": cgroup,
        "cgroup_identity": [group.st_dev, group.st_ino],
        "root_identity": [root.st_dev, root.st_ino],
        "mount_namespace": process._mount_namespace(pid),
        "argv": argv,
    }


def _process(role: str, container: str, accounts: dict, guard) -> dict:
    if role == "broker":
        return _broker_process(container, accounts, guard)
    return prior._process(role, container, accounts, guard)


def _joins(raw: dict[str, bytes], boot: str) -> dict:
    native = prior._joins(raw)
    binding = measurement._binding(
        raw[MEASUREMENT_BINDING], prior._digest(raw[MEASUREMENT_BINDING])
    )
    grant = parse_runtime_capability_grant(raw[prior._GRANT])
    worker, runtime, observation, policy = (
        prior._document(raw[path])
        for path in (prior._WORKER, prior._RUNTIME, prior._OBSERVATION, prior._POLICY)
    )
    sources = {
        name: prior._digest(raw[path]) for name, path in MEASUREMENT_SOURCES.items()
    }
    _require(
        binding["boot_id"] == boot
        and binding["source_pins"] == sources
        and binding["grant_digest"]
        == canonical_digest(grant)
        == prior._digest(raw[prior._GRANT])
        and all(
            binding[key] == grant[key]
            for key in (
                "runtime_digest",
                "runtime_profile_digest",
                "sensor_digest",
                "policy_digest",
                "active_skill_digest",
                "operation_digest",
            )
        )
        and binding["runtime_digest"]
        == worker["runtime_digest"]
        == runtime["runtime_digest"]
        and binding["runtime_profile_digest"] == runtime["runtime_profile_digest"]
        and binding["active_skill_digest"] == worker["active_skill_digest"]
        and binding["sensor_digest"]
        == observation["sensor_digest"]
        == policy["sensor_digest"]
        and binding["policy_digest"] == canonical_digest(policy)
        and grant["policy_version"] == worker["policy_version"] == policy["version"],
        "protected measurement, source, boot or grant joins changed",
    )
    return {
        **native,
        "measurement_binding_digest": prior._digest(raw[MEASUREMENT_BINDING]),
        "grant_digest": binding["grant_digest"],
        "runtime_profile_digest": binding["runtime_profile_digest"],
        "measurement_source_pins": sources,
        "measurement_boot_id": boot,
        "declared_input_digests_not_cas_readback": {
            key: binding[key]
            for key in (
                "deployment_identity_digest",
                "measurement_schedule_digest",
                "collection_commitment_digest",
                "scheduled_measurement_request_digest",
                "path_digest",
                "payload_digest",
            )
        },
    }


def _file_arguments(path: str, accounts: dict) -> dict:
    runtime = path == prior._ENTRY
    policy = path == prior._POLICY
    return {
        "owner": 1000 if runtime else accounts["broker"][0] if policy else 0,
        "owner_gid": 1000 if runtime else accounts["broker"][1] if policy else 0,
        "modes": {0o644}
        if path in MEASUREMENT_SOURCES.values()
        else {0o755}
        if runtime
        else {0o644, 0o755}
        if path in prior._CODE or path in (prior._PYTHON, "/usr/local/bin/node")
        else {0o400},
        "limit": prior._EXECUTABLE_LIMIT
        if path in (prior._PYTHON, "/usr/local/bin/node")
        else 4096
        if path == MEASUREMENT_BINDING
        else prior._LIMIT,
        "require_read_only": runtime,
    }


def read_native_common_identity(
    *, expected_container_id: str, expected_file_digests: dict[str, str]
) -> dict[str, Any]:
    """Measure the fixed26 files and actual process views, without returning raw bytes."""
    try:
        return _read(expected_container_id, expected_file_digests)
    except NativeCommonIdentityError:
        raise
    except (
        OSError,
        ValueError,
        TypeError,
        KeyError,
        subprocess.SubprocessError,
        prior.broker.RuntimeActionBrokerError,
        prior.process.RuntimeActionObservationPublisherError,
    ) as exc:
        raise NativeCommonIdentityError("fixed common identity read refused") from exc


def _read(container: str, expected: dict) -> dict:
    _require(
        sys.platform == "linux" and os.geteuid() == 0 and hasattr(os, "pidfd_open"),
        "common identity requires Linux root and PIDFD support",
    )
    _require(
        type(container) is str and re.fullmatch(r"[0-9a-f]{64}", container) is not None,
        "invalid owned fixture identity",
    )
    _require(
        type(expected) is dict and set(expected) == set(FILE_PATHS),
        "caller-held common file inventory changed",
    )
    pins = {path: prior._pin(pin) for path, pin in expected.items()}
    init_group = f"/docker/{container}/init.scope"
    process = prior.process
    _require(
        process._process_cgroup(1) == init_group, "observer is outside owned fixture"
    )
    boot, accounts = prior._boot(), prior._accounts()
    with ExitStack() as stack:
        root = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
        stack.callback(os.close, root)
        prior.broker.require_owned_directory(
            root, expected_uid=0, require_owner_write=False, label="observer root"
        )
        launcher = prior._python_link(root)
        fragment_alias = None

        def guard_alias():
            nonlocal fragment_alias
            if fragment_alias is None:
                fragment_alias = stack.enter_context(prior._systemd_library_alias(root))

        def processes():
            return {
                role: _process(role, container, accounts, guard_alias)
                for role in prior._UNITS
            }

        records = processes()
        _require(
            len({value["pid"] for value in records.values()}) == 4,
            "process PIDs overlap",
        )
        pidfds = {}
        for role, record in records.items():
            fd = prior._open_pidfd(record)
            stack.callback(os.close, fd)
            pidfds[role] = fd
        _require(records == processes(), "process identity changed after PIDFD open")
        raw, files, root_reads = {}, {}, []
        for path in FILE_PATHS:
            args = _file_arguments(path, accounts)
            content, metadata = prior._read_at(root, path, **args)
            _require(
                metadata["digest"] == pins[path],
                "protected bytes differ from caller pin",
            )
            raw[path], files[path] = content, metadata
            root_reads.append((root, path, args, content, metadata))
        loaded, module_views, view_reads = {}, {}, []
        for role, record in records.items():
            process.require_live_pidfd(pidfds[role])
            fd = os.open(
                f"/proc/{record['pid']}/root",
                os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC,
            )
            stack.callback(os.close, fd)
            prior.broker.require_owned_directory(
                fd, expected_uid=0, require_owner_write=False, label="process root"
            )
            held = os.fstat(fd)
            _require(
                [held.st_dev, held.st_ino] == record["root_identity"],
                "held process root differs",
            )
            measured = {}

            def view(path: str, source: str, args: dict) -> dict:
                content, metadata = prior._read_at(fd, path, **args)
                _require(
                    content == raw[source], "process view differs from protected source"
                )
                view_reads.append((fd, path, args, content, metadata))
                return metadata

            for name, source in CREDENTIALS[role].items():
                measured[name] = view(
                    f"/run/credentials/{prior._UNITS[role]}/{name}",
                    source,
                    {
                        "owner": 0,
                        "modes": {0o400, 0o440},
                        "credential_owner": accounts[role][0],
                        "credential_gid": accounts[role][1],
                        "limit": 4096
                        if source == MEASUREMENT_BINDING
                        else prior._LIMIT,
                    },
                )
            target = (
                prior._ENTRY
                if role == "gateway"
                else prior._WORKER_CODE
                if role == "worker"
                else "/usr/libexec/aragorn/" + prior._SHIMS[role]
            )
            args = (
                {
                    "owner": 1000,
                    "owner_gid": 1000,
                    "modes": {0o755},
                    "require_read_only": True,
                }
                if role == "gateway"
                else {"owner": 0, "modes": {0o644, 0o755}}
            )
            measured["code_view"] = view(target, target, args)
            if role == "broker":
                module_views = {
                    name: view(path, path, {"owner": 0, "modes": {0o644}})
                    for name, path in MEASUREMENT_SOURCES.items()
                }
            _require(
                process._executable_digest(record["pid"])
                == pins[prior._executable_path(role)],
                "running executable differs from caller pin",
            )
            loaded[role] = measured
        joins = _joins(raw, boot)
        for fd, path, args, content, metadata in (*root_reads, *view_reads):
            _require(
                prior._read_at(fd, path, **args) == (content, metadata),
                "protected source or process view changed during measurement",
            )
        for fd in pidfds.values():
            process.require_live_pidfd(fd)
        _require(
            records == processes(), "native process changed during byte measurement"
        )
        _require(
            prior._python_link(root) == launcher
            and prior._boot() == boot
            and process._process_cgroup(1) == init_group
            and prior._accounts() == accounts,
            "observer boot, cgroup or account identity changed",
        )
        return {
            "schema": SCHEMA,
            "authority": AUTHORITY,
            "status": "LOCAL_COMMON_IDENTITY_MEASURED",
            "container_id": container,
            "boot_id": boot,
            "files": files,
            "fixed_python_launcher": launcher,
            **(
                {"fixed_systemd_library_alias": fragment_alias}
                if fragment_alias is not None
                else {}
            ),
            "processes": records,
            "loaded_process_views": loaded,
            "broker_module_views": module_views,
            "measured_joins": joins,
            "unresolved_dimensions": {
                key: list(value) for key, value in UNRESOLVED_DIMENSIONS.items()
            },
            "limitations": list(LIMITATIONS),
            **dict.fromkeys(_FALSE, False),
        }


def compare_native_common_identity(before: dict, after: dict) -> dict:
    """Compare two retained observations without claiming another independent read."""
    _require(
        type(before) is dict
        and type(after) is dict
        and before == after
        and before.get("schema") == SCHEMA
        and before.get("authority") == AUTHORITY
        and before.get("status") == "LOCAL_COMMON_IDENTITY_MEASURED"
        and before.get("limitations") == list(LIMITATIONS)
        and before.get("unresolved_dimensions") == UNRESOLVED_DIMENSIONS
        and type(before.get("files")) is dict
        and set(before["files"]) == set(FILE_PATHS)
        and type(before.get("broker_module_views")) is dict
        and set(before["broker_module_views"]) == set(MEASUREMENT_SOURCES)
        and type(before.get("processes")) is dict
        and set(before["processes"]) == set(prior._UNITS)
        and all(type(record) is dict for record in before["processes"].values())
        and type(before.get("loaded_process_views")) is dict
        and set(before["loaded_process_views"]) == set(prior._UNITS)
        and all(
            type(before["loaded_process_views"][role]) is dict
            and set(before["loaded_process_views"][role]) == {*credentials, "code_view"}
            for role, credentials in CREDENTIALS.items()
        )
        and all(before.get(name) is False for name in _FALSE),
        "common identity changed or bounded contract is missing",
    )
    return {
        "status": "CALLER_COMMON_MEASUREMENTS_EQUAL",
        "authority": "COMPARISON_ONLY_NOT_INDEPENDENT_LIVE_READBACK",
        "snapshot_digest": prior._digest(canonical_json(before)),
        **dict.fromkeys(_FALSE, False),
    }
