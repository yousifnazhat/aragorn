"""Bounded cross-observation joins for the ingress common28 identity boundary.

Only retained dictionaries and caller-held file pins are consumed. Neither the
common identity producer nor the independent process observer is imported. The
outer capture must separately bind raw capture/source bytes and provisioning
closure. PIDFD use is an observer claim, never proven by this offline consumer.
"""

from __future__ import annotations

import re
import stat

from . import native_phase3_plugin_update_live_binding as frozen
from .oci_worker_protocol import canonical_json

SCHEMA = "aragorn/native-phase3-common-process-verification/v2"
AUTHORITY = "RETAINED_INDEPENDENT_OBSERVER_JOINS_NOT_LIVE_ATTESTATION"
IDENTITY_SCHEMA = "aragorn/native-phase3-common-live-identity/v2"
IDENTITY_AUTHORITY = (
    "LOCAL_COMMON_KERNEL_AND_PROTECTED_BYTES_NOT_DEPLOYMENT_ATTESTATION"
)
OBSERVER_SCHEMA = "aragorn/phase3-common-process-observation/v1"
OBSERVER_AUTHORITY = (
    "INDEPENDENT_LOCAL_PROCESS_READBACK_NOT_DEPLOYMENT_OR_APPLICATION_ACK"
)
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
ACTIVATOR = "/usr/libexec/aragorn/activate-runtime-action-worker-host.sh"
WORKER_INGRESS_SOURCES = {
    "runtime_worker_ingress_measurement.py": "/usr/lib/aragorn/aragorn/runtime_worker_ingress_measurement.py",
}
FILE_PATHS = (
    *frozen.FILE_PATHS,
    MEASUREMENT_BINDING,
    *MEASUREMENT_SOURCES.values(),
    ACTIVATOR,
    *WORKER_INGRESS_SOURCES.values(),
)
CREDENTIALS = {role: dict(values) for role, values in frozen._CREDENTIALS.items()}
CREDENTIALS["broker"]["decision-measurement-binding"] = MEASUREMENT_BINDING
FALSE_FLAGS = (
    "common_deployment_fully_verified",
    "route_qualified",
    "phase3_eligible",
    "live_deployment_attested",
    "metrics_eligible",
    "application_acknowledged",
)
IDENTITY_LIMITATIONS = (
    "POINT_IN_TIME_BEFORE_AFTER_READS_NOT_CONTINUOUS_IMMUTABILITY",
    "CALLER_FILE_PINS_REQUIRE_OUTER_COMMON_STAGED_PROFILE_BINDING",
    "SELECTED_MODULE_UNIT_AND_ACTIVATOR_BYTES_NOT_WHOLE_74_FILE_PROFILE_OR_RUNTIME_TREE",
    "PROCESS_ROOT_MODULE_BYTES_NOT_LOADED_PYTHON_MODULE_PROVENANCE",
    "LOADED_CREDENTIAL_BYTES_NOT_APPLICATION_ACK_OR_POLICY_SEMANTICS",
    "MEASUREMENT_BINDING_DIGESTS_NOT_INPUT_CAS_OR_DEPLOYMENT_CLOSURE_READBACK",
    "GRANT_STRUCTURE_AND_BINDING_JOINS_NOT_CURRENT_LIVENESS_OR_AUTHORIZATION",
    "LOCAL_ROOT_OBSERVER_NOT_HOSTILE_ROOT_RESISTANT_OR_EXTERNAL_ATTESTATION",
    "NO_ADMISSION_RUN_METRICS_OR_PHASE3_QUALIFICATION",
)
OBSERVER_LIMITATIONS = (
    "POINT_IN_TIME_PIDFD_HELD_PROCESS_READS_NOT_CONTINUOUS_IMMUTABILITY",
    "NO_PROTECTED_BYTES_LOADED_CREDENTIAL_OR_PYTHON_PROVENANCE_MEASURED",
    "LOCAL_ROOT_OBSERVER_NOT_HOSTILE_ROOT_RESISTANT_OR_EXTERNAL_ATTESTATION",
    "NO_ADMISSION_RUN_METRICS_OR_PHASE3_QUALIFICATION",
)
_UNRESOLVED = {
    **{name: list(parts) for name, parts in frozen._UNRESOLVED.items()},
    "os_profile": ["complete_installed_74_file_profile", "image_and_kernel_provenance"],
    "configuration": [
        "application_use_of_measured_loaded_configuration",
        "measurement_input_cas_and_deployment_closure",
    ],
}
_UNIT_FIELDS = {
    "Id",
    "MainPID",
    "ControlPID",
    "ControlGroup",
    "InvocationID",
    "ActiveState",
    "SubState",
    "User",
    "Group",
    "ExecStart",
    "FragmentPath",
    "DropInPaths",
}
_GATEWAY_FIELDS = {
    "Id",
    "LoadState",
    "ActiveState",
    "SubState",
    "MainPID",
    "ControlGroup",
    "User",
    "Group",
    "KillMode",
    "Delegate",
    "Restart",
    "ControlPID",
    "SendSIGKILL",
    "InvocationID",
}
_PROCESS_FIELDS = {
    "unit",
    "pid",
    "start_time_ticks",
    "uids",
    "gids",
    "groups",
    "cgroup",
    "cgroup_identity",
    "root_identity",
    "mount_namespace",
    "argv",
}


class NativeCommonProcessVerificationError(ValueError):
    """The exact retained common/independent-observer joins were refused."""


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise NativeCommonProcessVerificationError(message)


def _exact(value: object, fields: set[str], message: str) -> None:
    _require(type(value) is dict and set(value) == fields, message)


def _same(left: object, right: object) -> bool:
    # Canonical bytes also distinguish bool/int values that Python equality joins.
    return canonical_json(left) == canonical_json(right)


def _false(value: dict) -> None:
    _require(
        all(value.get(key) is False for key in FALSE_FLAGS), "proof ceiling changed"
    )


def _argv(role: str) -> list[str]:
    if role == "gateway":
        return [
            frozen._NODE,
            frozen._ENTRY,
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
    names = {
        "worker": ("worker-binding",),
        "sensor": ("observation-binding", "capability-grant"),
        "broker": (
            "runtime-binding",
            "capability-grant",
            "decision-measurement-binding",
        ),
    }[role]
    unit = frozen._UNITS[role]
    return [
        "/usr/bin/python3.12",
        "-I",
        "-S",
        "-B",
        frozen._SHIMS[role],
        *(f"/run/credentials/{unit}/{name}" for name in names),
    ]


def _envelopes(identity: dict, observer: dict, container: str) -> str:
    fields = {
        "schema",
        "authority",
        "status",
        "container_id",
        "boot_id",
        "files",
        "fixed_python_launcher",
        "processes",
        "loaded_process_views",
        "broker_module_views",
        "worker_module_views",
        "measured_joins",
        "unresolved_dimensions",
        "limitations",
        *FALSE_FLAGS,
    }
    if "fixed_systemd_library_alias" in identity:
        fields.add("fixed_systemd_library_alias")
    _exact(identity, fields, "common identity envelope changed")
    _exact(
        observer,
        {
            "schema",
            "authority",
            "container_id",
            "boot_id",
            "processes",
            "limitations",
            *FALSE_FLAGS,
        },
        "independent observer envelope changed",
    )
    _require(
        identity["schema"] == IDENTITY_SCHEMA
        and identity["authority"] == IDENTITY_AUTHORITY
        and identity["status"] == "LOCAL_COMMON_IDENTITY_MEASURED"
        and identity["limitations"] == list(IDENTITY_LIMITATIONS)
        and identity["unresolved_dimensions"] == _UNRESOLVED
        and observer["schema"] == OBSERVER_SCHEMA
        and observer["authority"] == OBSERVER_AUTHORITY
        and observer["limitations"] == list(OBSERVER_LIMITATIONS)
        and identity["container_id"] == observer["container_id"] == container,
        "common observation kind or container changed",
    )
    _false(identity)
    _false(observer)
    boot = identity["boot_id"]
    _require(
        type(boot) is str
        and re.fullmatch(r"[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}", boot)
        is not None
        and observer["boot_id"] == boot.replace("-", ""),
        "independent boot identity differs",
    )
    return boot


def _processes(identity: dict, observer: dict, container: str) -> dict:
    records, observed = identity["processes"], observer["processes"]
    _exact(records, set(frozen._UNITS), "common process inventory changed")
    _exact(observed, set(frozen._UNITS), "independent process inventory changed")
    accounts = {}
    for role in frozen._UNITS:
        _exact(observed[role], {"unit", "process"}, "independent role fields changed")
        process = observed[role]["process"]
        fields = {"pid", "uid", "gid", "start_time_ticks", "cgroup"}
        fields |= (
            {"cgroup_device", "cgroup_inode"}
            if role == "gateway"
            else {"uids", "gids", "executable", "command"}
        )
        _exact(process, fields, "independent kernel fields changed")
        for name in ("pid", "uid", "gid", "start_time_ticks"):
            _require(
                frozen._integer(process[name], 1), "invalid independent process scalar"
            )
        accounts[role] = (process["uid"], process["gid"])
    _require(
        accounts["broker"][1] == accounts["worker"][1],
        "broker group differs from worker",
    )
    _require(
        len({record["pid"] for record in records.values()}) == 4, "common PIDs overlap"
    )
    for role, unit in frozen._UNITS.items():
        record, separate = records[role], observed[role]
        process, state, other = separate["process"], record["unit"], separate["unit"]
        _exact(record, _PROCESS_FIELDS, "common kernel fields changed")
        _exact(state, _UNIT_FIELDS, "common unit fields changed")
        _exact(
            other,
            _GATEWAY_FIELDS if role == "gateway" else _UNIT_FIELDS | {"StandardOutput"},
            "independent unit fields changed",
        )
        _require(
            all(type(v) is str for v in (*state.values(), *other.values())),
            "nontext unit property",
        )
        uid, gid = accounts[role]
        fsuid, fsgid = accounts["worker"] if role == "sensor" else (uid, gid)
        groups = (
            sorted({accounts["worker"][1], accounts["sensor"][1]})
            if role in {"sensor", "broker"}
            else sorted({gid, accounts["gateway"][1]})
            if role == "worker"
            else [gid]
        )
        cgroup = f"/docker/{container}/system.slice/{unit}"
        _require(
            frozen._integer(record["pid"], 1)
            and frozen._integer(record["start_time_ticks"], 1)
            and record["pid"] == process["pid"]
            and record["start_time_ticks"] == process["start_time_ticks"]
            and _same(record["uids"], [uid, uid, uid, fsuid])
            and _same(record["gids"], [gid, gid, gid, fsgid])
            and _same(record["groups"], groups)
            and record["cgroup"] == process["cgroup"] == cgroup,
            "independent process epoch or accounts differ",
        )
        for name in ("cgroup_identity", "root_identity"):
            _require(
                type(record[name]) is list
                and len(record[name]) == 2
                and all(frozen._integer(n, 1) for n in record[name]),
                "invalid common inode identity",
            )
        _exact(
            record["mount_namespace"],
            {"device", "inode"},
            "common namespace fields changed",
        )
        _require(
            all(frozen._integer(n, 1) for n in record["mount_namespace"].values()),
            "invalid namespace identity",
        )
        argv = _argv(role)
        _require(
            record["argv"] == (["openclaw-gateway"] if role == "gateway" else argv)
            and state["Id"] == unit
            and state["MainPID"] == str(record["pid"])
            and state["ControlPID"] == "0"
            and state["ControlGroup"] == cgroup
            and state["ActiveState"] == "active"
            and state["SubState"] == "running"
            and state["User"] == frozen._ACCOUNTS[role][0]
            and state["Group"] == frozen._ACCOUNTS[role][1]
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
            and state["ExecStart"].count("argv[]=") == 1
            and all(state[key] == other[key] for key in state.keys() & other.keys()),
            "common or independent unit command changed",
        )
        if role == "gateway":
            _require(
                all(
                    frozen._integer(process[k], 1)
                    for k in ("cgroup_device", "cgroup_inode")
                )
                and record["cgroup_identity"]
                == [process["cgroup_device"], process["cgroup_inode"]],
                "independent gateway cgroup inode differs",
            )
            _require(
                all(
                    other[key] == value
                    for key, value in {
                        "LoadState": "loaded",
                        "KillMode": "control-group",
                        "Delegate": "no",
                        "Restart": "no",
                        "SendSIGKILL": "yes",
                    }.items()
                ),
                "independent gateway containment changed",
            )
        else:
            _require(
                _same(process["uids"], record["uids"])
                and _same(process["gids"], record["gids"])
                and process["executable"] == frozen._PYTHON
                and process["command"] == " ".join(argv)
                and other["StandardOutput"] == "journal",
                "independent executable or credentials changed",
            )
    frozen._aliases(identity)
    return accounts


def _files(identity: dict, pins: dict, accounts: dict) -> None:
    files = identity["files"]
    _exact(files, set(FILE_PATHS), "common28 file inventory changed")
    dynamic = {*frozen.DYNAMIC_PATHS, MEASUREMENT_BINDING}
    for path, record in files.items():
        owner = (
            accounts["broker"]
            if path == frozen._POLICY
            else (1000, 1000)
            if path == frozen._ENTRY
            else (0, 0)
        )
        modes = (
            {0o400}
            if path in dynamic
            else {0o644}
            if path in (*MEASUREMENT_SOURCES.values(), *WORKER_INGRESS_SOURCES.values())
            else {0o755}
            if path in (frozen._ENTRY, ACTIVATOR)
            else {0o644, 0o755}
        )
        frozen._metadata(record, owners={owner}, modes=modes)
        _require(
            record["digest"] == pins[path],
            "common protected bytes differ from caller pin",
        )
        _require(
            record["bytes"]
            <= (
                4096
                if path == MEASUREMENT_BINDING
                else 256 * 1024 * 1024
                if path in (frozen._PYTHON, frozen._NODE)
                else 2 * 1024 * 1024
            ),
            "common protected bytes exceed read bound",
        )
    loaded = identity["loaded_process_views"]
    _exact(loaded, set(frozen._UNITS), "common loaded role inventory changed")
    for role, credentials in CREDENTIALS.items():
        views, (uid, gid) = loaded[role], accounts[role]
        _exact(
            views, {*credentials, "code_view"}, "common credential inventory changed"
        )
        for name, path in credentials.items():
            view = frozen._metadata(
                views[name], owners={(0, 0), (uid, 0), (uid, gid)}, modes={0o400, 0o440}
            )
            _require(
                (view["identity"][3] == 0 or stat.S_IMODE(view["identity"][2]) == 0o400)
                and view["bytes"] == files[path]["bytes"]
                and view["digest"] == pins[path],
                "common loaded credential differs from protected source",
            )
        path = (
            frozen._ENTRY
            if role == "gateway"
            else frozen._WORKER_CODE
            if role == "worker"
            else frozen._SHIMS[role]
        )
        view = frozen._metadata(
            views["code_view"],
            owners={(1000, 1000)} if role == "gateway" else {(0, 0)},
            modes={0o755} if role == "gateway" else {0o644, 0o755},
        )
        _require(
            view["bytes"] == files[path]["bytes"] and view["digest"] == pins[path],
            "common code view differs",
        )
    modules = identity["broker_module_views"]
    _exact(modules, set(MEASUREMENT_SOURCES), "common broker module inventory changed")
    for name, path in MEASUREMENT_SOURCES.items():
        view = frozen._metadata(modules[name], owners={(0, 0)}, modes={0o644})
        _require(
            view["bytes"] == files[path]["bytes"] and view["digest"] == pins[path],
            "broker module view differs",
        )
    worker_modules = identity["worker_module_views"]
    _exact(
        worker_modules,
        set(WORKER_INGRESS_SOURCES),
        "common worker module inventory changed",
    )
    for name, path in WORKER_INGRESS_SOURCES.items():
        view = frozen._metadata(worker_modules[name], owners={(0, 0)}, modes={0o644})
        _require(
            view["bytes"] == files[path]["bytes"] and view["digest"] == pins[path],
            "worker ingress module view differs",
        )
    joins = identity["measured_joins"]
    declared = {
        "deployment_identity_digest",
        "measurement_schedule_digest",
        "collection_commitment_digest",
        "scheduled_measurement_request_digest",
        "path_digest",
        "payload_digest",
    }
    _exact(
        joins,
        {
            "configuration_digest",
            "worker_binding_digest",
            "policy_digest",
            "declared_runtime_digest_not_whole_tree_measurement",
            "measurement_binding_digest",
            "grant_digest",
            "runtime_profile_digest",
            "measurement_source_pins",
            "measurement_boot_id",
            "declared_input_digests_not_cas_readback",
        },
        "common measured join inventory changed",
    )
    for name, path in {
        "configuration_digest": frozen._CONFIG,
        "worker_binding_digest": frozen._WORKER,
        "policy_digest": frozen._POLICY,
        "measurement_binding_digest": MEASUREMENT_BINDING,
        "grant_digest": frozen._GRANT,
    }.items():
        _require(joins[name] == pins[path], "common measured digest does not join file")
    _require(
        joins["measurement_boot_id"] == identity["boot_id"]
        and joins["measurement_source_pins"]
        == {name: pins[path] for name, path in MEASUREMENT_SOURCES.items()},
        "common measurement source or boot join changed",
    )
    _exact(
        joins["declared_input_digests_not_cas_readback"],
        declared,
        "declared measurement input inventory changed",
    )
    for pin in (
        joins["runtime_profile_digest"],
        joins["declared_runtime_digest_not_whole_tree_measurement"],
        *joins["declared_input_digests_not_cas_readback"].values(),
    ):
        frozen._pin(pin)


def verify_native_common_process_observations(
    identity_before: dict,
    identity_after: dict,
    observer_before: dict,
    observer_after: dict,
    *,
    expected_container_id: str,
    expected_file_digests: dict[str, str],
) -> dict:
    """Join both acquired record pairs, not their execution or external authority."""
    try:
        _require(
            type(expected_container_id) is str
            and re.fullmatch(r"[0-9a-f]{64}", expected_container_id) is not None,
            "invalid caller container",
        )
        pins = frozen._pins(expected_file_digests, FILE_PATHS)
        for value in (identity_before, identity_after, observer_before, observer_after):
            _require(
                type(value) is dict
                and 0 < len(canonical_json(value)) <= 2 * 1024 * 1024,
                "unbounded retained observation",
            )
        _require(
            _same(identity_before, identity_after)
            and _same(observer_before, observer_after),
            "common or independent process epoch changed",
        )
        boot = _envelopes(identity_before, observer_before, expected_container_id)
        accounts = _processes(identity_before, observer_before, expected_container_id)
        _files(identity_before, pins, accounts)
        return {
            "schema": SCHEMA,
            "authority": AUTHORITY,
            "status": "BOUNDED_COMMON_PROCESS_JOINS_VERIFIED",
            "container_id": expected_container_id,
            "boot_id": boot,
            "identity_digest": frozen._digest(canonical_json(identity_before)),
            "observer_digest": frozen._digest(canonical_json(observer_before)),
            "joined_processes": list(frozen._UNITS),
            "caller_pinned_files": len(FILE_PATHS),
            "limitations": [
                "OUTER_CAPTURE_AND_SOURCE_CUSTODY_MUST_BE_VERIFIED_SEPARATELY",
                "RETAINED_READBACK_JOINS_NOT_PROOF_OF_PIDFD_USE_OR_OBSERVER_EXECUTION",
                "GROUPS_ROOT_AND_MOUNT_NAMESPACE_HAVE_NO_SECOND_OBSERVER_MEASUREMENT",
                "MODULE_AND_CREDENTIAL_VIEWS_NOT_LOADED_PYTHON_OR_APPLICATION_ACK",
                "DECLARED_BINDING_DIGESTS_NOT_RAW_INPUT_CAS_OR_PROVISIONING_SEMANTICS",
                "NO_ADMISSION_RUN_METRICS_OR_PHASE3_QUALIFICATION",
            ],
            **dict.fromkeys(FALSE_FLAGS, False),
        }
    except NativeCommonProcessVerificationError:
        raise
    except (
        KeyError,
        TypeError,
        ValueError,
        IndexError,
        OverflowError,
        RecursionError,
    ) as error:
        raise NativeCommonProcessVerificationError(
            "common retained process joins refused"
        ) from error
