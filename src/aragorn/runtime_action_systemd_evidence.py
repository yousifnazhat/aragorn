"""Verify the bounded P3.3b Linux systemd composition artifact."""

from __future__ import annotations

import base64
import errno
import hashlib
import re
from collections.abc import Mapping
from datetime import datetime, timezone
from typing import Any

from .admission_evidence import AdmissionEvidenceError, _time
from .oci_worker_protocol import canonical_digest, canonical_json
from .runtime_action_decision import evaluate_runtime_action

_SCHEMA = "aragorn/runtime-action-systemd-composition-evidence/v1"
_AUTHORITY = "BOUNDED_LINUX_SYSTEMD_COMPOSITION_ONLY_NOT_RUN_OR_EDR_AUTHORITY"
_EVIDENCE_DIGEST = "sha256:566fdcf610079c7ff8c83c083cc6e69b3e1e2c651182fa1d72effd765cf57f67"
_BASE_IMAGE = (
    "python@sha256:d50fb7611f86d04a3b0471b46d7557818d88983fc3136726336b2a4c657aa30b"
)
_RUNTIME_DIGEST = "sha256:" + "1" * 64
_SKILL_DIGEST = "sha256:" + "2" * 64
_SENSOR_DIGEST = "sha256:" + "3" * 64
_REVOCATION_SOURCE = "sha256:" + "4" * 64
_BROKER_UNIT = "aragorn-runtime-action-broker.service"
_SENSOR_UNIT = "aragorn-runtime-observation-publisher.service"
_LIMITATIONS = [
    "SINGLE_SYNTHETIC_CREATE_PROFILE_ONLY",
    "OPAQUE_SESSION_RUN_AND_TOOL_IDS_NOT_CAUSAL_ATTRIBUTION",
    "ACTIVE_SKILL_DIGEST_IS_DEPLOYMENT_PIN_NOT_CAUSAL_ATTRIBUTION",
    "OUTER_PRIVILEGED_DOCKER_HARNESS_AND_CONTROL_PLANE_NOT_ATTESTED",
    "SYSTEMD_PACKAGE_INSTALLED_FROM_NETWORKED_DEBIAN_REPOSITORY",
    "NO_PINNED_OPENCLAW_RUNTIME_COMPOSITION",
    "NO_DIRECT_WRITE_RENAME_SYMLINK_PROCESS_OR_NETWORK_ACTION_COVERAGE",
    "NO_FORCED_RESET_FILESYSTEM_OR_POWER_LOSS_QUALIFICATION",
    "RUN_01_NOT_ESTABLISHED",
    "RUN_02_NOT_ESTABLISHED",
    "PHASE_3_EXIT_NOT_ESTABLISHED",
    "EDR_CLAIM_NOT_ESTABLISHED",
    "PUBLIC_RELEASE_NOT_AUTHORIZED",
]
_DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
_NAMESPACE = re.compile(r"(?:mnt|net):\[[1-9][0-9]*\]\Z")
_PEER = re.compile(
    r"(?P<service>\d+)\s+getsockopt\((?P<fd>\d+), SOL_SOCKET, SO_PEERCRED, "
    r"\{pid=(?P<pid>\d+), uid=(?P<uid>\d+), gid=(?P<gid>\d+)\}, "
    r"\[12\]\) = 0"
)
_ACCEPT = re.compile(
    r"(?P<service>\d+)\s+accept4\(\d+, \{sa_family=AF_UNIX\}, "
    r"\[\d+ => \d+\], SOCK_CLOEXEC\) = (?P<fd>\d+)"
)
_DETACHED_ACCEPT = re.compile(
    r"(?P<service>\d+)\s+accept4\(\d+,\s+<detached \.\.\.>"
)
_CONNECT = re.compile(
    r'(?P<service>\d+)\s+connect\((?P<fd>\d+), '
    r'\{sa_family=AF_UNIX, sun_path="(?P<path>[^"]+)"\}, \d+\) = 0'
)
_SOURCES = {
    "/src/packaging/libexec/aragorn-runtime-action-service.py": (
        "/usr/libexec/aragorn/aragorn-runtime-action-service.py"
    ),
    "/src/packaging/libexec/aragorn-runtime-observation-service.py": (
        "/usr/libexec/aragorn/aragorn-runtime-observation-service.py"
    ),
    "/src/packaging/systemd/aragorn-gateway.sysusers": (
        "/usr/lib/sysusers.d/aragorn-gateway.conf"
    ),
    "/src/packaging/systemd/aragorn-runtime-action.tmpfiles": (
        "/usr/lib/tmpfiles.d/aragorn-runtime-action.conf"
    ),
    "/src/packaging/systemd/aragorn-runtime-action-broker.service": (
        "/usr/lib/systemd/system/aragorn-runtime-action-broker.service"
    ),
    "/src/packaging/systemd/aragorn-runtime-observation-publisher.service": (
        "/usr/lib/systemd/system/aragorn-runtime-observation-publisher.service"
    ),
    **{
        f"/src/src/aragorn/{name}": f"/usr/lib/aragorn/aragorn/{name}"
        for name in (
            "__init__.py",
            "oci_worker_protocol.py",
            "runtime_action_broker.py",
            "runtime_action_decision.py",
            "runtime_action_observation_publisher.py",
            "runtime_action_service.py",
            "runtime_observation_service.py",
        )
    },
}
_UNITS = {
    "broker": {
        "name": _BROKER_UNIT,
        "installed": "/usr/lib/systemd/system/aragorn-runtime-action-broker.service",
        "credential": (
            'a(ss) 1 "runtime-binding" '
            '"/etc/aragorn/runtime-action-runtime.json"'
        ),
        "command": (
            "/usr/bin/python3.12",
            "-I",
            "-S",
            "-B",
            "/usr/libexec/aragorn/aragorn-runtime-action-service.py",
            f"/run/credentials/{_BROKER_UNIT}/runtime-binding",
        ),
    },
    "sensor": {
        "name": _SENSOR_UNIT,
        "installed": (
            "/usr/lib/systemd/system/"
            "aragorn-runtime-observation-publisher.service"
        ),
        "credential": (
            'a(ss) 1 "observation-binding" '
            '"/etc/aragorn/runtime-action-observation.json"'
        ),
        "command": (
            "/usr/bin/python3.12",
            "-I",
            "-S",
            "-B",
            "/usr/libexec/aragorn/aragorn-runtime-observation-service.py",
            f"/run/credentials/{_SENSOR_UNIT}/observation-binding",
        ),
    },
}


def verify_runtime_action_systemd_composition_evidence(
    document: Mapping[str, Any],
) -> None:
    """Replay the exact artifact without granting RUN, EDR, or release authority."""

    try:
        _expect(
            set(document)
            == {
                "artifacts",
                "authority",
                "collector",
                "decision",
                "deployment",
                "environment",
                "harness",
                "identities",
                "inputs",
                "limitations",
                "peer_trace",
                "recorded_at",
                "scenarios",
                "schema",
            },
            "top-level fields changed",
        )
        _expect(canonical_digest(document) == _EVIDENCE_DIGEST, "evidence changed")
        _expect(not _contains_float(document), "floating-point evidence is invalid")
        _expect(document["schema"] == _SCHEMA, "schema changed")
        _expect(document["authority"] == _AUTHORITY, "authority changed")
        _expect(document["limitations"] == _LIMITATIONS, "limitations changed")
        _expect(
            _same_json(
                document["decision"],
                {
                "status": "P3_3B_OBSERVED",
                "bounded_systemd_profile_observed": True,
                "pinned_openclaw_composition_observed": False,
                "run_01_eligible": False,
                "run_02_eligible": False,
                "phase3_exit_eligible": False,
                "edr_claim_eligible": False,
                "public_release_eligible": False,
                },
            ),
            "authority ceiling changed",
        )
        _time(document["recorded_at"])
        identities = _verify_environment_and_artifacts(document)
        _verify_deployment(document, identities)
        _verify_peer_and_negative_cases(document, identities)
        _verify_effect_cases(document, identities)
        _verify_pid_separation(document)
        _verify_filesystem_identities(document)
        _verify_recording_time(document)
    except (IndexError, KeyError, RecursionError, TypeError, ValueError) as exc:
        if isinstance(exc, AdmissionEvidenceError):
            raise
        raise AdmissionEvidenceError(
            f"invalid runtime systemd composition evidence: {exc}"
        ) from exc


def _verify_environment_and_artifacts(
    document: Mapping[str, Any],
) -> dict[str, int]:
    environment = document["environment"]
    _expect(
        set(environment)
        == {
            "architecture",
            "base_image",
            "capture_identity",
            "container_id",
            "kernel_release",
            "pid1_mount_namespace",
            "pid1_network_namespace",
            "platform",
            "python",
            "strace",
            "systemd",
            "systemd_verify",
        }
        and environment["platform"] == "linux"
        and environment["architecture"] == "aarch64"
        and environment["base_image"] == _BASE_IMAGE
        and environment["python"] == "3.12.13"
        and re.fullmatch(
            r"[0-9]+\.[0-9]+\.[0-9]+[-+._0-9A-Za-z]*",
            environment["kernel_release"],
        )
        and environment["systemd"] == "systemd 252 (252.39-1~deb12u2)"
        and environment["strace"] == "strace -- version 6.1"
        and re.fullmatch(r"[0-9a-f]{12}", environment["container_id"])
        and _same_json(
            environment["systemd_verify"],
            {"exit_code": 0, "stdout": "", "stderr": ""},
        ),
        "Linux qualification environment changed",
    )
    capture = environment["capture_identity"]
    _expect(
        set(capture)
        == {"egid", "euid", "gid", "groups", "pid", "start_time_ticks", "uid"}
        and all(
            _nonnegative(capture[key]) and capture[key] == 0
            for key in ("uid", "euid", "gid", "egid")
        )
        and capture["groups"] == [0]
        and all(_nonnegative(value) for value in capture["groups"])
        and _positive(capture["pid"])
        and _positive_text(capture["start_time_ticks"]),
        "collector was not root",
    )
    harness = document["harness"]
    harness_document = harness["document"]
    _expect(
        set(harness) == {"digest", "document"}
        and harness["digest"] == canonical_digest(harness_document)
        and _same_json(
            harness_document,
            {
            "schema": "aragorn/runtime-action-systemd-harness/v1",
            "container_id": harness_document["container_id"],
            "image_id": harness_document["image_id"],
            "image_reference": "aragorn-p33b-systemd",
            "platform": "linux",
            "profile_label": "p3.3b",
            "host_config": {
                "binds": ["/sys/fs/cgroup:/sys/fs/cgroup:rw"],
                "cgroupns_mode": "host",
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
            },
            },
        )
        and re.fullmatch(r"[0-9a-f]{64}", harness_document["container_id"])
        and harness_document["container_id"].startswith(environment["container_id"])
        and _DIGEST.fullmatch(harness_document["image_id"]) is not None,
        "outer harness descriptor changed",
    )
    for name in ("pid1_mount_namespace", "pid1_network_namespace"):
        _expect(_NAMESPACE.fullmatch(environment[name]) is not None, "namespace invalid")

    identities = document["identities"]
    _expect(
        set(identities) == {"attacker_uid", "broker", "runtime", "sensor"}
        and set(identities["broker"]) == {"passwd_gid", "uid"}
        and set(identities["runtime"]) == {"gid", "uid"}
        and set(identities["sensor"]) == {"gid", "uid"},
        "identity fields changed",
    )
    values = {
        "broker_uid": identities["broker"]["uid"],
        "broker_gid": identities["broker"]["passwd_gid"],
        "runtime_uid": identities["runtime"]["uid"],
        "runtime_gid": identities["runtime"]["gid"],
        "sensor_uid": identities["sensor"]["uid"],
        "sensor_gid": identities["sensor"]["gid"],
        "attacker_uid": identities["attacker_uid"],
    }
    _expect(
        all(_positive(item) for item in values.values())
        and len(
            {
                values["broker_uid"],
                values["runtime_uid"],
                values["sensor_uid"],
                values["attacker_uid"],
            }
        )
        == 4
        and values["runtime_gid"] != values["sensor_gid"],
        "principal identities overlap",
    )

    artifacts = document["artifacts"]
    _expect(
        isinstance(artifacts, list) and len(artifacts) == len(_SOURCES),
        "artifact closure changed",
    )
    mapped = {item["source_path"]: item for item in artifacts}
    _expect(set(mapped) == set(_SOURCES), "artifact sources changed")
    for source, installed in _SOURCES.items():
        item = mapped[source]
        _expect(
            set(item)
            == {
                "source_path",
                "installed_path",
                "source_digest",
                "installed_digest",
                "source_bytes",
                "installed_bytes",
                "installed_stat",
            }
            and item["installed_path"] == installed
            and item["source_digest"] == item["installed_digest"]
            and item["source_bytes"] == item["installed_bytes"]
            and _positive(item["source_bytes"])
            and _positive(item["installed_bytes"])
            and _DIGEST.fullmatch(item["source_digest"]) is not None
            and set(item["installed_stat"])
            == {"device", "gid", "inode", "mode", "nlink", "size", "type", "uid"}
            and _same_json(
                item["installed_stat"],
                {
                    **item["installed_stat"],
                    "type": "file",
                    "uid": 0,
                    "gid": 0,
                    "mode": (
                        "0755"
                        if installed.startswith("/usr/libexec/")
                        else "0644"
                    ),
                    "nlink": 1,
                    "size": item["installed_bytes"],
                },
            )
            and _nonnegative(item["installed_stat"]["uid"])
            and _nonnegative(item["installed_stat"]["gid"])
            and _positive(item["installed_stat"]["nlink"])
            and _positive(item["installed_stat"]["size"]),
            f"installed artifact changed: {installed}",
        )
    collector = document["collector"]
    _expect(
        set(collector)
        == {"dockerfile", "dockerignore", "installer", "probe", "recipe"},
        "collector closure changed",
    )
    for name, path, mode in (
        ("dockerfile", "/src/benchmark/runtime-action-systemd/Dockerfile", "0644"),
        ("dockerignore", "/src/.dockerignore", "0644"),
        ("installer", "/src/packaging/install-runtime-action-host.sh", "0755"),
        ("probe", "/src/scripts/runtime_action_systemd_probe.py", "0644"),
        ("recipe", "/src/scripts/capture_runtime_action_systemd.sh", "0755"),
    ):
        item = collector[name]
        _expect(
            set(item) == {"bytes", "digest", "path", "stat"}
            and item["path"] == path
            and _DIGEST.fullmatch(item["digest"]) is not None
            and _positive(item["bytes"])
            and item["stat"]["type"] == "file"
            and set(item["stat"])
            == {"device", "gid", "inode", "mode", "nlink", "size", "type", "uid"}
            and item["stat"]["mode"] == mode
            and item["stat"]["uid"] == 0
            and item["stat"]["gid"] == 0
            and item["stat"]["nlink"] == 1
            and item["stat"]["size"] == item["bytes"]
            and _nonnegative(item["stat"]["uid"])
            and _nonnegative(item["stat"]["gid"])
            and _positive(item["stat"]["nlink"])
            and _positive(item["stat"]["size"]),
            f"collector {name} changed",
        )
    return values


def _verify_deployment(document: Mapping[str, Any], ids: Mapping[str, int]) -> None:
    deployment = document["deployment"]
    _expect(
        set(deployment)
        == {
            "directories",
            "mounts",
            "processes",
            "sensor_namespace_write_check",
            "sockets",
            "targets_before",
            "units",
        }
        and deployment["targets_before"] == [],
        "deployment fields changed or protected root was not empty",
    )
    directories = deployment["directories"]
    expected_directories = {
        "root": (0, 0, "0755"),
        "control": (ids["broker_uid"], ids["runtime_gid"], "0710"),
        "protected": (ids["broker_uid"], ids["runtime_gid"], "0710"),
        "staging": (ids["broker_uid"], ids["broker_gid"], "0700"),
        "runtime": (ids["sensor_uid"], ids["runtime_gid"], "0750"),
    }
    _expect(set(directories) == set(expected_directories), "directory set changed")
    for name, (uid, gid, mode) in expected_directories.items():
        value = directories[name]
        _expect(
            set(value)
            == {"device", "gid", "inode", "mode", "nlink", "size", "type", "uid"}
            and value["type"] == "directory"
            and (value["uid"], value["gid"], value["mode"]) == (uid, gid, mode)
            and _nonnegative(value["uid"])
            and _nonnegative(value["gid"])
            and _positive(value["device"])
            and _positive(value["inode"])
            and _positive(value["nlink"])
            and _nonnegative(value["size"]),
            f"{name} directory boundary changed",
        )
    sockets = deployment["sockets"]
    _expect(set(sockets) == {"backend", "frontend"}, "socket set changed")
    for name, (uid, gid) in {
        "backend": (ids["broker_uid"], ids["sensor_gid"]),
        "frontend": (ids["sensor_uid"], ids["runtime_gid"]),
    }.items():
        value = sockets[name]
        _expect(
            set(value)
            == {"device", "gid", "inode", "mode", "nlink", "size", "type", "uid"}
            and value["type"] == "socket"
            and (value["uid"], value["gid"], value["mode"], value["nlink"])
            == (uid, gid, "0660", 1)
            and _positive(value["nlink"])
            and _nonnegative(value["size"])
            and value["size"] == 0,
            f"{name} socket boundary changed",
        )
    _expect(
        sockets["backend"]["device"] == directories["control"]["device"]
        and sockets["frontend"]["device"] == directories["runtime"]["device"]
        and len(
            {
                directories[name]["device"]
                for name in ("root", "control", "protected", "staging")
            }
        )
        == 1
        and directories["runtime"]["device"] != directories["root"]["device"],
        "socket parent device changed",
    )

    units = deployment["units"]
    processes = deployment["processes"]
    _expect(
        set(units) == {"broker", "sensor"}
        and set(processes) == {"broker", "sensor"},
        "service set changed",
    )
    expected_units = {
        "broker": {
            "User": "aragorn-broker",
            "Group": "aragorn-runtime",
            "SupplementaryGroups": "aragorn-sensor",
            "ReadWritePaths": "/var/lib/aragorn-runtime-action",
            "ReadOnlyPaths": "",
            "InaccessiblePaths": "/etc/aragorn/runtime-action-runtime.json",
        },
        "sensor": {
            "User": "aragorn-sensor",
            "Group": "aragorn-sensor",
            "SupplementaryGroups": "aragorn-runtime",
            "ReadWritePaths": "",
            "ReadOnlyPaths": (
                "/var/lib/aragorn-runtime-action/control "
                "/var/lib/aragorn-runtime-action/protected"
            ),
            "InaccessiblePaths": (
                "/etc/aragorn/runtime-action-observation.json "
                "/var/lib/aragorn-runtime-action/staging"
            ),
        },
    }
    installed_artifacts = {
        item["installed_path"]: item for item in document["artifacts"]
    }
    first_event_unix = min(
        *(
            value["observed_at_unix"]
            for name, value in document["inputs"]["initial_controls"].items()
            if name != "policy" and "observed_at_unix" in value
        ),
        *(
            value["request"]["issued_at_unix"]
            for value in document["inputs"]["envelopes"].values()
        ),
    )
    for name, expected in expected_units.items():
        unit = units[name]
        process = processes[name]
        contract = _UNITS[name]
        unit_name = contract["name"]
        installed = contract["installed"]
        exec_start = _loaded_command_start(
            unit["ExecStart"], contract["command"], process["pid"], "ignore_errors=no"
        )
        exec_start_ex = _loaded_command_start(
            unit["ExecStartEx"], contract["command"], process["pid"], "flags="
        )
        _expect(
            set(unit)
            == set(expected)
            | {
                "ActiveState",
                "DropInPaths",
                "ExecStart",
                "ExecStartEx",
                "FragmentDigest",
                "FragmentPath",
                "FragmentResolvedPath",
                "LoadCredential",
                "MainPID",
                "NoNewPrivileges",
                "PrivateMounts",
                "PrivateNetwork",
                "ProtectSystem",
                "RestrictAddressFamilies",
                "SubState",
            }
            and all(unit[key] == value for key, value in expected.items())
            and unit["ActiveState"] == "active"
            and unit["SubState"] == "running"
            and unit["NoNewPrivileges"] == "yes"
            and unit["PrivateMounts"] == "yes"
            and unit["PrivateNetwork"] == "yes"
            and unit["ProtectSystem"] == "strict"
            and unit["RestrictAddressFamilies"] == "AF_UNIX"
            and int(unit["MainPID"]) == process["pid"]
            and unit["FragmentPath"] == f"/lib/systemd/system/{unit_name}"
            and unit["FragmentResolvedPath"] == installed
            and unit["FragmentDigest"]
            == installed_artifacts[installed]["installed_digest"]
            and unit["DropInPaths"] == ""
            and unit["LoadCredential"] == contract["credential"]
            and exec_start is not None
            and exec_start == exec_start_ex
            and _systemd_time(exec_start).timestamp() <= first_event_unix,
            f"{name} unit changed",
        )
        uid = ids[f"{name}_uid"]
        gid = ids["runtime_gid"] if name == "broker" else ids["sensor_gid"]
        _expect(
            set(process)
            == {
                "capabilities_effective",
                "cmdline",
                "gids",
                "groups",
                "mount_namespace",
                "network_namespace",
                "no_new_privileges",
                "pid",
                "start_time_ticks",
                "uids",
            }
            and process["cmdline"] == list(contract["command"])
            and process["uids"] == [uid] * 4
            and process["gids"] == [gid] * 4
            and process["groups"]
            == sorted([ids["runtime_gid"], ids["sensor_gid"]])
            and process["capabilities_effective"] == "0000000000000000"
            and process["no_new_privileges"] == 1
            and _positive(process["no_new_privileges"])
            and _positive(process["pid"])
            and _positive_text(process["start_time_ticks"])
            and _NAMESPACE.fullmatch(process["mount_namespace"]) is not None
            and _NAMESPACE.fullmatch(process["network_namespace"]) is not None,
            f"{name} process identity changed",
        )
    _expect(
        len(
            {
                processes["broker"]["mount_namespace"],
                processes["sensor"]["mount_namespace"],
                document["environment"]["pid1_mount_namespace"],
            }
        )
        == 3
        and len(
            {
                processes["broker"]["network_namespace"],
                processes["sensor"]["network_namespace"],
                document["environment"]["pid1_network_namespace"],
            }
        )
        == 3,
        "service namespaces overlap",
    )

    mounts = deployment["mounts"]
    _expect(
        set(mounts) == {"broker", "sensor"}
        and set(mounts["broker"]) == {"action_root", "credentials", "root"}
        and set(mounts["sensor"])
        == {"credentials", "root", "runtime", "staging"},
        "systemd mount set changed",
    )
    mount_records = []
    for value, expected in (
        (
            mounts["broker"]["root"],
            (
                "/",
                "/",
                "overlay",
                "overlay",
                {"ro", "nosuid"},
                {"rw"},
                directories["root"]["device"],
            ),
        ),
        (
            mounts["broker"]["action_root"],
            (
                "/var/lib/aragorn-runtime-action",
                "/var/lib/aragorn-runtime-action",
                "overlay",
                "overlay",
                {"rw", "nosuid"},
                {"rw"},
                directories["root"]["device"],
            ),
        ),
        (
            mounts["broker"]["credentials"],
            (
                f"/run/credentials/{_BROKER_UNIT}",
                "/",
                "ramfs",
                "ramfs",
                {"ro", "nodev", "noexec", "nosuid"},
                {"rw", "mode=700"},
            ),
        ),
        (
            mounts["sensor"]["root"],
            (
                "/",
                "/",
                "overlay",
                "overlay",
                {"ro", "nosuid"},
                {"rw"},
                directories["root"]["device"],
            ),
        ),
        (
            mounts["sensor"]["runtime"],
            (
                "/run/aragorn-runtime-observation",
                "/aragorn-runtime-observation",
                "tmpfs",
                "tmpfs",
                {"rw", "nodev", "noexec", "nosuid"},
                {"rw", "mode=755"},
                directories["runtime"]["device"],
            ),
        ),
        (
            mounts["sensor"]["staging"],
            (
                "/var/lib/aragorn-runtime-action/staging",
                "/systemd/inaccessible/dir",
                "tmpfs",
                "tmpfs",
                {"ro", "nodev", "noexec", "nosuid"},
                {"rw", "mode=755"},
            ),
        ),
        (
            mounts["sensor"]["credentials"],
            (
                f"/run/credentials/{_SENSOR_UNIT}",
                "/",
                "ramfs",
                "ramfs",
                {"ro", "nodev", "noexec", "nosuid"},
                {"rw", "mode=700"},
            ),
        ),
    ):
        mount_records.append(_verify_mount(value, *expected))
    mount_ids = [record[0] for record in mount_records]
    mount_devices = [record[2] for record in mount_records]
    _expect(
        len(mount_ids) == len(set(mount_ids))
        and all(mount_id != parent_id for mount_id, parent_id, _ in mount_records)
        and mount_records[1][1] == mount_records[0][0]
        and mount_records[5][1] == mount_records[3][0]
        and mount_devices[0] == mount_devices[1] == mount_devices[3]
        and mount_devices[4] == mount_devices[5]
        and _same_json(
            mounts["broker"]["root"]["super_options"],
            mounts["broker"]["action_root"]["super_options"],
        )
        and _same_json(
            mounts["broker"]["root"]["super_options"],
            mounts["sensor"]["root"]["super_options"],
        )
        and _same_json(
            mounts["sensor"]["runtime"]["super_options"],
            mounts["sensor"]["staging"]["super_options"],
        )
        and len(
            {
                mount_devices[0],
                mount_devices[2],
                mount_devices[4],
                mount_devices[6],
            }
        )
        == 4
        and mounts["broker"]["root"]["raw"]
        != mounts["sensor"]["root"]["raw"],
        "service mount tables overlap",
    )
    write_check = deployment["sensor_namespace_write_check"]
    _expect(
        set(write_check) == {"checks", "process"}
        and set(write_check["process"])
        == {"egid", "euid", "gid", "groups", "pid", "start_time_ticks", "uid"}
        and all(
            set(value) == {"blocked", "errno", "error"}
            for value in write_check["checks"].values()
        )
        and _client_identity_matches(
            write_check["process"],
            ids["sensor_uid"],
            ids["sensor_gid"],
            [ids["runtime_gid"]],
        )
        and _same_json(
            write_check["checks"],
            {
            "control_write": {
                "blocked": True,
                "errno": errno.EACCES,
                "error": "EACCES",
            },
            "credential_source_read": {
                "blocked": True,
                "errno": errno.EACCES,
                "error": "EACCES",
            },
            "protected_create": {
                "blocked": True,
                "errno": errno.EROFS,
                "error": "EROFS",
            },
            "staging_create": {
                "blocked": True,
                "errno": errno.EACCES,
                "error": "EACCES",
            },
            },
        ),
        "sensor namespace write test changed",
    )


def _verify_peer_and_negative_cases(
    document: Mapping[str, Any], ids: Mapping[str, int]
) -> None:
    scenarios = document["scenarios"]
    _expect(
        set(scenarios)
        == {
            "allowed_create",
            "runtime_direct_backend",
            "sensor_unavailable",
            "unhealthy_block",
            "wrong_backend_uid",
            "wrong_frontend_uid",
        }
        and all(item["status"] == "PASS" for item in scenarios.values()),
        "scenario set changed",
    )
    expected_scenario_fields = {
        "runtime_direct_backend": {"client", "control_after", "control_before", "status"},
        "wrong_backend_uid": {"client", "control_after", "control_before", "status"},
        "wrong_frontend_uid": {"client", "control_after", "control_before", "status"},
        "allowed_create": {
            "client",
            "control_after",
            "protected_entries",
            "staging_entries",
            "status",
            "target",
        },
        "unhealthy_block": {
            "client",
            "control_after",
            "protected_entries",
            "publication",
            "published_health",
            "staging_entries",
            "status",
            "target_exists",
        },
        "sensor_unavailable": {
            "client",
            "control_after",
            "control_before",
            "frontend_exists",
            "protected_entries",
            "staging_entries",
            "status",
            "target_exists",
            "units",
        },
    }
    _expect(
        all(
            set(scenarios[name]) == fields
            for name, fields in expected_scenario_fields.items()
        ),
        "scenario fields changed",
    )
    negative = document["inputs"]["envelopes"]["negative"]
    negative_raw = canonical_json(negative)
    negative_file_digest = "sha256:" + hashlib.sha256(negative_raw).hexdigest()
    direct = scenarios["runtime_direct_backend"]
    wrong_backend = scenarios["wrong_backend_uid"]
    wrong_frontend = scenarios["wrong_frontend_uid"]
    for item in (direct, wrong_backend, wrong_frontend):
        _expect(
            item["control_before"]
            == item["control_after"]
            == direct["control_before"]
            and item["client"]["request_bytes"] == len(negative_raw)
            and item["client"]["request_file_digest"] == negative_file_digest,
            "peer denial changed state or request",
        )
    _expect(
        set(direct["client"])
        == {
            "client",
            "elapsed_ns",
            "errno",
            "error",
            "outcome",
            "request_bytes",
            "request_file_digest",
        }
        and direct["client"]["outcome"] == "CONNECT_ERROR"
        and direct["client"]["errno"] == errno.EACCES
        and direct["client"]["error"] == "EACCES"
        and _positive(direct["client"]["elapsed_ns"])
        and direct["client"]["elapsed_ns"] < 500_000_000
        and _client_identity_matches(
            direct["client"]["client"],
            ids["runtime_uid"],
            ids["runtime_gid"],
            [],
        ),
        "runtime direct-backend denial changed",
    )
    broker_pid = document["deployment"]["processes"]["broker"]["pid"]
    sensor_pid = document["deployment"]["processes"]["sensor"]["pid"]
    peer_closed_fields = {
        "client",
        "elapsed_ns",
        "errno",
        "error",
        "outcome",
        "request_bytes",
        "request_file_digest",
        "server_peer",
    }
    _expect(
        set(wrong_backend["client"]) == peer_closed_fields
        and wrong_backend["client"]["outcome"] == "PEER_CLOSED"
        and wrong_backend["client"]["errno"] == 104
        and wrong_backend["client"]["error"] == "ECONNRESET"
        and _positive(wrong_backend["client"]["elapsed_ns"])
        and wrong_backend["client"]["elapsed_ns"] < 500_000_000
        and _client_identity_matches(
            wrong_backend["client"]["client"],
            ids["attacker_uid"],
            ids["sensor_gid"],
            [ids["runtime_gid"]],
        )
        and _same_json(
            wrong_backend["client"]["server_peer"],
            {"pid": broker_pid, "uid": ids["broker_uid"], "gid": ids["runtime_gid"]},
        )
        and set(wrong_frontend["client"]) == peer_closed_fields
        and wrong_frontend["client"]["outcome"] == "PEER_CLOSED"
        and wrong_frontend["client"]["errno"] == 104
        and wrong_frontend["client"]["error"] == "ECONNRESET"
        and _positive(wrong_frontend["client"]["elapsed_ns"])
        and wrong_frontend["client"]["elapsed_ns"] < 500_000_000
        and _client_identity_matches(
            wrong_frontend["client"]["client"],
            ids["attacker_uid"],
            ids["runtime_gid"],
            [],
        )
        and _same_json(
            wrong_frontend["client"]["server_peer"],
            {"pid": sensor_pid, "uid": ids["sensor_uid"], "gid": ids["sensor_gid"]},
        ),
        "wrong-UID denial changed",
    )

    traces = document["peer_trace"]
    _expect(set(traces) == {"broker", "sensor"}, "peer trace set changed")
    for name, service_pid in (("broker", broker_pid), ("sensor", sensor_pid)):
        trace = traces[name]
        peers = _trace_peers(
            trace["raw"],
            service_pid,
            (
                ["accept", "accept", "accept"]
                if name == "broker"
                else ["accept", "accept", "connect", "accept", "connect"]
            ),
        )
        _expect(
            set(trace) == {"peer_credentials", "raw", "raw_digest"}
            and all(set(peer) == {"gid", "pid", "uid"} for peer in trace["peer_credentials"])
            and trace["raw_digest"]
            == "sha256:" + hashlib.sha256(trace["raw"].encode()).hexdigest()
            and _same_json(trace["peer_credentials"], peers)
            and all(
                line.startswith(f"{service_pid} ")
                for line in trace["raw"].splitlines()
            ),
            f"{name} peer trace changed",
        )
    allow = scenarios["allowed_create"]["client"]
    unhealthy = scenarios["unhealthy_block"]["client"]
    _expect(
        _same_json(
            traces["broker"]["peer_credentials"],
            [
            {
                "pid": wrong_backend["client"]["client"]["pid"],
                "uid": ids["attacker_uid"],
                "gid": ids["sensor_gid"],
            },
            {"pid": sensor_pid, "uid": ids["sensor_uid"], "gid": ids["sensor_gid"]},
            {"pid": sensor_pid, "uid": ids["sensor_uid"], "gid": ids["sensor_gid"]},
            ],
        )
        and _same_json(
            traces["sensor"]["peer_credentials"],
            [
            {
                "pid": wrong_frontend["client"]["client"]["pid"],
                "uid": ids["attacker_uid"],
                "gid": ids["runtime_gid"],
            },
            {
                "pid": allow["client"]["pid"],
                "uid": ids["runtime_uid"],
                "gid": ids["runtime_gid"],
            },
            {"pid": broker_pid, "uid": ids["broker_uid"], "gid": ids["runtime_gid"]},
            {
                "pid": unhealthy["client"]["pid"],
                "uid": ids["runtime_uid"],
                "gid": ids["runtime_gid"],
            },
            {"pid": broker_pid, "uid": ids["broker_uid"], "gid": ids["runtime_gid"]},
            ],
        ),
        "peer relationships changed",
    )


def _verify_effect_cases(document: Mapping[str, Any], ids: Mapping[str, int]) -> None:
    inputs = document["inputs"]
    policy = inputs["policy"]
    _expect(
        set(inputs) == {"actions", "envelopes", "initial_controls", "policy"}
        and set(inputs["actions"]) == {"allow", "sensor_down", "unhealthy"}
        and set(inputs["envelopes"])
        == {"allow", "negative", "sensor_down", "unhealthy"}
        and policy == inputs["initial_controls"]["policy"],
        "input closure changed",
    )
    protected = document["deployment"]["directories"]["protected"]
    effects = {
        "allow": ("allowed.txt", b"Aragorn P3.3b allowed create\n"),
        "unhealthy": ("unhealthy.txt", b"Aragorn P3.3b unhealthy block\n"),
        "sensor_down": ("sensor-down.txt", b"Aragorn P3.3b sensor-down block\n"),
    }
    expected_rules = []
    for name in ("allow", "unhealthy", "sensor_down"):
        envelope = inputs["envelopes"][name]
        effect = envelope["effect"]
        request = envelope["request"]
        _expect(
            set(envelope) == {"effect", "request", "schema"}
            and envelope["schema"] == "aragorn/runtime-action-broker-request/v1"
            and set(effect)
            == {"operation", "payload_base64", "schema", "target_name"}
            and effect["schema"] == "aragorn/runtime-create-file/v1",
            f"{name} envelope changed",
        )
        _expect(
            set(request)
            == {
                "active_skill_digest",
                "authority",
                "expires_at_unix",
                "issued_at_unix",
                "operation_digest",
                "path_digest",
                "payload_digest",
                "policy_digest",
                "policy_version",
                "run_id",
                "runtime_digest",
                "schema",
                "session_id",
                "tool_call_id",
            }
            and request["schema"] == "aragorn/runtime-action-request/v1"
            and request["authority"]
            == "RUNTIME_ACTION_REQUEST_ONLY_NOT_EFFECT_AUTHORITY",
            f"{name} request fields changed",
        )
        payload = base64.b64decode(effect["payload_base64"], validate=True)
        expected_action = {
            "operation_digest": canonical_digest(
                {"schema": "aragorn/runtime-file-operation/v1", "operation": "create"}
            ),
            "path_digest": canonical_digest(
                {
                    "schema": "aragorn/runtime-protected-path/v1",
                    "root_device": protected["device"],
                    "root_inode": protected["inode"],
                    "target_name": effect["target_name"],
                }
            ),
            "payload_digest": "sha256:" + hashlib.sha256(payload).hexdigest(),
        }
        _expect(
            effect["operation"] == "create"
            and (effect["target_name"], payload) == effects[name]
            and expected_action == inputs["actions"][name]
            and all(request[key] == value for key, value in expected_action.items())
            and request["runtime_digest"] == _RUNTIME_DIGEST
            and request["session_id"] == "session-p3-3b"
            and request["run_id"] == "run-p3-3b"
            and request["tool_call_id"] == f"call-{name.replace('_', '-')}"
            and request["active_skill_digest"] == _SKILL_DIGEST
            and request["policy_digest"] == canonical_digest(policy)
            and request["policy_version"] == 1
            and _positive(request["policy_version"])
            and _positive(request["issued_at_unix"])
            and _positive(request["expires_at_unix"])
            and request["expires_at_unix"] == request["issued_at_unix"] + 5,
            f"{name} action binding changed",
        )
        expected_rules.append(
            {
                "runtime_digest": _RUNTIME_DIGEST,
                "active_skill_digest": _SKILL_DIGEST,
                **expected_action,
            }
        )
    _expect(
        _same_json(
            policy,
            {
            "schema": "aragorn/runtime-action-policy/v1",
            "id": "p3-3b-systemd-composition",
            "version": 1,
            "default": "BLOCK",
            "sensor_digest": _SENSOR_DIGEST,
            "revocation_source_digest": _REVOCATION_SOURCE,
            "allow": sorted(expected_rules, key=canonical_json),
            },
        ),
        "policy scope changed",
    )
    negative = inputs["envelopes"]["negative"]
    allow_request = inputs["envelopes"]["allow"]["request"]
    _expect(
        negative["schema"] == "aragorn/runtime-action-broker-request/v1"
        and negative["effect"] == inputs["envelopes"]["allow"]["effect"]
        and _same_json(
            negative["request"],
            {**allow_request, "tool_call_id": "call-negative"},
        ),
        "negative envelope changed",
    )
    _verify_initial_controls(inputs["initial_controls"], inputs["actions"]["allow"])

    scenarios = document["scenarios"]
    sensor_peer = {
        "pid": document["deployment"]["processes"]["sensor"]["pid"],
        "uid": ids["sensor_uid"],
        "gid": ids["sensor_gid"],
    }
    allowed = scenarios["allowed_create"]
    _verify_result_replay(
        inputs["envelopes"]["allow"],
        allowed["client"],
        allowed["control_after"],
        expected_client_uid=ids["runtime_uid"],
        expected_client_gid=ids["runtime_gid"],
        expected_server_peer=sensor_peer,
        expected_verdict="ALLOW",
        expected_reasons=[],
        expected_effect="CREATED",
    )
    target = allowed["target"]
    _expect(
        set(target) == {"bytes", "digest", "path", "stat"}
        and set(target["stat"])
        == {"device", "gid", "inode", "mode", "nlink", "size", "type", "uid"}
        and target["path"]
        == "/var/lib/aragorn-runtime-action/protected/allowed.txt"
        and target["digest"] == inputs["actions"]["allow"]["payload_digest"]
        and target["bytes"] == target["stat"]["size"] == len(effects["allow"][1])
        and _positive(target["bytes"])
        and target["stat"]["type"] == "file"
        and target["stat"]["device"] == protected["device"]
        and _positive(target["stat"]["inode"])
        and target["stat"]["uid"] == ids["broker_uid"]
        and target["stat"]["gid"] == ids["runtime_gid"]
        and target["stat"]["mode"] == "0400"
        and target["stat"]["nlink"] == 1
        and _positive(target["stat"]["nlink"]),
        "created target changed",
    )
    allow_state = allowed["control_after"]["state"]["document"]
    allow_response = allowed["client"]["response"]
    _expect(
        allowed["protected_entries"] == ["allowed.txt"]
        and allowed["staging_entries"] == []
        and allowed["control_after"]["policy"]["document"] == policy
        and allowed["control_after"]["revocations"]["document"]
        == inputs["initial_controls"]["revocations"]
        and allowed["control_after"]["health"]["document"]["status"]
        == "healthy"
        and allowed["control_after"]["health"]["document"]["epoch"] == 2
        and allowed["control_after"]["observation"]["document"]["sequence"] == 2
        and allow_state["minimum_revocation_generation"] == 1
        and allow_state["minimum_mediator_health_epoch"] == 2
        and allow_state["consumed"]
        == [
            {
                "request_digest": allow_response["request_digest"],
                "observation_digest": allow_response["observation_digest"],
                "expires_at_unix": (
                    allow_response["decision"]["evaluated_at_unix"] + 5
                ),
            }
        ]
        and allow_state["effect_journal"] is None,
        "allowed transition changed",
    )

    unhealthy = scenarios["unhealthy_block"]
    publication = unhealthy["publication"]
    published = publication["published"]
    _expect(
        set(publication) == {"process", "published"}
        and set(publication["process"])
        == {"egid", "euid", "gid", "groups", "pid", "start_time_ticks", "uid"}
        and set(unhealthy["published_health"]) == {"digest", "document"}
        and _same_json(
            published,
            {
            "schema": "aragorn/runtime-mediator-health/v1",
            "runtime_digest": _RUNTIME_DIGEST,
            "sensor_digest": _SENSOR_DIGEST,
            "epoch": 3,
            "status": "unhealthy",
            "observed_at_unix": published["observed_at_unix"],
            "expires_at_unix": published["observed_at_unix"] + 15,
            },
        )
        and _positive(published["observed_at_unix"])
        and _same_json(published, unhealthy["published_health"]["document"])
        and unhealthy["published_health"]["digest"]
        == canonical_digest(unhealthy["published_health"]["document"])
        and published["observed_at_unix"]
        <= unhealthy["client"]["response"]["decision"]["evaluated_at_unix"]
        < published["expires_at_unix"]
        and publication["process"]["uid"]
        == publication["process"]["euid"]
        == ids["broker_uid"]
        and publication["process"]["gid"]
        == publication["process"]["egid"]
        == ids["runtime_gid"]
        and publication["process"]["groups"] == [ids["sensor_gid"]]
        and _positive(publication["process"]["pid"])
        and _positive_text(publication["process"]["start_time_ticks"]),
        "unhealthy publication changed",
    )
    _verify_result_replay(
        inputs["envelopes"]["unhealthy"],
        unhealthy["client"],
        unhealthy["control_after"],
        expected_client_uid=ids["runtime_uid"],
        expected_client_gid=ids["runtime_gid"],
        expected_server_peer=sensor_peer,
        expected_verdict="BLOCK",
        expected_reasons=["MEDIATOR_UNHEALTHY"],
        expected_effect="NOT_PERFORMED",
    )
    unhealthy_state = unhealthy["control_after"]["state"]["document"]
    _expect(
        unhealthy["target_exists"] is False
        and unhealthy["protected_entries"] == ["allowed.txt"]
        and unhealthy["staging_entries"] == []
        and unhealthy["control_after"]["policy"]["document"] == policy
        and unhealthy["control_after"]["revocations"]["document"]
        == inputs["initial_controls"]["revocations"]
        and unhealthy["control_after"]["health"]["document"]["status"]
        == "unhealthy"
        and unhealthy["control_after"]["health"]["document"]["epoch"] == 4
        and unhealthy["control_after"]["observation"]["document"]["sequence"] == 3
        and unhealthy_state["minimum_revocation_generation"] == 1
        and unhealthy_state["minimum_mediator_health_epoch"] == 4
        and len(unhealthy_state["consumed"]) == 2
        and unhealthy_state["effect_journal"] is None,
        "unhealthy block changed",
    )
    consumed = {
        (
            item["request_digest"],
            item["observation_digest"],
            item["expires_at_unix"],
        )
        for item in unhealthy_state["consumed"]
    }
    _expect(
        consumed
        == {
            (
                allowed["client"]["response"]["request_digest"],
                allowed["client"]["response"]["observation_digest"],
                allowed["client"]["response"]["decision"]["evaluated_at_unix"]
                + 5,
            ),
            (
                unhealthy["client"]["response"]["request_digest"],
                unhealthy["client"]["response"]["observation_digest"],
                unhealthy["client"]["response"]["decision"][
                    "evaluated_at_unix"
                ]
                + 5,
            ),
        },
        "replay state changed",
    )

    sensor_down = scenarios["sensor_unavailable"]
    sensor_down_raw = canonical_json(inputs["envelopes"]["sensor_down"])
    prior_controls = {
        name: value["digest"] for name, value in unhealthy["control_after"].items()
    }
    initial_units = document["deployment"]["units"]
    sensor_argv = " ".join(_UNITS["sensor"]["command"])
    stopped_sensor = {
        **initial_units["sensor"],
        "ActiveState": "inactive",
        "ExecStart": (
            "{ path=/usr/bin/python3.12 ; argv[]="
            f"{sensor_argv} ; ignore_errors=no ; start_time=[n/a] ; "
            "stop_time=[n/a] ; pid=0 ; code=(null) ; status=0/0 }"
        ),
        "ExecStartEx": (
            "{ path=/usr/bin/python3.12 ; argv[]="
            f"{sensor_argv} ; flags= ; start_time=[n/a] ; "
            "stop_time=[n/a] ; pid=0 ; code=(null) ; status=0/0 }"
        ),
        "MainPID": "0",
        "SubState": "dead",
    }
    _expect(
        sensor_down["control_before"]
        == sensor_down["control_after"]
        == prior_controls
        and set(sensor_down["client"])
        == {
            "client",
            "elapsed_ns",
            "errno",
            "error",
            "outcome",
            "request_bytes",
            "request_file_digest",
        }
        and sensor_down["client"]["outcome"] == "CONNECT_ERROR"
        and sensor_down["client"]["errno"] == errno.ENOENT
        and sensor_down["client"]["error"] == "ENOENT"
        and _positive(sensor_down["client"]["elapsed_ns"])
        and sensor_down["client"]["elapsed_ns"] < 500_000_000
        and sensor_down["client"]["request_bytes"] == len(sensor_down_raw)
        and sensor_down["client"]["request_file_digest"]
        == "sha256:" + hashlib.sha256(sensor_down_raw).hexdigest()
        and _client_identity_matches(
            sensor_down["client"]["client"],
            ids["runtime_uid"],
            ids["runtime_gid"],
            [],
        )
        and sensor_down["frontend_exists"] is False
        and sensor_down["target_exists"] is False
        and sensor_down["protected_entries"] == ["allowed.txt"]
        and sensor_down["staging_entries"] == []
        and sensor_down["units"]["broker"]["ActiveState"] == "active"
        and sensor_down["units"]["broker"]["SubState"] == "running"
        and sensor_down["units"]["sensor"]["ActiveState"] == "inactive"
        and sensor_down["units"]["sensor"]["SubState"] == "dead"
        and sensor_down["units"]
        == {"broker": initial_units["broker"], "sensor": stopped_sensor},
        "sensor-unavailable result changed",
    )

    initial = inputs["initial_controls"]
    initial_raw_digests = {
        name: "sha256:" + hashlib.sha256(canonical_json(value)).hexdigest()
        for name, value in initial.items()
    }
    _expect(
        initial_raw_digests
        == scenarios["runtime_direct_backend"]["control_before"],
        "initial control closure changed",
    )


def _verify_initial_controls(
    controls: Mapping[str, Any], allow_action: Mapping[str, str]
) -> None:
    _expect(
        set(controls) == {"health", "observation", "policy", "revocations", "state"},
        "initial control set changed",
    )
    revocations = controls["revocations"]
    health = controls["health"]
    observation = controls["observation"]
    state = controls["state"]
    attribution = {
        "runtime_digest": _RUNTIME_DIGEST,
        "session_id": "session-p3-3b",
        "run_id": "run-p3-3b",
        "tool_call_id": "call-initial",
        "active_skill_digest": _SKILL_DIGEST,
    }
    active = {"schema": "aragorn/runtime-active-context/v1", **attribution}
    _expect(
        _same_json(
            revocations,
            {
            "schema": "aragorn/runtime-action-revocations/v1",
            "source_digest": _REVOCATION_SOURCE,
            "generation": 1,
            "observed_at_unix": revocations["observed_at_unix"],
            "expires_at_unix": revocations["observed_at_unix"] + 15,
            "skill_digests": [],
            },
        )
        and _same_json(
            health,
            {
            "schema": "aragorn/runtime-mediator-health/v1",
            "runtime_digest": _RUNTIME_DIGEST,
            "sensor_digest": _SENSOR_DIGEST,
            "epoch": 1,
            "status": "healthy",
            "observed_at_unix": health["observed_at_unix"],
            "expires_at_unix": health["observed_at_unix"] + 15,
            },
        )
        and _same_json(
            observation,
            {
            "schema": "aragorn/runtime-action-observation/v1",
            "authority": "SENSOR_OBSERVATION_ONLY_NOT_EFFECT_AUTHORITY",
            "sequence": 1,
            "sensor_digest": _SENSOR_DIGEST,
            "observed_at_unix": observation["observed_at_unix"],
            "expires_at_unix": observation["observed_at_unix"] + 5,
            "active": active,
            "measured_action": {
                "schema": "aragorn/measured-runtime-action/v1",
                **attribution,
                **allow_action,
            },
            },
        )
        and revocations["observed_at_unix"]
        == health["observed_at_unix"]
        == observation["observed_at_unix"]
        and all(
            _positive(value["observed_at_unix"])
            for value in (revocations, health, observation)
        )
        and _same_json(
            state,
            {
            "schema": "aragorn/runtime-action-broker-state/v2",
            "authority": "BROKER_STATE_ONLY_NOT_RUN_CONFORMANCE_AUTHORITY",
            "minimum_revocation_generation": 1,
            "minimum_mediator_health_epoch": 1,
            "consumed": [],
            "effect_journal": None,
            },
        ),
        "initial control state changed",
    )


def _verify_result_replay(
    envelope: Mapping[str, Any],
    client: Mapping[str, Any],
    controls: Mapping[str, Any],
    *,
    expected_client_uid: int,
    expected_client_gid: int,
    expected_server_peer: Mapping[str, int],
    expected_verdict: str,
    expected_reasons: list[str],
    expected_effect: str,
) -> None:
    response = client["response"]
    decision = response["decision"]
    observation = controls["observation"]["document"]
    health = controls["health"]["document"]
    revocations = controls["revocations"]["document"]
    policy = controls["policy"]["document"]
    state = controls["state"]["document"]
    identity = client["client"]
    _expect(
        set(controls) == {"health", "observation", "policy", "revocations", "state"}
        and all(
            set(value) == {"digest", "document"} for value in controls.values()
        )
        and set(state)
        == {
            "authority",
            "consumed",
            "effect_journal",
            "minimum_mediator_health_epoch",
            "minimum_revocation_generation",
            "schema",
        }
        and state["schema"] == "aragorn/runtime-action-broker-state/v2"
        and state["authority"]
        == "BROKER_STATE_ONLY_NOT_RUN_CONFORMANCE_AUTHORITY"
        and _positive(state["minimum_revocation_generation"])
        and _positive(state["minimum_mediator_health_epoch"])
        and isinstance(state["consumed"], list)
        and all(
            set(item) == {"expires_at_unix", "observation_digest", "request_digest"}
            and _positive(item["expires_at_unix"])
            and _DIGEST.fullmatch(item["observation_digest"]) is not None
            and _DIGEST.fullmatch(item["request_digest"]) is not None
            for item in state["consumed"]
        )
        and _same_json(
            state["consumed"], sorted(state["consumed"], key=canonical_json)
        )
        and len({item["request_digest"] for item in state["consumed"]})
        == len(state["consumed"])
        and len({item["observation_digest"] for item in state["consumed"]})
        == len(state["consumed"])
        and set(client)
        == {
            "client",
            "elapsed_ns",
            "outcome",
            "request_bytes",
            "request_file_digest",
            "response",
            "server_peer",
        }
        and _client_identity_matches(
            identity, expected_client_uid, expected_client_gid, []
        )
        and _same_json(client["server_peer"], expected_server_peer)
        and client["outcome"] == "RESPONSE"
        and _positive(client["elapsed_ns"])
        and client["elapsed_ns"] < 500_000_000
        and client["request_bytes"] == len(canonical_json(envelope))
        and client["request_file_digest"]
        == "sha256:" + hashlib.sha256(canonical_json(envelope)).hexdigest()
        and set(response)
        == {
            "authority",
            "decision",
            "effect_status",
            "observation_digest",
            "reason_codes",
            "request_digest",
            "schema",
            "target_name",
            "verdict",
        }
        and response["schema"] == "aragorn/runtime-action-broker-result/v1"
        and response["authority"]
        == "RUNTIME_EFFECT_RESULT_ONLY_NOT_RUN_CONFORMANCE_AUTHORITY"
        and response["target_name"] == envelope["effect"]["target_name"]
        and response["verdict"] == decision["verdict"] == expected_verdict
        and response["effect_status"] == expected_effect
        and response["reason_codes"] == decision["reason_codes"] == expected_reasons
        and response["request_digest"] == canonical_digest(envelope["request"])
        and response["observation_digest"] == canonical_digest(observation)
        and controls["health"]["digest"] == canonical_digest(health)
        and controls["observation"]["digest"] == canonical_digest(observation)
        and controls["policy"]["digest"] == canonical_digest(policy)
        and controls["revocations"]["digest"] == canonical_digest(revocations)
        and controls["state"]["digest"] == canonical_digest(state)
        and set(observation)
        == {
            "active",
            "authority",
            "expires_at_unix",
            "measured_action",
            "observed_at_unix",
            "schema",
            "sensor_digest",
            "sequence",
        }
        and observation["schema"] == "aragorn/runtime-action-observation/v1"
        and observation["authority"]
        == "SENSOR_OBSERVATION_ONLY_NOT_EFFECT_AUTHORITY"
        and observation["sensor_digest"] == _SENSOR_DIGEST
        and _positive(observation["sequence"])
        and _positive(observation["observed_at_unix"])
        and _positive(observation["expires_at_unix"])
        and observation["expires_at_unix"] == observation["observed_at_unix"] + 5
        and observation["observed_at_unix"]
        <= decision["evaluated_at_unix"]
        < observation["expires_at_unix"]
        and decision["minimum_revocation_generation"]
        == state["minimum_revocation_generation"]
        and decision["minimum_mediator_health_epoch"]
        == state["minimum_mediator_health_epoch"],
        "runtime result binding changed",
    )
    replay = evaluate_runtime_action(
        envelope["request"],
        policy,
        now_unix=decision["evaluated_at_unix"],
        active=observation["active"],
        measured_action=observation["measured_action"],
        revocations=revocations,
        minimum_revocation_generation=state["minimum_revocation_generation"],
        mediator_health=health,
        minimum_mediator_health_epoch=state["minimum_mediator_health_epoch"],
    )
    _expect(_same_json(replay, decision), "deterministic decision replay changed")


def _client_identity_matches(
    identity: Mapping[str, Any], uid: int, gid: int, groups: list[int]
) -> bool:
    return (
        set(identity)
        == {"egid", "euid", "gid", "groups", "pid", "start_time_ticks", "uid"}
        and identity["uid"] == identity["euid"] == uid
        and identity["gid"] == identity["egid"] == gid
        and identity["groups"] == groups
        and _positive(identity["pid"])
        and _positive_text(identity["start_time_ticks"])
    )


def _verify_pid_separation(document: Mapping[str, Any]) -> None:
    scenarios = document["scenarios"]
    deployment = document["deployment"]
    pids = [
        document["environment"]["capture_identity"]["pid"],
        *(value["pid"] for value in document["deployment"]["processes"].values()),
        document["deployment"]["sensor_namespace_write_check"]["process"]["pid"],
        scenarios["unhealthy_block"]["publication"]["process"]["pid"],
        *(value["client"]["client"]["pid"] for value in scenarios.values()),
    ]
    ordered_processes = [
        document["environment"]["capture_identity"],
        deployment["processes"]["broker"],
        deployment["processes"]["sensor"],
        scenarios["runtime_direct_backend"]["client"]["client"],
        scenarios["wrong_backend_uid"]["client"]["client"],
        scenarios["wrong_frontend_uid"]["client"]["client"],
        scenarios["allowed_create"]["client"]["client"],
        scenarios["unhealthy_block"]["publication"]["process"],
        scenarios["unhealthy_block"]["client"]["client"],
        deployment["sensor_namespace_write_check"]["process"],
        scenarios["sensor_unavailable"]["client"]["client"],
    ]
    start_ticks = [int(value["start_time_ticks"]) for value in ordered_processes]
    _expect(
        len(pids) == len(set(pids))
        and start_ticks == sorted(set(start_ticks)),
        "process role identity or chronology changed",
    )


def _verify_filesystem_identities(document: Mapping[str, Any]) -> None:
    deployment = document["deployment"]
    objects = [
        *deployment["directories"].values(),
        *deployment["sockets"].values(),
        *(item["installed_stat"] for item in document["artifacts"]),
        *(item["stat"] for item in document["collector"].values()),
        document["scenarios"]["allowed_create"]["target"]["stat"],
    ]
    identities = [(value["device"], value["inode"]) for value in objects]
    _expect(
        all(_positive(part) for identity in identities for part in identity)
        and len(identities) == len(set(identities)),
        "distinct retained filesystem objects alias",
    )


def _verify_recording_time(document: Mapping[str, Any]) -> None:
    scenarios = document["scenarios"]
    envelopes = document["inputs"]["envelopes"]
    scenario_envelopes = {
        "allowed_create": "allow",
        "runtime_direct_backend": "negative",
        "sensor_unavailable": "sensor_down",
        "unhealthy_block": "unhealthy",
        "wrong_backend_uid": "negative",
        "wrong_frontend_uid": "negative",
    }
    issued_times = [
        value["request"]["issued_at_unix"] for value in envelopes.values()
    ]
    event_times = [
        *issued_times,
        *(
            envelopes[envelope]["request"]["issued_at_unix"]
            + scenarios[scenario]["client"]["elapsed_ns"] / 1_000_000_000
            for scenario, envelope in scenario_envelopes.items()
        ),
        scenarios["allowed_create"]["client"]["response"]["decision"][
            "evaluated_at_unix"
        ],
        scenarios["unhealthy_block"]["client"]["response"]["decision"][
            "evaluated_at_unix"
        ],
        scenarios["unhealthy_block"]["publication"]["published"][
            "observed_at_unix"
        ],
    ]
    recorded_at = _time(document["recorded_at"]).timestamp()
    elapsed = recorded_at - max(event_times)
    _expect(
        0 <= elapsed < 2
        and all(0 <= recorded_at - issued_at < 2 for issued_at in issued_times),
        "recording time is inconsistent with capture events",
    )


def _trace_peers(
    raw: str, service_pid: int, expected_kinds: list[str]
) -> list[dict[str, int]]:
    lines = raw.splitlines()
    peers = []
    kinds = []
    _expect(len(lines) == len(expected_kinds) * 2 + 1, "peer trace shape changed")
    for index in range(0, len(lines) - 1, 2):
        precursor_line, peer_line = lines[index : index + 2]
        match = _PEER.fullmatch(peer_line)
        accept = _ACCEPT.fullmatch(precursor_line)
        connect = _CONNECT.fullmatch(precursor_line)
        precursor = accept or connect
        _expect(
            match is not None
            and precursor is not None
            and int(match["service"]) == int(precursor["service"]) == service_pid
            and match["fd"] == precursor["fd"]
            and (
                connect is None
                or connect["path"]
                == "/var/lib/aragorn-runtime-action/control/broker.sock"
            ),
            "SO_PEERCRED was not paired with a successful channel syscall",
        )
        kinds.append("accept" if accept is not None else "connect")
        peers.append(
            {name: int(match[name]) for name in ("pid", "uid", "gid")}
        )
    detached = _DETACHED_ACCEPT.fullmatch(lines[-1])
    _expect(
        detached is not None
        and int(detached["service"]) == service_pid
        and raw.count("SO_PEERCRED") == len(peers)
        and kinds == expected_kinds,
        "SO_PEERCRED trace direction changed",
    )
    return peers


def _loaded_command_start(
    raw: object,
    command: object,
    pid: object,
    property_flag: str,
) -> str | None:
    if (
        not isinstance(raw, str)
        or not isinstance(command, tuple)
        or not all(isinstance(item, str) for item in command)
        or not _positive(pid)
        or "\n" in raw
    ):
        return None
    argv = " ".join(command)
    prefix = (
        f"{{ path=/usr/bin/python3.12 ; argv[]={argv} ; "
        f"{property_flag} ; start_time=["
    )
    suffix = (
        f"] ; stop_time=[n/a] ; pid={pid} ; code=(null) ; status=0/0 }}"
    )
    if not raw.startswith(prefix) or not raw.endswith(suffix):
        return None
    return raw[len(prefix) : -len(suffix)]


def _systemd_time(value: str) -> datetime:
    return datetime.strptime(value, "%a %Y-%m-%d %H:%M:%S UTC").replace(
        tzinfo=timezone.utc
    )


def _verify_mount(
    value: Mapping[str, Any],
    mount_point: str,
    root: str,
    filesystem: str,
    source: str,
    required_mount_options: set[str],
    required_super_options: set[str],
    expected_device: int | None = None,
) -> tuple[int, int, tuple[int, int]]:
    _expect(
        set(value)
        == {
            "filesystem",
            "mount_options",
            "mount_point",
            "raw",
            "raw_digest",
            "root",
            "source",
            "super_options",
        }
        and isinstance(value["raw"], str)
        and "\n" not in value["raw"]
        and value["raw_digest"]
        == "sha256:" + hashlib.sha256(value["raw"].encode()).hexdigest(),
        f"mount record changed: {mount_point}",
    )
    left, right = value["raw"].split(" - ", 1)
    fields = left.split()
    observed_filesystem, observed_source, raw_super_options = right.split(" ", 2)
    device = fields[2].split(":", 1)
    observed_mount_options = sorted(fields[5].split(","))
    observed_super_options = sorted(raw_super_options.split(","))
    mount_options = set(observed_mount_options)
    super_options = set(observed_super_options)
    exclusive_options = (
        {"ro", "rw"},
        {"exec", "noexec"},
        {"dev", "nodev"},
        {"suid", "nosuid"},
    )
    _expect(
        len(fields) >= 6
        and _positive_text(fields[0])
        and _positive_text(fields[1])
        and len(device) == 2
        and all(part.isdigit() for part in device)
        and (
            expected_device is None
            or (int(device[0]), int(device[1])) == (0, expected_device)
        )
        and value["mount_point"] == fields[4] == mount_point
        and value["root"] == fields[3] == root
        and value["filesystem"] == observed_filesystem == filesystem
        and value["source"] == observed_source == source
        and value["mount_options"] == observed_mount_options
        and value["super_options"] == observed_super_options
        and required_mount_options.issubset(observed_mount_options)
        and required_super_options.issubset(observed_super_options)
        and all(not pair.issubset(mount_options) for pair in exclusive_options)
        and all(not pair.issubset(super_options) for pair in exclusive_options)
        and ({"ro", "rw"} & mount_options)
        == ({"ro", "rw"} & required_mount_options),
        f"mount boundary changed: {mount_point}",
    )
    return int(fields[0]), int(fields[1]), (int(device[0]), int(device[1]))


def _positive(value: object) -> bool:
    return not isinstance(value, bool) and isinstance(value, int) and value > 0


def _nonnegative(value: object) -> bool:
    return not isinstance(value, bool) and isinstance(value, int) and value >= 0


def _same_json(left: object, right: object) -> bool:
    return canonical_json(left) == canonical_json(right)


def _contains_float(value: object) -> bool:
    if isinstance(value, float):
        return True
    if isinstance(value, Mapping):
        return any(_contains_float(item) for item in value.values())
    if isinstance(value, list):
        return any(_contains_float(item) for item in value)
    return False


def _positive_text(value: object) -> bool:
    return isinstance(value, str) and value.isdigit() and int(value) > 0


def _expect(condition: bool, message: str) -> None:
    if not condition:
        raise AdmissionEvidenceError(
            f"invalid runtime systemd composition evidence: {message}"
        )
