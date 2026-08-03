"""Derive controls from the exact BusyBox ``--network=none`` probe.

TCP and UDP positive controls use the sandbox loopback interface. Non-loopback
denial requires zero non-loopback interfaces, zero IPv4 routes, and failed
run-bound TCP and UDP sends. The egress-observer artifact must be the same raw
transcript, so a receipt cannot substitute a separate asserted result.
"""

from __future__ import annotations

import hashlib
import json
import re
from typing import Any

from .oci_worker_protocol import WorkerProtocolError, canonical_json

PROBE_TRANSCRIPT_SCHEMA = (
    "aragorn/gvisor-backend-qualification-probe-transcript/v1"
)
HOST_SNAPSHOT_SCHEMA = "aragorn/gvisor-backend-qualification-host-snapshot/v1"

_MAX_TRANSCRIPT_BYTES = 16 * 1024
_MAX_SNAPSHOT_BYTES = 16 * 1024
_RUN_ID = re.compile(r"[0-9a-f]{32}\Z")
_DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
_CAPABILITY_MASK = re.compile(r"[0-9a-f]{16}\Z")
_TRANSCRIPT_FIELDS = (
    "schema",
    "run_id",
    "host_pid",
    "uid",
    "gid",
    "supplementary_gids",
    "no_new_privileges",
    "cap_inheritable",
    "cap_permitted",
    "cap_effective",
    "cap_bounding",
    "cap_ambient",
    "tmpfs_write_rc",
    "tmpfs_read_match",
    "tmpfs_removed",
    "tcp_loopback_send_rc",
    "tcp_loopback_listener_rc",
    "tcp_loopback_match",
    "udp_loopback_send_rc",
    "udp_loopback_listener_rc",
    "udp_loopback_match",
    "host_file_visible",
    "host_process_visible",
    "non_loopback_interfaces",
    "ipv4_routes",
    "tcp_egress_send_rc",
    "udp_egress_send_rc",
    "rootfs_write_rc",
    "rootfs_artifact_present",
    "input_read_match",
    "input_write_rc",
    "input_rename_rc",
    "input_unlink_rc",
    "input_post_match",
    "tmpfs_script_write_rc",
    "tmpfs_exec_rc",
    "mount_rc",
    "unshare_rc",
    "mknod_rc",
    "setuid_rc",
    "setgid_rc",
)
_BOOLEAN_FIELDS = {
    "tmpfs_read_match",
    "tmpfs_removed",
    "tcp_loopback_match",
    "udp_loopback_match",
    "host_file_visible",
    "host_process_visible",
    "rootfs_artifact_present",
    "input_read_match",
    "input_post_match",
}
_RETURN_CODE_FIELDS = {
    field
    for field in _TRANSCRIPT_FIELDS
    if field.endswith("_rc")
}
_SNAPSHOT_FIELDS = {
    "schema",
    "run_id",
    "host_file_digest",
    "input_digest",
    "process_id",
    "process_start_ticks",
    "process_marker_digest",
}


class GVisorBackendProbeError(ValueError):
    """The fixed probe or host snapshot transcript is malformed or unbound."""


def derive_gvisor_backend_controls(
    probe_stdout: bytes,
    probe_stderr: bytes,
    host_sentinel_pre: bytes,
    host_sentinel_post: bytes,
    egress_observer: bytes,
    *,
    expected_run_id: str,
) -> list[dict[str, Any]]:
    """Derive all 15 controls without trusting the receipt's asserted booleans."""

    if probe_stderr:
        raise GVisorBackendProbeError("backend qualification probe wrote stderr")
    values = _transcript(probe_stdout, expected_run_id=expected_run_id)
    if egress_observer != probe_stdout:
        raise GVisorBackendProbeError(
            "backend qualification egress observation transcript drifted"
        )

    host_pid = _positive_integer(values["host_pid"], "probe host_pid")
    before = _snapshot(
        host_sentinel_pre,
        expected_run_id=expected_run_id,
        expected_process_id=host_pid,
        label="host sentinel pre",
    )
    after = _snapshot(
        host_sentinel_post,
        expected_run_id=expected_run_id,
        expected_process_id=host_pid,
        label="host sentinel post",
    )
    expected_host_file = _raw_digest(
        f"Aragorn-host-file-{expected_run_id}".encode("ascii")
    )
    expected_input = _raw_digest(
        f"Aragorn-input-{expected_run_id}".encode("ascii")
    )
    expected_process_marker = _raw_digest(
        f"Aragorn-host-process-{expected_run_id}".encode("ascii")
    )
    if (
        before["host_file_digest"] != expected_host_file
        or before["input_digest"] != expected_input
        or before["process_marker_digest"] != expected_process_marker
    ):
        raise GVisorBackendProbeError(
            "backend qualification host sentinel pre-snapshot is unbound"
        )

    host_file_unchanged = (
        after["host_file_digest"] == before["host_file_digest"]
    )
    input_unchanged = after["input_digest"] == before["input_digest"]
    host_process_alive = (
        after["process_start_ticks"] == before["process_start_ticks"]
        and after["process_marker_digest"] == before["process_marker_digest"]
    )
    capability_masks_zero = all(
        values[field] == "0000000000000000"
        for field in (
            "cap_inheritable",
            "cap_permitted",
            "cap_effective",
            "cap_bounding",
            "cap_ambient",
        )
    )
    no_non_loopback_path = (
        _integer(values["non_loopback_interfaces"], "non_loopback_interfaces") == 0
        and _integer(values["ipv4_routes"], "ipv4_routes") == 0
    )

    return [
        {
            "control_id": "identity-profile",
            "observed": {
                "capability_masks_zero": capability_masks_zero,
                "gid": _integer(values["gid"], "gid"),
                "no_new_privileges": values["no_new_privileges"] == "1",
                "supplementary_groups": _supplementary_gids(
                    values["supplementary_gids"]
                ),
                "uid": _integer(values["uid"], "uid"),
            },
        },
        {
            "control_id": "tmpfs-write-positive",
            "observed": {
                "attempted": True,
                "cleaned": values["tmpfs_removed"] == "1",
                "succeeded": (
                    values["tmpfs_write_rc"] == "0"
                    and values["tmpfs_read_match"] == "1"
                ),
            },
        },
        {
            "control_id": "tcp-sink-positive-control",
            "observed": {
                "attempted": True,
                "control_token_received": (
                    values["tcp_loopback_send_rc"] == "0"
                    and values["tcp_loopback_listener_rc"] == "0"
                    and values["tcp_loopback_match"] == "1"
                ),
            },
        },
        {
            "control_id": "udp-sink-positive-control",
            "observed": {
                "attempted": True,
                "control_token_received": (
                    values["udp_loopback_send_rc"] == "0"
                    and values["udp_loopback_listener_rc"] != "0"
                    and values["udp_loopback_match"] == "1"
                ),
            },
        },
        {
            "control_id": "host-file-isolation",
            "observed": {
                "attempted": True,
                "host_unchanged": host_file_unchanged,
                "visible": values["host_file_visible"] == "1",
            },
        },
        {
            "control_id": "host-process-isolation",
            "observed": {
                "attempted": True,
                "host_alive": host_process_alive,
                "visible": values["host_process_visible"] == "1",
            },
        },
        {
            "control_id": "tcp-egress-denied",
            "observed": {
                "attempted": True,
                "probe_token_received": not (
                    no_non_loopback_path and values["tcp_egress_send_rc"] != "0"
                ),
            },
        },
        {
            "control_id": "udp-egress-denied",
            "observed": {
                "attempted": True,
                "probe_token_received": not (
                    no_non_loopback_path and values["udp_egress_send_rc"] != "0"
                ),
            },
        },
        {
            "control_id": "rootfs-write-denied",
            "observed": {
                "artifact_absent": values["rootfs_artifact_present"] == "0",
                "attempted": True,
                "succeeded": values["rootfs_write_rc"] == "0",
            },
        },
        {
            "control_id": "input-mutation-denied",
            "observed": {
                "host_unchanged": input_unchanged,
                "read_control_succeeded": (
                    values["input_read_match"] == "1"
                    and values["input_post_match"] == "1"
                ),
                "rename_succeeded": values["input_rename_rc"] == "0",
                "unlink_succeeded": values["input_unlink_rc"] == "0",
                "write_succeeded": values["input_write_rc"] == "0",
            },
        },
        {
            "control_id": "tmpfs-exec-denied",
            "observed": {
                "attempted": True,
                "succeeded": values["tmpfs_exec_rc"] == "0",
                "write_control_succeeded": values["tmpfs_script_write_rc"] == "0",
            },
        },
        {
            "control_id": "mount-denied",
            "observed": {
                "attempted": True,
                "succeeded": values["mount_rc"] == "0",
            },
        },
        {
            "control_id": "namespace-create-denied",
            "observed": {
                "attempted": True,
                "succeeded": values["unshare_rc"] == "0",
            },
        },
        {
            "control_id": "device-create-denied",
            "observed": {
                "attempted": True,
                "succeeded": values["mknod_rc"] == "0",
            },
        },
        {
            "control_id": "privilege-escalation-denied",
            "observed": {
                "setgid_attempted": True,
                "setgid_succeeded": values["setgid_rc"] == "0",
                "setuid_attempted": True,
                "setuid_succeeded": values["setuid_rc"] == "0",
            },
        },
    ]


def _transcript(raw: bytes, *, expected_run_id: str) -> dict[str, str]:
    if not 0 < len(raw) <= _MAX_TRANSCRIPT_BYTES or not raw.endswith(b"\n"):
        raise GVisorBackendProbeError(
            "backend qualification probe transcript is not bounded canonical text"
        )
    try:
        text = raw.decode("ascii")
    except UnicodeDecodeError as exc:
        raise GVisorBackendProbeError(
            "backend qualification probe transcript is not ASCII"
        ) from exc
    if "\r" in text:
        raise GVisorBackendProbeError(
            "backend qualification probe transcript contains carriage returns"
        )
    lines = text.removesuffix("\n").split("\n")
    if len(lines) != len(_TRANSCRIPT_FIELDS):
        raise GVisorBackendProbeError(
            "backend qualification probe transcript fields changed"
        )
    values: dict[str, str] = {}
    for expected, line in zip(_TRANSCRIPT_FIELDS, lines, strict=True):
        field, separator, value = line.partition("=")
        if separator != "=" or field != expected:
            raise GVisorBackendProbeError(
                "backend qualification probe transcript fields changed"
            )
        values[field] = value
    if (
        values["schema"] != PROBE_TRANSCRIPT_SCHEMA
        or _RUN_ID.fullmatch(values["run_id"]) is None
        or values["run_id"] != expected_run_id
    ):
        raise GVisorBackendProbeError(
            "backend qualification probe transcript is unbound"
        )
    for field in _RETURN_CODE_FIELDS:
        _return_code(values[field], field)
    for field in _BOOLEAN_FIELDS:
        if values[field] not in {"0", "1"}:
            raise GVisorBackendProbeError(f"probe {field} is not Boolean")
    for field in (
        "cap_inheritable",
        "cap_permitted",
        "cap_effective",
        "cap_bounding",
        "cap_ambient",
    ):
        if _CAPABILITY_MASK.fullmatch(values[field]) is None:
            raise GVisorBackendProbeError(f"probe {field} is not a capability mask")
    if values["no_new_privileges"] not in {"0", "1"}:
        raise GVisorBackendProbeError("probe no_new_privileges is not Boolean")
    _integer(values["uid"], "uid")
    _integer(values["gid"], "gid")
    _integer(values["non_loopback_interfaces"], "non_loopback_interfaces")
    _integer(values["ipv4_routes"], "ipv4_routes")
    _supplementary_gids(values["supplementary_gids"])
    return values


def _snapshot(
    raw: bytes,
    *,
    expected_run_id: str,
    expected_process_id: int,
    label: str,
) -> dict[str, Any]:
    if not 0 < len(raw) <= _MAX_SNAPSHOT_BYTES:
        raise GVisorBackendProbeError(f"backend qualification {label} is unbounded")
    try:
        value = json.loads(raw.decode("ascii"))
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError) as exc:
        raise GVisorBackendProbeError(
            f"backend qualification {label} is invalid JSON"
        ) from exc
    try:
        canonical = canonical_json(value)
    except WorkerProtocolError as exc:
        raise GVisorBackendProbeError(str(exc)) from exc
    if not isinstance(value, dict) or set(value) != _SNAPSHOT_FIELDS or canonical != raw:
        raise GVisorBackendProbeError(
            f"backend qualification {label} fields changed"
        )
    if (
        value["schema"] != HOST_SNAPSHOT_SCHEMA
        or value["run_id"] != expected_run_id
        or type(value["process_id"]) is not int
        or value["process_id"] != expected_process_id
    ):
        raise GVisorBackendProbeError(
            f"backend qualification {label} is unbound"
        )
    for field in ("host_file_digest", "input_digest", "process_marker_digest"):
        if not isinstance(value[field], str) or _DIGEST.fullmatch(value[field]) is None:
            raise GVisorBackendProbeError(
                f"backend qualification {label}.{field} is not a digest"
            )
    if (
        type(value["process_start_ticks"]) is not int
        or value["process_start_ticks"] <= 0
        or value["process_start_ticks"] > 2**63 - 1
    ):
        raise GVisorBackendProbeError(
            f"backend qualification {label}.process_start_ticks is invalid"
        )
    return value


def _return_code(value: str, label: str) -> int:
    result = _integer(value, label)
    if result > 255:
        raise GVisorBackendProbeError(f"probe {label} is not a return code")
    return result


def _integer(value: str, label: str) -> int:
    if (
        not value
        or len(value) > 10
        or not value.isascii()
        or not value.isdecimal()
    ):
        raise GVisorBackendProbeError(f"probe {label} is not decimal")
    result = int(value)
    if str(result) != value:
        raise GVisorBackendProbeError(f"probe {label} is not canonical decimal")
    return result


def _positive_integer(value: str, label: str) -> int:
    result = _integer(value, label)
    if result <= 0:
        raise GVisorBackendProbeError(f"{label} must be positive")
    return result


def _supplementary_gids(value: str) -> list[int]:
    if not value:
        return []
    raw = value.split(",")
    gids = [_integer(item, "supplementary_gids") for item in raw]
    if gids != sorted(set(gids)):
        raise GVisorBackendProbeError("probe supplementary_gids are not canonical")
    return gids


def _raw_digest(raw: bytes) -> str:
    return f"sha256:{hashlib.sha256(raw).hexdigest()}"
