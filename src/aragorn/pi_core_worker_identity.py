"""Protected Pi activation binding at the existing action-relay frontend.

This additive boundary authenticates the actual accepted Pi peer before reusing
the source-frozen relay. It does not make the downstream sensor's relay-process
attribution into Pi attribution, attest loaded JavaScript, launch a worker, or
establish a deployed isolation/Phase 3 result. No listener or CLI is installed.
"""

from __future__ import annotations

import os
from pathlib import Path
import re
import socket
import time
from typing import Any

from . import runtime_action_broker as broker
from . import runtime_action_worker as worker
from . import runtime_active_skill_lineage_v2 as lineage
from . import runtime_process_profile as process
from .oci_worker_protocol import canonical_digest, canonical_json


ACTIVATION_SCHEMA = "aragorn/pi-core-activation/v1"
ACTIVATION_AUTHORITY = "PROTECTED_LAUNCHER_BINDING_ONLY_NOT_EFFECT_AUTHORITY"
_MAX_ACTIVATION_BYTES = 8192
_MAX_UINT = 2**63 - 1
_PIN = re.compile(r"sha256:[0-9a-f]{64}\Z")
_ID = re.compile(r"[0-9a-f]{32}\Z")
_BOOT = re.compile(r"[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}\Z")
_PINS = frozenset((
    "profile_digest", "runtime_digest", "executable_digest",
    "active_skill_digest", "install_context_digest", "source_manifest_digest",
    "tree_digest", "active_record_digest", "deployment_digest", "policy_digest",
))
_FIELDS = frozenset((
    "schema", "authority", "activation_id", "session_id", "run_id", "pid",
    "uid", "gid", "start_time_ticks", "mount_namespace", "cgroup", "boot_id",
    "expires_at_monotonic_ns", *_PINS,
))
_ATTRIBUTION_FIELDS = (
    "pid", "uid", "gid", "start_time_ticks", "mount_namespace", "cgroup",
    "profile_digest", "runtime_digest", "executable_digest", "active_skill_digest",
)
_REFUSALS = (OSError, RuntimeError, ValueError, TypeError)


class PiWorkerIdentityError(worker.RuntimeActionWorkerError):
    """The protected Pi activation cannot authenticate this request."""


def _require(condition: bool, reason: str) -> None:
    if not condition:
        raise PiWorkerIdentityError(reason)


def _uint(value: object, *, minimum: int = 0, maximum: int = _MAX_UINT) -> None:
    _require(type(value) is int and minimum <= value <= maximum,
             "Pi activation integer is invalid")


def validate_activation(document: object) -> dict[str, Any]:
    """Validate shape only; caller-supplied bytes never become authority here."""

    _require(type(document) is dict and set(document) == _FIELDS,
             "Pi activation fields are invalid")
    _require(document["schema"] == ACTIVATION_SCHEMA
             and document["authority"] == ACTIVATION_AUTHORITY,
             "Pi activation schema or authority is invalid")
    activation_id = document["activation_id"]
    _require(type(activation_id) is str and _ID.fullmatch(activation_id) is not None
             and document["session_id"] == activation_id
             and document["run_id"] == activation_id,
             "Pi activation context is invalid")
    for name in _PINS:
        value = document[name]
        _require(type(value) is str and _PIN.fullmatch(value) is not None,
                 "Pi activation digest is invalid")
    for name in ("pid", "start_time_ticks", "expires_at_monotonic_ns"):
        _uint(document[name], minimum=1)
    for name in ("uid", "gid"):
        _uint(document[name], minimum=1, maximum=2**32 - 1)
    namespace = document["mount_namespace"]
    _require(type(namespace) is dict and set(namespace) == {"device", "inode"},
             "Pi activation mount namespace is invalid")
    _uint(namespace["device"])
    _uint(namespace["inode"], minimum=1)
    boot = document["boot_id"]
    _require(type(boot) is str and _BOOT.fullmatch(boot) is not None,
             "Pi activation boot identity is invalid")
    # Reuse the same finite cgroup/path rules as the kernel profile reader.
    cgroup = document["cgroup"]
    _require(type(cgroup) is str and len(cgroup) <= 4096,
             "Pi activation cgroup is invalid")
    try:
        process.runtime_process_profile({
            "schema": process.PROFILE_SCHEMA,
            "authority": process.PROFILE_AUTHORITY,
            "runtime_digest": document["runtime_digest"],
            "executable_digest": document["executable_digest"],
            "cgroup": cgroup,
            "skill_path": "/validated-activation/SKILL.md",
        })
    except _REFUSALS as exc:
        raise PiWorkerIdentityError("Pi activation process profile is invalid") from exc
    result = dict(document)
    result["mount_namespace"] = dict(namespace)
    _require(len(canonical_json(result)) <= _MAX_ACTIVATION_BYTES,
             "Pi activation exceeds its byte limit")
    return result


def read_activation(path: Path) -> dict[str, Any]:
    """Read canonical root-owned 0444 state beneath protected root ancestry.

    There is deliberately no expected-owner override or untrusted-byte input.
    The trusted launcher owns publishing and withdrawing this activation path.
    """

    _require(isinstance(path, Path) and path.is_absolute()
             and path != Path(path.anchor), "Pi activation path is invalid")
    descriptor = -1
    try:
        descriptor = broker._open_protected_directory(
            path.parent, 0, "Pi activation directory")
        before = os.stat(path.name, dir_fd=descriptor, follow_symlinks=False)
        raw = broker._read_owned_bytes_at(
            descriptor, path.name, max_bytes=_MAX_ACTIVATION_BYTES,
            expected_uid=0, exact_mode=0o444, label="Pi activation")
        after = os.stat(path.name, dir_fd=descriptor, follow_symlinks=False)
        _require(broker._file_identity(before) == broker._file_identity(after),
                 "Pi activation name changed while read")
        document = validate_activation(
            broker._parse_canonical_document(raw, "Pi activation"))
        _require(path.name == document["activation_id"] + ".json",
                 "Pi activation filename is not its exact identity")
        return document
    except _REFUSALS as exc:
        if isinstance(exc, PiWorkerIdentityError):
            raise
        raise PiWorkerIdentityError("protected Pi activation cannot be read") from exc
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def _boot_id() -> str:
    with open("/proc/sys/kernel/random/boot_id", "rb") as handle:
        raw = handle.read(38)
    _require(len(raw) == 37 and raw[-1:] == b"\n",
             "kernel boot identity is invalid")
    value = raw[:-1].decode("ascii")
    _require(_BOOT.fullmatch(value) is not None, "kernel boot identity is invalid")
    return value


def _remaining(deadline: float, activation: dict[str, Any]) -> None:
    _require(time.monotonic() < deadline, "Pi identity request deadline expired")
    _require(time.monotonic_ns() < activation["expires_at_monotonic_ns"],
             "Pi activation expired")
    _require(_boot_id() == activation["boot_id"], "Pi activation boot changed")


def _measured(connection: socket.socket, pidfd: int,
              profile: process.RuntimeProcessProfile,
              activation: dict[str, Any], deadline: float) -> dict[str, Any]:
    _remaining(deadline, activation)
    peer = worker._valid_peer(broker._peer_credentials(connection), "Pi worker")
    _require(peer == (activation["pid"], activation["uid"], activation["gid"]),
             "Pi socket peer changed")
    measured = process.measure_runtime_process_profile(
        peer[0], pidfd, profile, expected_uid=peer[1], expected_gid=peer[2])
    _require(all(measured.get(key) == activation[key] for key in _ATTRIBUTION_FIELDS),
             "Pi process does not match protected activation")
    _require(measured.get("skill_path") == str(profile.skill_path),
             "Pi process skill path changed")
    _remaining(deadline, activation)
    return measured


def _lineage_matches(active: dict[str, Any], activation: dict[str, Any],
                     profile: process.RuntimeProcessProfile,
                     protected_root: Path) -> None:
    pairs = (
        ("active_skill_digest", "active_skill_digest"),
        ("context_digest", "install_context_digest"),
        ("manifest_digest", "source_manifest_digest"),
        ("tree_digest", "tree_digest"),
        ("active_record_digest", "active_record_digest"),
    )
    _require(all(active.get(source) == activation[target] for source, target in pairs),
             "Pi installed bundle does not match protected activation")
    version = active.get("version_path")
    _require(type(version) is str
             and profile.skill_path == protected_root / version / "SKILL.md",
             "Pi profile is not bound to the immutable installed version")


def handle_pi_worker_connection(
    connection: socket.socket,
    config: worker.RuntimeActionWorkerConfig,
    *,
    activation_path: Path,
    profile: process.RuntimeProcessProfile,
    protected_install_root: Path,
    timeout_seconds: float = 0.5,
) -> dict[str, Any]:
    """Authenticate one accepted peer and relay at most one bounded request.

    The caller owns the accepted connection; this function owns only its newly
    obtained PIDFD and the lineage context. All paths are operator-provisioned.
    There is one original deadline, no effect retries and no fallback authority.
    A post-dispatch identity/cleanup failure returns INDETERMINATE without a
    broker result, even when a lower layer previously reported completion.
    """

    _require(worker._valid_timeout(timeout_seconds), "Pi request timeout is invalid")
    deadline = time.monotonic() + timeout_seconds
    worker._validate_config(config)
    _require(isinstance(profile, process.RuntimeProcessProfile),
             "Pi process profile is invalid")
    _require(isinstance(protected_install_root, Path)
             and protected_install_root.is_absolute()
             and protected_install_root != Path(protected_install_root.anchor),
             "Pi protected install root is invalid")
    activation = read_activation(activation_path)
    _remaining(deadline, activation)
    _require(config.expected_gateway_uid == activation["uid"]
             and config.expected_gateway_gid == activation["gid"]
             and config.binding.runtime_digest == activation["runtime_digest"]
             and config.binding.active_skill_digest == activation["active_skill_digest"]
             and config.binding.policy_digest == activation["policy_digest"]
             and profile.digest == activation["profile_digest"],
             "Pi relay configuration does not match activation")
    peer = worker._valid_peer(broker._peer_credentials(connection), "Pi worker")
    _require(peer == (activation["pid"], activation["uid"], activation["gid"]),
             "Pi socket peer is not the protected activation")
    pidfd = -1
    dispatched = False
    request_digest = None
    result = None
    try:
        pidfd = process.open_peer_pidfd(connection, peer[0])
        measured = _measured(connection, pidfd, profile, activation, deadline)
        grant = {name: activation[name] for name in (
            "active_skill_digest", "install_context_digest", "source_manifest_digest")}
        with lineage.hold_runtime_active_skill_lineage(
            peer[0], measured, grant, protected_root=protected_install_root,
            expected_install_uid=0, deadline=deadline,
        ) as active:
            _lineage_matches(active, activation, profile, protected_install_root)
            request = broker._read_frame(connection, deadline)
            validated, _payload = worker._worker_request(request)
            request_digest = canonical_digest(validated)
            _require(validated["session_id"] == activation["session_id"]
                     and validated["run_id"] == activation["run_id"],
                     "Pi request is not bound to the protected activation")
            _require(read_activation(activation_path) == activation,
                     "Pi activation changed before submission")
            _require(_measured(connection, pidfd, profile, activation, deadline) == measured,
                     "Pi process changed before submission")
            # Set before the call: an exception cannot establish no submission.
            dispatched = True
            result = worker._relay_request(validated, config, deadline=deadline)
            _require(read_activation(activation_path) == activation,
                     "Pi activation changed after submission")
            _require(_measured(connection, pidfd, profile, activation, deadline) == measured,
                     "Pi process changed after submission")
    except _REFUSALS as exc:
        if not dispatched:
            if isinstance(exc, PiWorkerIdentityError):
                raise
            raise PiWorkerIdentityError("Pi peer or bundle identity refused") from exc
        result = worker._worker_result(request_digest, "INDETERMINATE", None)
    finally:
        if pidfd >= 0:
            try:
                os.close(pidfd)
            except OSError as exc:
                if not dispatched:
                    raise PiWorkerIdentityError("Pi identity cleanup failed") from exc
                result = worker._worker_result(request_digest, "INDETERMINATE", None)
    # All owned handles/locks have been released before a success is reported.
    _require(type(result) is dict, "Pi relay has no result")
    broker._send_frame(connection, canonical_json(result), deadline)
    return result
