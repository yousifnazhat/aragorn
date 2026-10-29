"""Fixed absent-only measurement provisioning, without activation or repair.

Call require_native_measurement_unused BEFORE any legacy fixture setup/reset.
That read-only guard does not make a later reset safe: the caller must already
own the disposable fixture and serialize its lifecycle. Provisioning separately
holds the existing activation/broker locks, publishes only new paths, and keeps
all partial output on failure. It never clears a pending attempt or retries an
effect. Root custody and stopped-unit snapshots are not hostile-root attestation.
"""

from __future__ import annotations

import hashlib
import os
import re
import stat
import sys
import time
from contextlib import ExitStack
from pathlib import Path

from . import runtime_action_broker as broker
from . import runtime_action_decision as decision
from . import runtime_native_tool_provisioning as custody
from . import runtime_response_service as response
from . import runtime_skill_startup_service as startup
from .cas import CAS
from .oci_worker_protocol import canonical_digest, canonical_json
from .runtime_capability_grant import parse_runtime_capability_grant
from .runtime_native_measurement_inputs import (
    validate_prepared_native_measurement_inputs,
)

_ROOT_UID = 0
_ROOT_GID = 0
_RUNTIME_ROOT = Path("/var/lib/aragorn-runtime-action")
_CONTROL = _RUNTIME_ROOT / "control"
_PROTECTED = _RUNTIME_ROOT / "protected"
_STORE = _CONTROL / "decision-measurement-inputs"
_EVIDENCE = _CONTROL / "decision-measurement-evidence"
_PENDING = _CONTROL / "decision-measurement-pending.json"
_COMPLETE = _CONTROL / "decision-measurement-complete.json"
_CREDENTIAL = Path("/etc/aragorn/runtime-broker-decision-measurement.json")
_WORKER = Path("/etc/aragorn/runtime-action-worker.json")
_RUNTIME = Path("/etc/aragorn/runtime-action-runtime.json")
_GRANT = Path("/etc/aragorn/runtime-capability-grant.json")
_SOURCES = Path("/usr/lib/aragorn/aragorn")
_BOOT = Path("/proc/sys/kernel/random/boot_id")
_CGROUP = Path("/sys/fs/cgroup")
_MAX_BLOB = 1024 * 1024
_SOURCE_NAMES = frozenset(
    {
        "runtime_action_broker.py",
        "runtime_action_broker_v4.py",
        "runtime_action_broker_v5.py",
        "runtime_action_service_v5.py",
        "runtime_broker_decision_measurement.py",
        "phase3_deployment.py",
        "phase3_quantitative_metrics.py",
    }
)
_UNITS = {
    "aragorn-agent-gateway.service": ("aragorn-agent-gateway", "aragorn-agent-gateway"),
    "aragorn-runtime-action-worker.service": ("aragorn-runtime", "aragorn-runtime"),
    "aragorn-runtime-lineage-capability-action-broker.service": (
        "aragorn-broker",
        "aragorn-runtime",
    ),
    "aragorn-runtime-lineage-capability-observation-publisher.service": (
        "aragorn-sensor",
        "aragorn-sensor",
    ),
}
_PROPERTIES = (
    "Id",
    "LoadState",
    "ActiveState",
    "SubState",
    "MainPID",
    "ControlPID",
    "ControlGroup",
    "User",
    "Group",
    "KillMode",
    "Delegate",
    "Restart",
)
_PRIOR_RESULTS = (
    "capability-grant-state.json",
    "profile-pending.json",
    "profile-receipt.json",
)


class NativeMeasurementProvisioningError(RuntimeError):
    """Refuse activation; partial files/evidence must be retained, never reset."""


def _require(value: bool) -> None:
    if not value:
        raise NativeMeasurementProvisioningError(
            "native measurement provisioning refused"
        )


def _require_root() -> None:
    _require(sys.platform == "linux" and os.geteuid() == 0 and os.getegid() == 0)


def _digest(raw: bytes) -> str:
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def _held_directory(
    parent: int, name: str, uid: int, gid: int, mode: int, held: list
) -> custody._Held:
    fd = os.open(name, custody._DIRECTORY_FLAGS, dir_fd=parent)
    try:
        metadata = os.fstat(fd)
        _require(
            stat.S_ISDIR(metadata.st_mode)
            and metadata.st_uid == uid
            and metadata.st_gid == gid
            and stat.S_IMODE(metadata.st_mode) == mode
        )
        entry = custody._Held(
            parent, name, fd, broker._directory_identity(metadata), True
        )
        custody._recheck([entry])
        held.append(entry)
        return entry
    except BaseException:
        os.close(fd)
        raise


def _optional_control(identities: tuple, held: list) -> int | None:
    parent = custody._root_directory(_RUNTIME_ROOT.parent, held)
    try:
        os.stat(_RUNTIME_ROOT.name, dir_fd=parent, follow_symlinks=False)
    except FileNotFoundError:
        return None
    runtime = _held_directory(
        parent, _RUNTIME_ROOT.name, _ROOT_UID, _ROOT_GID, 0o755, held
    )
    try:
        os.stat(_CONTROL.name, dir_fd=runtime.fd, follow_symlinks=False)
    except FileNotFoundError:
        return None
    return _held_directory(
        runtime.fd, _CONTROL.name, identities[0], identities[2], 0o710, held
    ).fd


def _unused_control(fd: int, *, include_store: bool = True) -> None:
    names = [_EVIDENCE.name, _PENDING.name, _COMPLETE.name, *_PRIOR_RESULTS]
    if include_store:
        names.append(_STORE.name)
    for name in names:
        custody._absent(fd, name)
    # A previous immutable grant archive is history, even if its live state was
    # removed. Never let the legacy reset discard its remaining authority trail.
    _require(
        not any(
            name.startswith(
                ("capability-grant-state-", "capability-grant-profile-receipt-")
            )
            for name in os.listdir(fd)
        )
    )


def _empty_cgroup(path: str) -> dict:
    directory = _CGROUP / path.removeprefix("/")
    try:
        fd = os.open(directory, custody._DIRECTORY_FLAGS)
    except FileNotFoundError:
        return {"path": path, "status": "ABSENT"}
    try:
        before = os.fstat(fd)
        _require(stat.S_ISDIR(before.st_mode) and before.st_uid == _ROOT_UID)
        events = os.open(
            "cgroup.events",
            os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC,
            dir_fd=fd,
        )
        try:
            info = os.fstat(events)
            _require(stat.S_ISREG(info.st_mode) and info.st_uid == _ROOT_UID)
            raw = os.read(events, 4097)
        finally:
            os.close(events)
        _require(0 < len(raw) <= 4096)
        values = {}
        for line in raw.decode("ascii").splitlines():
            fields = line.split()
            _require(
                len(fields) == 2 and fields[0] not in values and fields[1] in {"0", "1"}
            )
            values[fields[0]] = fields[1]
        _require(values.get("populated") == "0")
        _require(
            broker._directory_identity(before)
            == broker._directory_identity(os.fstat(fd))
            == broker._directory_identity(directory.lstat())
        )
        return {"path": path, "status": "EMPTY"}
    finally:
        os.close(fd)


def _stopped() -> dict:
    pid1 = response._process_cgroup(1)
    _require(
        pid1 == "/init.scope"
        or re.fullmatch(r"/docker/[0-9a-f]{64}/init\.scope", pid1) is not None
    )
    prefix = pid1.removesuffix("/init.scope")
    result = {}
    for unit, (user, group) in _UNITS.items():
        raw = response._command(
            [
                "/usr/bin/systemctl",
                "--system",
                "--no-pager",
                "--no-ask-password",
                "show",
                "--property=" + ",".join(_PROPERTIES),
                unit,
            ],
            timeout=3,
        )
        state = {}
        for line in raw.decode("ascii").splitlines():
            key, separator, value = line.partition("=")
            _require(bool(separator) and key not in state)
            state[key] = value
        path = prefix + "/system.slice/" + unit
        _require(
            set(state) == set(_PROPERTIES)
            and state["Id"] == unit
            and state["LoadState"] == "loaded"
            and state["User"] == user
            and state["Group"] == group
            and state["KillMode"] == "control-group"
            and state["Delegate"] == "no"
            and state["Restart"] == "no"
            and state["ActiveState"] == "inactive"
            and state["SubState"] == "dead"
            and state["MainPID"] == state["ControlPID"] == "0"
            and state["ControlGroup"] in {"", path}
        )
        result[unit] = {"unit": state, "cgroup": _empty_cgroup(path)}
    _require(response._process_cgroup(1) == pid1)
    return result


def require_native_measurement_unused() -> dict:
    """Read-only pre-reset guard, not permission to reset or re-use a fixture."""
    try:
        _require_root()
        with ExitStack() as stack:
            held = []
            stack.callback(custody._close, held)
            identities = response._identities()
            stopped = _stopped()
            etc = custody._root_directory(_CREDENTIAL.parent, held)
            custody._absent(etc, _CREDENTIAL.name)
            control = _optional_control(identities, held)
            if control is not None:
                _unused_control(control)
            custody._recheck(held)
            report = {
                "status": "MEASUREMENT_PATHS_ABSENT",
                "units": stopped,
                "reset_authorized": False,
                "activation_performed": False,
            }
        return report
    except BaseException as exc:
        raise NativeMeasurementProvisioningError(
            "measurement state is not unused; do not reset"
        ) from exc


def _boot_id() -> str:
    fd = os.open(_BOOT, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    try:
        before = os.fstat(fd)
        _require(stat.S_ISREG(before.st_mode) and before.st_uid == _ROOT_UID)
        raw = os.read(fd, 65)
        _require(
            broker._file_identity(before)
            == broker._file_identity(os.fstat(fd))
            == broker._file_identity(_BOOT.lstat())
        )
    finally:
        os.close(fd)
    _require(
        re.fullmatch(rb"[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}\n?", raw)
        is not None
    )
    return raw.decode("ascii").rstrip("\n")


def _actual_inputs(
    bound: dict, identities: tuple, expected_sources: dict, held: list
) -> tuple:
    binding = bound["binding"]
    _require(
        set(expected_sources) == _SOURCE_NAMES
        and binding["source_pins"] == expected_sources
    )
    etc = custody._root_directory(_CREDENTIAL.parent, held)
    documents = {}
    for path in (_WORKER, _RUNTIME, _GRANT):
        _require(path.parent == _CREDENTIAL.parent)
        entry = custody._hold_file(
            etc, path.name, _ROOT_UID, _ROOT_GID, 0o400, 4096, held
        )
        documents[path] = entry
    worker = startup._binding(documents[_WORKER].raw)
    runtime = broker._parse_canonical_document(
        documents[_RUNTIME].raw, "runtime binding"
    )
    _require(
        set(runtime) == {"schema", "runtime_digest", "runtime_profile_digest"}
        and runtime["schema"] == "aragorn/runtime-action-runtime-binding/v2"
        and runtime["runtime_digest"]
        == worker.runtime_digest
        == binding["runtime_digest"]
        and runtime["runtime_profile_digest"] == binding["runtime_profile_digest"]
    )
    grant = parse_runtime_capability_grant(documents[_GRANT].raw, int(time.time()))
    _require(
        grant == bound["grant"]
        and canonical_digest(grant) == binding["grant_digest"]
        and worker.active_skill_digest == binding["active_skill_digest"]
        and worker.policy_digest == binding["policy_digest"]
        and worker.policy_version == grant["policy_version"]
    )
    for key in (
        "runtime_digest",
        "runtime_profile_digest",
        "policy_digest",
        "active_skill_digest",
        "sensor_digest",
        "operation_digest",
    ):
        _require(grant[key] == binding[key])
    modules = custody._root_directory(_SOURCES, held)
    for name, pin in sorted(expected_sources.items()):
        entry = custody._hold_file(
            modules, name, _ROOT_UID, _ROOT_GID, 0o644, _MAX_BLOB, held
        )
        _require(_digest(entry.raw) == pin)
    _require(_boot_id() == binding["boot_id"])
    return etc, worker, documents[_GRANT].raw


def _protected_inputs(
    bound: dict, identities: tuple, control_fd: int, held: list
) -> custody._Held:
    _require(
        _CONTROL == _RUNTIME_ROOT / "control"
        and _PROTECTED == _RUNTIME_ROOT / "protected"
    )
    policy_file = custody._hold_file(
        control_fd,
        "policy.json",
        identities[0],
        identities[2],
        0o400,
        broker._MAX_CONTROL_BYTES,
        held,
    )
    policy, _ = decision._policy(
        broker._parse_canonical_document(policy_file.raw, "measurement policy")
    )
    binding, grant, path = bound["binding"], bound["grant"], bound["path_descriptor"]
    _require(
        canonical_digest(policy) == binding["policy_digest"]
        and policy["version"] == grant["policy_version"]
        and policy["sensor_digest"] == binding["sensor_digest"]
    )
    runtime_fd = custody._root_directory(_RUNTIME_ROOT, held)
    protected = _held_directory(
        runtime_fd, _PROTECTED.name, identities[0], identities[2], 0o710, held
    )
    metadata = os.fstat(protected.fd)
    actual = {
        "schema": "aragorn/runtime-protected-path/v1",
        "root_device": metadata.st_dev,
        "root_inode": metadata.st_ino,
        "target_name": path["target_name"],
    }
    _require(actual == path and canonical_digest(actual) == binding["path_digest"])
    _require(re.fullmatch(broker._TARGET_NAME, path["target_name"]) is not None)
    custody._absent(protected.fd, path["target_name"])
    return protected


def _readback(held: list) -> None:
    for entry in held:
        if not entry.directory and entry.raw is not None:
            os.lseek(entry.fd, 0, os.SEEK_SET)
            _require(os.read(entry.fd, len(entry.raw) + 1) == entry.raw)
    custody._recheck(held)


def _create_blob(parent: int, name: str, raw: bytes, held: list) -> custody._Held:
    fd = os.open(
        name,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
        0o600,
        dir_fd=parent,
    )
    try:
        broker.write_all(fd, raw)
        os.fchmod(fd, 0o444)
        os.fsync(fd)
    finally:
        os.close(fd)
    entry = custody._hold_file(
        parent, name, _ROOT_UID, _ROOT_GID, 0o444, len(raw), held
    )
    _require(entry.raw == raw)
    os.fsync(parent)
    return entry


def _audit(entries: list, inventory: dict[int, set[str]], uid: int, gid: int) -> None:
    for entry in entries:
        metadata = os.fstat(entry.fd)
        _require(
            metadata.st_uid == uid
            and metadata.st_gid == gid
            and stat.S_IMODE(metadata.st_mode) == (0o700 if entry.directory else 0o444)
        )
        if entry.directory:
            _require(
                stat.S_ISDIR(metadata.st_mode)
                and set(os.listdir(entry.fd)) == inventory[entry.fd]
            )
        else:
            _require(
                stat.S_ISREG(metadata.st_mode)
                and metadata.st_nlink == 1
                and metadata.st_size == len(entry.raw)
            )
            os.lseek(entry.fd, 0, os.SEEK_SET)
            _require(os.read(entry.fd, len(entry.raw) + 1) == entry.raw)
        os.fsync(entry.fd)
    custody._recheck(entries)


def provision_runtime_native_measurement(
    *,
    prepared_raw: bytes,
    expected_prepared_digest: str,
    expected_binding_digest: str,
    expected_broker_source_pins: dict[str, str],
    source_cas: CAS,
) -> dict:
    """Install one validated binding/input closure; publish root authority last."""
    try:
        _require_root()
        bound = validate_prepared_native_measurement_inputs(
            prepared_raw=prepared_raw,
            expected_prepared_digest=expected_prepared_digest,
            expected_binding_digest=expected_binding_digest,
            expected_broker_source_pins=expected_broker_source_pins,
            source_cas=source_cas,
        )
        input_blobs = dict(bound["input_blobs"])
        source_root = source_cas.root.resolve(strict=True)
        _require(
            not source_root.is_relative_to(_STORE)
            and not _STORE.is_relative_to(source_root)
        )
        with ExitStack() as stack:
            stack.enter_context(response._activation_guard())
            held = []
            stack.callback(custody._close, held)
            identities = response._identities()
            stopped = _stopped()
            etc, worker, grant_raw = _actual_inputs(
                bound, identities, expected_broker_source_pins, held
            )
            custody._absent(etc, _CREDENTIAL.name)
            config = response._broker_config(identities, worker)
            _require(config.control_root == _CONTROL)
            control = stack.enter_context(response._broker_guard(config))
            # Retain a distinct descriptor so the directory identity participates
            # in the same named/held readback as all input and new output files.
            control_copy = os.dup(control)
            control_entry = custody._Held(
                None,
                _CONTROL,
                control_copy,
                broker._directory_identity(os.fstat(control_copy)),
                True,
            )
            held.append(control_entry)
            _require(
                os.fstat(control_copy).st_gid == identities[2]
                and stat.S_IMODE(os.fstat(control_copy).st_mode) == 0o710
            )
            _unused_control(control)
            protected = _protected_inputs(bound, identities, control, held)
            custody._recheck(held)
            _stopped()
            for pin, raw in input_blobs.items():
                _require(
                    type(raw) is bytes
                    and 0 < len(raw) <= _MAX_BLOB
                    and _digest(raw) == pin
                    and source_cas.read(pin, max_bytes=_MAX_BLOB) == raw
                )
            start = len(held)
            root = custody._mkdir(control, _STORE.name, held)
            blobs = custody._mkdir(root.fd, "blobs", held)
            sha = custody._mkdir(blobs.fd, "sha256", held)
            inventory = {root.fd: {"blobs"}, blobs.fd: {"sha256"}, sha.fd: set()}
            prefixes = {}
            for pin, raw in sorted(input_blobs.items()):
                prefix, name = pin[7:9], pin[9:]
                if prefix not in prefixes:
                    entry = custody._mkdir(sha.fd, prefix, held)
                    prefixes[prefix] = entry.fd
                    inventory[sha.fd].add(prefix)
                    inventory[entry.fd] = set()
                _create_blob(prefixes[prefix], name, raw, held)
                inventory[prefixes[prefix]].add(name)
            entries = held[start:]
            _audit(entries, inventory, _ROOT_UID, _ROOT_GID)
            for entry in reversed(entries):
                custody._recheck([entry])
                os.fchown(entry.fd, identities[0], identities[2])
                entry.identity = custody._identity(os.fstat(entry.fd), entry.directory)
            _audit(entries, inventory, identities[0], identities[2])
            os.fsync(control)
            _readback(held)
            _stopped()
            _unused_control(control, include_store=False)
            custody._absent(protected.fd, bound["path_descriptor"]["target_name"])
            _require(_boot_id() == bound["binding"]["boot_id"])
            _require(
                parse_runtime_capability_grant(grant_raw, int(time.time()))
                == bound["grant"]
            )
            for pin, raw in input_blobs.items():
                _require(source_cas.read(pin, max_bytes=_MAX_BLOB) == raw)
            credential = custody._create_document(
                etc, _CREDENTIAL.name, bound["binding_raw"], held
            )
            _require(
                credential.raw == bound["binding_raw"]
                and _digest(credential.raw) == expected_binding_digest
            )
            _audit(entries, inventory, identities[0], identities[2])
            _readback(held)
            _stopped()
            _require(_boot_id() == bound["binding"]["boot_id"])
            _require(
                parse_runtime_capability_grant(grant_raw, int(time.time()))
                == bound["grant"]
            )
            custody._absent(protected.fd, bound["path_descriptor"]["target_name"])
            for pin, raw in input_blobs.items():
                _require(source_cas.read(pin, max_bytes=_MAX_BLOB) == raw)
            custody._recheck(held)
            os.fsync(etc)
            os.fsync(control)
            report = {
                "schema": "aragorn/native-measurement-provisioning/v1",
                "authority": "ROOT_PROVISIONED_INPUTS_ONLY_NOT_ACTIVATION_MEASUREMENT_OR_PHASE3",
                "prepared_digest": bound["prepared_digest"],
                "binding_digest": expected_binding_digest,
                "credential": str(_CREDENTIAL),
                "input_store": str(_STORE),
                "input_blobs": [
                    {"digest": pin, "bytes": len(raw)}
                    for pin, raw in sorted(input_blobs.items())
                ],
                "broker_uid": identities[0],
                "broker_gid": identities[2],
                "boot_id": bound["binding"]["boot_id"],
                "stopped_units": stopped,
                "payload_digest_expectation": bound["binding"]["payload_digest"],
                "payload_bytes_verified": False,
                "activation_performed": False,
                "measurement_collected": False,
                "run_qualified": False,
                "quantitative_metrics_eligible": False,
                "phase3_exit_eligible": False,
                "limitations": [
                    "CALLER_MUST_GUARD_OWNED_FIXTURE_BEFORE_LEGACY_SETUP_RESET",
                    "POINT_IN_TIME_ROOT_CUSTODY_NOT_HOSTILE_ROOT_ATTESTATION",
                    "NO_SERVICE_START_STOP_STATE_RESET_OR_EFFECT_RETRY",
                    "PAYLOAD_DIGEST_IS_CALLER_EXPECTATION_NOT_RETAINED_PAYLOAD_BYTES",
                    "NO_FULL_INGRESS_CLOCK_DOMAIN_ATTRIBUTION_OR_RESIDUE_QUALIFICATION",
                ],
            }
        return report
    except BaseException as exc:
        raise NativeMeasurementProvisioningError(
            "native measurement provisioning failed; preserve partial state and do not activate"
        ) from exc
