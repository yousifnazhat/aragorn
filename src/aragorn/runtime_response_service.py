"""Manual, root-authorized termination of one revoked runtime profile."""

from __future__ import annotations

import fcntl
import grp
import os
import pwd
import re
import signal
import stat
import subprocess
import sys
import tempfile
import time
from collections.abc import Iterator, Sequence
from contextlib import contextmanager
from pathlib import Path
from typing import Any

from . import runtime_action_broker as broker
from . import runtime_action_worker as worker
from .oci_worker_protocol import canonical_digest, canonical_json
from .runtime_action_decision import qualify_runtime_revocation_generation
from .runtime_process_profile import (
    _process_cgroup,
    _process_start_time,
    _require_process_status,
)

_UNITS = ("aragorn-agent-gateway.service", "aragorn-runtime-action-worker.service")
_NAMES = ("aragorn-agent-gateway", "aragorn-runtime")
_CONTROL_ROOT = Path("/var/lib/aragorn-runtime-action/control")
_ACTIVATION_LOCK = Path("/run/lock/aragorn-runtime-capability-activation.lock")
_WORKER_BINDING = Path("/etc/aragorn/runtime-action-worker.json")
_LIVE_WORKER_BINDING = Path(
    "/run/credentials/aragorn-runtime-action-worker.service/worker-binding"
)
_CGROUP_ROOT = Path("/sys/fs/cgroup")
_PROPERTIES = (
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
)
_MAX_BYTES = broker._MAX_CONTROL_BYTES


class RuntimeResponseError(RuntimeError):
    """The response was refused before the stop command was submitted."""


class RuntimeResponseIndeterminate(RuntimeResponseError):
    """Stopping was attempted, but complete termination was not confirmed."""


def main(argv: Sequence[str] | None = None) -> int:
    arguments = list(sys.argv[1:] if argv is None else argv)
    if len(arguments) != 2:
        print(
            "usage: aragorn-runtime-response-service EXPECTED_SKILL_DIGEST "
            "EXPECTED_REVOCATION_SNAPSHOT_DIGEST",
            file=sys.stderr,
        )
        return 64
    completed = False
    try:
        result = _run(*arguments)
        completed = True
        print(canonical_json(result).decode("ascii"))
        return 0
    except RuntimeResponseIndeterminate as exc:
        print(f"aragorn runtime response: INDETERMINATE: {exc}", file=sys.stderr)
        return 125
    except KeyboardInterrupt:
        if completed:
            print(
                "aragorn runtime response: INDETERMINATE: result delivery interrupted "
                "after termination",
                file=sys.stderr,
            )
            return 125
        return 130
    except (
        OSError,
        ValueError,
        TypeError,
        RuntimeError,
        KeyError,
        subprocess.SubprocessError,
    ) as exc:
        if completed:
            print(
                "aragorn runtime response: INDETERMINATE: termination completed "
                "but result delivery failed",
                file=sys.stderr,
            )
            return 125
        print(f"aragorn runtime response: REFUSED: {exc}", file=sys.stderr)
        return 126


def _run(expected_skill_digest: str, expected_snapshot_digest: str) -> dict[str, Any]:
    broker._require_digest(expected_skill_digest, "expected skill digest")
    broker._require_digest(expected_snapshot_digest, "expected revocation snapshot")
    if sys.platform != "linux" or os.geteuid() != 0:
        raise RuntimeResponseError("root Linux execution is required")
    stop_attempted = False
    try:
        with _activation_guard():
            identities = _identities()
            before = [_unit_state(unit) for unit in _UNITS]
            processes = [
                _process_identity(unit, state, uid, gid)
                for unit, state, (uid, gid) in zip(
                    _UNITS,
                    before,
                    ((identities[3], identities[4]), (identities[1], identities[2])),
                    strict=True,
                )
            ]
            binding = _read_bindings(identities[1])
            if binding.active_skill_digest != expected_skill_digest:
                raise RuntimeResponseError(
                    "requested digest is not the running binding"
                )
            config = _broker_config(identities, binding)
            with _broker_guard(config) as control_fd:
                accepted = _locked_revocations(
                    control_fd,
                    config,
                    binding,
                    expected_snapshot_digest,
                )
                # The activation lock serializes this fixed profile with its activator.
                # ponytail: whole-profile stop; per-capability units need a new binding.
                if _read_bindings(identities[1]) != binding:
                    raise RuntimeResponseError("worker binding changed before stop")
                for unit, state, process, (uid, gid) in zip(
                    _UNITS,
                    before,
                    processes,
                    ((identities[3], identities[4]), (identities[1], identities[2])),
                    strict=True,
                ):
                    current = _unit_state(unit)
                    if (
                        current != state
                        or _process_identity(unit, current, uid, gid) != process
                    ):
                        raise RuntimeResponseError(
                            "runtime identity changed before stop"
                        )
                if (
                    _locked_revocations(
                        control_fd,
                        config,
                        binding,
                        expected_snapshot_digest,
                    )
                    != accepted
                ):
                    raise RuntimeResponseError(
                        "revocation authority changed before stop"
                    )
                stop_attempted = True
                _stop_units()
                after = []
                for unit, state, process in zip(_UNITS, before, processes, strict=True):
                    current = _unit_state(unit)
                    if (
                        current["ActiveState"] != "inactive"
                        or current["SubState"] != "dead"
                        or current["MainPID"] != "0"
                        or current["ControlPID"] != "0"
                        or current["ControlGroup"] not in {"", state["ControlGroup"]}
                    ):
                        raise RuntimeResponseError("unit termination was not confirmed")
                    empty = _cgroup_empty(unit, state)
                    if empty["status"] == "EMPTY" and (
                        empty["device"] != process["cgroup_device"]
                        or empty["inode"] != process["cgroup_inode"]
                    ):
                        raise RuntimeResponseError(
                            "termination cgroup identity changed"
                        )
                    after.append({"unit": current, "cgroup": empty})
                result = {
                    "authority": "LOCAL_ROOT_RESPONSE_RESULT_NOT_RUN_OR_PHASE3_CONFORMANCE",
                    "status": "TERMINATED_FIXED_RUNTIME_PROFILE",
                    "expected_skill_digest": expected_skill_digest,
                    "revocation_snapshot_digest": expected_snapshot_digest,
                    "accepted_revocation": accepted,
                    "before": [
                        {"unit": unit, "process": process}
                        for unit, process in zip(before, processes, strict=True)
                    ],
                    "after": after,
                    "limitations": [
                        "MANUAL_ROOT_COMMAND_NOT_AUTOMATIC_RESPONSE_DISPATCH",
                        "FIXED_SINGLE_PROFILE_NOT_ARBITRARY_CAPABILITY_TARGETING",
                        "NO_FUTURE_START_REVOCATION_OR_INSTALLED_DIGEST_QUARANTINE",
                        "NO_PROTECTION_AGAINST_INDEPENDENT_ROOT_CONTROL",
                        "NO_RUN_PHASE3_EDR_OR_RELEASE_CONFORMANCE_AUTHORITY",
                    ],
                }
        return result
    except BaseException as exc:
        if stop_attempted:
            raise RuntimeResponseIndeterminate(
                "stop was submitted; complete termination or cleanup is unconfirmed"
            ) from exc
        raise


def _identities() -> tuple[int, int, int, int, int, int, int]:
    names = (
        "aragorn-broker",
        "aragorn-runtime",
        "aragorn-agent-gateway",
        "aragorn-sensor",
    )
    accounts = [pwd.getpwnam(name) for name in names]
    groups = [grp.getgrnam(name).gr_gid for name in names[1:]]
    if (
        len({account.pw_uid for account in accounts}) != 4
        or any(account.pw_uid <= 0 for account in accounts)
        or len(set(groups)) != 3
        or any(gid <= 0 for gid in groups)
        or any(
            account.pw_gid != gid
            for account, gid in zip(accounts[1:], groups, strict=True)
        )
    ):
        raise RuntimeResponseError("fixed service identities are unsafe")
    return (
        accounts[0].pw_uid,
        accounts[1].pw_uid,
        groups[0],
        accounts[2].pw_uid,
        groups[1],
        accounts[3].pw_uid,
        groups[2],
    )


def _read_regular(
    path: Path, expected_uid: int, modes: set[int], *, dir_fd: int | None = None
) -> bytes:
    descriptor = os.open(
        path.name if dir_fd is not None else path,
        os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC,
        dir_fd=dir_fd,
    )
    try:
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_uid != expected_uid
            or before.st_nlink != 1
            or stat.S_IMODE(before.st_mode) not in modes
            or not 0 < before.st_size <= _MAX_BYTES
        ):
            raise RuntimeResponseError(f"unsafe response authority file: {path}")
        raw = os.read(descriptor, _MAX_BYTES + 1)
        after = os.fstat(descriptor)
        named = os.stat(
            path.name if dir_fd is not None else path,
            dir_fd=dir_fd,
            follow_symlinks=False,
        )
        if (
            len(raw) != before.st_size
            or broker._file_identity(before) != broker._file_identity(after)
            or broker._file_identity(after) != broker._file_identity(named)
        ):
            raise RuntimeResponseError(f"response authority file changed: {path}")
        return raw
    finally:
        os.close(descriptor)


def _read_bindings(worker_uid: int) -> worker.RuntimeActionWorkerBinding:
    bindings = []
    for path in (_WORKER_BINDING, _LIVE_WORKER_BINDING):
        if path == _LIVE_WORKER_BINDING:
            broker._require_protected_ancestry(path.parent.parent, 0)
            parent = os.lstat(path.parent)
            if (
                not stat.S_ISDIR(parent.st_mode)
                or parent.st_uid not in {0, worker_uid}
                or stat.S_IMODE(parent.st_mode) & 0o022
            ):
                raise RuntimeResponseError(
                    "loaded worker credential directory is unsafe"
                )
        else:
            broker._require_protected_ancestry(path.parent, 0)
        metadata = os.lstat(path)
        allowed_owner = metadata.st_uid == 0 or (
            path == _LIVE_WORKER_BINDING and metadata.st_uid == worker_uid
        )
        if not allowed_owner or (metadata.st_uid == 0 and metadata.st_gid != 0):
            raise RuntimeResponseError("worker credential owner is unsafe")
        if (
            path == _LIVE_WORKER_BINDING
            and worker_uid in {parent.st_uid, metadata.st_uid}
            and not os.statvfs(path.parent).f_flag & os.ST_RDONLY
        ):
            raise RuntimeResponseError(
                "service-owned loaded credentials are not read-only"
            )
        raw = _read_regular(
            path, metadata.st_uid, {0o400, 0o440} if metadata.st_uid == 0 else {0o400}
        )
        document = broker._exact(
            broker._parse_canonical_document(raw, "worker binding"),
            worker._BINDING_FIELDS,
            "worker binding",
        )
        if document["schema"] != worker._BINDING_SCHEMA:
            raise RuntimeResponseError("worker binding schema is invalid")
        bindings.append(
            worker.RuntimeActionWorkerBinding(
                runtime_digest=worker._worker_digest(
                    document["runtime_digest"], "runtime"
                ),
                active_skill_digest=worker._worker_digest(
                    document["active_skill_digest"], "skill"
                ),
                policy_digest=worker._worker_digest(
                    document["policy_digest"], "policy"
                ),
                policy_version=worker._positive_uint(
                    document["policy_version"], "policy version"
                ),
            )
        )
    if bindings[0] != bindings[1]:
        raise RuntimeResponseError("provisioned and running worker bindings differ")
    return bindings[0]


def _broker_config(
    identities: tuple[int, ...], binding: worker.RuntimeActionWorkerBinding
) -> broker.RuntimeActionBrokerConfig:
    root = _CONTROL_ROOT
    return broker.RuntimeActionBrokerConfig(
        socket_path=root / "broker.sock",
        instance_lock_path=root / "broker.instance.lock",
        lock_path=root / "broker.lock",
        control_root=root,
        protected_root=root.parent / "protected",
        staging_root=root.parent / "staging",
        policy_path=root / "policy.json",
        revocations_path=root / "revocations.json",
        health_path=root / "health.json",
        observation_path=root / "observation.json",
        state_path=root / "state.json",
        expected_broker_uid=identities[0],
        expected_peer_uid=identities[5],
        expected_peer_gid=identities[6],
        expected_runtime_digest=binding.runtime_digest,
        expected_runtime_uid=identities[1],
        expected_runtime_gid=identities[2],
    )


@contextmanager
def _activation_guard() -> Iterator[None]:
    parent = os.lstat(_ACTIVATION_LOCK.parent)
    broker._require_protected_ancestry(_ACTIVATION_LOCK.parent.parent, 0)
    if (
        not stat.S_ISDIR(parent.st_mode)
        or parent.st_uid != 0
        or (stat.S_IMODE(parent.st_mode) & 0o022 and not parent.st_mode & stat.S_ISVTX)
    ):
        raise RuntimeResponseError("activation lock directory is unsafe")
    descriptor = os.open(
        _ACTIVATION_LOCK,
        os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC,
        0o600,
    )
    try:
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_uid != 0
            or before.st_nlink != 1
            or stat.S_IMODE(before.st_mode) & 0o022
        ):
            raise RuntimeResponseError("activation lock is unsafe")
        fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        if broker._file_identity(before) != broker._file_identity(
            os.lstat(_ACTIVATION_LOCK)
        ):
            raise RuntimeResponseError("activation lock identity changed")
        yield
    finally:
        os.close(descriptor)


@contextmanager
def _broker_guard(config: broker.RuntimeActionBrokerConfig) -> Iterator[int]:
    root_fd = broker._open_protected_directory(
        config.control_root, config.expected_broker_uid, "runtime response control root"
    )
    lock_fd = -1
    locked = False
    try:
        # Preflight avoids the legacy lock helper's blocking FIFO open.
        lock = os.stat(config.lock_path.name, dir_fd=root_fd, follow_symlinks=False)
        if not stat.S_ISREG(lock.st_mode):
            raise RuntimeResponseError("broker lock is not regular")
        lock_fd = broker._open_lock_file(root_fd, config)
        broker._acquire_lock(lock_fd, time.monotonic() + 0.5)
        locked = True
        yield root_fd
    finally:
        if broker._release_lock_and_close(lock_fd, locked, root_fd) is not None:
            raise RuntimeResponseError("response broker lock cleanup failed")


def _locked_revocations(
    control_fd: int,
    config: broker.RuntimeActionBrokerConfig,
    binding: worker.RuntimeActionWorkerBinding,
    expected_digest: str,
) -> dict[str, Any]:
    def read(path: Path) -> dict[str, Any]:
        return broker._parse_canonical_document(
            _read_regular(path, config.expected_broker_uid, {0o400}, dir_fd=control_fd),
            "runtime response control",
        )

    policy = read(config.policy_path)
    state = broker._state(read(config.state_path))
    snapshot = read(config.revocations_path)
    generation = qualify_runtime_revocation_generation(
        policy,
        snapshot,
        now_unix=int(time.time()),
        minimum_revocation_generation=state["minimum_revocation_generation"],
    )
    if (
        generation is None
        or generation != state["minimum_revocation_generation"]
        or canonical_digest(snapshot) != expected_digest
        or binding.active_skill_digest not in snapshot["skill_digests"]
        or canonical_digest(policy) != binding.policy_digest
        or policy["version"] != binding.policy_version
    ):
        raise RuntimeResponseError(
            "revocation snapshot is stale, unbound, or does not revoke this skill"
        )
    return {
        "generation": generation,
        "minimum_revocation_generation": state["minimum_revocation_generation"],
        "policy_digest": canonical_digest(policy),
        "worker_runtime_digest": binding.runtime_digest,
        "expires_at_unix": snapshot["expires_at_unix"],
    }


def _command(argv: list[str], *, timeout: float) -> bytes:
    with tempfile.TemporaryFile() as stdout, tempfile.TemporaryFile() as stderr:
        process = subprocess.Popen(
            argv,
            stdin=subprocess.DEVNULL,
            stdout=stdout,
            stderr=stderr,
            start_new_session=True,
            env={"PATH": "/usr/bin:/bin", "LC_ALL": "C"},
        )
        try:
            status = process.wait(timeout=timeout)
        except BaseException:
            for sig in (signal.SIGTERM, signal.SIGKILL):
                try:
                    os.killpg(process.pid, sig)
                except ProcessLookupError:
                    pass
                try:
                    process.wait(timeout=1)
                    break
                except subprocess.TimeoutExpired:
                    continue
            raise
        stdout.seek(0)
        raw = stdout.read(_MAX_BYTES + 1)
        stderr.seek(0)
        error = stderr.read(_MAX_BYTES + 1)
        if status != 0 or error or len(raw) > _MAX_BYTES:
            raise RuntimeResponseError(
                "fixed systemd command failed or returned unsafe output"
            )
        return raw


def _unit_state(unit: str) -> dict[str, str]:
    if unit not in _UNITS:
        raise RuntimeResponseError("unsupported response unit")
    raw = _command(
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
    document = {}
    for line in raw.decode("ascii").splitlines():
        key, separator, value = line.partition("=")
        if not separator or key in document:
            raise RuntimeResponseError("systemd properties are malformed")
        document[key] = value
    name = _NAMES[_UNITS.index(unit)]
    if (
        set(document) != set(_PROPERTIES)
        or document["Id"] != unit
        or document["LoadState"] != "loaded"
        or document["User"] != name
        or document["Group"] != name
        or document["KillMode"] != "control-group"
        or document["Delegate"] != "no"
        or document["Restart"] != "no"
        or document["SendSIGKILL"] != "yes"
    ):
        raise RuntimeResponseError("fixed unit security properties changed")
    return document


def _process_identity(
    unit: str, state: dict[str, str], uid: int, gid: int
) -> dict[str, Any]:
    pid = int(state["MainPID"])
    cgroup = f"/system.slice/{unit}"
    if (
        str(pid) != state["MainPID"]
        or pid <= 0
        or state["ActiveState"] != "active"
        or state["SubState"] != "running"
        or state["ControlGroup"] != cgroup
        or state["ControlPID"] != "0"
        or re.fullmatch(r"[0-9a-f]{32}", state["InvocationID"]) is None
    ):
        raise RuntimeResponseError("fixed runtime process is not active")
    started = _process_start_time(pid)
    _require_process_status(pid, uid, gid)
    if _process_cgroup(pid) != cgroup or _process_start_time(pid) != started:
        raise RuntimeResponseError("kernel runtime identity changed")
    directory = _CGROUP_ROOT / cgroup.removeprefix("/")
    metadata = os.lstat(directory)
    if not stat.S_ISDIR(metadata.st_mode) or metadata.st_uid != 0:
        raise RuntimeResponseError("runtime cgroup is unsafe")
    return {
        "pid": pid,
        "start_time_ticks": started,
        "uid": uid,
        "gid": gid,
        "cgroup": cgroup,
        "cgroup_device": metadata.st_dev,
        "cgroup_inode": metadata.st_ino,
    }


def _stop_units() -> None:
    _command(
        [
            "/usr/bin/systemctl",
            "--system",
            "--no-pager",
            "--no-ask-password",
            "stop",
            *_UNITS,
        ],
        timeout=15,
    )


def _cgroup_empty(unit: str, before: dict[str, str]) -> dict[str, Any]:
    cgroup = f"/system.slice/{unit}"
    if unit not in _UNITS or before["ControlGroup"] != cgroup:
        raise RuntimeResponseError("unbound termination cgroup")
    path = _CGROUP_ROOT / cgroup.removeprefix("/")
    try:
        descriptor = os.open(
            path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
        )
    except FileNotFoundError:
        return {"path": cgroup, "status": "ABSENT"}
    try:
        metadata = os.fstat(descriptor)
        if metadata.st_uid != 0:
            raise RuntimeResponseError("termination cgroup owner changed")
        events_fd = os.open(
            "cgroup.events",
            os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC,
            dir_fd=descriptor,
        )
        try:
            raw = os.read(events_fd, 4097)
        finally:
            os.close(events_fd)
        if len(raw) > 4096:
            raise RuntimeResponseError("cgroup events exceed the byte limit")
        events = {}
        for line in raw.decode("ascii").splitlines():
            fields = line.split()
            if len(fields) != 2 or fields[0] in events or fields[1] not in {"0", "1"}:
                raise RuntimeResponseError("cgroup events are malformed")
            events[fields[0]] = fields[1]
        if events.get("populated") != "0":
            raise RuntimeResponseError(
                "runtime cgroup still contains capability processes"
            )
        return {
            "path": cgroup,
            "status": "EMPTY",
            "events": events,
            "device": metadata.st_dev,
            "inode": metadata.st_ino,
        }
    finally:
        os.close(descriptor)


if __name__ == "__main__":
    raise SystemExit(main())
