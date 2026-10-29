"""Absent-only root provisioning for the fixed private native receipt stream.

No service is stopped, started, installed or activated. Any failure may leave a
partial final store/source; existing paths are never repaired, reset or removed.
The sole root genesis source is intended for identical worker/gateway systemd
credential projections. Provisioning is not deployment, native capture or RUN.
Inherited activation/broker locks serialize cooperating provisioners, not hostile
root actions; no cross-restart owner-authorized history rollback is detected.
"""

from __future__ import annotations

import os
import secrets
import stat
import sys
from contextlib import ExitStack
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from aragorn import runtime_action_broker as broker
from aragorn import runtime_action_decision as decision
from aragorn import runtime_native_tool_receipts as receipts
from aragorn import runtime_response_service as response
from aragorn import runtime_skill_startup_service as startup
from aragorn.oci_worker_protocol import canonical_digest, canonical_json

_ROOT_UID = 0
_ROOT_GID = 0
_STORE = Path("/var/lib/aragorn-runtime-tool-receipts")
_GENESIS_SOURCE = Path("/etc/aragorn/runtime-native-tool-genesis.json")
_WORKER_BINDING = Path("/etc/aragorn/runtime-action-worker.json")
_WORKER_SOCKET = Path("/run/aragorn-runtime-action-worker/worker.sock")
_DIRECTORY_FLAGS = (
    os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC
)


class NativeToolProvisioningError(RuntimeError):
    """Refuse activation; this failure does not imply absence or rollback."""


@dataclass
class _Held:
    parent: int | None
    name: str | Path
    fd: int
    identity: tuple[int, ...]
    directory: bool
    raw: bytes | None = None


def _require(condition: bool) -> None:
    if not condition:
        raise NativeToolProvisioningError("native receipt provisioning refused")


def _require_root() -> None:
    _require(sys.platform == "linux" and os.geteuid() == 0 and os.getegid() == 0)


def _identity(metadata: os.stat_result, directory: bool) -> tuple[int, ...]:
    return (
        broker._directory_identity(metadata)
        if directory
        else broker._file_identity(metadata)
    )


def _recheck(held: list[_Held]) -> None:
    for entry in held:
        _require(
            entry.identity
            == _identity(os.fstat(entry.fd), entry.directory)
            == _identity(
                os.stat(entry.name, dir_fd=entry.parent, follow_symlinks=False),
                entry.directory,
            )
        )


def _close(held: list[_Held]) -> None:
    failure = None
    for entry in reversed(held):
        try:
            os.close(entry.fd)
        except BaseException as exc:  # noqa: BLE001 - close every held descriptor
            failure = failure or exc
    if failure is not None:
        raise NativeToolProvisioningError(
            "native receipt descriptor cleanup failed"
        ) from failure


def _root_directory(path: Path, held: list[_Held]) -> int:
    fd = broker._open_protected_directory(
        path, _ROOT_UID, "receipt provisioning parent"
    )
    try:
        metadata = os.fstat(fd)
        _require(metadata.st_gid == _ROOT_GID)
        held.append(_Held(None, path, fd, broker._directory_identity(metadata), True))
        return fd
    except BaseException:
        os.close(fd)
        raise


def _absent(parent: int, name: str) -> None:
    try:
        os.stat(name, dir_fd=parent, follow_symlinks=False)
    except FileNotFoundError:
        return
    raise NativeToolProvisioningError("native receipt destination already exists")


def _hold_file(
    parent: int, name: str, uid: int, gid: int, mode: int, limit: int, held: list[_Held]
) -> _Held:
    fd = os.open(
        name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=parent
    )
    try:
        metadata = os.fstat(fd)
        _require(
            stat.S_ISREG(metadata.st_mode)
            and stat.S_IMODE(metadata.st_mode) == mode
            and metadata.st_uid == uid
            and metadata.st_gid == gid
            and metadata.st_nlink == 1
            and 0 <= metadata.st_size <= limit
        )
        raw = bytearray()
        while chunk := os.read(fd, min(8192, limit + 1 - len(raw))):
            raw.extend(chunk)
            _require(len(raw) <= limit)
        _require(len(raw) == metadata.st_size)
        entry = _Held(
            parent, name, fd, broker._file_identity(metadata), False, bytes(raw)
        )
        _recheck([entry])
        held.append(entry)
        return entry
    except BaseException:
        os.close(fd)
        raise


def _mkdir(parent: int, name: str, held: list[_Held]) -> _Held:
    # mkdir itself is the no-replace boundary. Never accept even an empty path.
    os.mkdir(name, mode=0o700, dir_fd=parent)
    fd = os.open(name, _DIRECTORY_FLAGS, dir_fd=parent)
    try:
        os.fchmod(fd, 0o700)
        metadata = os.fstat(fd)
        _require(
            stat.S_ISDIR(metadata.st_mode)
            and metadata.st_uid == _ROOT_UID
            and metadata.st_gid == _ROOT_GID
            and metadata.st_nlink > 0
            and stat.S_IMODE(metadata.st_mode) == 0o700
        )
        entry = _Held(parent, name, fd, broker._directory_identity(metadata), True)
        _recheck([entry])
        held.append(entry)
        os.fsync(fd)
        os.fsync(parent)
        return entry
    except BaseException:
        if not any(entry.fd == fd for entry in held):
            os.close(fd)
        raise


def _create_document(parent: int, name: str, raw: bytes, held: list[_Held]) -> _Held:
    # The frozen helper uses a no-replace hard link, never rename/replace. Final
    # publication is retained on indeterminate failure, including cleanup failure.
    _require(broker._atomic_create(parent, parent, name, raw) is True)
    entry = _hold_file(parent, name, _ROOT_UID, _ROOT_GID, 0o400, len(raw), held)
    _require(entry.raw == raw)
    os.fsync(entry.fd)
    os.fsync(parent)
    return entry


def _create_lock(parent: int, held: list[_Held]) -> _Held:
    # Only this fixed zero-byte lock differs from the immutable document mode.
    fd = os.open(
        "receipt.lock",
        os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
        0o600,
        dir_fd=parent,
    )
    try:
        os.fchmod(fd, 0o600)
        os.fsync(fd)
        os.fsync(parent)
    finally:
        os.close(fd)
    return _hold_file(parent, "receipt.lock", _ROOT_UID, _ROOT_GID, 0o600, 0, held)


def _audit_store(
    entries: list[_Held], genesis_raw: bytes, state_raw: bytes, uid: int, gid: int
) -> None:
    _require(len(entries) == 7)
    root, cas, blobs, sha, genesis, state, lock = entries
    for entry in entries:
        metadata = os.fstat(entry.fd)
        mode = 0o700 if entry.directory else (0o600 if entry is lock else 0o400)
        _require(
            metadata.st_uid == uid
            and metadata.st_gid == gid
            and stat.S_IMODE(metadata.st_mode) == mode
        )
        _require(
            (stat.S_ISDIR(metadata.st_mode) and metadata.st_nlink > 0)
            if entry.directory
            else (stat.S_ISREG(metadata.st_mode) and metadata.st_nlink == 1)
        )
        if not entry.directory:
            os.lseek(entry.fd, 0, os.SEEK_SET)
            expected = (
                genesis_raw
                if entry is genesis
                else state_raw
                if entry is state
                else b""
            )
            _require(
                os.fstat(entry.fd).st_size == len(expected)
                and os.read(entry.fd, len(expected) + 1) == expected
            )
        os.fsync(entry.fd)
    for entry, expected in (
        (root, {"genesis.json", "state.json", "receipt.lock", "cas"}),
        (cas, {"blobs"}),
        (blobs, {"sha256"}),
        (sha, set()),
    ):
        receipts._inventory(entry.fd, expected)
    _recheck(entries)


def _stopped() -> None:
    for unit in response._UNITS:
        state = response._unit_state(unit)
        _require(
            state["ActiveState"] == "inactive"
            and state["SubState"] == "dead"
            and state["MainPID"] == state["ControlPID"] == "0"
        )
        expected = response._service_cgroup(unit)
        _require(state["ControlGroup"] in {"", expected})
        # Inactive units may clear ControlGroup. Inspect the independently fixed
        # expected cgroup, not a caller-supplied path or invented observed field.
        response._cgroup_empty(unit, {"ControlGroup": expected})
    try:
        os.lstat(_WORKER_SOCKET)
    except FileNotFoundError:
        return
    raise NativeToolProvisioningError("native receipt worker endpoint is present")


def provision_runtime_native_tool_receipts() -> dict[str, Any]:
    """Provision only the fixed absent store and common root genesis source.

    All returned success follows lock/descriptor cleanup. Partial final paths
    remain on failure and every later call refuses them; there is no retry/reset
    mode. A separate authorized successor must validate the same genesis in both
    read-only credentials before activation. No application ACK is implied.
    """
    try:
        _require_root()
        with ExitStack() as stack:
            stack.enter_context(response._activation_guard())
            held: list[_Held] = []
            stack.callback(_close, held)
            identities = response._identities()
            worker_uid, worker_gid = identities[1:3]
            receipts._uint(worker_uid, 2**32 - 1, 1)
            receipts._uint(worker_gid, 2**32 - 1, 1)
            _stopped()
            var_fd = _root_directory(_STORE.parent, held)
            etc_fd = _root_directory(_GENESIS_SOURCE.parent, held)
            _require(_WORKER_BINDING.parent == _GENESIS_SOURCE.parent)
            _absent(var_fd, _STORE.name)
            _absent(etc_fd, _GENESIS_SOURCE.name)
            binding_file = _hold_file(
                etc_fd, _WORKER_BINDING.name, _ROOT_UID, _ROOT_GID, 0o400, 4096, held
            )
            binding = startup._binding(binding_file.raw)
            receipts._uint(binding.policy_version, 2**53 - 1, 1)
            config = response._broker_config(identities, binding)
            control_fd = stack.enter_context(response._broker_guard(config))
            policy_file = _hold_file(
                control_fd,
                config.policy_path.name,
                identities[0],
                worker_gid,
                0o400,
                broker._MAX_CONTROL_BYTES,
                held,
            )
            policy = broker._parse_canonical_document(
                policy_file.raw, "native receipt policy"
            )
            policy, _rules = decision._policy(policy)
            _require(
                canonical_digest(policy) == binding.policy_digest
                and policy["version"] == binding.policy_version
            )
            genesis = {
                "schema": "aragorn/native-tool-receipt-genesis/v1",
                "authority": "ROOT_PROVISIONED_WORKER_RECEIPT_STREAM_NOT_RUN_AUTHORITY",
                "stream_id": canonical_digest({"nonce": secrets.token_hex(32)}),
                "worker_uid": worker_uid,
                "worker_gid": worker_gid,
                "runtime_digest": binding.runtime_digest,
                "policy_digest": binding.policy_digest,
                "policy_version": binding.policy_version,
            }
            genesis_raw = canonical_json(genesis)
            genesis_digest = canonical_digest(genesis)
            state_raw = canonical_json(
                {
                    "schema": "aragorn/native-tool-receipt-state/v1",
                    "authority": receipts._RETAINED_AUTHORITY,
                    "genesis_digest": genesis_digest,
                    "receipts": [],
                }
            )
            _require(
                len(genesis_raw) <= 4096 and len(state_raw) <= receipts._MAX_STATE_BYTES
            )
            _recheck(held)
            _stopped()
            root = _mkdir(var_fd, _STORE.name, held)
            cas = _mkdir(root.fd, "cas", held)
            blobs = _mkdir(cas.fd, "blobs", held)
            sha = _mkdir(blobs.fd, "sha256", held)
            genesis_file = _create_document(root.fd, "genesis.json", genesis_raw, held)
            state_file = _create_document(root.fd, "state.json", state_raw, held)
            lock = _create_lock(root.fd, held)
            entries = [root, cas, blobs, sha, genesis_file, state_file, lock]
            _audit_store(entries, genesis_raw, state_raw, _ROOT_UID, _ROOT_GID)
            # Children first, store root last. Only these held, just-created
            # descriptors can change ownership; no path-based recursive chown.
            for entry in [*entries[1:], root]:
                _recheck([entry])
                os.fchown(entry.fd, worker_uid, worker_gid)
                entry.identity = _identity(os.fstat(entry.fd), entry.directory)
            _audit_store(entries, genesis_raw, state_raw, worker_uid, worker_gid)
            os.fsync(var_fd)
            _recheck(held)
            _stopped()
            # The common root authority is published only after complete store
            # handoff/readback. It never overwrites or removes an existing source.
            source = _create_document(etc_fd, _GENESIS_SOURCE.name, genesis_raw, held)
            _audit_store(entries, genesis_raw, state_raw, worker_uid, worker_gid)
            _require(source.raw == genesis_raw)
            _recheck(held)
            _stopped()
            os.fsync(var_fd)
            os.fsync(etc_fd)
            report = {
                "schema": "aragorn/native-tool-receipt-provisioning/v1",
                "authority": "ROOT_PROVISIONED_EMPTY_STREAM_ONLY_NOT_ACTIVATION_OR_RUN_AUTHORITY",
                "genesis_digest": genesis_digest,
                "genesis_source": str(_GENESIS_SOURCE),
                "store": str(_STORE),
                "worker_uid": worker_uid,
                "worker_gid": worker_gid,
                "runtime_digest": binding.runtime_digest,
                "policy_digest": binding.policy_digest,
                "policy_version": binding.policy_version,
                "receipts": 0,
                "activation_performed": False,
                "native_capture": False,
                "run_qualified": False,
                "limitations": [
                    "SEPARATE_SAME_SOURCE_WORKER_GATEWAY_RO_CREDENTIAL_PROJECTION_REQUIRED",
                    "NO_SERVICE_START_INSTALLATION_OR_AUTOMATIC_REPAIR",
                    "ONLY_GENESIS_EXTERNALLY_PINNED_NO_HOSTILE_OWNER_ROOT_ANTI_ROLLBACK",
                    "NO_HARD_STORAGE_DEADLINE_OR_NATIVE_CAPTURE_QUALIFICATION",
                ],
            }
        return report
    except BaseException as exc:
        raise NativeToolProvisioningError(
            "native receipt provisioning failed; do not activate or reset"
        ) from exc
