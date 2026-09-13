"""Bounded worker-owned native tool receipts; no transport or effect authority.

The caller must obtain expected_genesis_digest from a root-provisioned binding.
This module never provisions, resets, rotates, or repairs a store. CAS supplies
bounded immutable blobs, not sequence or acknowledgement semantics. The broker's
atomic publisher supplies file/directory syncing and readback; a private lock and
this fixed receipt chain supply ordering. Full bounded replay occurs per write;
neither a hard storage deadline nor runtime overhead is qualified.

Only genesis is externally pinned. The remembered state digest detects changes
during this object lifetime, not a coherent owner-written history-prefix rollback
with matching CAS removal across restart. Hostile owner/root replacement is
outside this private worker-store boundary; no external anti-rollback is claimed.
"""

from __future__ import annotations

import os
import re
import stat
import time
from collections.abc import Iterator
from contextlib import contextmanager
from io import BytesIO
from pathlib import Path
from typing import Any

from aragorn import runtime_action_broker as broker
from aragorn.cas import CAS
from aragorn.oci_worker_protocol import canonical_digest, canonical_json

_MAX_CALLS = 512
_MAX_EVENT_BYTES = 4096
_MAX_STATE_BYTES = 128 * 1024
_MAX_REPORTED_BYTES = 16 * 1024 * 1024
_AUTHORITY = "AUTHENTICATED_GATEWAY_REPORT_ONLY_NOT_CAUSATION_EFFECT_OR_RUN_AUTHORITY"
_RETAINED_AUTHORITY = "WORKER_LOCAL_DURABLE_RECEIPT_ONLY_NOT_EFFECT_OR_RUN_AUTHORITY"
_CORRELATION = {"session_id", "run_id", "session_key_digest", "tool_call_digest"}
_ATTEMPT_FIELDS = {
    "schema",
    "authority",
    "tool_name",
    *_CORRELATION,
    "params_digest",
    "params_bytes",
    "worker_request_digest",
}
_TERMINAL_FIELDS = {
    "schema",
    "authority",
    "tool_name",
    *_CORRELATION,
    "attempt_digest",
    "outcome",
    "result_digest",
    "result_bytes",
    "error_code",
}
_GENESIS_FIELDS = {
    "schema",
    "authority",
    "stream_id",
    "worker_uid",
    "worker_gid",
    "runtime_digest",
    "policy_digest",
    "policy_version",
}


class NativeToolReceiptRejected(ValueError):
    """A request is invalid, conflicting, replayed, or outside the fixed capacity."""


class NativeToolReceiptFatal(RuntimeError):
    """Stop the worker; never catch this as an ordinary per-connection refusal."""


def _require(condition: bool) -> None:
    if not condition:
        raise NativeToolReceiptRejected("native tool receipt contract refused")


def _trust(condition: bool) -> None:
    if not condition:
        raise NativeToolReceiptFatal("native tool receipt custody changed")


def _digest(value: Any) -> None:
    _require(
        type(value) is str and re.fullmatch(r"sha256:[0-9a-f]{64}", value) is not None
    )


def _uint(value: Any, maximum: int, minimum: int = 0) -> None:
    _require(type(value) is int and minimum <= value <= maximum)


def _exact(value: Any, fields: set[str]) -> None:
    _require(type(value) is dict and set(value) == fields)


def _inventory(fd: int, expected: set[str]) -> None:
    found = set()
    with os.scandir(fd) as entries:
        for offset, entry in enumerate(entries):
            _trust(offset < len(expected))
            found.add(entry.name)
    _trust(found == expected)


def _event(value: Any, *, terminal: bool) -> dict[str, Any]:
    _exact(value, _TERMINAL_FIELDS if terminal else _ATTEMPT_FIELDS)
    _require(
        value["schema"]
        == f"aragorn/native-tool-{'terminal' if terminal else 'attempt'}/v1"
    )
    _require(value["authority"] == _AUTHORITY)
    _require(value["tool_name"] in {"read", "aragorn_runtime_create"})
    for name in ("session_id", "run_id"):
        _require(
            type(value[name]) is str
            and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,255}", value[name])
            is not None
        )
    for name in ("session_key_digest", "tool_call_digest"):
        _digest(value[name])
    if not terminal:
        _digest(value["params_digest"])
        _uint(value["params_bytes"], _MAX_REPORTED_BYTES)
        if value["tool_name"] == "read":
            _require(value["worker_request_digest"] is None)
        else:
            _digest(value["worker_request_digest"])
    else:
        _digest(value["attempt_digest"])
        _require(value["outcome"] in {"RETURNED", "RAISED", "CANCELLED"})
        if value["outcome"] == "RETURNED":
            _digest(value["result_digest"])
            _uint(value["result_bytes"], _MAX_REPORTED_BYTES)
            _require(value["error_code"] is None)
        else:
            _require(value["result_digest"] is None and value["result_bytes"] is None)
            _require(
                value["error_code"]
                == ("ABORTED" if value["outcome"] == "CANCELLED" else "NATIVE_ERROR")
            )
    raw = canonical_json(value)
    _require(len(raw) <= _MAX_EVENT_BYTES)
    # Detach caller-owned dictionaries before any retention operation.
    return broker._parse_canonical_document(raw, "native tool receipt")


def _request(value: Any, *, terminal: bool) -> dict[str, Any]:
    try:
        return _event(value, terminal=terminal)
    except Exception as exc:
        raise NativeToolReceiptRejected("native tool receipt request refused") from exc


def _call_key(event: dict[str, Any], genesis_digest: str) -> str:
    return canonical_digest(
        {
            "genesis_digest": genesis_digest,
            **{name: event[name] for name in sorted(_CORRELATION)},
        }
    )


def _joins_terminal(event: dict[str, Any], attempt: dict[str, Any]) -> None:
    _require(event["attempt_digest"] == canonical_digest(attempt))
    _require(
        all(
            event[name] == attempt["event"][name]
            for name in {*_CORRELATION, "tool_name"}
        )
    )


class NativeToolReceiptStore:
    """One initialized worker lifetime, one in-flight native call, fixed capacity.

    # ponytail: serial admission is an explicit fail-closed first-slice ceiling;
    # future native integration must serialize read/create until terminal ACK.
    Root-provisioned genesis/state/lock/CAS directories must already exist.
    Startup with an unmatched attempt or orphaned blob refuses, never repairs.
    """

    def __init__(self, root: Path, expected_genesis_digest: str) -> None:
        self._halted = False
        self._state_digest: str | None = None
        self._root_identity: tuple[int, ...] | None = None
        self._cas_identity: tuple[int, ...] | None = None
        self._lock_identity: tuple[int, ...] | None = None
        self.root = root
        self.genesis_digest = expected_genesis_digest
        try:
            _require(isinstance(root, Path) and root.is_absolute())
            _digest(expected_genesis_digest)
            _require(os.geteuid() > 0)
            with self._locked() as fd:
                state, receipts = self._load(fd)
                _require(len(receipts) % 2 == 0)
                self._state_digest = canonical_digest(state)
        except BaseException as exc:
            self._halted = True
            raise NativeToolReceiptFatal("native tool receipt startup refused") from exc

    def _directory(self, fd: int) -> tuple[int, ...]:
        info = os.fstat(fd)
        _trust(stat.S_ISDIR(info.st_mode) and stat.S_IMODE(info.st_mode) == 0o700)
        _trust(
            info.st_uid == os.geteuid()
            and info.st_gid == os.getegid()
            and info.st_nlink > 0
        )
        return broker._directory_identity(info)

    def _open_file(self, fd: int, name: str, mode: int, limit: int) -> int:
        opened = os.open(
            name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=fd
        )
        try:
            info = os.fstat(opened)
            _trust(stat.S_ISREG(info.st_mode) and stat.S_IMODE(info.st_mode) == mode)
            _trust(
                info.st_uid == os.geteuid()
                and info.st_gid == os.getegid()
                and info.st_nlink == 1
            )
            _trust(0 <= info.st_size <= limit)
            _trust(
                broker._file_identity(info)
                == broker._file_identity(
                    os.stat(name, dir_fd=fd, follow_symlinks=False)
                )
            )
            return opened
        except BaseException:
            os.close(opened)
            raise

    def _read_file(
        self, fd: int, name: str, mode: int, limit: int, *, sync: bool = False
    ) -> bytes:
        opened = self._open_file(fd, name, mode, limit)
        try:
            before = os.fstat(opened)
            raw = bytearray()
            while chunk := os.read(opened, min(8192, limit + 1 - len(raw))):
                raw.extend(chunk)
                _require(len(raw) <= limit)
            _require(len(raw) == before.st_size)
            _require(
                broker._file_identity(before)
                == broker._file_identity(os.fstat(opened))
                == broker._file_identity(
                    os.stat(name, dir_fd=fd, follow_symlinks=False)
                )
            )
            if sync:
                os.fsync(opened)
            return bytes(raw)
        finally:
            os.close(opened)

    @contextmanager
    def _locked(self) -> Iterator[int]:
        if self._halted:
            raise NativeToolReceiptFatal("native tool receipt store is halted")
        root_fd = lock_fd = -1
        locked = False
        try:
            root_fd = broker._open_protected_directory(
                self.root, os.geteuid(), "native tool receipts"
            )
            identity = self._directory(root_fd)
            _trust(self._root_identity in (None, identity))
            self._root_identity = identity
            lock_fd = self._open_file(root_fd, "receipt.lock", 0o600, 0)
            lock_identity = broker._file_identity(os.fstat(lock_fd))
            _trust(self._lock_identity in (None, lock_identity))
            self._lock_identity = lock_identity
            broker._acquire_lock(lock_fd, time.monotonic() + 0.5)
            locked = True
            _trust(
                lock_identity
                == broker._file_identity(
                    os.stat("receipt.lock", dir_fd=root_fd, follow_symlinks=False)
                )
            )
            yield root_fd
            _trust(identity == broker._directory_identity(os.lstat(self.root)))
            _trust(
                lock_identity
                == broker._file_identity(
                    os.stat("receipt.lock", dir_fd=root_fd, follow_symlinks=False)
                )
            )
        except NativeToolReceiptRejected:
            raise
        except BaseException as exc:
            self._halted = True
            raise NativeToolReceiptFatal(
                "native tool receipt operation failed"
            ) from exc
        finally:
            try:
                failure = broker._release_lock_and_close(lock_fd, locked, root_fd)
                if failure is not None:
                    raise failure
            except BaseException as exc:
                self._halted = True
                raise NativeToolReceiptFatal(
                    "native tool receipt cleanup failed"
                ) from exc

    def _load(
        self, fd: int, *, expected_state_digest: str | None = None, sync: bool = False
    ) -> tuple[dict[str, Any], list[dict[str, Any]]]:
        try:
            _inventory(fd, {"genesis.json", "state.json", "receipt.lock", "cas"})
            genesis = broker._parse_canonical_document(
                self._read_file(fd, "genesis.json", 0o400, _MAX_EVENT_BYTES),
                "receipt genesis",
            )
            _exact(genesis, _GENESIS_FIELDS)
            _require(genesis["schema"] == "aragorn/native-tool-receipt-genesis/v1")
            _require(
                genesis["authority"]
                == "ROOT_PROVISIONED_WORKER_RECEIPT_STREAM_NOT_RUN_AUTHORITY"
            )
            _digest(genesis["stream_id"])
            _digest(genesis["runtime_digest"])
            _digest(genesis["policy_digest"])
            _uint(genesis["policy_version"], 2**53 - 1, 1)
            for name, expected in (
                ("worker_uid", os.geteuid()),
                ("worker_gid", os.getegid()),
            ):
                _uint(genesis[name], 2**32 - 1, 1)
                _require(genesis[name] == expected)
            _require(canonical_digest(genesis) == self.genesis_digest)
            state = broker._parse_canonical_document(
                self._read_file(fd, "state.json", 0o400, _MAX_STATE_BYTES, sync=sync),
                "receipt state",
            )
            _exact(state, {"schema", "authority", "genesis_digest", "receipts"})
            _require(
                state["schema"] == "aragorn/native-tool-receipt-state/v1"
                and state["authority"] == _RETAINED_AUTHORITY
            )
            _require(state["genesis_digest"] == self.genesis_digest)
            expected = expected_state_digest or self._state_digest
            _require(expected is None or canonical_digest(state) == expected)
            digests = state["receipts"]
            _require(type(digests) is list and len(digests) <= 2 * _MAX_CALLS)
            for digest in digests:
                _digest(digest)
            _require(len(set(digests)) == len(digests))
            self._audit_cas(fd, digests, sync=sync)
            store = CAS(self.root / "cas", read_only=True)
            receipts = []
            calls = set()
            previous = self.genesis_digest
            for offset, digest in enumerate(digests):
                raw = store.read(digest, max_bytes=_MAX_EVENT_BYTES)
                receipt = broker._parse_canonical_document(
                    raw, "retained native tool receipt"
                )
                _exact(
                    receipt,
                    {
                        "schema",
                        "authority",
                        "genesis_digest",
                        "sequence",
                        "previous_digest",
                        "event",
                    },
                )
                _require(
                    receipt["schema"] == "aragorn/native-tool-receipt/v1"
                    and receipt["authority"] == _RETAINED_AUTHORITY
                )
                _uint(receipt["sequence"], 2 * _MAX_CALLS, 1)
                _require(
                    receipt["sequence"] == offset + 1
                    and receipt["previous_digest"] == previous
                    and receipt["genesis_digest"] == self.genesis_digest
                )
                event = _event(receipt["event"], terminal=bool(offset % 2))
                if offset % 2:
                    _joins_terminal(event, receipts[-1])
                else:
                    key = _call_key(event, self.genesis_digest)
                    _require(key not in calls)
                    calls.add(key)
                receipts.append(receipt)
                previous = digest
            return state, receipts
        except BaseException as exc:
            self._halted = True
            raise NativeToolReceiptFatal(
                "native tool receipt state cannot be verified"
            ) from exc

    def _audit_cas(self, root_fd: int, digests: list[str], *, sync: bool) -> None:
        descriptors = []
        aliases = []
        try:
            parent = root_fd
            for name in ("cas", "blobs", "sha256"):
                child = os.open(
                    name,
                    os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                    dir_fd=parent,
                )
                descriptors.append(child)
                identity = self._directory(child)
                aliases.append((parent, name, child, identity))
                if name == "cas":
                    _require(self._cas_identity in (None, identity))
                    self._cas_identity = identity
                if name != "sha256":
                    _inventory(child, {"blobs" if name == "cas" else "sha256"})
                parent = child
            wanted = {digest[7:9] for digest in digests}
            _inventory(parent, wanted)
            for prefix in sorted(wanted):
                child = os.open(
                    prefix,
                    os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                    dir_fd=parent,
                )
                try:
                    identity = self._directory(child)
                    names = {digest[9:] for digest in digests if digest[7:9] == prefix}
                    _inventory(child, names)
                    for name in names:
                        self._read_file(child, name, 0o444, _MAX_EVENT_BYTES, sync=sync)
                    if sync:
                        os.fsync(child)
                    _trust(
                        identity
                        == self._directory(child)
                        == broker._directory_identity(
                            os.stat(prefix, dir_fd=parent, follow_symlinks=False)
                        )
                    )
                finally:
                    os.close(child)
            if sync:
                for opened in reversed(descriptors):
                    os.fsync(opened)
                os.fsync(root_fd)
                parent_fd = os.open(
                    self.root.parent,
                    os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                )
                try:
                    os.fsync(parent_fd)
                finally:
                    os.close(parent_fd)
            for parent, name, child, identity in aliases:
                _trust(
                    identity
                    == self._directory(child)
                    == broker._directory_identity(
                        os.stat(name, dir_fd=parent, follow_symlinks=False)
                    )
                )
        finally:
            for opened in reversed(descriptors):
                os.close(opened)

    def _append(
        self, fd: int, state: dict[str, Any], event: dict[str, Any]
    ) -> dict[str, Any]:
        try:
            receipt = {
                "schema": "aragorn/native-tool-receipt/v1",
                "authority": _RETAINED_AUTHORITY,
                "genesis_digest": self.genesis_digest,
                "sequence": len(state["receipts"]) + 1,
                "previous_digest": state["receipts"][-1]
                if state["receipts"]
                else self.genesis_digest,
                "event": event,
            }
            raw = canonical_json(receipt)
            _require(len(raw) <= _MAX_EVENT_BYTES)
            digest = canonical_digest(receipt)
            store = CAS(self.root / "cas")
            _require(
                store.put_expected(
                    BytesIO(raw), expected_digest=digest, max_bytes=_MAX_EVENT_BYTES
                )
                == digest
            )
            _require(store.read(digest, max_bytes=_MAX_EVENT_BYTES) == raw)
            updated = {**state, "receipts": [*state["receipts"], digest]}
            broker._atomic_publish_at(
                fd, "state.json", canonical_json(updated), expected_uid=os.geteuid()
            )
            updated_digest = canonical_digest(updated)
            self._load(fd, expected_state_digest=updated_digest, sync=True)
            self._state_digest = updated_digest
            return receipt
        except BaseException as exc:
            self._halted = True
            raise NativeToolReceiptFatal(
                "native tool receipt retention is indeterminate"
            ) from exc

    def _ack(self, receipt: dict[str, Any], status: str) -> dict[str, Any]:
        return {
            "schema": "aragorn/native-tool-receipt-ack/v1",
            "authority": _RETAINED_AUTHORITY,
            "genesis_digest": self.genesis_digest,
            "receipt_digest": canonical_digest(receipt),
            "event_digest": canonical_digest(receipt["event"]),
            "sequence": receipt["sequence"],
            "status": status,
            "effect_authorized": False,
            "run_qualified": False,
        }

    def retain_attempt(self, document: dict[str, Any]) -> dict[str, Any]:
        event = _request(document, terminal=False)
        with self._locked() as fd:
            state, receipts = self._load(fd)
            key = _call_key(event, self.genesis_digest)
            prior = next(
                (
                    item
                    for item in receipts[::2]
                    if _call_key(item["event"], self.genesis_digest) == key
                ),
                None,
            )
            if prior is not None:
                _require(prior["event"] == event)
                self._load(fd, sync=True)
                ack = self._ack(prior, "ALREADY_RECORDED_DO_NOT_EXECUTE")
            else:
                _require(len(receipts) % 2 == 0 and len(receipts) < 2 * _MAX_CALLS)
                ack = self._ack(
                    self._append(fd, state, event), "ATTEMPT_RECORDED_EXECUTE_ONCE"
                )
        return ack

    def retain_terminal(self, document: dict[str, Any]) -> dict[str, Any]:
        event = _request(document, terminal=True)
        with self._locked() as fd:
            state, receipts = self._load(fd)
            prior = next(
                (
                    item
                    for item in receipts[1::2]
                    if item["event"]["attempt_digest"] == event["attempt_digest"]
                ),
                None,
            )
            if prior is not None:
                _require(prior["event"] == event)
                self._load(fd, sync=True)
                ack = self._ack(prior, "TERMINAL_ALREADY_RECORDED")
            else:
                _require(len(receipts) % 2 == 1)
                _joins_terminal(event, receipts[-1])
                ack = self._ack(self._append(fd, state, event), "TERMINAL_RECORDED")
        return ack
