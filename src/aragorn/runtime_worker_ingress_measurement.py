"""One durable worker ingress observation, never effect or timing qualification.

The fixed directory must already be privately provisioned for the worker. A
startup claim permanently consumes that directory: failed, partial and complete
records are never erased, repaired, reopened as a new run, or retried. This is a
local owner-controlled retry barrier, not hostile-owner/root anti-rollback.
Only the renderer places these calls at the named runtime boundaries. Retained
bytes alone do not attest that placement or the running source. Synchronous
retention adds unqualified overhead. No broker final decision is observed here.
"""

from __future__ import annotations

import base64
import hashlib
import os
import re
import stat
import sys
import threading
import time
from pathlib import Path

from . import runtime_action_broker as broker
from . import runtime_native_tool_receipts as receipts
from . import runtime_process_profile as process
from .oci_worker_protocol import canonical_digest, canonical_json

ROOT = Path("/var/lib/aragorn-runtime-worker-measurement")
SCHEMA = "aragorn/native-worker-ingress-record/v1"
AUTHORITY = "WORKER_LOCAL_DURABLE_INGRESS_JOINS_NOT_EFFECT_OR_RUN_AUTHORITY"
STAGES = ("startup", "ingress", "attempt", "action")
MAX_RECORD_BYTES = 192 * 1024
FALSE_FLAGS = (
    "common_deployment_fully_verified",
    "route_qualified",
    "phase3_eligible",
    "live_deployment_attested",
    "metrics_eligible",
    "application_acknowledged",
    "effect_observed",
    "broker_decision_observed",
    "elapsed_time_derived",
    "clock_domain_verified",
    "boot_observed",
)
LIMITATIONS = (
    "AUTHENTICATED_NON_RECEIPT_FRAME_BEFORE_OPEN_ATTEMPT_GATE_NOT_NATIVE_CALL_START",
    "LOCAL_WORKER_OWNED_STORE_NOT_HOSTILE_OWNER_OR_ROOT_RESISTANT",
    "STARTUP_AND_ONE_INGRESS_ONLY_NO_RETRY_REPAIR_OR_RESET",
    "SELF_ACTIVE_TIME_NAMESPACE_ONLY_NO_BOOT_ID_OR_CROSS_PROCESS_CLOCK_PROOF",
    "POINT_IN_TIME_IDENTITY_READBACKS_NOT_CONTINUOUS_IMMUTABILITY",
    "NO_BROKER_DECISION_EFFECT_ACK_ELAPSED_TIME_OR_QUALIFICATION",
    "SYNC_RETENTION_ADDS_UNQUALIFIED_OVERHEAD_NO_HARD_DEADLINE",
)
_BINDING_FIELDS = {
    "schema",
    "runtime_digest",
    "active_skill_digest",
    "policy_digest",
    "policy_version",
}
_RECEIPT_AUTHORITY = "WORKER_LOCAL_DURABLE_RECEIPT_ONLY_NOT_EFFECT_OR_RUN_AUTHORITY"


class NativeWorkerIngressFatal(receipts.NativeToolReceiptFatal):
    """Fail-stop the worker; do not turn this into an ordinary relay refusal."""


def _require(condition: bool) -> None:
    if not condition:
        raise NativeWorkerIngressFatal("worker ingress contract or custody refused")


def _integer(value: object, minimum: int = 0) -> bool:
    return type(value) is int and minimum <= value < 2**63


def _pin(value: object) -> str:
    _require(
        type(value) is str and re.fullmatch(r"sha256:[0-9a-f]{64}", value) is not None
    )
    return value


def _document(value: object, maximum: int) -> dict:
    _require(type(value) is dict)
    raw = canonical_json(value)
    _require(0 < len(raw) <= maximum)
    return broker._parse_canonical_document(raw, "worker ingress input")


def _environment(uid: int, gid: int) -> None:
    _require(
        sys.platform == "linux"
        and _integer(uid, 1)
        and _integer(gid, 1)
        and os.geteuid() == uid
        and os.getegid() == gid
        and threading.get_native_id() == os.getpid()
        and hasattr(time, "CLOCK_BOOTTIME")
    )


def _stamp() -> int:
    value = time.clock_gettime_ns(time.CLOCK_BOOTTIME)
    _require(_integer(value))
    return value


def _self_identity() -> dict:
    pid = os.getpid()
    _require(_integer(pid, 1))
    started = process._process_start_time(pid)
    _require(_integer(started, 1))
    raw = process._read_virtual_file(Path(f"/proc/{pid}/status"), 16384)
    accounts = {}
    for line in raw.decode("ascii").splitlines():
        key, separator, value = line.partition(":")
        if key not in {"Uid", "Gid"}:
            continue
        parts = value.split()
        _require(
            separator == ":"
            and key not in accounts
            and len(parts) == 4
            and all(
                re.fullmatch(r"(?:0|[1-9][0-9]*)", part) is not None for part in parts
            )
        )
        numbers = [int(part) for part in parts]
        _require(all(_integer(item, 1) for item in numbers) and len(set(numbers)) == 1)
        accounts[key] = numbers
    _require(set(accounts) == {"Uid", "Gid"})
    _require(process._process_start_time(pid) == started)
    return {
        "pid": pid,
        "start_time_ticks": started,
        "uid": accounts["Uid"][0],
        "gid": accounts["Gid"][0],
        "uids": accounts["Uid"],
        "gids": accounts["Gid"],
    }


def _namespace(pid: int, descriptor: int) -> dict:
    path = f"/proc/{pid}/ns/time"
    held, named = os.fstat(descriptor), os.stat(path)
    _require(
        stat.S_ISREG(held.st_mode)
        and stat.S_ISREG(named.st_mode)
        and _integer(held.st_dev)
        and _integer(held.st_ino, 1)
        and (held.st_dev, held.st_ino) == (named.st_dev, named.st_ino)
        and os.readlink(path) == f"time:[{held.st_ino}]"
    )
    return {"device": held.st_dev, "inode": held.st_ino}


def _worker_request(value: dict) -> tuple[dict, bytes]:
    request = _document(value, 64 * 1024)
    _require(
        set(request)
        == {
            "schema",
            "authority",
            "target_name",
            "payload_base64",
            "session_id",
            "run_id",
            "tool_call_digest",
        }
    )
    _require(
        request["schema"] == "aragorn/runtime-action-worker-request/v1"
        and request["authority"] == "GATEWAY_REQUEST_ONLY_NOT_EFFECT_AUTHORITY"
        and type(request["target_name"]) is str
        and re.fullmatch(r"[a-z0-9][a-z0-9._-]{0,127}", request["target_name"])
        is not None
    )
    for key in ("session_id", "run_id"):
        _require(
            type(request[key]) is str
            and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,255}", request[key])
            is not None
        )
    _pin(request["tool_call_digest"])
    encoded = request["payload_base64"]
    _require(type(encoded) is str and len(encoded) <= ((32768 + 2) // 3) * 4)
    payload = base64.b64decode(encoded, validate=True)
    _require(
        len(payload) <= 32768 and base64.b64encode(payload).decode("ascii") == encoded
    )
    return request, payload


class NativeWorkerIngress:
    """Fixed one-startup/one-ingress lifecycle; no caller path or clock override."""

    def __init__(
        self, *, expected_worker_uid: int, expected_worker_gid: int, binding: dict
    ) -> None:
        self._uid, self._gid = expected_worker_uid, expected_worker_gid
        self._root_fd = self._namespace_fd = -1
        self._files: dict[str, tuple[int, bytes, tuple[int, ...]]] = {}
        self._descriptors: list[int] = []
        self._documents: list[dict] = []
        self._trace: object | None = None
        self._halted = False
        self._closed = False
        try:
            _environment(self._uid, self._gid)
            self._binding = _document(binding, 4096)
            _require(set(self._binding) == _BINDING_FIELDS)
            _require(
                self._binding["schema"] == "aragorn/runtime-action-worker-binding/v1"
            )
            for key in ("runtime_digest", "active_skill_digest", "policy_digest"):
                _pin(self._binding[key])
            _require(
                type(self._binding["policy_version"]) is int
                and 1 <= self._binding["policy_version"] <= 2**53 - 1
            )
            self._root_fd = broker._open_protected_directory(
                ROOT, self._uid, "worker ingress"
            )
            self._descriptors.append(self._root_fd)
            self._root_identity = self._directory()
            self._inventory()
            self._identity = _self_identity()
            _require(
                self._identity["uid"] == self._uid
                and self._identity["gid"] == self._gid
            )
            # ns/time is a proc magic link; O_NOFOLLOW would reject the intended namespace.
            self._namespace_fd = os.open(
                f"/proc/{self._identity['pid']}/ns/time", os.O_RDONLY | os.O_CLOEXEC
            )
            self._descriptors.append(self._namespace_fd)
            self._time_namespace = _namespace(self._identity["pid"], self._namespace_fd)
            self._guard()
            self._append("startup", {}, _stamp())
        except BaseException as exc:
            self._abort(exc)

    def _directory(self) -> tuple[int, ...]:
        info = os.fstat(self._root_fd)
        _require(
            stat.S_ISDIR(info.st_mode)
            and stat.S_IMODE(info.st_mode) == 0o700
            and info.st_uid == self._uid
            and info.st_gid == self._gid
            and info.st_nlink > 0
        )
        return broker._directory_identity(info)

    def _inventory(self) -> None:
        names = set()
        with os.scandir(self._root_fd) as entries:
            for index, entry in enumerate(entries):
                _require(index < len(self._files))
                names.add(entry.name)
        _require(names == set(self._files))

    def _guard(self) -> None:
        _require(not self._halted and not self._closed)
        _environment(self._uid, self._gid)
        _require(ROOT.resolve(strict=True) == ROOT)
        broker._require_protected_ancestry(ROOT.parent, self._uid)
        _require(
            self._directory()
            == self._root_identity
            == broker._directory_identity(os.lstat(ROOT))
        )
        _require(_self_identity() == self._identity)
        _require(
            _namespace(self._identity["pid"], self._namespace_fd)
            == self._time_namespace
        )
        self._inventory()
        for name, (descriptor, expected, identity) in self._files.items():
            _require(
                identity
                == broker._file_identity(os.fstat(descriptor))
                == broker._file_identity(
                    os.stat(name, dir_fd=self._root_fd, follow_symlinks=False)
                )
            )
            os.lseek(descriptor, 0, os.SEEK_SET)
            raw = bytearray()
            while chunk := os.read(
                descriptor, min(8192, MAX_RECORD_BYTES + 1 - len(raw))
            ):
                raw.extend(chunk)
                _require(len(raw) <= MAX_RECORD_BYTES)
            _require(bytes(raw) == expected)
            _require(
                identity
                == broker._file_identity(os.fstat(descriptor))
                == broker._file_identity(
                    os.stat(name, dir_fd=self._root_fd, follow_symlinks=False)
                )
            )

    def _append(self, stage: str, body: dict, stamp: int) -> None:
        self._guard()
        _require(len(self._documents) < 4 and STAGES[len(self._documents)] == stage)
        _require(
            _integer(stamp)
            and (not self._documents or stamp > self._documents[-1]["boottime_ns"])
        )
        record = {
            "schema": SCHEMA,
            "authority": AUTHORITY,
            "stage": stage,
            "previous_digest": canonical_digest(self._documents[-1])
            if self._documents
            else None,
            "worker_binding": self._binding,
            "worker_binding_digest": canonical_digest(self._binding),
            "worker_identity": self._identity,
            "time_namespace": self._time_namespace,
            "boottime_ns": stamp,
            "body": body,
            "decision": dict.fromkeys(FALSE_FLAGS, False),
            "limitations": list(LIMITATIONS),
        }
        raw = canonical_json(record)
        _require(0 < len(raw) <= MAX_RECORD_BYTES)
        name = stage + ".json"
        # The final name is the permanent claim. A short/failed write is residue,
        # never a temporary object to unlink or replace.
        descriptor = os.open(
            name,
            os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
            0o400,
            dir_fd=self._root_fd,
        )
        self._descriptors.append(descriptor)
        offset = 0
        while offset < len(raw):
            written = os.write(descriptor, raw[offset:])
            _require(type(written) is int and 0 < written <= len(raw) - offset)
            offset += written
        os.fchmod(descriptor, 0o400)
        os.fsync(descriptor)
        os.fsync(self._root_fd)
        info = os.fstat(descriptor)
        _require(
            stat.S_ISREG(info.st_mode)
            and stat.S_IMODE(info.st_mode) == 0o400
            and info.st_uid == self._uid
            and info.st_gid == self._gid
            and info.st_nlink == 1
            and info.st_size == len(raw)
        )
        self._files[name] = (descriptor, raw, broker._file_identity(info))
        self._documents.append(
            broker._parse_canonical_document(raw, "worker ingress record")
        )
        self._guard()

    def begin(self, request: dict, peer: tuple[int, int, int]) -> object:
        """Sample after the authenticated frame, before open-attempt admission."""
        try:
            stamp = _stamp()
            self._guard()
            _require(len(self._documents) == 1 and self._trace is None)
            _require(
                type(peer) is tuple
                and len(peer) == 3
                and all(_integer(item, 1) for item in peer)
            )
            request = _document(request, 64 * 1024)
            self._append(
                "ingress",
                {
                    "worker_request": request,
                    "worker_request_digest": canonical_digest(request),
                    "gateway_peer": dict(zip(("pid", "uid", "gid"), peer)),
                },
                stamp,
            )
            self._trace = object()
            return self._trace
        except BaseException as exc:
            self._abort(exc)

    def bind_attempt(
        self, trace: object, attempt: dict, state: dict, genesis_digest: str
    ) -> None:
        """Join actual open receipt/state while the caller holds its receipt lock."""
        try:
            self._guard()
            _require(
                trace is self._trace and trace is not None and len(self._documents) == 2
            )
            genesis_digest = _pin(genesis_digest)
            attempt = _document(attempt, 4096)
            state = _document(state, 128 * 1024)
            _require(
                set(attempt)
                == {
                    "schema",
                    "authority",
                    "genesis_digest",
                    "sequence",
                    "previous_digest",
                    "event",
                }
            )
            _require(
                set(state) == {"schema", "authority", "genesis_digest", "receipts"}
            )
            _require(
                attempt["schema"] == "aragorn/native-tool-receipt/v1"
                and state["schema"] == "aragorn/native-tool-receipt-state/v1"
                and attempt["authority"] == state["authority"] == _RECEIPT_AUTHORITY
                and attempt["genesis_digest"]
                == state["genesis_digest"]
                == genesis_digest
            )
            pins = state["receipts"]
            _require(
                type(pins) is list and 0 < len(pins) <= 1024 and len(pins) % 2 == 1
            )
            for value in pins:
                _pin(value)
            _require(
                len(set(pins)) == len(pins)
                and type(attempt["sequence"]) is int
                and attempt["sequence"] == len(pins)
            )
            digest = canonical_digest(attempt)
            _require(
                pins[-1] == digest
                and attempt["previous_digest"]
                == (genesis_digest if len(pins) == 1 else pins[-2])
            )
            event = receipts._event(attempt["event"], terminal=False)
            request, _payload = _worker_request(
                self._documents[1]["body"]["worker_request"]
            )
            request_digest = canonical_digest(request)
            _require(
                event["tool_name"] == "aragorn_runtime_create"
                and event["worker_request_digest"] == request_digest
                and all(
                    event[key] == request[key]
                    for key in ("session_id", "run_id", "tool_call_digest")
                )
            )
            self._append(
                "attempt",
                {
                    "attempt": attempt,
                    "attempt_digest": digest,
                    "receipt_state": state,
                    "receipt_state_digest": canonical_digest(state),
                    "genesis_digest": genesis_digest,
                    "worker_request_digest": request_digest,
                },
                _stamp(),
            )
        except BaseException as exc:
            self._abort(exc)

    def bind_action(self, trace: object, action_request: dict) -> None:
        """Join the actual constructed action request before sensor connection."""
        try:
            self._guard()
            _require(
                trace is self._trace and trace is not None and len(self._documents) == 3
            )
            action = _document(action_request, 16384)
            broker._validate_runtime_action_request(action)
            request, payload = _worker_request(
                self._documents[1]["body"]["worker_request"]
            )
            _require(
                all(
                    action[key] == self._binding[key]
                    for key in (
                        "runtime_digest",
                        "active_skill_digest",
                        "policy_digest",
                        "policy_version",
                    )
                )
            )
            _require(
                type(action["policy_version"]) is int
                and all(action[key] == request[key] for key in ("session_id", "run_id"))
                and action["tool_call_id"] == request["tool_call_digest"]
            )
            _require(
                action["payload_digest"]
                == "sha256:" + hashlib.sha256(payload).hexdigest()
                and action["operation_digest"]
                == canonical_digest(
                    {
                        "schema": "aragorn/runtime-file-operation/v1",
                        "operation": "create",
                    }
                )
            )
            _require(
                all(
                    _integer(action[key])
                    for key in ("issued_at_unix", "expires_at_unix")
                )
                and action["expires_at_unix"] == action["issued_at_unix"] + 5
            )
            self._append(
                "action",
                {
                    "action_request": action,
                    "action_request_digest": canonical_digest(action),
                    "worker_request_digest": canonical_digest(request),
                    "attempt_digest": self._documents[2]["body"]["attempt_digest"],
                },
                _stamp(),
            )
        except BaseException as exc:
            self._abort(exc)

    def _close_all(self) -> BaseException | None:
        first = None
        descriptors, self._descriptors = self._descriptors, []
        self._closed = True
        for descriptor in reversed(descriptors):
            try:
                os.close(descriptor)
            except BaseException as exc:
                if first is None:
                    first = exc
        return first

    def _abort(self, cause: BaseException) -> None:
        self._halted = True
        failure = self._close_all()
        error = NativeWorkerIngressFatal("worker ingress retention halted permanently")
        if failure is not None:
            error.add_note("worker ingress descriptor cleanup also failed")
        raise error from cause

    def close(self) -> None:
        """Check retained custody and attempt every close; never remove records."""
        if self._closed:
            return
        failure = None
        try:
            self._guard()
        except BaseException as exc:
            failure = exc
        cleanup = self._close_all()
        if failure is not None or cleanup is not None:
            self._halted = True
            raise NativeWorkerIngressFatal("worker ingress cleanup failed") from (
                failure or cleanup
            )
