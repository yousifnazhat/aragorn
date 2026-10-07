"""One broker-process readiness GET before listen; never action authority.

The fixed startup seam runs in the actual broker service, not a root/runuser
proxy. A durable absent-only claim prevents restart retries. Root provisioning
and broker publication are separate fixed paths; partial files are never erased.
"""

from __future__ import annotations

import os
from pathlib import Path
import socket
import stat
import sys
import time

from . import native_phase3_http_canary_contract as canary
from . import runtime_action_broker as core
from . import runtime_http_action as http
from . import runtime_http_provisioning as provision
from .native_phase3_http_fixture import owned_http_fixture
from .oci_worker_protocol import canonical_digest, canonical_json

CREDENTIAL = Path("/etc/aragorn/runtime-http-readiness.json")
CLAIM = Path("/var/lib/aragorn-runtime-action/control/http-readiness-used.json")
RESULT = Path("/var/lib/aragorn-runtime-action/control/http-readiness-result.json")
REQUEST_SCHEMA = "aragorn/runtime-http-readiness-input/v1"
CLAIM_SCHEMA = "aragorn/runtime-http-readiness-claim/v1"
RESULT_SCHEMA = "aragorn/runtime-http-broker-readiness/v1"
AUTHORITY = "BROKER_PROCESS_BOUNDED_READINESS_ONLY_NOT_EFFECT_OR_QUALIFICATION"
TIMEOUT_MS = 500
FALSE_FLAGS = (*canary.FALSE_FLAGS, "broker_restricted_readiness_verified")
_SECURITY = {
    "CapInh": "0000000000000000",
    "CapPrm": "0000000000000000",
    "CapEff": "0000000000000000",
    "CapBnd": "0000000000000000",
    "CapAmb": "0000000000000000",
    "NoNewPrivs": "1",
    "Seccomp": "2",
}


class HttpReadinessError(ValueError):
    """Fixed failure reason with optional retained, non-secret observation."""


def _require(value, reason):
    if not value:
        raise HttpReadinessError(reason)


def _now():
    return time.clock_gettime_ns(time.CLOCK_BOOTTIME)


def build_readiness_input(*, fixture_binding, readiness_nonce):
    binding = http.validate_fixture_binding(fixture_binding)
    canary.readiness_request(readiness_nonce)
    return {
        "schema": REQUEST_SCHEMA,
        "readiness_nonce": readiness_nonce,
        "fixture_binding_digest": canonical_digest(binding),
        "timeout_ms": TIMEOUT_MS,
    }


def _input(raw, binding):
    value = core._parse_canonical_document(raw, "HTTP readiness input")
    expected = build_readiness_input(
        fixture_binding=binding, readiness_nonce=value.get("readiness_nonce")
    )
    _require(
        value == expected and type(value.get("timeout_ms")) is int,
        "HTTP_READINESS_INPUT_REFUSED",
    )
    return expected


def _close(primary, callback):
    try:
        callback()
    except BaseException as error:
        retained = http._preserve_failure(primary, error)
        if retained is not error:
            retained.add_note("HTTP_READINESS_CLEANUP_FAILED")
        for name in ("http_readiness_observation", "http_readiness_publication"):
            if hasattr(primary, name):
                setattr(retained, name, getattr(primary, name))
        raise retained from (error if retained is not error else primary)


def _read_owned(path, *, uid, gid, mode):
    parent = core._open_protected_directory(path.parent, uid, "HTTP readiness parent")
    descriptor = -1
    try:
        parent_identity = core._directory_identity(os.fstat(parent))
        descriptor = os.open(
            path.name,
            os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK,
            dir_fd=parent,
        )
        before = os.fstat(descriptor)
        _require(
            stat.S_ISREG(before.st_mode)
            and before.st_uid == uid
            and before.st_gid == gid
            and before.st_nlink == 1
            and stat.S_IMODE(before.st_mode) == mode
            and 0 < before.st_size <= 16384,
            "HTTP_READINESS_FILE_CUSTODY_REFUSED",
        )
        raw = bytearray()
        while chunk := os.read(descriptor, min(4096, 16385 - len(raw))):
            raw.extend(chunk)
            _require(len(raw) <= 16384, "HTTP_READINESS_FILE_LIMIT")
        named = os.stat(path.name, dir_fd=parent, follow_symlinks=False)
        file_identity = core._file_identity(before)
        _require(
            len(raw) == before.st_size
            and file_identity
            == core._file_identity(os.fstat(descriptor))
            == core._file_identity(named)
            and parent_identity
            == core._directory_identity(os.fstat(parent))
            == core._directory_identity(path.parent.lstat()),
            "HTTP_READINESS_FILE_CHANGED",
        )
        return bytes(raw), {"identity": list(file_identity), "bytes": len(raw)}
    finally:
        primary = sys.exception()
        try:
            if descriptor >= 0:
                _close(primary, lambda: os.close(descriptor))
        finally:
            _close(sys.exception(), lambda: os.close(parent))


def _publish_absent(path, raw, binding, *, root_writer=False):
    """Fixed-path single write, held parent, exact protected readback; no retry."""
    _require(
        type(raw) is bytes and 0 < len(raw) <= 16384,
        "HTTP_READINESS_PUBLICATION_REFUSED",
    )
    _require(
        path == CREDENTIAL if root_writer else path in (CLAIM, RESULT),
        "HTTP_READINESS_PUBLICATION_PATH_REFUSED",
    )
    uid = 0 if root_writer else binding["expected_broker_uid"]
    gid = binding["expected_broker_gid"]
    mode = 0o440 if root_writer else 0o400
    _require(os.geteuid() == uid, "HTTP_READINESS_WRITER_IDENTITY_REFUSED")
    parent = descriptor = -1
    observation = {
        "path": str(path),
        "created": False,
        "bytes_written": 0,
        "completed": False,
        "cleanup_failed": False,
    }
    try:
        parent = core._open_protected_directory(
            path.parent, uid, "HTTP readiness parent"
        )
        before = core._directory_identity(os.fstat(parent))
        observation["created"] = None
        descriptor = os.open(
            path.name,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
            0o400,
            dir_fd=parent,
        )
        observation["created"] = True
        if root_writer:
            os.fchown(descriptor, uid, gid)
        os.fchmod(descriptor, mode)
        metadata = os.fstat(descriptor)
        _require(
            stat.S_ISREG(metadata.st_mode)
            and metadata.st_uid == uid
            and metadata.st_gid == gid
            and metadata.st_nlink == 1
            and metadata.st_size == 0
            and stat.S_IMODE(metadata.st_mode) == mode,
            "HTTP_READINESS_PUBLICATION_CUSTODY_CHANGED",
        )
        observation["bytes_written"] = None
        observation["bytes_written"] = os.write(descriptor, raw)
        _require(observation["bytes_written"] == len(raw), "HTTP_READINESS_SHORT_WRITE")
        os.fsync(descriptor)
        os.fsync(parent)
        _require(
            before
            == core._directory_identity(os.fstat(parent))
            == core._directory_identity(path.parent.lstat()),
            "HTTP_READINESS_PARENT_CHANGED",
        )
        _require(
            _read_owned(path, uid=uid, gid=gid, mode=mode)[0] == raw,
            "HTTP_READINESS_PUBLICATION_CHANGED",
        )
        observation["completed"] = True
    except BaseException as error:
        error.http_readiness_publication = observation
        raise
    finally:
        primary = sys.exception()
        cleanup = None
        for fd in (descriptor, parent):
            if fd >= 0:
                try:
                    os.close(fd)
                except BaseException as error:
                    cleanup = http._preserve_failure(cleanup, error)
        if cleanup is not None:
            observation.update(completed=False, cleanup_failed=True)
            retained = http._preserve_failure(primary, cleanup)
            retained.http_readiness_publication = observation
            raise retained from (cleanup if retained is not cleanup else primary)
    return observation


def provision_readiness_input(*, expected_fixture, readiness_nonce):
    """Root-only, all four services stopped; never activates or opens a socket."""
    result = {
        "schema": "aragorn/runtime-http-readiness-provisioning/v1",
        "request_digest": None,
        "publication": None,
        "completed": False,
        "activation_performed": False,
        **dict.fromkeys(FALSE_FLAGS, False),
    }
    try:
        with owned_http_fixture(expected_fixture) as held:
            binding = http.load_fixture_binding()
            _require(
                binding == provision._new_binding(expected_fixture),
                "HTTP_READINESS_FIXTURE_BINDING_CHANGED",
            )
            request = build_readiness_input(
                fixture_binding=binding, readiness_nonce=readiness_nonce
            )
            result["request_digest"] = canonical_digest(request)
            provision._stopped()
            _require(
                not any(os.path.lexists(path) for path in (CREDENTIAL, CLAIM, RESULT)),
                "HTTP_READINESS_ALREADY_PROVISIONED",
            )
            held.guard()
            result["publication"] = _publish_absent(
                CREDENTIAL, canonical_json(request), binding, root_writer=True
            )
            held.guard()
            provision._stopped()
            _require(
                http.load_fixture_binding() == binding,
                "HTTP_READINESS_FIXTURE_BINDING_CHANGED",
            )
        result["completed"] = True
        return result
    except BaseException as error:
        if result["publication"] is None:
            result["publication"] = getattr(error, "http_readiness_publication", None)
        error.http_readiness_provisioning = result
        raise


def _security():
    values = {}
    for line in http._read("/proc/self/status", 16384).splitlines():
        name, separator, value = line.partition(b":")
        if separator and name.decode("ascii") in _SECURITY:
            key = name.decode("ascii")
            _require(key not in values, "HTTP_READINESS_RESTRICTIONS_REFUSED")
            values[key] = value.strip().decode("ascii")
    _require(values == _SECURITY, "HTTP_READINESS_RESTRICTIONS_REFUSED")
    return values


def _probe(request, binding, claim):
    """Called only after durable claim publication by the actual broker startup."""
    wire = canary.readiness_request(request["readiness_nonce"])
    record = {
        "schema": RESULT_SCHEMA,
        "authority": AUTHORITY,
        "request_digest": canonical_digest(request),
        "claim_digest": canonical_digest(claim),
        "fixture_binding_digest": canonical_digest(binding),
        "readiness_nonce": request["readiness_nonce"],
        "identity": None,
        "security": None,
        "status": "NOT_PERFORMED",
        "error_code": None,
        "connect_attempted": False,
        "local_port": None,
        "sent_bytes": 0,
        "response_bytes": 0,
        "response_digest": canary.digest(b""),
        "interval": {
            "clock_id": "CLOCK_BOOTTIME",
            "started_ns": None,
            "finished_ns": None,
            "deadline_ns": None,
        },
        **dict.fromkeys(FALSE_FLAGS, False),
    }
    held = stream = failure = None
    received = bytearray()
    try:
        start = _now()
        record["interval"].update(
            started_ns=start, deadline_ns=start + TIMEOUT_MS * 1_000_000
        )
        deadline = time.monotonic() + TIMEOUT_MS / 1000
        held = http._ExecutionGuard(binding)
        record["identity"] = held.identity()
        _require(
            record["identity"] == claim["identity"], "HTTP_READINESS_PROCESS_CHANGED"
        )
        record["security"] = _security()
        stream = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        held.guard()
        stream.settimeout(http._remaining(deadline))
        record["connect_attempted"] = True
        stream.connect((canary.HOST, canary.PORT))
        local = stream.getsockname()
        _require(
            type(local) is tuple
            and len(local) == 2
            and local[0] == canary.HOST
            and type(local[1]) is int
            and 0 < local[1] < 65536,
            "HTTP_READINESS_LOCAL_ENDPOINT_CHANGED",
        )
        record["local_port"] = local[1]
        held.guard()
        stream.settimeout(http._remaining(deadline))
        record["sent_bytes"] = None
        record["sent_bytes"] = stream.send(wire)
        _require(
            type(record["sent_bytes"]) is int and record["sent_bytes"] == len(wire),
            "HTTP_READINESS_SHORT_SEND",
        )
        stream.settimeout(http._remaining(deadline))
        stream.shutdown(socket.SHUT_WR)
        while True:
            held.guard()
            stream.settimeout(http._remaining(deadline))
            chunk = stream.recv(canary.MAX_BYTES + 1 - len(received))
            _require(type(chunk) is bytes, "HTTP_READINESS_RESPONSE_REFUSED")
            if not chunk:
                break
            received.extend(chunk)
            _require(len(received) <= canary.MAX_BYTES, "HTTP_READINESS_RESPONSE_LIMIT")
        _require(
            bytes(received) == canary.RESPONSE_BYTES, "HTTP_READINESS_RESPONSE_REFUSED"
        )
        held.guard()
        _require(
            _security() == record["security"], "HTTP_READINESS_RESTRICTIONS_CHANGED"
        )
        http._remaining(deadline)
    except BaseException as error:
        failure = error
        record["error_code"] = (
            "HTTP_READINESS_INTERRUPTED"
            if not isinstance(error, Exception)
            else "HTTP_READINESS_REFUSED"
        )
    finally:
        for callback in ([stream.close] if stream is not None else []) + (
            [held.guard, held.close] if held is not None else []
        ):
            try:
                callback()
            except BaseException as error:
                failure = http._preserve_failure(failure, error)
                record["error_code"] = "HTTP_READINESS_CLEANUP_FAILED"
        record.update(
            response_bytes=len(received), response_digest=canary.digest(bytes(received))
        )
        try:
            finish = _now()
            record["interval"]["finished_ns"] = finish
            start, deadline = (
                record["interval"]["started_ns"],
                record["interval"]["deadline_ns"],
            )
            _require(
                type(start) is int and start <= finish <= deadline,
                "HTTP_READINESS_CLOCK_OR_DEADLINE_REFUSED",
            )
        except BaseException as error:
            failure = http._preserve_failure(failure, error)
            record["error_code"] = "HTTP_READINESS_CLOCK_OR_DEADLINE_REFUSED"
    record["status"] = (
        "READY"
        if failure is None
        else "INDETERMINATE"
        if record["connect_attempted"]
        else "NOT_PERFORMED"
    )
    if failure is not None:
        if not isinstance(failure, Exception):
            failure.http_readiness_observation = record
            raise failure
        error = HttpReadinessError(record["error_code"])
        error.http_readiness_observation = record
        raise error from None
    return record


def run_startup_readiness():
    """Exactly one claim before connect, one probe, one result; no service launch."""
    binding = http.load_fixture_binding()
    request_raw, metadata = _read_owned(
        CREDENTIAL, uid=0, gid=binding["expected_broker_gid"], mode=0o440
    )
    request = _input(request_raw, binding)
    held = http._ExecutionGuard(binding)
    failure = record = None
    try:
        _security()
        claim = {
            "schema": CLAIM_SCHEMA,
            "authority": AUTHORITY,
            "request_digest": canonical_digest(request),
            "fixture_binding_digest": canonical_digest(binding),
            "identity": held.identity(),
            "claimed_boottime_ns": _now(),
        }
        _require(not os.path.lexists(RESULT), "HTTP_READINESS_RESULT_ALREADY_EXISTS")
        held.guard()
        _publish_absent(CLAIM, canonical_json(claim), binding)
        _require(
            _read_owned(
                CREDENTIAL, uid=0, gid=binding["expected_broker_gid"], mode=0o440
            )
            == (request_raw, metadata),
            "HTTP_READINESS_CREDENTIAL_CHANGED",
        )
        try:
            record = _probe(request, binding, claim)
        except BaseException as error:
            failure = error
            record = getattr(error, "http_readiness_observation", None)
        _require(
            _read_owned(
                CREDENTIAL, uid=0, gid=binding["expected_broker_gid"], mode=0o440
            )
            == (request_raw, metadata),
            "HTTP_READINESS_CREDENTIAL_CHANGED",
        )
        held.guard()
    except BaseException as error:
        failure = http._preserve_failure(failure, error)
    finally:
        # No READY result exists until the outer process/namespace guard has
        # completed and closed. Never publish success before this cleanup.
        for callback in (held.guard, held.close):
            try:
                callback()
            except BaseException as error:
                failure = http._preserve_failure(failure, error)
    if failure is not None and record is not None:
        record["status"] = (
            "INDETERMINATE" if record["connect_attempted"] else "NOT_PERFORMED"
        )
        record["error_code"] = "HTTP_READINESS_STARTUP_FINALIZATION_REFUSED"
        failure.http_readiness_observation = record
    if record is not None:
        try:
            _publish_absent(RESULT, canonical_json(record), binding)
        except BaseException as error:
            retained = http._preserve_failure(failure, error)
            record["status"] = (
                "INDETERMINATE" if record["connect_attempted"] else "NOT_PERFORMED"
            )
            record["error_code"] = "HTTP_READINESS_RESULT_PUBLICATION_UNCONFIRMED"
            retained.http_readiness_observation = record
            if hasattr(error, "http_readiness_publication"):
                retained.http_readiness_publication = error.http_readiness_publication
            raise retained from (error if retained is not error else failure)
    if failure is not None:
        raise failure
    _require(
        record is not None and record["status"] == "READY", "HTTP_READINESS_NOT_READY"
    )
    return record
