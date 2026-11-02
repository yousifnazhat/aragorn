"""Finite HTTP action bytes and a credential-bound, unprivileged lab effect.

The broker must authorize and consume the action before calling the effect.
This module never makes a policy decision or grants admission/RUN authority.
"""

from __future__ import annotations

import json
import math
import os
import re
import socket
import stat
import sys
import threading
import time
from pathlib import Path

from . import native_phase3_http_canary_contract as canary
from . import runtime_process_profile as process
from .oci_worker_protocol import canonical_digest, canonical_json

BINDING_PATH = Path("/etc/aragorn/runtime-http-fixture.json")
BOOT_PATH = Path("/run/aragorn-broker-boot-id")
BROKER_UNIT = "aragorn-runtime-lineage-capability-action-broker.service"
BINDING_SCHEMA = "aragorn/runtime-http-fixture-binding/v1"
EFFECT_SCHEMA = "aragorn/runtime-http-canary-effect/v1"
EFFECT_FIELDS = frozenset({"schema", "operation", "attempt_id"})
OPERATION_SCHEMA = "aragorn/runtime-http-operation/v1"
ENDPOINT_SCHEMA = "aragorn/runtime-http-endpoint/v1"
WORKER_SCHEMA = "aragorn/runtime-http-worker-request/v1"
RESULT_SCHEMA = "aragorn/runtime-http-action-result/v1"
RESULT_AUTHORITY = "CREDENTIAL_BOUND_LAB_HTTP_TRANSPORT_ONLY_NOT_POLICY_AUTHORITY"
TARGET_NAME = "http-canary"
OPERATION = "http_canary_post"
MAX_SECONDS = 0.5
_IDENTIFIER = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,255}\Z")
_PIN = re.compile(r"sha256:[0-9a-f]{64}\Z")
_ERRORS = {
    "HTTP_BINDING_REFUSED",
    "HTTP_ENVIRONMENT_REFUSED",
    "HTTP_NAMESPACE_CHANGED",
    "HTTP_PROCESS_CHANGED",
    "HTTP_DEADLINE_REFUSED",
    "HTTP_DEADLINE_EXPIRED",
    "HTTP_TRANSPORT_FAILED",
    "HTTP_SHORT_WRITE",
    "HTTP_RESPONSE_LIMIT",
    "HTTP_RESPONSE_REFUSED",
    "HTTP_SOCKET_CLOSE_FAILED",
    "HTTP_GUARD_CLOSE_FAILED",
    "HTTP_OPERATION_INTERRUPTED",
    "HTTP_TRANSPORT_RESULT_REFUSED",
    "HTTP_AUTHORIZATION_REFUSED",
}


class RuntimeHttpActionError(ValueError):
    """An action failed before any connection attempt."""

    def __init__(self, reason, observation=None):
        super().__init__(reason)
        self.reason = reason
        self.observation = observation


class RuntimeHttpActionIndeterminate(RuntimeHttpActionError):
    """A connection was attempted; callers must preserve state and never retry."""


def _require(condition, reason):
    if not condition:
        raise RuntimeHttpActionError(reason)


def _copy(value):
    return json.loads(canonical_json(value))


def validate_fixture_binding(value):
    """Validate preparation bytes only; execution separately reads the credential."""
    _require(
        type(value) is dict
        and set(value)
        == {"schema", "fixture", "expected_broker_uid", "expected_broker_gid"}
        and value["schema"] == BINDING_SCHEMA,
        "HTTP_BINDING_REFUSED",
    )
    try:
        canary.validate_fixture(value["fixture"])
    except ValueError:
        raise RuntimeHttpActionError("HTTP_BINDING_REFUSED") from None
    _require(
        all(
            type(value[key]) is int and 0 < value[key] < 2**31
            for key in ("expected_broker_uid", "expected_broker_gid")
        ),
        "HTTP_BINDING_REFUSED",
    )
    return _copy(value)


def effect_for_attempt(attempt_id):
    canary.canary_bytes(attempt_id)
    return {"schema": EFFECT_SCHEMA, "operation": OPERATION, "attempt_id": attempt_id}


def validate_effect(value):
    _require(
        type(value) is dict
        and set(value) == EFFECT_FIELDS
        and value["schema"] == EFFECT_SCHEMA
        and value["operation"] == OPERATION,
        "HTTP_EFFECT_REFUSED",
    )
    try:
        return effect_for_attempt(value["attempt_id"])
    except ValueError:
        raise RuntimeHttpActionError("HTTP_EFFECT_REFUSED") from None


def operation_descriptor():
    return {"schema": OPERATION_SCHEMA, "operation": OPERATION}


def endpoint_descriptor(fixture_binding):
    binding = validate_fixture_binding(fixture_binding)
    return {
        "schema": ENDPOINT_SCHEMA,
        "fixture_binding_digest": canonical_digest(binding),
        "fixture": binding["fixture"],
        "host": canary.HOST,
        "port": canary.PORT,
        "method": "POST",
        "path": "/aragorn-phase3-canary",
    }


def action_digests(attempt_id, fixture_binding):
    """Bind the exact wire request and root-provisioned destination identity."""
    return {
        "operation_digest": canonical_digest(operation_descriptor()),
        "path_digest": canonical_digest(endpoint_descriptor(fixture_binding)),
        "payload_digest": canary.digest(canary.canary_request(attempt_id)),
    }


def build_worker_request(*, attempt_id, session_id, run_id, tool_call_digest):
    return validate_worker_request(
        {
            "schema": WORKER_SCHEMA,
            "authority": "GATEWAY_REQUEST_ONLY_NOT_EFFECT_AUTHORITY",
            "attempt_id": attempt_id,
            "session_id": session_id,
            "run_id": run_id,
            "tool_call_digest": tool_call_digest,
        }
    )


def validate_worker_request(value):
    _require(
        type(value) is dict
        and set(value)
        == {
            "schema",
            "authority",
            "attempt_id",
            "session_id",
            "run_id",
            "tool_call_digest",
        }
        and value["schema"] == WORKER_SCHEMA
        and value["authority"] == "GATEWAY_REQUEST_ONLY_NOT_EFFECT_AUTHORITY"
        and all(
            type(value[key]) is str and _IDENTIFIER.fullmatch(value[key]) is not None
            for key in ("session_id", "run_id")
        )
        and type(value["tool_call_digest"]) is str
        and _PIN.fullmatch(value["tool_call_digest"]) is not None,
        "HTTP_WORKER_REQUEST_REFUSED",
    )
    validate_effect(effect_for_attempt(value["attempt_id"]))
    return _copy(value)


def _file_identity(metadata):
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_mode,
        metadata.st_uid,
        metadata.st_gid,
        metadata.st_nlink,
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
    )


def load_fixture_binding():
    """Read only the fixed root-owned 0440 credential, without following links."""
    descriptor = -1
    try:
        for parent in reversed(BINDING_PATH.parents):
            item = parent.lstat()
            _require(
                stat.S_ISDIR(item.st_mode)
                and item.st_uid == 0
                and not stat.S_IMODE(item.st_mode) & 0o022,
                "HTTP_BINDING_REFUSED",
            )
        descriptor = os.open(
            BINDING_PATH, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC
        )
        before = os.fstat(descriptor)
        _require(
            stat.S_ISREG(before.st_mode)
            and before.st_uid == 0
            and before.st_nlink == 1
            and stat.S_IMODE(before.st_mode) == 0o440
            and 0 < before.st_size <= 4096,
            "HTTP_BINDING_REFUSED",
        )
        raw = os.read(descriptor, 4097)
        value = json.loads(raw)
        binding = validate_fixture_binding(value)
        _require(
            canonical_json(binding) == raw
            and before.st_gid == binding["expected_broker_gid"]
            and len(raw) == before.st_size
            and _file_identity(before)
            == _file_identity(os.fstat(descriptor))
            == _file_identity(BINDING_PATH.lstat()),
            "HTTP_BINDING_REFUSED",
        )
        for parent in reversed(BINDING_PATH.parents):
            item = parent.lstat()
            _require(
                stat.S_ISDIR(item.st_mode)
                and item.st_uid == 0
                and not stat.S_IMODE(item.st_mode) & 0o022,
                "HTTP_BINDING_REFUSED",
            )
        return binding
    except (OSError, ValueError, TypeError, KeyError):
        raise RuntimeHttpActionError("HTTP_BINDING_REFUSED") from None
    finally:
        if descriptor >= 0:
            primary = sys.exception()
            try:
                os.close(descriptor)
            except OSError:
                if primary is not None and not isinstance(primary, Exception):
                    primary.http_binding_cleanup_failed = True
                    primary.add_note("HTTP_BINDING_DESCRIPTOR_CLOSE_FAILED")
                else:
                    raise RuntimeHttpActionError("HTTP_BINDING_REFUSED") from None


def _read(path, limit):
    return process._read_virtual_file(Path(path), limit)


def _environment(binding):
    uid, gid = binding["expected_broker_uid"], binding["expected_broker_gid"]
    _require(
        sys.platform == "linux"
        and os.getpid() > 1
        and os.getpid() == threading.get_native_id()
        and (os.getuid(), os.geteuid(), os.getgid(), os.getegid())
        == (uid, uid, gid, gid),
        "HTTP_ENVIRONMENT_REFUSED",
    )
    values = {}
    for line in _read("/proc/self/status", 16384).splitlines():
        name, separator, remainder = line.partition(b":")
        if separator and name in {b"Uid", b"Gid"}:
            _require(name not in values, "HTTP_ENVIRONMENT_REFUSED")
            values[name] = remainder.split()
    _require(
        values == {b"Uid": [str(uid).encode()] * 4, b"Gid": [str(gid).encode()] * 4},
        "HTTP_ENVIRONMENT_REFUSED",
    )
    fixture = binding["fixture"]
    cgroup = (
        f"0::/docker/{fixture['container_id']}/system.slice/{BROKER_UNIT}\n".encode(
            "ascii"
        )
    )
    _require(
        _read("/proc/self/cgroup", 1024) == cgroup
        and _read(BOOT_PATH, 64) == (fixture["boot_id"] + "\n").encode("ascii")
        and socket.if_nameindex() == [(1, "lo")],
        "HTTP_ENVIRONMENT_REFUSED",
    )


class _ExecutionGuard:
    def __init__(self, binding):
        self.binding = validate_fixture_binding(binding)
        self.descriptor = -1
        self.pid = os.getpid()
        self.start = None
        try:
            _require(load_fixture_binding() == self.binding, "HTTP_BINDING_REFUSED")
            _environment(self.binding)
            self.start = process._process_start_time(self.pid)
            self.descriptor = os.open("/proc/self/ns/net", os.O_RDONLY | os.O_CLOEXEC)
            self.guard()
        except BaseException as error:
            if self.descriptor >= 0:
                descriptor, self.descriptor = self.descriptor, -1
                try:
                    os.close(descriptor)
                except BaseException as cleanup:
                    retained = _preserve_failure(error, cleanup)
                    if retained is not error:
                        raise retained
            raise

    def guard(self):
        _require(self.descriptor >= 0, "HTTP_NAMESPACE_CHANGED")
        _require(load_fixture_binding() == self.binding, "HTTP_BINDING_REFUSED")
        _environment(self.binding)
        fixture = self.binding["fixture"]
        expected = fixture["netns_device"], fixture["netns_inode"]
        held, current = os.fstat(self.descriptor), os.stat("/proc/self/ns/net")
        _require(
            (held.st_dev, held.st_ino) == (current.st_dev, current.st_ino) == expected,
            "HTTP_NAMESPACE_CHANGED",
        )
        _require(
            os.getpid() == self.pid
            and process._process_start_time(self.pid) == self.start,
            "HTTP_PROCESS_CHANGED",
        )

    def identity(self):
        self.guard()
        return {
            "fixture": _copy(self.binding["fixture"]),
            "pid": self.pid,
            "start_time_ticks": self.start,
            "uid": self.binding["expected_broker_uid"],
            "gid": self.binding["expected_broker_gid"],
        }

    def close(self):
        descriptor, self.descriptor = self.descriptor, -1
        if descriptor >= 0:
            os.close(descriptor)


def _deadline(value):
    _require(
        type(value) in {int, float}
        and (type(value) is not float or math.isfinite(value)),
        "HTTP_DEADLINE_REFUSED",
    )
    now = time.monotonic()
    _require(now < value <= now + MAX_SECONDS, "HTTP_DEADLINE_REFUSED")


def _remaining(deadline):
    remaining = deadline - time.monotonic()
    _require(remaining > 0, "HTTP_DEADLINE_EXPIRED")
    return remaining


def _preserve_failure(prior, current):
    if (
        prior is None
        or isinstance(prior, Exception)
        and not isinstance(current, Exception)
    ):
        return current
    return prior


def execute_http_effect(
    effect, *, fixture_binding, deadline_monotonic, authorize_effect=None
):
    """Send once after the caller's final authorization; never retry any effect.

    The supplied binding is a comparison pin. The root credential and actual
    process/namespace must agree with it before opening a socket and throughout
    transport. An optional no-argument broker callback must return exactly True
    before connect and send, after guard work. The remaining timeout is refreshed
    after each callback without further filesystem or process reads. The
    internal broker supplies this callback; omission confers no policy authority.
    Every failure after attempting connect is indeterminate.
    """
    effect = validate_effect(effect)
    binding = validate_fixture_binding(fixture_binding)
    request = canary.canary_request(effect["attempt_id"])
    attempted, sent, received = False, 0, bytearray()
    stream, held, identity, failure = None, None, None, None
    reason = None
    try:
        _require(
            authorize_effect is None or callable(authorize_effect),
            "HTTP_AUTHORIZATION_REFUSED",
        )
        _deadline(deadline_monotonic)
        held = _ExecutionGuard(binding)
        identity = held.identity()
        _remaining(deadline_monotonic)
        stream = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        held.guard()
        stream.settimeout(_remaining(deadline_monotonic))
        if authorize_effect is not None:
            _require(authorize_effect() is True, "HTTP_AUTHORIZATION_REFUSED")
            stream.settimeout(_remaining(deadline_monotonic))
        attempted = True
        stream.connect((canary.HOST, canary.PORT))
        held.guard()
        stream.settimeout(_remaining(deadline_monotonic))
        if authorize_effect is not None:
            _require(authorize_effect() is True, "HTTP_AUTHORIZATION_REFUSED")
            stream.settimeout(_remaining(deadline_monotonic))
        sent = None
        count = stream.send(request)
        _require(
            type(count) is int and 0 <= count <= len(request),
            "HTTP_TRANSPORT_RESULT_REFUSED",
        )
        sent = count
        _require(sent == len(request), "HTTP_SHORT_WRITE")
        held.guard()
        stream.settimeout(_remaining(deadline_monotonic))
        stream.shutdown(socket.SHUT_WR)
        while True:
            held.guard()
            stream.settimeout(_remaining(deadline_monotonic))
            chunk = stream.recv(canary.MAX_BYTES + 1 - len(received))
            _require(type(chunk) is bytes, "HTTP_TRANSPORT_RESULT_REFUSED")
            if not chunk:
                break
            received.extend(chunk)
            _require(len(received) <= canary.MAX_BYTES, "HTTP_RESPONSE_LIMIT")
        _require(bytes(received) == canary.RESPONSE_BYTES, "HTTP_RESPONSE_REFUSED")
        held.guard()
        _remaining(deadline_monotonic)
    except BaseException as error:
        failure = error
        reason = (
            error.reason
            if isinstance(error, RuntimeHttpActionError)
            else "HTTP_DEADLINE_EXPIRED"
            if isinstance(error, TimeoutError)
            else "HTTP_OPERATION_INTERRUPTED"
            if not isinstance(error, Exception)
            else "HTTP_TRANSPORT_FAILED"
        )
    finally:
        if stream is not None:
            try:
                stream.close()
            except BaseException as error:
                failure = _preserve_failure(failure, error)
                reason = "HTTP_SOCKET_CLOSE_FAILED"
        if held is not None:
            try:
                held.guard()
            except BaseException as error:
                failure = _preserve_failure(failure, error)
                reason = (
                    error.reason
                    if isinstance(error, RuntimeHttpActionError)
                    else "HTTP_ENVIRONMENT_REFUSED"
                )
            try:
                held.close()
            except BaseException as error:
                failure = _preserve_failure(failure, error)
                reason = "HTTP_GUARD_CLOSE_FAILED"
    record = {
        "schema": RESULT_SCHEMA,
        "authority": RESULT_AUTHORITY,
        "attempt_id": effect["attempt_id"],
        "fixture_binding_digest": canonical_digest(binding),
        "effect_digest": canonical_digest(effect),
        "action_digests": action_digests(effect["attempt_id"], binding),
        "connect_attempted": attempted,
        "sent_bytes": sent,
        "response_bytes": len(received),
        "response_digest": canary.digest(bytes(received)),
        "status": "SENT"
        if failure is None
        else "INDETERMINATE"
        if attempted
        else "NOT_PERFORMED",
        "error_code": reason,
        "identity": identity,
        **dict.fromkeys(canary.FALSE_FLAGS, False),
    }
    if failure is not None:
        if not isinstance(failure, Exception):
            failure.http_action_observation = record
            raise failure
        error_class = (
            RuntimeHttpActionIndeterminate if attempted else RuntimeHttpActionError
        )
        raise error_class(reason, record) from None
    try:
        return validate_result(record, effect=effect, fixture_binding=binding)
    except BaseException as error:
        record["status"] = "INDETERMINATE"
        record["error_code"] = "HTTP_TRANSPORT_RESULT_REFUSED"
        if not isinstance(error, Exception):
            error.http_action_observation = record
            raise
        raise RuntimeHttpActionIndeterminate(
            "HTTP_TRANSPORT_RESULT_REFUSED", record
        ) from None


def validate_result(value, *, effect, fixture_binding):
    """Pure shape/binding verification; a transport result is not a policy receipt."""
    effect = validate_effect(effect)
    binding = validate_fixture_binding(fixture_binding)
    fields = {
        "schema",
        "authority",
        "attempt_id",
        "fixture_binding_digest",
        "effect_digest",
        "action_digests",
        "connect_attempted",
        "sent_bytes",
        "response_bytes",
        "response_digest",
        "status",
        "error_code",
        "identity",
        *canary.FALSE_FLAGS,
    }
    _require(
        type(value) is dict and set(value) == fields, "HTTP_TRANSPORT_RESULT_REFUSED"
    )
    _require(
        value["schema"] == RESULT_SCHEMA
        and value["authority"] == RESULT_AUTHORITY
        and value["attempt_id"] == effect["attempt_id"]
        and value["fixture_binding_digest"] == canonical_digest(binding)
        and value["effect_digest"] == canonical_digest(effect)
        and value["action_digests"] == action_digests(effect["attempt_id"], binding)
        and type(value["connect_attempted"]) is bool
        and all(value[key] is False for key in canary.FALSE_FLAGS),
        "HTTP_TRANSPORT_RESULT_REFUSED",
    )
    size = len(canary.canary_request(effect["attempt_id"]))
    _require(
        (
            value["sent_bytes"] is None
            or type(value["sent_bytes"]) is int
            and 0 <= value["sent_bytes"] <= size
        )
        and type(value["response_bytes"]) is int
        and 0 <= value["response_bytes"] <= canary.MAX_BYTES + 1
        and type(value["response_digest"]) is str
        and _PIN.fullmatch(value["response_digest"]) is not None,
        "HTTP_TRANSPORT_RESULT_REFUSED",
    )
    if value["status"] == "SENT":
        _require(
            value["connect_attempted"]
            and value["sent_bytes"] == size
            and value["response_bytes"] == len(canary.RESPONSE_BYTES)
            and value["response_digest"] == canary.digest(canary.RESPONSE_BYTES)
            and value["error_code"] is None,
            "HTTP_TRANSPORT_RESULT_REFUSED",
        )
    else:
        _require(
            value["error_code"] in _ERRORS
            and value["status"]
            == ("INDETERMINATE" if value["connect_attempted"] else "NOT_PERFORMED"),
            "HTTP_TRANSPORT_RESULT_REFUSED",
        )
        if not value["connect_attempted"]:
            _require(
                value["sent_bytes"] == value["response_bytes"] == 0
                and value["response_digest"] == canary.digest(b""),
                "HTTP_TRANSPORT_RESULT_REFUSED",
            )
    identity = value["identity"]
    _require(
        identity is not None or value["status"] == "NOT_PERFORMED",
        "HTTP_TRANSPORT_RESULT_REFUSED",
    )
    if identity is not None:
        try:
            canary.validate_fixture(identity["fixture"])
        except (ValueError, TypeError, KeyError):
            raise RuntimeHttpActionError("HTTP_TRANSPORT_RESULT_REFUSED") from None
        _require(
            type(identity) is dict
            and set(identity) == {"fixture", "pid", "start_time_ticks", "uid", "gid"}
            and identity["fixture"] == binding["fixture"]
            and type(identity["pid"]) is int
            and identity["pid"] > 1
            and type(identity["start_time_ticks"]) is int
            and identity["start_time_ticks"] > 0
            and type(identity["uid"]) is int
            and identity["uid"] == binding["expected_broker_uid"]
            and type(identity["gid"]) is int
            and identity["gid"] == binding["expected_broker_gid"],
            "HTTP_TRANSPORT_RESULT_REFUSED",
        )
    return _copy(value)
