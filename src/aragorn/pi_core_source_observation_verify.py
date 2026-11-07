"""Independent offline replay of the bounded, single-thread source observer.

No producer code is imported. A pinned JSON capture proves neither acquisition
authenticity nor active health; the protected live lease must enforce those. This
consumer reconstructs recorded read ranges only, never V8 execution semantics.
"""

from __future__ import annotations

import hashlib
import json
import re
import stat
from typing import Any

from .cas import CAS
from .oci_worker_protocol import canonical_json
from .phase3_exit_gate_manifest import _reject_duplicate_pairs, _reject_noninteger_number


_MAX_RAW = 4 * 1024 * 1024
_MAX_EVENTS = 4096
_MAX_SOURCE = 16 * 1024 * 1024
_UINT_MAX = (1 << 63) - 1
_BINDINGS = {"deployment_digest", "runtime_digest", "gate_digest", "node_digest", "producer_digest", "source_inventory_digest"}
_IDENTITY = {"device", "inode", "mode", "nlink", "uid", "gid", "size", "mtime_ns", "ctime_ns"}
_WORKER = {"pid", "start_ticks", "uid", "gid", "cgroup", "unit", "invocation_id"}
_CLOCK = {"boot_id", "clock_id", "time_namespace_inode"}
_COMMON = {"seq", "boottime_ns", "kind"}
_ARM64_READS = {63: "read", 67: "pread64"}
_ARM64_ALLOWED = {
    56, 57, 62, 63, 67, 79, 80, 93, 94, 98, 113, 124, 134, 135, 172, 173,
    174, 175, 176, 177, 178, 214, 215, 221, 222, 226, 233, 261, 278,
}


class PiSourceObservationVerificationError(ValueError):
    """Preserve the capture: it cannot establish complete source-range evidence."""


def _require(condition, reason):
    if not condition:
        raise PiSourceObservationVerificationError(reason)


def _fields(value, names):
    _require(type(value) is dict and set(value) == set(names), "SOURCE_REPLAY_FIELDS")
    return value


def _uint(value, minimum=0, maximum=_UINT_MAX):
    _require(type(value) is int and minimum <= value <= maximum, "SOURCE_REPLAY_INTEGER")
    return value


def _pin(value):
    _require(type(value) is str and re.fullmatch(r"sha256:[0-9a-f]{64}", value), "SOURCE_REPLAY_PIN")
    return value


def _digest(raw):
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def _document(raw):
    _require(type(raw) is bytes and 0 < len(raw) <= _MAX_RAW and b"\x00" not in raw, "SOURCE_REPLAY_RAW_BOUND")
    try:
        value = json.loads(raw.decode("utf-8", "strict"), object_pairs_hook=_reject_duplicate_pairs,
                           parse_float=_reject_noninteger_number, parse_constant=_reject_noninteger_number)
        _require(type(value) is dict and canonical_json(value) == raw, "SOURCE_REPLAY_CANONICAL")
        return value
    except (ValueError, UnicodeError, RecursionError) as exc:
        raise PiSourceObservationVerificationError("SOURCE_REPLAY_JSON") from exc


def _same(left, right, reason):
    _require(canonical_json(left) == canonical_json(right), reason)


def _identity(value):
    _fields(value, _IDENTITY)
    for name in _IDENTITY:
        _uint(value[name], minimum=1 if name in {"inode", "nlink"} else 0)
    return value


def _worker(value):
    _fields(value, _WORKER)
    for field in ("pid", "start_ticks", "uid", "gid"):
        _uint(value[field], 1)
    for field in ("cgroup", "unit", "invocation_id"):
        _require(type(value[field]) is str and 0 < len(value[field]) <= 4096, "SOURCE_REPLAY_WORKER")
    return value


def _clock(value):
    _fields(value, _CLOCK)
    _require(value["clock_id"] == "CLOCK_BOOTTIME" and type(value["boot_id"]) is str
             and re.fullmatch(r"[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}", value["boot_id"]), "SOURCE_REPLAY_CLOCK")
    _uint(value["time_namespace_inode"], 1)
    return value


def _sources(raw, expected_pin, evidence_cas):
    _require(type(raw) is bytes and 0 < len(raw) <= _MAX_RAW, "SOURCE_REPLAY_RAW_BOUND")
    _require(_digest(raw) == _pin(expected_pin), "SOURCE_REPLAY_INVENTORY_PIN")
    inventory = _fields(_document(raw), {"schema", "sources"})
    _require(inventory["schema"] == "aragorn/pi-core-source-inventory/v1", "SOURCE_REPLAY_INVENTORY_SCHEMA")
    _require(evidence_cas.read(expected_pin, max_bytes=_MAX_RAW) == raw, "SOURCE_REPLAY_INVENTORY_CUSTODY")
    rows = inventory["sources"]
    _require(type(rows) is list and 0 < len(rows) <= 512, "SOURCE_REPLAY_SOURCE_COUNT")
    sources, identities = {}, set()
    for row in rows:
        _fields(row, {"path", "digest", "identity"})
        path = row["path"]
        _require(type(path) is str and path.startswith("/") and len(path) <= 4096
                 and not any(part in {"", ".", ".."} for part in path.split("/")[1:])
                 and path not in sources, "SOURCE_REPLAY_SOURCE_PATH")
        identity = _identity(row["identity"])
        _require(stat.S_ISREG(identity["mode"]) and identity["nlink"] == 1
                 and identity["uid"] == identity["gid"] == 0
                 and not identity["mode"] & 0o7222 and identity["size"] <= _MAX_SOURCE,
                 "SOURCE_REPLAY_IMMUTABLE_FILE")
        object_id = identity["device"], identity["inode"]
        _require(object_id not in identities, "SOURCE_REPLAY_SOURCE_ALIAS")
        identities.add(object_id)
        source = evidence_cas.read(_pin(row["digest"]), max_bytes=_MAX_SOURCE)
        _require(len(source) == identity["size"] and _digest(source) == row["digest"], "SOURCE_REPLAY_SOURCE_BYTES")
        sources[path] = row
    return inventory, sources


def verify_pi_source_observation(
    raw: bytes, *, expected_observation_digest: str, expected_bindings: dict,
    expected_worker: dict, expected_clock: dict, source_inventory_raw: bytes,
    expected_gate_identity: dict,
    expected_challenge: dict, boundary_boottime_ns: int, evidence_cas: CAS,
) -> dict[str, Any]:
    """Replay exact operator-pinned records; return no active authority.

    Expected identity, pins, challenge and boundary time must be independently
    held by the caller, not copied out of the capture under evaluation. Refused or
    closed captures remain retained but raise instead of qualifying coverage.
    """
    _require(type(raw) is bytes and 0 < len(raw) <= _MAX_RAW, "SOURCE_REPLAY_RAW_BOUND")
    _require(_digest(raw) == _pin(expected_observation_digest), "SOURCE_REPLAY_CAPTURE_PIN")
    _require(evidence_cas.read(expected_observation_digest, max_bytes=_MAX_RAW) == raw, "SOURCE_REPLAY_CAPTURE_CUSTODY")
    record = _fields(_document(raw), {"schema", "architecture", "bindings", "worker", "clock", "sources", "state", "events", "accounting"})
    _require(record["schema"] == "aragorn/pi-core-source-observation/v1" and record["state"] == "HELD", "SOURCE_REPLAY_NOT_HELD")
    _require(record["architecture"] == "linux-arm64", "SOURCE_REPLAY_UNSUPPORTED_ABI")
    _fields(expected_bindings, _BINDINGS)
    for pin in expected_bindings.values():
        _pin(pin)
    _same(record["bindings"], expected_bindings, "SOURCE_REPLAY_BINDINGS")
    _same(_worker(record["worker"]), _worker(expected_worker), "SOURCE_REPLAY_WORKER_JOIN")
    _same(_clock(record["clock"]), _clock(expected_clock), "SOURCE_REPLAY_CLOCK_JOIN")
    inventory, sources = _sources(source_inventory_raw, expected_bindings["source_inventory_digest"], evidence_cas)
    _same(record["sources"], inventory["sources"], "SOURCE_REPLAY_SOURCE_JOIN")
    _fields(expected_challenge, {"nonce", "issued_ns", "deadline_ns"})
    _require(type(expected_challenge["nonce"]) is str and re.fullmatch(r"[0-9a-f]{64}", expected_challenge["nonce"]), "SOURCE_REPLAY_NONCE")
    issued, deadline = (_uint(expected_challenge[name]) for name in ("issued_ns", "deadline_ns"))
    _require(deadline - issued == 100_000_000, "SOURCE_REPLAY_CHALLENGE_BUDGET")
    _uint(boundary_boottime_ns)
    events = record["events"]
    _require(type(events) is list and 0 < len(events) <= _MAX_EVENTS, "SOURCE_REPLAY_EVENT_BOUND")
    pid = expected_worker["pid"]
    counters = dict(stops_acquired=0, reads_entered=0, reads_exited=0, bytes_read=0, pending_reads=0, refusals=0, events_retained=len(events))
    pending, completed, coverage, read_paths = {}, set(), {path: [] for path in sources}, set()
    armed, executed, challenged, previous_time, last_stop = False, False, False, 0, None
    syscall_pending = None
    challenge_nonces, last_challenge_stamp = set(), None
    for index, event in enumerate(events, 1):
        _require(type(event) is dict and _COMMON <= set(event), "SOURCE_REPLAY_EVENT_FIELDS")
        _require(type(event["seq"]) is int and event["seq"] == index, "SOURCE_REPLAY_SEQUENCE")
        stamp = _uint(event["boottime_ns"])
        _require(previous_time <= stamp <= boundary_boottime_ns, "SOURCE_REPLAY_CHRONOLOGY")
        previous_time = stamp
        kind = event["kind"]
        _require(type(kind) is str, "SOURCE_REPLAY_EVENT_KIND")
        if "pid" in event:
            _uint(event["pid"], 1, (1 << 31) - 1)
        if kind == "ARMED":
            _fields(event, _COMMON | {"tasks", "options", "gate_identity"})
            _require(index == 1 and not armed and event["tasks"] == [pid], "SOURCE_REPLAY_ARMING")
            _require(type(event["options"]) is int and event["options"] == 0x10005f, "SOURCE_REPLAY_PTRACE_OPTIONS")
            _same(_identity(event["gate_identity"]), _identity(expected_gate_identity), "SOURCE_REPLAY_GATE_IDENTITY")
            armed = True
        elif kind == "STOP":
            _fields(event, _COMMON | {"pid", "status", "op", "syscall", "args", "result", "is_error", "event", "event_message"})
            _require(armed and event["pid"] == pid, "SOURCE_REPLAY_STOP_OWNER")
            _uint(event["status"], 0, (1 << 32) - 1)
            _uint(event["event"], 0, 65535)
            _require(event["status"] & 255 == 127 and event["status"] >> 16 == event["event"], "SOURCE_REPLAY_STOP_STATUS")
            _require(event["event"] not in {1, 2, 3}, "SOURCE_REPLAY_UNSUPPORTED_THREAD_OR_FORK")
            if event["event_message"] is not None:
                _uint(event["event_message"])
            _require(type(event["op"]) is str and event["op"] in {"ENTRY", "EXIT", "NONE"}, "SOURCE_REPLAY_STOP_OP")
            signal = event["status"] >> 8 & 255
            if event["op"] in {"ENTRY", "EXIT"}:
                _require(event["event"] == 0 and signal == 133, "SOURCE_REPLAY_SYSCALL_STOP")
            else:
                allowed_signals = {5, 19} if index == 2 and event["event"] == 128 else {5}
                _require(event["event"] in {4, 128} and signal in allowed_signals, "SOURCE_REPLAY_UNSUPPORTED_STOP")
            _require(index != 2 or event["op"] == "NONE" and event["event"] == 128, "SOURCE_REPLAY_INITIAL_STOP")
            if event["op"] == "ENTRY":
                syscall = _uint(event["syscall"])
                _require(syscall_pending is None and (executed or syscall == 221), "SOURCE_REPLAY_SYSCALL_PAIRING")
                syscall_pending = event
                _require(type(event["args"]) is list and len(event["args"]) == 6, "SOURCE_REPLAY_SYSCALL_ARGUMENTS")
                for argument in event["args"]:
                    _uint(argument, maximum=(1 << 64) - 1)
                _require(event["result"] is event["is_error"] is None, "SOURCE_REPLAY_ENTRY_RESULT")
                _require(syscall in _ARM64_ALLOWED and not (executed and syscall == 221), "SOURCE_REPLAY_UNSUPPORTED_SYSCALL")
                if syscall == 222:
                    _require(event["args"][3] & 0x20 and event["args"][4] == (1 << 64) - 1,
                             "SOURCE_REPLAY_FILE_BACKED_MMAP")
                if executed and syscall in _ARM64_READS:
                    _require(index < len(events) and type(events[index]) is dict
                             and events[index].get("kind") == "READ_ENTER", "SOURCE_REPLAY_MISSING_READ_ENTRY")
            elif event["op"] == "EXIT":
                _require(syscall_pending is not None, "SOURCE_REPLAY_ORPHAN_SYSCALL_EXIT")
                _require(type(event["result"]) is int and -(1 << 63) <= event["result"] <= _UINT_MAX
                         and type(event["is_error"]) is bool and event["syscall"] is event["args"] is None,
                         "SOURCE_REPLAY_EXIT_RESULT")
                if syscall_pending["syscall"] == 221:
                    _require(executed and event["result"] == 0 and event["is_error"] is False, "SOURCE_REPLAY_FAILED_EXEC")
                syscall_pending = None
                if pending:
                    _require(index < len(events) and type(events[index]) is dict
                             and events[index].get("kind") == "READ_EXIT", "SOURCE_REPLAY_MISSING_READ_EXIT")
            else:
                _require(event["syscall"] is event["args"] is event["result"] is event["is_error"] is None,
                         "SOURCE_REPLAY_NONE_FIELDS")
            counters["stops_acquired"] += 1
            last_stop = event
            if event["event"] == 4:
                _require(not executed and syscall_pending is not None and syscall_pending["syscall"] == 221,
                         "SOURCE_REPLAY_EXEC_SYSCALL")
                _require(index < len(events) and type(events[index]) is dict
                         and events[index].get("kind") == "EXEC", "SOURCE_REPLAY_MISSING_EXEC")
        elif kind == "EXEC":
            _fields(event, _COMMON | {"pid", "digest"})
            _require(armed and not executed and not pending and event["pid"] == pid
                     and event["digest"] == expected_bindings["node_digest"]
                     and last_stop is not None and last_stop["event"] == 4
                     and last_stop["event_message"] == pid
                     and events[index - 2] is last_stop, "SOURCE_REPLAY_NODE_EXEC")
            executed = True
        elif kind == "READ_ENTER":
            _fields(event, _COMMON | {"call_id", "pid", "syscall", "fd", "offset", "count", "path", "digest", "identity"})
            call_id = _uint(event["call_id"], 1)
            _require(executed and not pending and call_id not in completed
                     and event["pid"] == pid and event["syscall"] in {"read", "pread64"}, "SOURCE_REPLAY_READ_ENTRY")
            _uint(event["fd"], maximum=(1 << 31) - 1)
            _uint(event["offset"])
            _uint(event["count"], maximum=_MAX_SOURCE)
            path = event["path"]
            _require(type(path) is str and path in sources, "SOURCE_REPLAY_UNKNOWN_SOURCE")
            _same(event["identity"], sources[path]["identity"], "SOURCE_REPLAY_READ_IDENTITY")
            _require(event["digest"] == sources[path]["digest"], "SOURCE_REPLAY_READ_DIGEST")
            _require(event["offset"] <= sources[path]["identity"]["size"]
                     and event["offset"] + event["count"] <= _UINT_MAX, "SOURCE_REPLAY_ENTRY_RANGE")
            _require(last_stop is not None and last_stop["op"] == "ENTRY"
                     and events[index - 2] is last_stop
                     and _ARM64_READS.get(last_stop["syscall"]) == event["syscall"], "SOURCE_REPLAY_READ_ENTRY_STOP")
            arguments = last_stop["args"]
            _require(arguments[0] == event["fd"] and arguments[2] == event["count"], "SOURCE_REPLAY_READ_ARGUMENT_JOIN")
            if event["syscall"] == "pread64":
                _require(arguments[3] == event["offset"], "SOURCE_REPLAY_PREAD_OFFSET")
            pending[call_id] = event
            counters["reads_entered"] += 1
        elif kind == "READ_EXIT":
            _fields(event, _COMMON | {"call_id", "pid", "result", "is_error", "identity"})
            call_id = _uint(event["call_id"], 1)
            _require(call_id in pending and event["pid"] == pid, "SOURCE_REPLAY_UNPAIRED_EXIT")
            entry = pending.pop(call_id)
            _same(event["identity"], entry["identity"], "SOURCE_REPLAY_CHANGED_FILE")
            value = event["result"]
            _require(type(value) is int and -(1 << 63) <= value <= _UINT_MAX
                     and type(event["is_error"]) is bool and event["is_error"] == (value < 0), "SOURCE_REPLAY_READ_RESULT")
            _require(last_stop is not None and last_stop["op"] == "EXIT"
                     and events[index - 2] is last_stop and last_stop["result"] == value
                     and last_stop["is_error"] == event["is_error"], "SOURCE_REPLAY_READ_EXIT_STOP")
            if value > 0:
                _require(value <= entry["count"] and entry["offset"] + value <= entry["identity"]["size"], "SOURCE_REPLAY_RANGE_BOUND")
                coverage[entry["path"]].append((entry["offset"], entry["offset"] + value))
                counters["bytes_read"] += value
            elif value < 0:
                _require(value >= -4095, "SOURCE_REPLAY_ERRNO")
            counters["reads_exited"] += 1
            if not event["is_error"]:
                read_paths.add(entry["path"])
            completed.add(call_id)
        elif kind == "CHALLENGE":
            _fields(event, _COMMON | {"nonce", "issued_ns", "deadline_ns", "stops_before", "stops_after", "tasks", "all_stopped"})
            _require(executed and not pending and syscall_pending is None, "SOURCE_REPLAY_CHALLENGE_STATE")
            nonce = event["nonce"]
            _require(type(nonce) is str and re.fullmatch(r"[0-9a-f]{64}", nonce)
                     and nonce not in challenge_nonces, "SOURCE_REPLAY_CHALLENGE_REUSE")
            challenge_nonces.add(nonce)
            issued, deadline = _uint(event["issued_ns"]), _uint(event["deadline_ns"])
            _require(deadline - issued == 100_000_000 and (last_challenge_stamp is None or last_challenge_stamp < issued),
                     "SOURCE_REPLAY_CHALLENGE_BUDGET_OR_OVERLAP")
            if index == len(events):
                _same({key: event[key] for key in expected_challenge}, expected_challenge, "SOURCE_REPLAY_CHALLENGE_JOIN")
                _require(boundary_boottime_ns - stamp < 200_000_000, "SOURCE_REPLAY_STALE_CHALLENGE")
            before, after = _uint(event["stops_before"]), _uint(event["stops_after"])
            _require(after == counters["stops_acquired"] and after == before + 1
                     and event["tasks"] == [pid] and event["all_stopped"] is True
                     and issued <= stamp < deadline,
                     "SOURCE_REPLAY_CHALLENGE_PROGRESS")
            _require(last_stop is not None and last_stop["op"] == "NONE" and last_stop["event"] == 128
                     and events[index - 2] is last_stop and issued <= last_stop["boottime_ns"] <= stamp,
                     "SOURCE_REPLAY_CHALLENGE_INTERRUPT")
            stops = [row for row in events[:index - 1] if row["kind"] == "STOP"]
            _require(all(issued <= row["boottime_ns"] <= stamp for row in stops[before:after]), "SOURCE_REPLAY_CHALLENGE_STOP_INTERVAL")
            challenged = True
            last_challenge_stamp = stamp
        elif kind in {"REFUSED", "CLEANUP"}:
            raise PiSourceObservationVerificationError("SOURCE_REPLAY_RETAINED_REFUSAL_OR_CLEANUP")
        else:
            raise PiSourceObservationVerificationError("SOURCE_REPLAY_UNSUPPORTED_EVENT")
    _require(armed and executed and challenged and not pending and syscall_pending is None
             and events[1]["kind"] == "STOP" and events[-1]["kind"] == "CHALLENGE"
             and read_paths == set(sources), "SOURCE_REPLAY_INCOMPLETE_INTERVAL")
    counters["pending_reads"] = len(pending)
    _same(record["accounting"], counters, "SOURCE_REPLAY_ACCOUNTING")
    for path, ranges in coverage.items():
        end = 0
        for start, finish in sorted(ranges):
            _require(start <= end, "SOURCE_REPLAY_SOURCE_GAP")
            end = max(end, finish)
        _require(end == sources[path]["identity"]["size"], "SOURCE_REPLAY_SOURCE_INCOMPLETE")
    for row in sources.values():
        evidence_cas.verify(row["digest"], max_bytes=_MAX_SOURCE)
    evidence_cas.verify(expected_observation_digest, max_bytes=_MAX_RAW)
    evidence_cas.verify(expected_bindings["source_inventory_digest"], max_bytes=_MAX_RAW)
    return {
        "schema": "aragorn/pi-core-source-observation-replay/v1",
        "status": "CONSISTENT_SOURCE_READ_COVERAGE",
        "authority": "OFFLINE_RECORDED_FILE_DELIVERY_ONLY_NOT_ACTIVE_HEALTH_OR_V8_EXECUTION",
        "observation_digest": expected_observation_digest,
        "source_inventory_digest": expected_bindings["source_inventory_digest"],
        "source_count": len(sources), "completed_reads": counters["reads_exited"],
        "bytes_read": counters["bytes_read"], "challenge_count": len(challenge_nonces),
        "acquisition_authenticity_verified": False, "sensor_health_verified": False,
        "effect_authorized": False, "v8_execution_verified": False, "phase3_qualified": False,
    }
