"""Independent replay of the bounded Node thread/source acquisition contract.

Recorded file delivery and loader mappings are separate claims. This module
imports no acquisition producer and never mints active health or effect authority.
"""

from __future__ import annotations

import re
import stat

from .oci_worker_protocol import canonical_json
from .pi_core_source_observation_verify import (
    PiSourceObservationVerificationError, _clock, _digest, _document, _fields,
    _identity, _pin, _require, _same, _uint, _worker,
)


_MAX_RAW = 4 * 1024 * 1024
_MAX_EVENTS = 4096
_MAX_SOURCE = 16 * 1024 * 1024
_MAX_LOADER = 256 * 1024 * 1024
_MAX_TASKS = 64
_U64 = (1 << 64) - 1
_I64 = (1 << 63) - 1
_PINS = {"gate_digest", "node_digest", "producer_digest", "node_observer_digest",
         "source_inventory_digest", "loader_inventory_digest"}
_BINDINGS = _PINS | {"deployment_digest", "runtime_digest", "profile_digest"}
_COMMON = {"seq", "boottime_ns", "kind"}
_STOP = {"pid", "start_ticks", "status", "op", "syscall", "args", "result",
         "is_error", "event", "event_message"}
_READS = {63: "read", 67: "pread64", 65: "readv", 69: "preadv"}
_CREATE = {19: "eventfd", 59: "pipe", 199: "socketpair"}
_CLONE_REQUIRED = 0x50F00
_CLONE_ALLOWED = 0x13D0F00
_ORDINARY = frozenset({20, 21, 22, 23, 24, 25, 29, 48, 56, 57, 61, 62, 64, 66,
    72, 73, 79, 80, 93, 94, 96, 98, 99, 113, 114, 115, 124, 129, 130, 131,
    132, 134, 135, 139, 160, 163, 164, 165, 166, 167, 172, 173, 174, 175,
    176, 177, 178, 198, 200, 201, 202, 203, 204, 205, 208, 209, 210,
    214, 215, 216, 226, 233, 261, 278, 283, 291, 293})


def _tasks(rows):
    _require(type(rows) is list and 0 < len(rows) <= _MAX_TASKS, "NODE_REPLAY_TASK_BOUND")
    result = dict(_task(row) for row in rows)
    _require(len(result) == len(rows) and list(result) == sorted(result), "NODE_REPLAY_TASK_SET")
    return result


def _path(value):
    _require(type(value) is str and value.startswith("/") and len(value) <= 4096
             and not any(part in {"", ".", ".."} for part in value.split("/")[1:])
             and not any(ord(char) < 32 or ord(char) == 127 for char in value), "NODE_REPLAY_PATH")
    return value


def _retained(raw, pin, cas, reason):
    _require(type(raw) is bytes and 0 < len(raw) <= _MAX_RAW
             and _digest(raw) == _pin(pin)
             and cas.read(pin, max_bytes=_MAX_RAW) == raw, reason)
    return _document(raw)


def _inventory(raw, pin, cas, *, loaders=False):
    key = "loaders" if loaders else "sources"
    value = _fields(_retained(raw, pin, cas, "NODE_REPLAY_INVENTORY_PIN"), {"schema", key})
    schema = "aragorn/pi-core-loader-inventory/v1" if loaders else "aragorn/pi-core-node-source-inventory/v2"
    _require(value["schema"] == schema, "NODE_REPLAY_INVENTORY_SCHEMA")
    rows = value[key]
    _require(type(rows) is list and 0 < len(rows) <= 512, "NODE_REPLAY_INVENTORY_BOUND")
    result, objects = {}, set()
    maximum = _MAX_LOADER if loaders else _MAX_SOURCE
    for row in rows:
        _fields(row, {"path", "digest", "identity", "readonly_view"})
        path, identity = _path(row["path"]), _identity(row["identity"])
        _require(path not in result and stat.S_ISREG(identity["mode"])
                 and identity["uid"] == identity["gid"] == 0 and identity["nlink"] == 1
                 and not identity["mode"] & 0o7022 and identity["size"] <= maximum
                 and row["readonly_view"] is True,
                 "NODE_REPLAY_IMMUTABLE_FILE")
        object_id = identity["device"], identity["inode"]
        _require(object_id not in objects, "NODE_REPLAY_FILE_ALIAS")
        objects.add(object_id)
        data = cas.read(_pin(row["digest"]), max_bytes=maximum)
        _require(len(data) == identity["size"] and _digest(data) == row["digest"], "NODE_REPLAY_FILE_BYTES")
        result[path] = row
    return value, result


def _profile(raw, bindings, sources, loaders, cas):
    value = _fields(_retained(raw, bindings["profile_digest"], cas, "NODE_REPLAY_PROFILE_PIN"),
                    {"schema", "pins", "sources", "required_sources", "loader_files"})
    _require(value["schema"] == "aragorn/pi-core-node-source-profile/v1", "NODE_REPLAY_PROFILE_SCHEMA")
    _fields(value["pins"], _PINS)
    _same(value["pins"], {key: bindings[key] for key in _PINS}, "NODE_REPLAY_PROFILE_BINDINGS")
    for key, inventory in (("sources", sources), ("loader_files", loaders)):
        rows = value[key]
        _require(type(rows) is list and len(rows) == len(inventory), "NODE_REPLAY_PROFILE_INVENTORY")
        seen = set()
        for row in rows:
            _fields(row, {"path", "digest"})
            path = _path(row["path"])
            _require(path in inventory and path not in seen and row["digest"] == inventory[path]["digest"],
                     "NODE_REPLAY_PROFILE_FILE")
            seen.add(path)
    required = value["required_sources"]
    _require(type(required) is list and required and all(type(path) is str for path in required)
             and len(required) == len(set(required)) and set(required) <= set(sources),
             "NODE_REPLAY_REQUIRED_SOURCES")
    return value, set(required)


def _task(value):
    _fields(value, {"pid", "start_ticks"})
    _uint(value["pid"], 1, (1 << 31) - 1)
    _uint(value["start_ticks"], 1)
    return value["pid"], value["start_ticks"]


def _result(value, is_error):
    _require(type(value) is int and -4095 <= value <= _I64 and type(is_error) is bool
             and is_error == (value < 0), "NODE_REPLAY_SYSCALL_RESULT")


def _input_arguments(event, entry):
    number, args = entry["syscall"], entry["args"]
    _require(number in _READS and event["syscall"] == _READS[number]
             and type(event["fd"]) is int and event["fd"] == args[0]
             and 0 <= event["fd"] < 2**31, "NODE_REPLAY_READ_ARGUMENTS")
    if number in {65, 69}:
        _require(0 < args[2] <= 128 and type(event["iovecs"]) is str
                 and re.fullmatch(r"[0-9a-f]+", event["iovecs"]) is not None
                 and len(event["iovecs"]) == args[2] * 32,
                 "NODE_REPLAY_IOVECS")
        raw = bytes.fromhex(event["iovecs"])
        count = sum(int.from_bytes(raw[pos + 8:pos + 16], "little") for pos in range(0, len(raw), 16))
    else:
        _require(event["iovecs"] is None, "NODE_REPLAY_NONVECTOR_INPUT")
        count = args[2]
    _require(type(event["count"]) is int and event["count"] == count and 0 <= count <= _MAX_SOURCE,
             "NODE_REPLAY_INPUT_BOUND")
    _require(number != 69 or args[4] == 0, "NODE_REPLAY_PREADV_OFFSET")


def _fd_identity(value):
    _fields(value, {"device", "inode", "mode"})
    for name in value:
        _uint(value[name], 1 if name == "inode" else 0)
    return value["device"], value["inode"], value["mode"]


def verify_pi_node_source_observation(
    raw, *, expected_observation_digest, expected_bindings, expected_worker,
    expected_clock, expected_gate_identity, expected_profile_raw,
    source_inventory_raw, loader_inventory_raw, expected_root_peer,
    expected_root_endpoints, expected_challenge, boundary_boottime_ns, evidence_cas,
):
    """Replay caller-pinned recorded delivery only, not acquisition authenticity."""
    record = _fields(_retained(raw, expected_observation_digest, evidence_cas, "NODE_REPLAY_CAPTURE_PIN"),
                     {"schema", "architecture", "bindings", "worker", "clock", "sources",
                      "required_sources", "loaders", "state", "events", "accounting"})
    _require(record["schema"] == "aragorn/pi-core-node-source-observation/v2"
             and record["architecture"] == "linux-arm64" and record["state"] == "HELD",
             "NODE_REPLAY_HELD_ARM64_REQUIRED")
    _fields(expected_bindings, _BINDINGS)
    for pin in expected_bindings.values():
        _pin(pin)
    _same(record["bindings"], expected_bindings, "NODE_REPLAY_BINDINGS")
    _same(_worker(record["worker"]), _worker(expected_worker), "NODE_REPLAY_WORKER")
    _same(_clock(record["clock"]), _clock(expected_clock), "NODE_REPLAY_CLOCK")
    source_document, sources = _inventory(source_inventory_raw, expected_bindings["source_inventory_digest"], evidence_cas)
    loader_document, loaders = _inventory(loader_inventory_raw, expected_bindings["loader_inventory_digest"], evidence_cas, loaders=True)
    _require(not set(sources) & set(loaders), "NODE_REPLAY_SOURCE_LOADER_OVERLAP")
    objects = [(row["identity"]["device"], row["identity"]["inode"]) for row in (*sources.values(), *loaders.values())]
    _require(len(objects) == len(set(objects)), "NODE_REPLAY_CROSS_INVENTORY_ALIAS")
    profile, required = _profile(expected_profile_raw, expected_bindings, sources, loaders, evidence_cas)
    _same(record["sources"], source_document["sources"], "NODE_REPLAY_SOURCES")
    _same(record["loaders"], loader_document["loaders"], "NODE_REPLAY_LOADERS")
    _same(record["required_sources"], profile["required_sources"], "NODE_REPLAY_REQUIRED_JOIN")
    _require(type(expected_root_peer) in (tuple, list) and len(expected_root_peer) == 3
             and type(expected_root_peer[0]) is int and expected_root_peer[0] > 0
             and type(expected_root_peer[1]) is int and expected_root_peer[1] == 0
             and type(expected_root_peer[2]) is int and expected_root_peer[2] == 0,
             "NODE_REPLAY_ROOT_PEER")
    _require(type(expected_root_endpoints) in {list, tuple} and expected_root_endpoints
             and len(expected_root_endpoints) <= 8, "NODE_REPLAY_ROOT_ENDPOINTS")
    endpoint_paths = {_path(path) for path in expected_root_endpoints}
    _require(len(endpoint_paths) == len(expected_root_endpoints), "NODE_REPLAY_DUPLICATE_ROOT_ENDPOINT")
    _fields(expected_challenge, {"nonce", "issued_ns", "deadline_ns"})
    _uint(boundary_boottime_ns)
    leader = expected_worker["pid"]
    generations = {leader: expected_worker["start_ticks"]}
    tasks = {leader: {"joined": True, "stopped": False, "initial": True, "stop": None, "call": None}}
    counters = dict(stops_acquired=0, reads_entered=0, reads_exited=0, bytes_read=0,
                    pending_reads=0, refusals=0, events_retained=0, threads_observed=1,
                    threads_exited=0, maps_entered=0, maps_exited=0, io_entered=0,
                    io_exited=0, pending_syscalls=0)
    events = record["events"]
    _require(type(events) is list and 0 < len(events) <= _MAX_EVENTS, "NODE_REPLAY_EVENT_BOUND")
    armed, executed, stamp, epoch = False, False, 0, 0
    gate_release, awaiting_gate_release, awaiting_thread_start = False, None, None
    barrier, file_operation = None, None
    seen_nonces, last_challenge = set(), 0
    completed_calls, created_objects, stdio = set(), {}, {}
    ranges, read_paths = {path: [] for path in sources}, set()
    pending_children = {}

    def held_epoch(value):
        _require(type(value) is int and value == epoch and barrier is not None
                 and set(barrier["tasks"]) == set(tasks), "NODE_REPLAY_EPOCH")
        for tid, task in tasks.items():
            _require(task["joined"] and task["stopped"] and task["stop"]["seq"] == barrier["stops"][tid]
                     and generations[tid] == barrier["tasks"][tid], "NODE_REPLAY_NOT_ALL_STOPPED")

    def entered(event, number=None):
        tid = _uint(event["pid"], 1, (1 << 31) - 1)
        _require(tid in tasks and tasks[tid]["joined"], "NODE_REPLAY_UNKNOWN_THREAD")
        call = tasks[tid]["call"]
        _require(call is not None and call["entry"]["seq"] == event["call_id"]
                 and event["call_id"] not in completed_calls and call.get("exit") is None
                 and call.get("operation") is None
                 and (number is None or call["entry"]["syscall"] == number), "NODE_REPLAY_ENTRY_JOIN")
        held_epoch(event["epoch"])
        return tid, call

    for index, event in enumerate(events, 1):
        _require(type(event) is dict and _COMMON <= set(event) and type(event["seq"]) is int
                 and event["seq"] == index, "NODE_REPLAY_SEQUENCE")
        now = _uint(event["boottime_ns"])
        _require(stamp <= now <= boundary_boottime_ns, "NODE_REPLAY_CHRONOLOGY")
        stamp = now
        kind = event["kind"]
        _require(type(kind) is str, "NODE_REPLAY_EVENT_KIND")
        _require(awaiting_gate_release is None or kind == "GATE_RELEASE", "NODE_REPLAY_MISSING_GATE_RELEASE")
        _require(awaiting_thread_start is None or kind == "THREAD_START", "NODE_REPLAY_MISSING_THREAD_START")
        if kind == "ARMED":
            _fields(event, _COMMON | {"tasks", "options", "gate_identity"})
            _require(index == 1 and not armed and event["tasks"] == [leader]
                     and type(event["options"]) is int and event["options"] == 0x10005F,
                     "NODE_REPLAY_ARMING")
            _same(_identity(event["gate_identity"]), _identity(expected_gate_identity), "NODE_REPLAY_GATE")
            armed = True
        elif kind == "RESUME":
            _fields(event, _COMMON | {"pid", "start_ticks", "request"})
            tid, generation = _task({key: event[key] for key in ("pid", "start_ticks")})
            _require(tid in tasks and generations[tid] == generation and tasks[tid]["joined"]
                     and tasks[tid]["stopped"] and not tasks[tid]["initial"] and len(stdio) == 3,
                     "NODE_REPLAY_RESUME_CUSTODY")
            _require(event["request"] in {"SYSCALL", "CONT"}, "NODE_REPLAY_RESUME_REQUEST")
            if event["request"] == "CONT":
                _require(tasks[tid]["stop"]["event"] == 6, "NODE_REPLAY_CONT_ONLY_EXIT")
            else:
                _require(tasks[tid]["stop"]["event"] != 6, "NODE_REPLAY_EXIT_REQUIRES_CONT")
            call = tasks[tid]["call"]
            if call is not None and call.get("exit") is None:
                number, args = call["entry"]["syscall"], call["entry"]["args"]
                sensitive = number in _READS or number in {220, 435} or number == 222 and not args[3] & 0x20
                _require(not sensitive or call.get("operation") is not None, "NODE_REPLAY_UNANNOTATED_EFFECT")
                if number in _CREATE:
                    held_epoch(epoch)
                    _require(file_operation is None or file_operation == tid, "NODE_REPLAY_CREATE_FD_RACE")
                    file_operation = tid
            _require(call is None or call.get("exit") is None, "NODE_REPLAY_UNCONSUMED_EXIT")
            _require(file_operation is None or file_operation == tid, "NODE_REPLAY_SHARED_FD_RACE")
            tasks[tid]["resumes"] = tasks[tid].get("resumes", 0) + 1
            tasks[tid]["stopped"] = False
        elif kind == "STOP":
            _fields(event, _COMMON | _STOP)
            tid, generation = _task({key: event[key] for key in ("pid", "start_ticks")})
            _require(armed and tid in tasks and not tasks[tid]["stopped"], "NODE_REPLAY_STOP_OWNER")
            if generations[tid] is None:
                generations[tid] = generation
            _require(generations[tid] == generation, "NODE_REPLAY_THREAD_REUSED")
            status = _uint(event["status"], 0, (1 << 32) - 1)
            code, signal = status >> 16, status >> 8 & 255
            _require(type(event["event"]) is int and event["event"] == code,
                     "NODE_REPLAY_STOP_EVENT")
            counters["stops_acquired"] += 1
            task = tasks[tid]
            task["stop"] = event
            if status & 255 != 127:
                _require(task.get("exit_seen") and event["op"] == "NONE"
                         and event["syscall"] is event["args"] is event["result"] is event["is_error"] is None,
                         "NODE_REPLAY_UNEXPECTED_TERMINAL")
                _require(code == 0 and event["event_message"] is None
                         and (status & 127 == 0 or 0 < status & 127 < 127), "NODE_REPLAY_TERMINAL_STATUS")
                task["terminal"] = status
                continue
            task["stopped"] = True
            _require(event["op"] in {"NONE", "ENTRY", "EXIT"}, "NODE_REPLAY_STOP_OPERATION")
            if event["op"] == "NONE":
                _require(event["syscall"] is event["args"] is event["result"] is event["is_error"] is None
                         and code in {3, 4, 6, 128}, "NODE_REPLAY_EVENT_FIELDS")
                allowed = {5, 19} if task["initial"] else {5}
                _require(signal in allowed and (not task["initial"] or code == 128), "NODE_REPLAY_STOP_SIGNAL")
                task["initial"] = False
                if code == 3:
                    call = task["call"]
                    _require(call is not None and call.get("operation", {}).get("kind") == "CLONE_REQUEST",
                             "NODE_REPLAY_UNREQUESTED_CLONE")
                    _require("child" not in call, "NODE_REPLAY_REPEATED_CLONE_EVENT")
                    child = _uint(event["event_message"], 1, (1 << 31) - 1)
                    _require(child not in generations and len(tasks) < _MAX_TASKS, "NODE_REPLAY_THREAD_BOUND_OR_REUSE")
                    generations[child] = None
                    tasks[child] = {"joined": False, "stopped": False, "initial": True, "stop": None, "call": None}
                    pending_children[child] = (tid, call["operation"])
                    call["child"] = child
                elif code == 4:
                    _require(tid == leader and not executed and task["call"] is not None
                             and task["call"]["entry"]["syscall"] == 221 and event["event_message"] == leader,
                             "NODE_REPLAY_FIXED_EXEC")
                elif code == 6:
                    task["exit_seen"] = True
                elif event["event_message"] is not None:
                    raise PiSourceObservationVerificationError("NODE_REPLAY_INTERRUPT_MESSAGE")
            else:
                _require(code == 0 and signal == 133 and not task["initial"] and task["joined"]
                         and event["event_message"] is None, "NODE_REPLAY_SYSCALL_STOP")
                if event["op"] == "ENTRY":
                    number = _uint(event["syscall"])
                    _require(task["call"] is None and (executed or tid == leader and number == 221),
                             "NODE_REPLAY_SYSCALL_PAIRING")
                    _require(type(event["args"]) is list and len(event["args"]) == 6
                             and event["result"] is event["is_error"] is None, "NODE_REPLAY_SYSCALL_ARGUMENTS")
                    for argument in event["args"]:
                        _uint(argument, maximum=_U64)
                    _require(not (executed and number == 221), "NODE_REPLAY_LATER_EXEC")
                    _require(number in _ORDINARY or number in _READS or number in _CREATE
                             or number in {220, 221, 222, 435}, "NODE_REPLAY_UNSUPPORTED_SYSCALL")
                    args = event["args"]
                    if number == 56:
                        _require(args[2] & (3 | 0x40 | 0x200 | 0x400 | 0x410000) == 0,
                                 "NODE_REPLAY_WRITE_OPEN")
                    elif number == 29:
                        _require(args[0] in {0, 1, 2} and args[1] in {0x5401, 0x5413},
                                 "NODE_REPLAY_IOCTL_SCOPE")
                    elif number == 222 and args[3] & 0x20:
                        _require(args[4] == _U64, "NODE_REPLAY_ANONYMOUS_MAP_FD")
                    task["call"] = {"entry": event}
                    task["virgin"] = False
                else:
                    call = task["call"]
                    if call is None and not executed and not gate_release and tid == leader:
                        _require(task.get("resumes") == 1 and event["syscall"] is event["args"] is None
                                 and event["result"] == 0 and event["is_error"] is False,
                                 "NODE_REPLAY_GATE_RELEASE_EXIT")
                        awaiting_gate_release = event["seq"]
                        continue
                    if call is None and tid != leader and task.get("virgin"):
                        _require(task.get("resumes") == 1 and event["syscall"] is event["args"] is None and event["result"] == 0
                                 and event["is_error"] is False, "NODE_REPLAY_THREAD_START_EXIT")
                        awaiting_thread_start = tid, event["seq"]
                        continue
                    _require(call is not None and event["syscall"] is event["args"] is None,
                             "NODE_REPLAY_ORPHAN_EXIT")
                    _result(event["result"], event["is_error"])
                    number = call["entry"]["syscall"]
                    if number == 221:
                        _require(executed and event["result"] == 0, "NODE_REPLAY_FAILED_EXEC")
                    operation = call.get("operation")
                    if operation is not None and operation["kind"] in {"READ_ENTER", "LOADER_READ_ENTER", "MAP_ENTER", "IO_ENTER"}:
                        call["exit"] = event
                    elif number in _CREATE and not event["is_error"]:
                        call["exit"] = event
                    else:
                        if operation is not None and operation["kind"] == "CLONE_REQUEST":
                            _require(event["is_error"] and "child" not in call or
                                     not event["is_error"] and call.get("child") == event["result"]
                                     and tasks[call["child"]]["joined"] and not tasks[call["child"]]["initial"],
                                     "NODE_REPLAY_CLONE_RESULT")
                            file_operation = None
                        elif number in _CREATE:
                            file_operation = None
                        completed_calls.add(call["entry"]["seq"])
                        task["call"] = None
        elif kind == "GATE_RELEASE":
            _fields(event, _COMMON | {"pid", "stop_seq"})
            _require(awaiting_gate_release is not None and event["pid"] == leader
                     and event["stop_seq"] == awaiting_gate_release, "NODE_REPLAY_GATE_RELEASE_JOIN")
            gate_release, awaiting_gate_release = True, None
        elif kind == "THREAD_START":
            _fields(event, _COMMON | {"pid", "stop_seq", "clone_call_seq"})
            _require(awaiting_thread_start == (event["pid"], event["stop_seq"])
                     and event["clone_call_seq"] == tasks[event["pid"]]["clone_call_seq"],
                     "NODE_REPLAY_THREAD_START_JOIN")
            tasks[event["pid"]]["virgin"] = False
            awaiting_thread_start = None
        elif kind == "EXEC":
            _fields(event, _COMMON | {"pid", "digest"})
            stop = tasks[leader]["stop"]
            _require(not executed and event["pid"] == leader and event["digest"] == expected_bindings["node_digest"]
                     and stop is not None and stop["event"] == 4 and events[index - 2] is stop,
                     "NODE_REPLAY_EXEC_JOIN")
            executed = True
        elif kind == "THREAD":
            _fields(event, _COMMON | {"pid", "start_ticks", "parent_pid", "flags", "clone_call_seq"})
            child, generation = _task({key: event[key] for key in ("pid", "start_ticks")})
            _require(child in pending_children and not tasks[child]["joined"], "NODE_REPLAY_THREAD_ORIGIN")
            parent, request = pending_children.pop(child)
            _require(event["parent_pid"] == parent and event["flags"] == request["flags"]
                     and event["clone_call_seq"] == request["seq"], "NODE_REPLAY_THREAD_CLONE_JOIN")
            _require(generations[child] in {None, generation}, "NODE_REPLAY_THREAD_GENERATION")
            generations[child] = generation
            tasks[child]["joined"] = True
            tasks[child]["virgin"] = True
            tasks[child]["clone_call_seq"] = event["clone_call_seq"]
            counters["threads_observed"] += 1
        elif kind == "ALL_STOP":
            _fields(event, _COMMON | {"epoch", "tasks", "stop_seqs"})
            _require(type(event["epoch"]) is int and event["epoch"] == epoch + 1, "NODE_REPLAY_EPOCH_SEQUENCE")
            inventory = _tasks(event["tasks"])
            _require(inventory == {tid: generations[tid] for tid in tasks} and not pending_children,
                     "NODE_REPLAY_INCOMPLETE_TASK_INVENTORY")
            _require(type(event["stop_seqs"]) is list and len(event["stop_seqs"]) == len(inventory),
                     "NODE_REPLAY_STOP_INVENTORY")
            stops = dict(zip(inventory, event["stop_seqs"]))
            for tid, sequence in stops.items():
                _uint(sequence, 1)
                _require(tasks[tid]["joined"] and tasks[tid]["stopped"]
                         and tasks[tid]["stop"]["seq"] == sequence, "NODE_REPLAY_UNHELD_STOP")
            epoch += 1
            barrier = {"tasks": inventory, "stops": stops}
        elif kind == "STDIO":
            _fields(event, _COMMON | {"descriptors", "epoch"})
            held_epoch(event["epoch"])
            _require(not executed and not stdio and type(event["descriptors"]) is list
                     and len(event["descriptors"]) == 3, "NODE_REPLAY_STDIO_SCOPE")
            for row in event["descriptors"]:
                _fields(row, {"fd", "identity", "rdev"})
                fd = _uint(row["fd"], 0, 2)
                object_id = _fd_identity(row["identity"])
                _require(fd not in stdio and stat.S_ISCHR(object_id[2])
                         and type(row["rdev"]) is int and row["rdev"] == 259,
                         "NODE_REPLAY_STDIO_NULL")
                stdio[fd] = object_id
        elif kind in {"READ_ENTER", "LOADER_READ_ENTER", "IO_ENTER"}:
            fields = {"pid", "call_id", "syscall", "fd", "count", "iovecs", "epoch", "identity"}
            fields |= {"channel"} if kind == "IO_ENTER" else {"offset", "path", "digest"}
            _fields(event, _COMMON | fields)
            tid, call = entered(event)
            _input_arguments(event, call["entry"])
            if kind == "IO_ENTER":
                object_id = _fd_identity(event["identity"])
                channel = event["channel"]
                _require(type(channel) is dict and type(channel.get("kind")) is str,
                         "NODE_REPLAY_CHANNEL")
                if channel["kind"] == "root-unix":
                    _fields(channel, {"kind", "peer", "endpoint"})
                    _require(stat.S_ISSOCK(object_id[2]), "NODE_REPLAY_ROOT_SOCKET")
                    _same(channel["peer"], list(expected_root_peer), "NODE_REPLAY_ROOT_PEER_JOIN")
                    _require(_path(channel["endpoint"]) in endpoint_paths, "NODE_REPLAY_ROOT_ENDPOINT_JOIN")
                elif channel["kind"] == "stdio-null":
                    _fields(channel, {"kind", "fd"})
                    fd = _uint(channel["fd"], 0, 2)
                    _require(event["fd"] == fd and stdio.get(fd) == object_id, "NODE_REPLAY_STDIO_IDENTITY")
                else:
                    _fields(channel, {"kind", "created_by"})
                    origin = _uint(channel["created_by"], 1)
                    key = object_id, origin
                    _require(key in created_objects and channel == created_objects[key],
                             "NODE_REPLAY_INTERNAL_CHANNEL_ORIGIN")
                counters["io_entered"] += 1
            else:
                inventory = sources if kind == "READ_ENTER" else loaders
                path = _path(event["path"])
                _require(path in inventory, "NODE_REPLAY_UNPINNED_FILE_READ")
                row = inventory[path]
                _require(event["digest"] == row["digest"], "NODE_REPLAY_READ_DIGEST")
                _same(_identity(event["identity"]), row["identity"], "NODE_REPLAY_READ_IDENTITY")
                offset = _uint(event["offset"], 0, row["identity"]["size"])
                _require(offset + event["count"] < 2**63, "NODE_REPLAY_READ_INTERVAL")
                if call["entry"]["syscall"] in {67, 69}:
                    _require(offset == call["entry"]["args"][3], "NODE_REPLAY_PREAD_OFFSET")
                _require(file_operation is None, "NODE_REPLAY_OVERLAPPING_FILE_OPERATION")
                file_operation = tid
                if kind == "READ_ENTER":
                    counters["reads_entered"] += 1
            call["operation"] = event
        elif kind == "MAP_ENTER":
            _fields(event, _COMMON | {"pid", "call_id", "fd", "offset", "length", "prot", "flags",
                                     "path", "digest", "identity", "epoch"})
            tid, call = entered(event, 222)
            args = call["entry"]["args"]
            path = _path(event["path"])
            _require(path in loaders, "NODE_REPLAY_UNPINNED_LOADER")
            row = loaders[path]
            _require(event["digest"] == row["digest"], "NODE_REPLAY_MAP_DIGEST")
            _same(_identity(event["identity"]), row["identity"], "NODE_REPLAY_MAP_IDENTITY")
            _require([event[key] for key in ("length", "prot", "flags", "fd", "offset")] == args[1:]
                     and all(type(event[key]) is int for key in ("length", "prot", "flags", "fd", "offset"))
                     and 0 < args[1] <= _MAX_LOADER and args[2] & ~7 == 0 and args[2] & 6 != 6
                     and args[3] & 3 == 2 and not args[3] & 0x20 and 0 <= args[4] < 2**31
                     and args[5] % 4096 == 0 and args[5] < row["identity"]["size"],
                     "NODE_REPLAY_MAP_ARGUMENTS")
            _require(evidence_cas.read(row["digest"], max_bytes=_MAX_LOADER).startswith(b"\x7fELF"),
                     "NODE_REPLAY_LOADER_ELF")
            _require(file_operation is None, "NODE_REPLAY_OVERLAPPING_FILE_OPERATION")
            file_operation = tid
            call["operation"] = event
            counters["maps_entered"] += 1
        elif kind in {"READ_EXIT", "LOADER_READ_EXIT", "MAP_EXIT", "IO_EXIT"}:
            fields = {"pid", "call_id", "result", "is_error", "epoch"}
            if kind != "IO_EXIT":
                fields.add("identity")
            _fields(event, _COMMON | fields)
            tid = _uint(event["pid"], 1, 2**31 - 1)
            _require(tid in tasks and tasks[tid]["stopped"], "NODE_REPLAY_EXIT_CUSTODY")
            call = tasks[tid]["call"]
            _require(call is not None and call["entry"]["seq"] == event["call_id"]
                     and call.get("operation", {}).get("kind") == kind[:-4] + "ENTER"
                     and call.get("exit") is not None and tasks[tid]["stop"] is call["exit"],
                     "NODE_REPLAY_DELIVERY_EXIT_JOIN")
            operation, stop = call["operation"], call["exit"]
            _require(event["result"] == stop["result"] and event["is_error"] is stop["is_error"],
                     "NODE_REPLAY_DELIVERY_RESULT_JOIN")
            _result(event["result"], event["is_error"])
            if kind == "IO_EXIT":
                _uint(event["epoch"], operation["epoch"], epoch)
                counters["io_exited"] += 1
            else:
                held_epoch(event["epoch"])
                _require(event["epoch"] > operation["epoch"] and file_operation == tid,
                         "NODE_REPLAY_STABLE_FILE_INTERVAL")
                _same(_identity(event["identity"]), operation["identity"], "NODE_REPLAY_STABLE_FILE_IDENTITY")
                file_operation = None
                if kind == "MAP_EXIT":
                    _require(event["is_error"] or event["result"] % 4096 == 0, "NODE_REPLAY_MAP_RESULT")
                    counters["maps_exited"] += 1
                elif kind == "READ_EXIT":
                    counters["reads_exited"] += 1
                    if not event["is_error"]:
                        read_paths.add(operation["path"])
                        counters["bytes_read"] += event["result"]
                        if event["result"]:
                            ranges[operation["path"]].append((operation["offset"], operation["offset"] + event["result"]))
            if kind != "MAP_EXIT":
                _require(event["is_error"] or event["result"] <= operation["count"], "NODE_REPLAY_INPUT_RESULT_BOUND")
                if kind != "IO_EXIT":
                    _require(event["is_error"] or operation["offset"] + event["result"] <= operation["identity"]["size"],
                             "NODE_REPLAY_READ_PAST_FILE")
            completed_calls.add(event["call_id"])
            tasks[tid]["call"] = None
        elif kind == "CLONE_REQUEST":
            _fields(event, _COMMON | {"pid", "call_id", "syscall", "flags", "clone_args", "epoch"})
            tid, call = entered(event)
            number, args = call["entry"]["syscall"], call["entry"]["args"]
            _require(number in {220, 435} and event["syscall"] == number, "NODE_REPLAY_CLONE_NUMBER")
            flags = _uint(event["flags"], 0, _U64)
            _require(flags & _CLONE_REQUIRED == _CLONE_REQUIRED and flags & ~_CLONE_ALLOWED == 0,
                     "NODE_REPLAY_NONTHREAD_CLONE")
            if number == 220:
                _require(event["clone_args"] is None and flags == args[0] and args[1] != 0,
                         "NODE_REPLAY_CLONE_ARGUMENTS")
            else:
                value = event["clone_args"]
                _require(0 < args[0] < 2**63 and args[1] in {64, 80, 88}
                         and args[0] + args[1] < 2**63 and type(value) is str and len(value) == 2 * args[1]
                         and re.fullmatch(r"[0-9a-f]+", value) is not None, "NODE_REPLAY_CLONE3_BYTES")
                raw_args = bytes.fromhex(value)
                fields = [int.from_bytes(raw_args[pos:pos+8], "little") for pos in range(0, len(raw_args), 8)]
                _require(fields[0] == flags and fields[1] == fields[4] == 0 and fields[5] and fields[6]
                         and all(value == 0 for value in fields[8:]), "NODE_REPLAY_CLONE3_SCOPE")
            _require(file_operation is None, "NODE_REPLAY_OVERLAPPING_FILE_OPERATION")
            file_operation = tid
            call["operation"] = event
        elif kind == "FD_CREATE":
            _fields(event, _COMMON | {"pid", "call_id", "kind_name", "descriptors", "epoch"})
            tid = _uint(event["pid"], 1, 2**31 - 1)
            _require(tid in tasks and tasks[tid]["stopped"], "NODE_REPLAY_FD_CREATE_CUSTODY")
            call = tasks[tid]["call"]
            _require(call is not None and call["entry"]["seq"] == event["call_id"]
                     and call["entry"]["syscall"] in _CREATE and call.get("exit") is not None
                     and not call["exit"]["is_error"], "NODE_REPLAY_FD_CREATE_CALL")
            held_epoch(event["epoch"])
            number, args = call["entry"]["syscall"], call["entry"]["args"]
            name = _CREATE[number]
            _require(event["kind_name"] == name and type(event["descriptors"]) is list
                     and len(event["descriptors"]) == (1 if name == "eventfd" else 2), "NODE_REPLAY_FD_CREATE_KIND")
            if number == 199:
                _require(args[0] == 1 and args[1] & 15 in {1, 5} and args[2] == 0,
                         "NODE_REPLAY_SOCKETPAIR_SCOPE")
            _require(name == "eventfd" or call["exit"]["result"] == 0, "NODE_REPLAY_FD_CREATE_RESULT")
            seen_fds = set()
            for descriptor in event["descriptors"]:
                _fields(descriptor, {"fd", "identity"})
                fd = _uint(descriptor["fd"], 0, 2**31 - 1)
                _require(fd not in seen_fds and (name != "eventfd" or fd == call["exit"]["result"]),
                         "NODE_REPLAY_FD_CREATE_DESCRIPTOR")
                seen_fds.add(fd)
                object_id = _fd_identity(descriptor["identity"])
                _require(name == "pipe" and stat.S_ISFIFO(object_id[2])
                         or name == "socketpair" and stat.S_ISSOCK(object_id[2])
                         or name == "eventfd" and stat.S_IFMT(object_id[2]) == 0,
                         "NODE_REPLAY_FD_CREATE_TYPE")
                channel = {"kind": name, "created_by": event["call_id"]}
                # anon_inode eventfds can share stat identity while being
                # different open descriptions. The producer joins the retained
                # description; replay joins that declared creation event, never
                # treating dev/ino/mode as a unique eventfd birth.
                key = object_id, event["call_id"]
                _require(key not in created_objects or created_objects[key] == channel,
                         "NODE_REPLAY_REUSED_INTERNAL_IDENTITY")
                created_objects[key] = channel
            completed_calls.add(event["call_id"])
            tasks[tid]["call"] = None
            file_operation = None
        elif kind == "THREAD_EXIT":
            _fields(event, _COMMON | {"pid", "start_ticks", "status"})
            tid, generation = _task({key: event[key] for key in ("pid", "start_ticks")})
            _require(tid in tasks and tid != leader and generations[tid] == generation
                     and tasks[tid].get("terminal") == event["status"] and not tasks[tid]["stopped"]
                     and events[index - 2] is tasks[tid]["stop"], "NODE_REPLAY_THREAD_EXIT_JOIN")
            call = tasks[tid]["call"]
            _require(call is None or call["entry"]["syscall"] in {93, 94}, "NODE_REPLAY_EXIT_WITH_PENDING_INPUT")
            del tasks[tid]
            counters["threads_exited"] += 1
        elif kind == "CHALLENGE":
            _fields(event, _COMMON | {"nonce", "issued_ns", "deadline_ns", "epoch", "tasks",
                                     "stops_before", "stops_after", "all_stopped"})
            issued, deadline = _uint(event["issued_ns"]), _uint(event["deadline_ns"])
            nonce = event["nonce"]
            _require(type(nonce) is str and re.fullmatch(r"[0-9a-f]{64}", nonce) is not None
                     and nonce not in seen_nonces and last_challenge < issued <= now < deadline
                     and deadline - issued == 100_000_000, "NODE_REPLAY_CHALLENGE_BUDGET")
            held_epoch(event["epoch"])
            _require(_tasks(event["tasks"]) == barrier["tasks"] and event["all_stopped"] is True
                     and file_operation is None, "NODE_REPLAY_CHALLENGE_TASKS")
            before, after = _uint(event["stops_before"]), _uint(event["stops_after"])
            _require(after == counters["stops_acquired"] and after - before >= len(tasks),
                     "NODE_REPLAY_CHALLENGE_ACCOUNTING")
            for tid, task in tasks.items():
                stop = task["stop"]
                _require(stop["boottime_ns"] >= issued and stop["seq"] > 1
                         and any(row["kind"] == "RESUME" and row["pid"] == tid
                                 and issued <= row["boottime_ns"] <= stop["boottime_ns"]
                                 for row in events[:stop["seq"] - 1]), "NODE_REPLAY_CHALLENGE_PROGRESS")
                call = task["call"]
                _require(call is None or call.get("exit") is None and (
                         call["entry"]["syscall"] in {22, 72, 73, 98} and call.get("operation") is None
                         or call.get("operation", {}).get("kind") == "IO_ENTER"),
                         "NODE_REPLAY_CHALLENGE_PENDING_INPUT")
            seen_nonces.add(nonce)
            last_challenge = now
            if index == len(events):
                _same({key: event[key] for key in expected_challenge}, expected_challenge,
                      "NODE_REPLAY_EXPECTED_CHALLENGE")
        elif kind in {"REFUSED", "CLEANUP"}:
            raise PiSourceObservationVerificationError("NODE_REPLAY_RETAINED_REFUSAL_OR_CLEANUP")
        else:
            raise PiSourceObservationVerificationError("NODE_REPLAY_UNSUPPORTED_EVENT")

    _require(armed and executed and events[-1]["kind"] == "CHALLENGE" and awaiting_gate_release is None
             and awaiting_thread_start is None
             and boundary_boottime_ns - last_challenge <= 200_000_000,
             "NODE_REPLAY_FRESH_FINAL_CHALLENGE_REQUIRED")
    counters["events_retained"] = len(events)
    counters["pending_reads"] = counters["reads_entered"] - counters["reads_exited"]
    counters["pending_syscalls"] = sum(task["call"] is not None for task in tasks.values())
    _fields(record["accounting"], set(counters))
    for key, value in record["accounting"].items():
        _uint(value)
        _require(value == counters[key], "NODE_REPLAY_LOSS_ACCOUNTING")
    for path in required:
        _require(path in read_paths, "NODE_REPLAY_REQUIRED_SOURCE_UNREAD")
        end = 0
        for low, high in sorted(ranges[path]):
            _require(low <= end, "NODE_REPLAY_SOURCE_DELIVERY_GAP")
            end = max(end, high)
        _require(end == sources[path]["identity"]["size"], "NODE_REPLAY_INCOMPLETE_SOURCE_DELIVERY")
    return dict(schema="aragorn/pi-core-node-source-replay/v2", status="CONSISTENT_REQUIRED_SOURCE_DELIVERY",
                observation_digest=expected_observation_digest, required_source_count=len(required),
                threads_observed=counters["threads_observed"], threads_exited=counters["threads_exited"],
                bytes_read=counters["bytes_read"], loader_mapping_attempts=counters["maps_exited"],
                loader_mappings=sum(event["kind"] == "MAP_EXIT" and not event["is_error"] for event in events),
                acquisition_authenticity_verified=False, sensor_health_verified=False,
                effect_authorized=False, v8_execution_verified=False, phase3_qualified=False)


