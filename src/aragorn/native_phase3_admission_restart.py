"""Independent finite restart joins over retained bytes; never native qualification."""
from __future__ import annotations

import base64
from datetime import datetime, timezone
import re
import stat

from . import native_phase3_admission_direct_write as shared
from .oci_worker_protocol import canonical_json

PROBE = "/opt/aragorn/runtime_native_admission_restart.py"
VERIFIER = "/usr/lib/aragorn/aragorn/native_phase3_admission_restart.py"
SOURCE_PATHS = (PROBE, VERIFIER, shared.PROBE, shared.VERIFIER,
                "/usr/lib/aragorn/aragorn/oci_worker_protocol.py",
                "/usr/lib/aragorn/aragorn/__init__.py")
SCHEMA = "aragorn/native-admission-restart-observation/v1"
SNAPSHOT_SCHEMA = "aragorn/native-restart-file-lifecycle-snapshot/v1"
NODE = "/usr/local/bin/node"
ARGV = (NODE, shared.ENTRY, "gateway", "restart", "--safe", "--json")
DENIAL_ARGV = (NODE, shared.ENTRY, "gateway", "call", "system.info", "--token",
               "aragorn-native-restart-invalid-token-v1", "--json", "--timeout", "5000")
CATALOGS = tuple((NODE, shared.ENTRY, *args) for _, args in shared.COMMANDS)
TRACE_FIELDS = ("traceId", "spanId", "parentSpanId", "traceFlags")
MAX_ENVELOPE = 1500000
MAX_OBSERVATION = 12 * 1024 * 1024
LIMITATIONS = (
    "PROTECTED_PROVIDER_AND_CALLER_PINS_REQUIRE_INDEPENDENT_CUSTODY",
    "FILE_RECORDS_ARE_RUNTIME_ASSERTIONS_NOT_KERNEL_EMITTER_ATTESTATION",
    "DIGEST_JOINS_NOT_CONTINUOUS_CUSTODY_OR_CLOCK_STABILITY_PROOF",
    "METADATA_READBACK_NOT_RETAINED_ADMITTED_FILE_BYTES",
    "CATALOG_NOT_ACTIVE_SESSION_CONSUMPTION",
    "NO_NATIVE_PROVIDER_DEPLOYMENT_HEALTH_OR_ADMISSION_QUALIFICATION",
)


class NativeRestartError(ValueError):
    pass


def require(condition, reason):
    if not condition:
        raise NativeRestartError(reason)


digest = shared.digest


def exact(value, fields):
    require(type(value) is dict and set(value) == set(fields), "FIELD_INVENTORY_CHANGED")


def integer(value, minimum=0):
    require(type(value) is int and minimum <= value <= 2**63 - 1, "INVALID_INTEGER")
    return value


def parse(raw):
    try:
        return shared.parse(raw.decode("utf-8"))
    except (ValueError, UnicodeError, RecursionError) as error:
        raise NativeRestartError("INVALID_JSON") from error


def decode(value, limit):
    require(type(value) is str and len(value) <= ((limit + 2) // 3) * 4,
            "ENCODED_BYTES_EXCEEDED")
    try:
        raw = base64.b64decode(value, validate=True)
    except (ValueError, UnicodeError) as error:
        raise NativeRestartError("INVALID_BASE64") from error
    require(len(raw) <= limit and base64.b64encode(raw).decode("ascii") == value,
            "NONCANONICAL_BASE64")
    return raw


def encode(raw):
    return base64.b64encode(raw).decode("ascii")


def validate_bindings(bindings):
    exact(bindings, {"container", "gateway", "namespaces", "capture_nonce",
                     "context_digest", "runtime_inventory_digest", "config_digest",
                     "entry_digest", "admitted_digest", "source_pins"})
    for key in ("container", "capture_nonce"):
        require(type(bindings[key]) is str and re.fullmatch(r"[0-9a-f]{64}", bindings[key]),
                "INVALID_CAPTURE_IDENTITY")
    for key in ("context_digest", "runtime_inventory_digest", "config_digest",
                "entry_digest", "admitted_digest"):
        shared.pin(bindings[key])
    exact(bindings["source_pins"], SOURCE_PATHS)
    for pin in bindings["source_pins"].values():
        shared.pin(pin)
    gateway = bindings["gateway"]
    exact(gateway, {"pid", "start_time_ticks", "cgroup", "mount_namespace",
                    "effective_capabilities", "no_new_privileges", "uid", "gid"})
    for key in ("pid", "start_time_ticks", "mount_namespace"):
        integer(gateway[key], 2 if key == "pid" else 1)
    require(gateway["cgroup"] == "0::/docker/" + bindings["container"]
            + "/system.slice/aragorn-agent-gateway.service\n"
            and gateway["effective_capabilities"] == "0000000000000000"
            and gateway["no_new_privileges"] == "1"
            and gateway["uid"] == gateway["gid"] == [992] * 4,
            "GATEWAY_IDENTITY_REFUSED")
    exact(bindings["namespaces"], {"mnt", "pid", "user", "time"})
    for value in bindings["namespaces"].values():
        integer(value, 1)
    require(bindings["namespaces"]["mnt"] == gateway["mount_namespace"],
            "NAMESPACE_BINDING_CHANGED")


def validate_boundary(value, bindings):
    """Own the fresh-pin boundary; never substitute records into a frozen validator."""
    exact(value, {"gateway", "roots", "admitted", "sources", "entry", "config"})
    require(canonical_json(value["gateway"]) == canonical_json(bindings["gateway"]), "GATEWAY_IDENTITY_CHANGED")
    exact(value["roots"], shared.ROOTS)
    for tree in value["roots"].values():
        exact(tree, {"identity", "read_only", "entries", "candidate_absent"})
        shared._identity(tree["identity"])
        require(stat.S_ISDIR(tree["identity"][2]) and tree["read_only"] is True
                and type(tree["candidate_absent"]) is bool
                and type(tree["entries"]) is list and len(tree["entries"]) <= 512,
                "UNSEALED_ROOT")
        names, total = [], 0
        for row in tree["entries"]:
            exact(row, {"path", "kind", "identity", "bytes", "digest"})
            name = row["path"]
            require(type(name) is str and name and not name.startswith("/")
                    and all(p not in ("", ".", "..") for p in name.split("/")),
                    "INVALID_TREE_PATH")
            shared._identity(row["identity"])
            if row["kind"] == "file":
                size = integer(row["bytes"])
                require(size <= 1048576 and stat.S_ISREG(row["identity"][2])
                        and row["identity"][5] == 1 and row["identity"][6] == size,
                        "TREE_FILE_REFUSED")
                shared.pin(row["digest"])
                total += size
            else:
                require(row["kind"] == "directory" and stat.S_ISDIR(row["identity"][2])
                        and row["bytes"] is None and row["digest"] is None,
                        "TREE_DIRECTORY_REFUSED")
            names.append(name)
        require(names == sorted(set(names)) and total <= 8388608, "TREE_INVENTORY_REFUSED")
    for field in ("admitted", "entry", "config"):
        shared._file(value[field], bindings[field + "_digest"])
        require(value[field]["read_only"] is True, "PROTECTED_FILE_WRITABLE")
    exact(value["sources"], SOURCE_PATHS)
    for path, pin in bindings["source_pins"].items():
        shared._file(value["sources"][path], pin)
        identity = value["sources"][path]["identity"]
        require(identity[3:6] == [0, 0, 1] and stat.S_IMODE(identity[2]) == 0o444,
                "SOURCE_CUSTODY_CHANGED")


def snapshot(raw, *, phase, bindings, previous=None):
    require(type(raw) is bytes and 0 < len(raw) <= MAX_ENVELOPE, "SNAPSHOT_BOUND")
    value = parse(raw)
    exact(value, {"schema", "capture_nonce", "phase", "context_digest",
                  "previous_snapshot_digest", "file_identity", "prefix_bytes",
                  "prefix_digest", "raw_base64", "cursor", "acquisition",
                  "emission_clock", "complete"})
    require(raw.isascii() and canonical_json(value) == raw
            and value["schema"] == SNAPSHOT_SCHEMA and value["phase"] == phase
            and value["capture_nonce"] == bindings["capture_nonce"]
            and value["context_digest"] == bindings["context_digest"]
            and value["complete"] is True, "SNAPSHOT_CONTEXT_CHANGED")
    identity = value["file_identity"]
    exact(identity, {"dev", "ino", "mode", "uid", "gid", "nlink"})
    for number in identity.values():
        integer(number)
    require(identity["ino"] > 0 and identity["mode"] == stat.S_IFREG | 0o600
            and identity["uid"] == identity["gid"] == 992 and identity["nlink"] == 1,
            "LIFECYCLE_FILE_CUSTODY_CHANGED")
    require(type(value["cursor"]) is str and re.fullmatch(r"[0-9a-f]{64}", value["cursor"]),
            "CURSOR_REFUSED")
    acquisition = value["acquisition"]
    exact(acquisition, {"clock", "started_ns", "completed_ns"})
    start, end = integer(acquisition["started_ns"]), integer(acquisition["completed_ns"])
    require(acquisition["clock"] == "CLOCK_MONOTONIC" and start <= end
            and end - start <= (20000000000 if phase == "AFTER" else 3000000000),
            "ACQUISITION_CLOCK_REFUSED")
    require(canonical_json(value["emission_clock"]) == canonical_json({
        "clock": "CLOCK_REALTIME", "timezone": "UTC", "precision_ns": 1000000}),
        "EMISSION_CLOCK_REFUSED")
    prefix = decode(value["raw_base64"], 1048576)
    require(integer(value["prefix_bytes"]) == len(prefix)
            and value["prefix_digest"] == digest(prefix), "PREFIX_DIGEST_CHANGED")
    if previous is None:
        require(phase == "INITIAL" and value["previous_snapshot_digest"] is None,
                "INITIAL_CHAIN_REFUSED")
    else:
        old, old_prefix, old_raw = previous
        require(value["previous_snapshot_digest"] == digest(old_raw)
                and prefix.startswith(old_prefix) and identity == old["file_identity"]
                and value["cursor"] != old["cursor"]
                and start >= old["acquisition"]["completed_ns"], "SNAPSHOT_CHAIN_CHANGED")
    records(prefix)
    return value, prefix, raw


def records(prefix):
    require(prefix and prefix.endswith(b"\n"), "INCOMPLETE_LIFECYCLE")
    lines = prefix.splitlines(keepends=True)
    require(len(lines) <= 512, "RECORD_COUNT_EXCEEDED")
    result, offset = [], 0
    for line in lines:
        require(1 < len(line) <= 65536 and line.endswith(b"\n") and b"\r" not in line,
                "RECORD_BOUND_OR_FRAMING")
        record = parse(line[:-1])
        require(type(record) is dict, "RECORD_OBJECT_REQUIRED")
        result.append((offset, line, record))
        offset += len(line)
    return result


def _time_interval(text):
    require(type(text) is str and re.fullmatch(
        r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}\+00:00", text), "EMISSION_TIME_REFUSED")
    try:
        delta = datetime.fromisoformat(text) - datetime(1970, 1, 1, tzinfo=timezone.utc)
    except ValueError as error:
        raise NativeRestartError("EMISSION_TIME_REFUSED") from error
    lower = (delta.days * 86400 + delta.seconds) * 1000000000 + delta.microseconds * 1000
    integer(lower)
    return lower, lower + 999999


def initial_readiness(initial, boundary):
    require(boundary.startswith(initial), "INITIAL_PREFIX_CHANGED")
    before = records(boundary)
    ready = [row for row in before if row[2].get("message") == "gateway ready"]
    require(len(ready) == 1 and ready[0][0] < len(initial), "INITIAL_READINESS_REFUSED")
    _time_interval(ready[0][2].get("time"))
    for _, _, record in before:
        message = record.get("message", "")
        require(not (type(message) is str and re.search(
            r"restart|shutdown|SIGUSR|signal .*received", message, re.I)), "PREEXISTING_RESTART_REFUSED")
    return ready[0]


def markers(initial, boundary, after):
    initial_readiness(initial, boundary)
    before = records(boundary)
    ready = [row for row in before if row[2].get("message") == "gateway ready"]
    require(len(ready) == 1 and ready[0][0] < len(initial), "INITIAL_READINESS_REFUSED")
    selected = [ready[0]]
    patterns = (r"signal SIGUSR1 received", r"received SIGUSR1; restarting",
                r"shutdown completed cleanly in [0-9]+ms",
                r"restart mode: in-process restart \(OPENCLAW_NO_RESPAWN\)", r"gateway ready")
    suffix = [row for row in records(after) if row[0] >= len(boundary)]
    for pattern in patterns:
        candidates = [row for row in suffix if type(row[2].get("message")) is str
                      and re.fullmatch(pattern, row[2]["message"])]
        require(len(candidates) == 1, "LIFECYCLE_MARKER_AMBIGUOUS_OR_MISSING")
        selected.append(candidates[0])
    allowed = {row[0] for row in selected}
    for offset, _, record in before + suffix:
        message = record.get("message", "")
        if type(message) is str and re.search(r"restart|shutdown|SIGUSR|signal .*received", message, re.I):
            require(offset in allowed, "UNRELATED_LIFECYCLE_REFUSED")
    require([row[0] for row in selected] == sorted({row[0] for row in selected}),
            "LIFECYCLE_ORDER_CHANGED")
    result = []
    for offset, raw, record in selected:
        lower, upper = _time_interval(record.get("time"))
        trace = {key: ({"present": True, "value": record[key]} if key in record
                       else {"present": False}) for key in TRACE_FIELDS}
        result.append({"offset": offset, "bytes": len(raw), "digest": digest(raw),
                       "message": record["message"], "time": record["time"],
                       "lower_ns": lower, "upper_ns": upper, "trace": trace})
    require([row["lower_ns"] for row in result] == sorted(row["lower_ns"] for row in result),
            "EMISSION_CLOCK_REGRESSED")
    return result


def restart_response(pid):
    return {"ok": True, "result": "scheduled",
            "message": "safe restart requested; gateway will restart momentarily",
            "preflight": {"safe": True, "counts": dict.fromkeys(
                ("queueSize", "pendingReplies", "embeddedRuns", "cronRuns", "activeTasks", "totalActive"), 0),
                "blockers": [], "summary": "safe to restart now"},
            "restart": {"ok": True, "pid": pid, "signal": "SIGUSR1", "delayMs": 0,
                        "reason": "gateway.restart.safe", "mode": "emit", "coalesced": False,
                        "cooldownMsApplied": 0, "emitHooksQueued": False}}


def command(row, argv, pid):
    exact(row, {"argv", "pid", "start_time_ticks", "started_realtime_ns", "completed_realtime_ns",
                "started_monotonic_ns", "completed_monotonic_ns", "exit_code", "stdout_base64",
                "stderr_base64", "group_cleanup", "leader_reaped", "cleanup_failures",
                "start_clock", "completion_clock"})
    require(row["argv"] == list(argv) and row["group_cleanup"] is True
            and row["leader_reaped"] is True and row["cleanup_failures"] == [], "COMMAND_CUSTODY_REFUSED")
    integer(row["pid"], 2)
    integer(row["start_time_ticks"], 1)
    require(row["pid"] != pid, "COMMAND_GATEWAY_IDENTITY_COLLISION")
    for clock in ("realtime", "monotonic"):
        start = integer(row["started_" + clock + "_ns"])
        end = integer(row["completed_" + clock + "_ns"])
        require(start <= end, "COMMAND_CLOCK_REGRESSED")
    require(row["completed_monotonic_ns"] - row["started_monotonic_ns"] <= 15000000000,
            "COMMAND_DEADLINE_EXCEEDED")
    for prefix, label in (("started", "start_clock"), ("completed", "completion_clock")):
        sample = row[label]
        exact(sample, {"monotonic_before_ns", "realtime_ns", "monotonic_after_ns"})
        for number in sample.values():
            integer(number)
        require(sample["monotonic_before_ns"] <= sample["monotonic_after_ns"]
                and row[prefix + "_realtime_ns"] == sample["realtime_ns"]
                and row[prefix + "_monotonic_ns"] == sample[
                    "monotonic_before_ns" if prefix == "started" else "monotonic_after_ns"],
                "CLOCK_BRACKET_CHANGED")
    stdout, stderr = (decode(row[key + "_base64"], shared.MAX_COMMAND) for key in ("stdout", "stderr"))
    require(type(row["exit_code"]) is int, "INVALID_EXIT_CODE")
    if argv == ARGV:
        require(row["exit_code"] == 0 and not stdout
                and canonical_json(parse(stderr)) == canonical_json(restart_response(pid)),
                "RESTART_RESPONSE_REFUSED")
    elif argv == DENIAL_ARGV:
        require(row["exit_code"] == 1 and len(stdout) == 481 and len(stderr) == 143
                and digest(stdout) == "sha256:d88557eaf82b003daed20aeb2d0c1c9a6271e9c3bb95686181e9ecf19d4668ae"
                and digest(stderr) == "sha256:25b45fe227920562cda00967eb52d40dd6380d96f3c7112b267f16fec27f7322",
                "DENIAL_RESPONSE_REFUSED")
        parse(stdout)
    else:
        require(argv in CATALOGS and row["exit_code"] == 0 and not stderr and stdout,
                "CATALOG_RESPONSE_REFUSED")
        parse(stdout)
    return stdout


def catalogs(rows, pid):
    require(type(rows) is list and len(rows) == 5, "CATALOG_COUNT_CHANGED")
    converted, inventories = [], {}
    for row, (kind, _), argv in zip(rows[:4], shared.COMMANDS, CATALOGS, strict=True):
        raw = command(row, argv, pid)
        response = parse(raw)
        require(type(response) is dict, "CATALOG_OBJECT_REQUIRED")
        if kind != "system-info":
            skills = [response] if kind == "skill-info" else response.get("skills")
            require(type(skills) is list and all(type(s) is dict for s in skills), "CATALOG_SHAPE_CHANGED")
            names = [skill.get("name") for skill in skills]
            require(all(type(name) is str for name in names) and len(set(names)) == len(names),
                    "CATALOG_NAMES_AMBIGUOUS")
            inventories[kind] = set(names)
            for skill in skills:
                if skill.get("name") != "template-skill":
                    for key in ("eligible", "modelVisible", "commandVisible"):
                        require((key not in skill and kind == "skill-list") or skill.get(key) is False,
                                "UNADMITTED_CAPABILITY_VISIBLE_OR_UNKNOWN")
        converted.append({"kind": kind, "argv": list(argv), "exit_code": 0,
                          "stdout": raw.decode("utf-8"), "stdout_bytes": len(raw),
                          "stdout_digest": digest(raw), "stderr_bytes": 0})
    require(inventories["skill-list"] == inventories["gateway-skills"], "DISCOVERY_CATALOG_JOIN_CHANGED")
    command(rows[-1], DENIAL_ARGV, pid)
    return shared._commands(converted, pid)


def verify_native_admission_restart(raw, *, expected_raw_digest, expected_bindings):
    require(type(raw) is bytes and 0 < len(raw) <= MAX_OBSERVATION
            and digest(raw) == shared.pin(expected_raw_digest), "OBSERVATION_PIN_CHANGED")
    validate_bindings(expected_bindings)
    value = parse(raw)
    exact(value, {"schema", "status", "bindings", "before", "dispatch_boundary", "after",
                  "commands_before", "commands_after", "restart", "lifecycle", "markers",
                  "refusal", "partial", "cleanup_failures", "limitations", *shared.FALSE_FLAGS})
    require(canonical_json(value) == raw and value["schema"] == SCHEMA
            and value["status"] == "OBSERVED" and value["refusal"] is None
            and value["partial"] == [] and value["cleanup_failures"] == []
            and canonical_json(value["bindings"]) == canonical_json(expected_bindings)
            and value["limitations"] == list(LIMITATIONS)
            and all(value[key] is False for key in shared.FALSE_FLAGS), "OBSERVATION_REFUSED")
    for name in ("before", "dispatch_boundary", "after"):
        validate_boundary(value[name], expected_bindings)
    require(value["before"] == value["dispatch_boundary"] == value["after"], "PROTECTED_STATE_CHANGED")
    pid = expected_bindings["gateway"]["pid"]
    require(catalogs(value["commands_before"], pid) == catalogs(value["commands_after"], pid),
            "CATALOG_CHANGED")
    require(value["commands_before"][3]["stdout_base64"] == value["commands_after"][3]["stdout_base64"],
            "RAW_GATEWAY_CATALOG_CHANGED")
    command(value["restart"], ARGV, pid)
    all_commands = value["commands_before"] + [value["restart"]] + value["commands_after"]
    require(len({r["pid"] for r in all_commands}) == len(all_commands), "COMMAND_PID_REUSE")
    # A common offset must fit every actual bracket; never convert event time to monotonic.
    brackets = [row[k] for row in all_commands for k in ("start_clock", "completion_clock")]
    require(max(b["realtime_ns"] - b["monotonic_after_ns"] for b in brackets)
            <= min(b["realtime_ns"] - b["monotonic_before_ns"] for b in brackets),
            "OBSERVED_CLOCK_DISCONTINUITY")
    for earlier, later in zip(all_commands, all_commands[1:]):
        for clock in ("realtime", "monotonic"):
            require(earlier["completed_" + clock + "_ns"] <= later["started_" + clock + "_ns"],
                    "COMMAND_ORDER_CHANGED")
    require(type(value["lifecycle"]) is list and len(value["lifecycle"]) == 3, "SNAPSHOT_COUNT_CHANGED")
    chain = []
    for retained, phase in zip(value["lifecycle"], ("INITIAL", "BOUNDARY", "AFTER"), strict=True):
        exact(retained, {"raw_base64", "call_started_ns", "call_completed_ns", "deadline_ns"})
        start, end, deadline = (integer(retained[k]) for k in
                                ("call_started_ns", "call_completed_ns", "deadline_ns"))
        require(start <= end <= deadline and deadline - start <=
                (20000000000 if phase == "AFTER" else 3000000000), "READER_CALL_DEADLINE_REFUSED")
        chain.append(snapshot(decode(retained["raw_base64"], MAX_ENVELOPE), phase=phase,
                              bindings=expected_bindings, previous=chain[-1] if chain else None))
        acquired = chain[-1][0]["acquisition"]
        require(start <= acquired["started_ns"] <= acquired["completed_ns"] <= end,
                "LIFECYCLE_ACQUISITION_OUTSIDE_CALL")
    require(len({s[0]["cursor"] for s in chain}) == 3, "CURSOR_REUSED")
    initial, boundary, after = (s[0]["acquisition"] for s in chain)
    pre, restart, post = value["commands_before"], value["restart"], value["commands_after"]
    require(initial["completed_ns"] <= pre[0]["started_monotonic_ns"]
            and pre[-1]["completed_monotonic_ns"] <= boundary["started_ns"]
            and boundary["completed_ns"] <= restart["started_monotonic_ns"]
            and restart["completed_monotonic_ns"] <= after["started_ns"]
            and after["completed_ns"] <= restart["started_monotonic_ns"] + 20000000000
            and after["completed_ns"] <= post[0]["started_monotonic_ns"], "ACQUISITION_ORDER_CHANGED")
    initial_call, boundary_call, after_call = value["lifecycle"]
    require(initial_call["call_completed_ns"] <= pre[0]["started_monotonic_ns"]
            and pre[-1]["completed_monotonic_ns"] <= boundary_call["call_started_ns"]
            and boundary_call["call_completed_ns"] <= restart["started_monotonic_ns"]
            and restart["completed_monotonic_ns"] <= after_call["call_started_ns"]
            and after_call["deadline_ns"] == restart["started_monotonic_ns"] + 20000000000
            and after_call["call_completed_ns"] <= post[0]["started_monotonic_ns"],
            "READER_CALL_ORDER_CHANGED")
    selected = markers(*(s[1] for s in chain))
    require(canonical_json(value["markers"]) == canonical_json(selected), "MARKER_REFERENCE_CHANGED")
    require(restart["started_realtime_ns"] <= selected[1]["lower_ns"]
            and selected[2]["upper_ns"] <= restart["completed_realtime_ns"] <= selected[3]["lower_ns"]
            and post[0]["started_realtime_ns"] >= selected[-1]["upper_ns"], "RESTART_CAUSAL_CLOCK_REFUSED")
    return {"schema": "aragorn/native-admission-restart-replay/v1",
            "status": "BOUNDED_RESTART_JOINS_VERIFIED", "observation_digest": expected_raw_digest,
            "limitations": list(LIMITATIONS), **dict.fromkeys(shared.FALSE_FLAGS, False)}
