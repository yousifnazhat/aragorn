"""Offline consistency checks for a normal B47 owner lifecycle, not proof of authorization or boot."""
import json
import re
import uuid

from scripts.build_pi_core_linux import BuildError, canonical, require, sha256


GRAPH = {"platform": "generic-arm64-efi", "cpu_count": 2, "memory_bytes": 4 << 30,
         "nvme_controllers": 1, "raw_disks": 1, "attachment_read_only": True,
         "serial_output_only": 1, "guest_serial_input": False, "other_devices": 0, "variable_store_bound": True}
CLOCK = "CLOCK_MONOTONIC_RAW"
EVENTS = ("armed", "recorder-armed", "start-issued", "start-completion-returned", "active-observed",
          "delegate-guest-stop", "stopped-observed", "retired")
BRIDGE = ("armed", "active-observed", "stopped-observed", "retired")
ID_KEYS = ("fixture_identity", "attempt_identity", "disk_identity", "store_identity")
HASH_KEYS = ("runner_sha256", "runner_cdhash", "disk_sha256", "store_sha256_before", "policy_sha256_before")


def _object(raw):
    def unique(pairs):
        obj = dict(pairs)
        require(len(obj) == len(pairs), "duplicate owner JSON field")
        return obj

    def bad_number(_):
        raise BuildError("non-integral owner JSON number")

    try:
        obj = json.loads(raw.decode("utf-8"), object_pairs_hook=unique, parse_float=bad_number, parse_constant=bad_number)
    except (ValueError, RecursionError) as exc:
        raise BuildError("invalid owner JSON") from exc
    require(type(obj) is dict, "expected owner JSON object")
    return obj


def _uint(n, minimum=1):
    return type(n) is int and minimum <= n < 1 << 64


def _keys(record, keys):
    require(type(record) is dict and record.keys() == set(keys), "missing or unexpected owner fields")


def _same(record, expected, error):
    # JSON booleans and numbers must not compare equal (Python's True == 1).
    try:
        match = canonical(record) == canonical(expected)
    except (TypeError, ValueError, RecursionError) as exc:
        raise BuildError(error) from exc
    require(match, error)


def verify_owner_records(uid, files, expected):
    """Join original bytes to independent expected bindings; return RAW times for the external watchdog join.

    No access to disk, credentials, producer code or the current VM. A matching tuple
    alone cannot authenticate these bytes, demonstrate a guest observation or prove restoration.
    """
    try:
        valid_uuid = type(uid) is str and str(uuid.UUID(uid)) == uid and uuid.UUID(uid).int != 0
    except ValueError:
        valid_uuid = False
    require(valid_uuid, "invalid attempt UUID")
    _keys(expected, (*HASH_KEYS, *ID_KEYS))
    for k in HASH_KEYS:
        width = 40 if k == "runner_cdhash" else 64
        require(type(expected[k]) is str and re.fullmatch("[0-9a-f]{%d}" % width, expected[k]), "invalid expected digest")
    nodes = set()
    for k in ID_KEYS:
        ident = expected[k]
        _keys(ident, ("dev", "ino"))
        require(_uint(ident["dev"], 0) and _uint(ident["ino"]), "invalid expected filesystem identity")
        nodes.add((ident["dev"], ident["ino"]))
    require(len(nodes) == 4, "aliased fixture, attempt, disk or store")
    require(type(files) is dict, "expected owner files")
    for n, limit in (("owner-terminal.json", 32768), ("owner-events.jsonl", 48 * 2048), ("serial.raw", (8 << 20) - 1)):
        require(type(files.get(n)) is bytes and 0 < len(files[n]) <= limit, "missing or invalid size: " + n)

    raw = files["serial.raw"]
    terminal = _object(files["owner-terminal.json"])
    fixed = {"schema": "aragorn/b47-bound-owner-terminal/v1", "attempt_uuid": uid, "phase3_exit_eligible": False,
             "runner": {k: expected[k] for k in ("runner_sha256", "runner_cdhash")}, "graph": GRAPH,
             **{k: expected[k] for k in (*ID_KEYS, *HASH_KEYS[2:])}}
    _keys(terminal, (*fixed, "owner"))
    _same({k: terminal[k] for k in fixed}, fixed, "terminal binding differs from independent inputs")
    owner = terminal["owner"]
    fixed = {"schema": "aragorn/pi-core-vm-owner/v1", "attempt_uuid": uid, "status": "stopped-observed",
             "start_issued": True, "stopped_observed": True, "complete": True, "supervision_lost": False,
             "journal_sealed": True, "recorder_joined": True, "boot_observed": False, "phase3_exit_eligible": False}
    _keys(owner, (*fixed, "events", "capture"))
    _same({k: owner[k] for k in fixed}, fixed, "not a normal complete owner report")

    lines = files["owner-events.jsonl"].split(b"\n")
    require(len(lines) == len(EVENTS) + 1 and lines[-1] == b"", "missing, extra or truncated owner journal records")
    events, times = [], {}
    for name, line in zip(EVENTS, lines):
        require(0 < len(line) < 2048, "invalid owner journal line size")
        event = _object(line)
        t = event.get("monotonic_ns")
        require(_uint(t), "invalid owner event time")
        want = {"event": name, "attempt_uuid": uid, "clock": CLOCK, "monotonic_ns": t, "schema": "aragorn/b47-owner-event/v1"}
        if name in BRIDGE:
            want.update(schema="pi-core-vz-stop-event/v1", sequence=BRIDGE.index(name) + 1)
        _same(event, want, "non-normal or out-of-order owner event")
        events.append(event)
        times[name] = t
    require(list(times.values()) == sorted(times.values()), "owner event clock moved backwards")
    _same(owner["events"], events, "embedded events differ from original journal")

    c = owner["capture"]
    time_keys = ("attempt_start_ns", "record_start_ns", "record_end_ns")
    fixed = {"schema": "aragorn/bounded-host-serial/v1", "status": "eof", "stream_termination": "eof", "clock": CLOCK,
             "raw_file": "serial.raw", "capture_bytes": len(raw), "capture_sha256": sha256(raw), "sync_verified": True,
             "pipe_eof": True, "boot_observed": False, "phase3_exit_eligible": False}
    _keys(c, (*fixed, *time_keys))
    _same({k: c[k] for k in fixed}, fixed, "serial termination or original bytes differ")
    start, entered, end = (c[k] for k in time_keys)
    require(all(_uint(n) for n in (start, entered, end)) and start <= times["armed"] and
            start <= entered <= times["recorder-armed"] and times["retired"] <= end < start + 180_000_000_000 and
            times["start-issued"] - times["armed"] < 5_000_000_000, "capture and owner clocks inconsistent")
    return {"attempt_uuid": uid, **{k: c[k] for k in time_keys}, "observer_armed_ns": times["armed"],
            "recorder_armed_ns": times["recorder-armed"], "start_issued_ns": times["start-issued"],
            "active_observed_ns": times["active-observed"], "stopped_observed_ns": times["stopped-observed"],
            "retired_ns": times["retired"]}
