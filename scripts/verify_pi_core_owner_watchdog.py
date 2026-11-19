"""Read-only consistency checks on original B46/B47 watchdog bytes. Not boot or release evidence."""
import json
import uuid

from scripts.build_pi_core_linux import BuildError, canonical, require


WATCH = "watchdog.json"
START = WATCH + ".started"
ARM = WATCH + ".owner-arm"
REFUSAL = "refusal.stderr"
HOLD = b"B47 held: no approved boot attempt\n"
CLOCK = "CLOCK_MONOTONIC_RAW"
SCHEMA = "aragorn/b46-owned-host-watchdog/v1"


def _object(raw):
    require(type(raw) is bytes and 0 < len(raw) <= 65536, "watchdog record absent or oversized")
    try:
        value = json.loads(raw)
        # The watchdog writes canonical bytes without a trailing newline. This also rejects duplicate keys.
        require(type(value) is dict and canonical(value) == raw, "invalid watchdog record encoding")
    except (ValueError, UnicodeError, RecursionError) as exc:
        raise BuildError("invalid watchdog JSON") from exc
    return value


def _time(doc, key):
    n = doc.get(key)
    require(type(n) is int and 0 < n < 1 << 64, "invalid watchdog/owner timestamp: " + key)
    return n


def verify_watchdog_records(uid, files, owner=None):
    """Cross-check a whole ledger; owner, if present, must be the independent owner verifier's result."""
    try:
        require(isinstance(uid, str) and str(uuid.UUID(uid)) == uid and uuid.UUID(uid).int, "invalid attempt UUID")
    except ValueError as exc:
        raise BuildError("invalid attempt UUID") from exc
    held = owner is None
    require(set(files) == {START, WATCH, REFUSAL if held else ARM}, "unexpected/missing watchdog evidence")
    terminal, started = _object(files[WATCH]), _object(files[START])
    identity = {"schema": SCHEMA, "attempt_uuid": uid, "clock": CLOCK}
    reserved = _time(started, "reserved_raw_ns")
    require(started == dict(identity, reserved_raw_ns=reserved, disposition="reserved-before-spawn"),
            "watchdog reservation mismatch")
    begin, end = _time(terminal, "start_raw_ns"), _time(terminal, "exit_observed_raw_ns")
    # The independent B44 contract fixes one 180/15/15 budget; cancellation must not masquerade as normal retirement.
    deadlines = [begin + sec * 1_000_000_000 for sec in (180, 195, 210)]
    pid = terminal.get("child_pid")
    require(type(pid) is int and 0 < pid < 1 << 31 and reserved <= begin <= end < deadlines[0] and
            deadlines[-1] < 1 << 64, "invalid child identity or watchdog lifetime")
    arm = terminal.get("owner_arm")
    require(type(arm) is dict, "missing owner-arm status")
    if held:
        require(files[REFUSAL] == HOLD and arm.get("status") in ("not-granted", "peer-eof"),
                "not the B47 pre-target refusal")
        ready = queued = None
    else:
        require(type(owner) is dict and owner.get("attempt_uuid") == uid, "different owner attempt")
        ready, queued = _time(arm, "ready_raw_ns"), _time(arm, "queued_raw_ns")
        require(arm.get("status") == "queued", "watchdog did not report queuing the grant")
        decision = {"schema": "aragorn/b47-owned-child-arm-decision/v1", "attempt_uuid": uid, "child_pid": pid,
                    "clock": CLOCK, "run_deadline_raw_ns": deadlines[0], "ready_raw_ns": ready,
                    "disposition": "decision-not-delivery"}
        require(canonical(_object(files[ARM])) == canonical(decision), "foreign or inconsistent watchdog decision")
        # queued_raw_ns is sampled AFTER send. Native start may run before that sample.
        require(begin <= _time(owner,"attempt_start_ns") <= _time(owner,"observer_armed_ns") <=
                _time(owner,"recorder_armed_ns") <= ready <= _time(owner,"start_issued_ns") <=
                _time(owner,"active_observed_ns") <= _time(owner,"stopped_observed_ns") <=
                _time(owner,"retired_ns") <= _time(owner,"record_end_ns") <= end and
                owner["attempt_start_ns"] <= _time(owner,"record_start_ns") <= owner["recorder_armed_ns"] and
                ready <= queued <= end, "owner and watchdog RAW intervals do not join")
    expected = dict(identity, child_pid=pid, child_reaped=True, child_returncode=78 if held else 0,
                    outcome="child-exited", exit_observed_raw_ns=end, start_raw_ns=begin,
                    effective_deadlines_raw_ns=deadlines, run_deadline_raw_ns=deadlines[0],
                    graceful_deadline_raw_ns=deadlines[1], force_deadline_raw_ns=deadlines[2],
                    interrupted=False, interrupt_signal=None, host_kill_requested=False, host_kill_raw_ns=None,
                    graceful=None, force=None, vm_stopped_verified=False,
                    owner_arm=dict(status=arm["status"], ready_raw_ns=ready, queued_raw_ns=queued))
    require(canonical(terminal) == canonical(expected), "watchdog terminal is not a normal, non-escalated exit")
    return {"disposition": "consistent-held-refusal" if held else "consistent-supervised-transcript",
            "attempt_uuid": uid, "child_pid": pid, "start_raw_ns": begin, "exit_observed_raw_ns": end,
            "ready_raw_ns": ready, "queued_raw_ns": queued}
