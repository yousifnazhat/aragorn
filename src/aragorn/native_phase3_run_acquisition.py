"""Project bounded retained acquisition reports; no live custody or effect authority."""

import hashlib
import json
import re


def _canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()


def _digest(value):
    return "sha256:" + hashlib.sha256(_canonical(value)).hexdigest()


def _require(condition, message):
    if not condition:
        raise ValueError(message)


def _keys(value, names):
    _require(type(value) is dict and set(value) == set(names.split()), "record fields")
    return value


def _uint(value, minimum=0):
    _require(type(value) is int and minimum <= value < 2**63, "record integer")
    return value


def _pin(value):
    _require(type(value) is str and re.fullmatch(r"sha256:[0-9a-f]{64}", value), "record pin")


def project_acquisition(raw: bytes, *, bindings: dict) -> bytes:
    """Refuse invalid joins; partial broker state never implies non-submission."""
    _require(type(raw) is bytes and 0 < len(raw) <= 32768, "acquisition size")
    try:
        bundle = json.loads(raw)
        _require(_canonical(bundle) == raw, "acquisition canonical encoding")
    except (ValueError, UnicodeError, RecursionError) as exc:
        raise ValueError("acquisition encoding") from exc
    _keys(bindings, "epoch challenge request process clock loss_scope policy")
    for pin in bindings.values():
        _pin(pin)
    _keys(bundle, "schema epoch challenge reader loss submission")
    _require(bundle["schema"] == "aragorn/native-phase3-run-acquisition/v1", "acquisition schema")
    epoch = _keys(bundle["epoch"], "process clock loss_scope policy deployment_digest")
    _pin(epoch["deployment_digest"])
    _require(_digest(epoch) == bindings["epoch"], "epoch binding")
    for role in ("process", "clock", "loss_scope", "policy"):
        _require(_digest(epoch[role]) == bindings[role], "epoch component binding")
    process = _keys(epoch["process"], "boot_id reader_pid reader_start_ticks sensor_pid sensor_start_ticks "
                    "reader_uid reader_gid sensor_uid sensor_gid reader_source_digest sensor_source_digest "
                    "stream_digest program_map_digest")
    _require(type(process["boot_id"]) is str and re.fullmatch(
        r"[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}", process["boot_id"]), "process boot")
    for field in ("reader_pid", "reader_start_ticks", "sensor_pid", "sensor_start_ticks"):
        _uint(process[field], 1)
    for field in ("reader_uid", "reader_gid", "sensor_uid", "sensor_gid"):
        _uint(process[field])
    for field in ("reader_source_digest", "sensor_source_digest", "stream_digest", "program_map_digest"):
        _pin(process[field])
    clock = _keys(epoch["clock"], "boot_id clock_id time_namespace_inode")
    _require(clock["boot_id"] == process["boot_id"] and clock["clock_id"] == "CLOCK_BOOTTIME", "clock domain")
    _uint(clock["time_namespace_inode"], 1)
    scope = epoch["loss_scope"]
    _require(type(scope) is list and 1 <= len(scope) <= 32, "loss scope size")
    for series in scope:
        _pin(series)
    _require(scope == sorted(set(scope)), "loss scope order")
    policy = _keys(epoch["policy"], "timeout_ns max_age_ns")
    _uint(policy["timeout_ns"], 1)
    _uint(policy["max_age_ns"], 1)

    challenge = _keys(bundle["challenge"], "epoch_digest request_digest boundary nonce issued_ns deadline_ns sequence_before")
    _require(_digest(challenge) == bindings["challenge"], "challenge binding")
    _require(challenge["boundary"] == "BEFORE_FIRST_EFFECT", "effect boundary")
    _require(type(challenge["nonce"]) is str and re.fullmatch(r"[0-9a-f]{64}", challenge["nonce"]), "challenge nonce")
    issued = _uint(challenge["issued_ns"])
    deadline = _uint(challenge["deadline_ns"])
    baseline = _uint(challenge["sequence_before"])
    _require(deadline == issued + policy["timeout_ns"], "challenge deadline")
    reader = _keys(bundle["reader"], "epoch_digest challenge_digest request_digest process_before process_after "
                   "clock_before clock_after peer status sequence_after ack_ns received_ns")
    loss = _keys(bundle["loss"], "epoch_digest challenge_digest request_digest scope_digest before after")
    # Missing submission has no trustworthy checked timestamp; never invent one.
    submission = _keys(bundle["submission"], "epoch_digest challenge_digest request_digest checked_ns custody intent effect_possible")
    for record in (challenge, reader, loss, submission):
        for field, anchor in (("epoch_digest", "epoch"), ("challenge_digest", "challenge"),
                              ("request_digest", "request"), ("scope_digest", "loss_scope")):
            if field in record:
                _require(record[field] == bindings[anchor], "nested binding")
    checked = _uint(submission["checked_ns"])
    _require(checked >= deadline, "open window")
    for role in ("process", "clock"):
        for edge in ("before", "after"):
            _require(_digest(reader[f"{role}_{edge}"]) == bindings[role], "reader identity changed")
    sequence = _uint(reader["sequence_after"])
    if reader["peer"] is not None:
        peer = _keys(reader["peer"], "pid uid gid")
        for name in ("pid", "uid", "gid"):
            _uint(peer[name], 1 if name == "pid" else 0)
            _require(peer[name] == process[f"reader_{name}"], "reader peer")
    if reader["status"] == "ACK":
        _require(reader["peer"] is not None, "missing sender")
        ack = _uint(reader["ack_ns"])
        received = _uint(reader["received_ns"])
        _require(issued <= ack <= received <= checked and sequence > baseline, "reader acknowledgement")
    elif reader["status"] == "TIMEOUT":
        _require(reader["ack_ns"] is None and reader["received_ns"] is None and sequence == baseline, "timeout progress")
        ack = None
    else:
        raise ValueError("reader status")

    totals = []
    for edge in ("before", "after"):
        sample = loss[edge]
        if sample is None:
            totals.append(None)
            continue
        _keys(sample, "start_ns end_ns counters")
        start, end = _uint(sample["start_ns"]), _uint(sample["end_ns"])
        _require(start <= end <= checked, "loss bracket")
        _require(end <= issued if edge == "before" else start >= deadline, "loss window")
        values = sample["counters"]
        _require(type(values) is list and len(values) == len(scope), "loss inventory")
        for value in values:
            if value is not None:
                _uint(value)
        total = None if None in values else _uint(sum(values))
        totals.append(total)
    if loss["before"] is not None and loss["after"] is not None:
        if any(a is not None and b is not None and b < a for a, b in zip(
                loss["before"]["counters"], loss["after"]["counters"], strict=True)):
            totals = [None, None]
    _require(submission["custody"] in ("EXCLUSIVE", "PARTIAL"), "submission custody")
    for name in ("intent", "effect_possible"):
        _require(submission[name] is None or type(submission[name]) is bool, "submission indication")
    if submission["intent"] is True or submission["effect_possible"] is True:
        effect_state = "SUBMITTED"
    elif submission["custody"] == "EXCLUSIVE" and submission["intent"] is False and submission["effect_possible"] is False:
        effect_state = "NOT_SUBMITTED"
    else:
        effect_state = "UNKNOWN"
    return _canonical({
        "schema": "aragorn/native-phase3-run-progress-window/v1",
        "epoch": bindings["epoch"], "challenge": bindings["challenge"], "clock_id": "CLOCK_BOOTTIME",
        "issued_ns": issued, "deadline_ns": deadline, "checked_ns": checked,
        "max_age_ns": policy["max_age_ns"], "ack_ns": ack,
        "sequence_before": baseline, "sequence_after": sequence,
        "loss_before": totals[0], "loss_after": totals[1], "effect_state": effect_state,
    })
