"""Independent retained-reader byte consistency, never native custody or authority.

A complete supplement can predate failed retention and an unsuccessful leaf call.
Caller identity pins and the explicit Linux ABI are assumptions, not observations.
"""

import base64
import hashlib
import json
import re


_COMMON = set("""
schema status claim_attempted claim_confirmed send_attempted
sensor_health_verified effect_authorized run_qualified
epoch_base64 challenge_base64 connection_epoch
observed_fields supplied_process_fields peer_credentials_base64
claim_base64 claim_readback_base64
send_started_ns send_call_flags send_finished_ns send_bytes accepted_ns
failure_type cleanup_failure_count cleanup_failure_types
cleanup_failure_types_complete descriptor_cleanup
""".split())
_EDGE = """started_ns pidfd_info_base64
reader_stat_before_base64 reader_status_base64 reader_stat_after_base64
observer_stat_before_base64 observer_status_base64 observer_stat_after_base64
boot_base64 namespaces finished_ns processes""".split()
_COMMON |= {edge + "_" + field for edge in ("before", "after") for field in _EDGE}
_PACKET = set("recvmsg_call_flags response_base64 controls receive_flags received_ns".split())
_OBSERVED = ["reader_pid", "reader_start_ticks", "reader_uid", "reader_gid", "boot_id", "clock"]
_SUPPLIED = ["program_map_digest", "reader_source_digest", "sensor_gid", "sensor_pid",
             "sensor_source_digest", "sensor_start_ticks", "sensor_uid", "stream_digest"]


def _check(condition, reason):
    if not condition:
        raise ValueError(reason)


def _encode(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False).encode("ascii")


def _hash(raw):
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def _shape(value, fields):
    wanted = set(fields.split()) if type(fields) is str else fields
    _check(type(value) is dict and set(value) == wanted, "field inventory")
    return value


def _integer(value, low=0, high=2**63):
    _check(type(value) is int and low <= value < high, "integer range")
    return value


def _pattern(value, pattern):
    _check(type(value) is str and re.fullmatch(pattern, value) is not None, "identifier")


def _pin(value):
    _pattern(value, r"sha256:[0-9a-f]{64}")


def _pairs(items):
    result = {}
    for key, value in items:
        _check(key not in result, "duplicate JSON field")
        result[key] = value
    return result


def _constant(_value):
    raise ValueError("nonfinite JSON constant")


def _document(raw, maximum):
    _check(type(raw) is bytes and 0 < len(raw) <= maximum, "raw size")
    try:
        value = json.loads(raw.decode("ascii"), object_pairs_hook=_pairs, parse_constant=_constant)
        _check(_encode(value) == raw, "canonical JSON")
        return value
    except (UnicodeError, RecursionError) as exc:
        raise ValueError("raw encoding") from exc


def _binary(value, maximum):
    _check(type(value) is str and 0 < len(value) <= 4 * ((maximum + 2) // 3), "base64 size")
    raw = base64.b64decode(value, validate=True)
    _check(0 < len(raw) <= maximum and base64.b64encode(raw).decode("ascii") == value, "canonical base64")
    return raw


def _equal(actual, expected):
    # Canonical comparison also excludes bool/int and float/int equality aliases.
    _check(_encode(actual) == _encode(expected), "reconstructed record mismatch")


def _identity(value):
    _shape(value, "pid start_time_ticks uid gid")
    _integer(value["pid"], 1, 2**31)
    _integer(value["start_time_ticks"], 1)
    for field in ("uid", "gid"):
        _integer(value[field], 0, 2**32)
    return value


def _namespace(value):
    _shape(value, "device inode")
    _integer(value["device"])
    _integer(value["inode"], 1)
    return value


def _credentials(raw):
    _check(len(raw) == 12, "Linux ucred size")
    pid = _integer(int.from_bytes(raw[:4], "little", signed=True), 1, 2**31)
    return {"pid": pid, "uid": int.from_bytes(raw[4:8], "little"),
            "gid": int.from_bytes(raw[8:12], "little")}


def _decimal(token, low=0, high=2**63):
    _check(re.fullmatch(rb"0|[1-9][0-9]*", token) is not None, "proc decimal")
    return _integer(int(token), low, high)


def _proc_identity(stat_before, status, stat_after, restricted):
    def stat_identity(raw):
        # The parenthesized comm may itself contain spaces, parentheses or newlines.
        match = re.fullmatch(rb"([1-9][0-9]*) \((.*)\) ([^\r\n]+)\n?", raw, re.DOTALL)
        _check(match is not None, "proc stat framing")
        tail = match[3].split()
        _check(len(tail) >= 20, "truncated proc stat")
        return _decimal(match[1], 1, 2**31), _decimal(tail[19], 1)

    for raw in (stat_before, status, stat_after):
        try:
            raw.decode("ascii")
        except UnicodeError as exc:
            raise ValueError("proc encoding") from exc
    pid, start = stat_identity(stat_before)
    _check(stat_identity(stat_after) == (pid, start), "proc start discontinuity")
    required = {b"Uid", b"Gid"}
    caps = {b"CapInh", b"CapPrm", b"CapEff", b"CapBnd", b"CapAmb"}
    if restricted:
        required |= caps | {b"NoNewPrivs"}
    columns = {}
    for line in status.splitlines():
        key, separator, value = line.partition(b":")
        if key.strip() in required:
            _check(key in required and separator and key not in columns, "duplicate or malformed proc status field")
            columns[key] = value.split()
    _check(set(columns) == required, "missing proc status field")
    result = {"pid": pid, "start_time_ticks": start}
    for field in (b"Uid", b"Gid"):
        vector = columns[field]
        _check(len(vector) == 4, "proc account vector")
        accounts = [_decimal(token, 0, 2**32) for token in vector]
        _check(len(set(accounts)) == 1, "changing proc account")
        result[field.decode().lower()] = accounts[0]
    if restricted:
        _check(columns[b"NoNewPrivs"] == [b"1"], "reader privilege escalation")
        for field in caps:
            vector = columns[field]
            _check(len(vector) == 1 and re.fullmatch(rb"[0-9a-fA-F]+", vector[0]) is not None
                   and int(vector[0], 16) == 0, "reader capabilities")
    return result


def _epoch(raw, bindings):
    epoch = _shape(_document(raw, 32768), "process clock loss_scope policy deployment_digest")
    _check(_hash(raw) == bindings["epoch"], "epoch pin")
    for key in ("process", "clock", "loss_scope", "policy"):
        _check(_hash(_encode(epoch[key])) == bindings[key], "component pin")
    _pin(epoch["deployment_digest"])
    process = _shape(epoch["process"], "boot_id reader_pid reader_start_ticks sensor_pid sensor_start_ticks "
                     "reader_uid reader_gid sensor_uid sensor_gid reader_source_digest sensor_source_digest "
                     "stream_digest program_map_digest")
    _pattern(process["boot_id"], r"[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}")
    for role in ("reader", "sensor"):
        _identity({"pid": process[role + "_pid"], "start_time_ticks": process[role + "_start_ticks"],
                   "uid": process[role + "_uid"], "gid": process[role + "_gid"]})
    for name in ("reader_source_digest", "sensor_source_digest", "stream_digest", "program_map_digest"):
        _pin(process[name])
    clock = _shape(epoch["clock"], "boot_id clock_id time_namespace_inode")
    _integer(clock["time_namespace_inode"], 1)
    _check(clock["boot_id"] == process["boot_id"] and clock["clock_id"] == "CLOCK_BOOTTIME", "clock domain")
    policy = _shape(epoch["policy"], "timeout_ns max_age_ns")
    for number in policy.values():
        _integer(number, 1)
    scope = epoch["loss_scope"]
    _check(type(scope) is list and 1 <= len(scope) <= 32, "loss inventory size")
    for pin in scope:
        _pin(pin)
    _check(scope == sorted(set(scope)), "loss inventory order")
    return epoch


def verify_reader_evidence(evidence_raw: bytes, reader_raw: bytes, *, bindings: dict,
                           expected_evidence_digest: str, expected_reader_digest: str,
                           expected_observer: dict, expected_connection_epoch: str,
                           credential_abi: str) -> dict:
    """Reconstruct a complete ACK/TIMEOUT summary without trusting producer parsers."""
    _check(credential_abi == "linux-le-ucred32-v1", "unsupported credential ABI")
    _shape(bindings, "epoch challenge request process clock loss_scope policy")
    for pin in (*bindings.values(), expected_evidence_digest, expected_reader_digest):
        _pin(pin)
    for raw, maximum, pin in ((evidence_raw, 131072, expected_evidence_digest),
                              (reader_raw, 32768, expected_reader_digest)):
        _check(type(raw) is bytes and 0 < len(raw) <= maximum and _hash(raw) == pin, "raw bytes pin")
    evidence = _document(evidence_raw, 131072)
    _document(reader_raw, 32768)
    _check(type(evidence) is dict and evidence.get("status") in ("ACK", "TIMEOUT"), "complete status required")
    ack_record = evidence["status"] == "ACK"
    optional = {"recvmsg_call_flags"} if "recvmsg_call_flags" in evidence else set()
    _shape(evidence, _COMMON | (_PACKET if ack_record else optional))
    _check(evidence["schema"] == "aragorn/native-phase3-run-reader-evidence/v1", "evidence schema")
    for flag in ("claim_attempted", "claim_confirmed", "send_attempted", "cleanup_failure_types_complete"):
        _check(evidence[flag] is True, "incomplete exchange")
    for flag in ("sensor_health_verified", "effect_authorized", "run_qualified"):
        _check(evidence[flag] is False, "unsupported authority")
    _check(evidence["failure_type"] is None and _integer(evidence["cleanup_failure_count"]) == 0
           and evidence["cleanup_failure_types"] == [], "failed acquisition")
    cleanup = evidence["descriptor_cleanup"]
    _check(type(cleanup) is list and len(cleanup) == 3, "cleanup inventory")
    descriptors = []
    for row in cleanup:
        _check(type(row) is list and len(row) == 3 and row[1] == "OWNED" and row[2] is True, "cleanup outcome")
        descriptors.append(_integer(row[0], 0, 2**31))
    _check(len(set(descriptors)) == 3, "duplicate cleanup descriptor")
    _equal(evidence["observed_fields"], _OBSERVED)
    _equal(evidence["supplied_process_fields"], _SUPPLIED)
    _pattern(expected_connection_epoch, r"[0-9a-f]{64}")
    _check(evidence["connection_epoch"] == expected_connection_epoch, "connection epoch")
    _shape(expected_observer, "pid start_time_ticks uid gid time_namespace")
    observer = _identity({key: expected_observer[key] for key in ("pid", "start_time_ticks", "uid", "gid")})
    namespace = _namespace(expected_observer["time_namespace"])
    epoch = _epoch(_binary(evidence["epoch_base64"], 32768), bindings)
    p = epoch["process"]
    reader = {"pid": p["reader_pid"], "start_time_ticks": p["reader_start_ticks"],
              "uid": p["reader_uid"], "gid": p["reader_gid"]}
    _check(observer["pid"] != reader["pid"] and namespace["inode"] == epoch["clock"]["time_namespace_inode"], "observer domain")
    challenge_raw = _binary(evidence["challenge_base64"], 4096)
    challenge = _shape(_document(challenge_raw, 4096), "epoch_digest request_digest boundary nonce issued_ns deadline_ns sequence_before")
    _check(_hash(challenge_raw) == bindings["challenge"] and challenge["epoch_digest"] == bindings["epoch"]
           and challenge["request_digest"] == bindings["request"], "challenge pins")
    _check(challenge["boundary"] == "BEFORE_FIRST_EFFECT", "effect boundary")
    _pattern(challenge["nonce"], r"[0-9a-f]{64}")
    issued, deadline, baseline = (_integer(challenge[key]) for key in ("issued_ns", "deadline_ns", "sequence_before"))
    _check(deadline - issued == epoch["policy"]["timeout_ns"], "challenge policy deadline")
    claim_raw = _binary(evidence["claim_base64"], 4096)
    claim = _shape(_document(claim_raw, 4096), "schema connection_epoch challenge")
    _check(claim["schema"] == "aragorn/native-phase3-run-reader-claim/v1"
           and claim["connection_epoch"] == expected_connection_epoch, "claim identity")
    _check(_encode(claim["challenge"]) == challenge_raw
           and _binary(evidence["claim_readback_base64"], 4096) == claim_raw, "claim readback")
    peer_raw = _binary(evidence["peer_credentials_base64"], 12)
    peer = _credentials(peer_raw)
    _equal(peer, {key: reader[key] for key in ("pid", "uid", "gid")})
    for edge in ("before", "after"):
        decoded = {}
        for role in ("reader", "observer"):
            raws = [_binary(evidence[f"{edge}_{role}_{name}_base64"], 16384)
                    for name in ("stat_before", "status", "stat_after")]
            decoded[role] = _proc_identity(*raws, restricted=role == "reader")
        _equal(decoded, {"reader": reader, "observer": observer})
        _equal(evidence[edge + "_processes"], decoded)
        _equal(evidence[edge + "_namespaces"], {"reader": namespace, "observer": namespace})
        fdinfo = _binary(evidence[edge + "_pidfd_info_base64"], 4096)
        try:
            fdinfo.decode("ascii")
        except UnicodeError as exc:
            raise ValueError("pidfd report encoding") from exc
        pid_fields = [line.partition(b":")[2].strip() for line in fdinfo.splitlines()
                      if line.partition(b":")[0].strip() == b"Pid"]
        _check(pid_fields == [str(reader["pid"]).encode("ascii")], "pidfd reported PID")
        boot = _binary(evidence[edge + "_boot_base64"], 64)
        _check(boot == (p["boot_id"] + "\n").encode("ascii"), "boot binding")
    _check(_integer(evidence["send_call_flags"]) == 0x4040
           and _integer(evidence["send_bytes"]) == len(challenge_raw), "send report")
    if "recvmsg_call_flags" in evidence:
        _check(_integer(evidence["recvmsg_call_flags"]) == 0x40000040, "recvmsg report")
    before_start, before_end, send_start, send_end, after_start, after_end, accepted = (
        _integer(evidence[key]) for key in ("before_started_ns", "before_finished_ns", "send_started_ns",
                                          "send_finished_ns", "after_started_ns", "after_finished_ns", "accepted_ns"))
    _check(issued <= before_start <= before_end <= send_start <= send_end < deadline
           and after_start <= after_end <= accepted, "exchange chronology")
    ack, received, sequence = None, None, baseline
    if ack_record:
        controls = evidence["controls"]
        _check(type(controls) is list and len(controls) == 1, "credential control inventory")
        row = controls[0]
        _check(type(row) is list and len(row) == 3 and _integer(row[0]) == 1 and _integer(row[1]) == 2, "Linux credential control")
        sender = _binary(row[2], 12)
        _equal(_credentials(sender), peer)
        _check(sender == peer_raw, "sender bytes")
        _check(_integer(evidence["receive_flags"]) & ~0x40000080 == 0, "returned message flags")
        response = _shape(_document(_binary(evidence["response_base64"], 4096), 4096),
                          "schema epoch_digest challenge_digest request_digest sequence_after ack_ns")
        _check(response["schema"] == "aragorn/native-phase3-run-reader-response/v1", "response schema")
        for role in ("epoch", "challenge", "request"):
            _check(response[role + "_digest"] == bindings[role], "response pin")
        ack, received, sequence = _integer(response["ack_ns"]), _integer(evidence["received_ns"]), _integer(response["sequence_after"])
        _check(sequence > baseline and send_start <= ack <= received
               and send_end <= received <= after_start <= after_end <= accepted < deadline, "ACK chronology")
    else:
        _check(deadline <= after_start, "TIMEOUT chronology")
    reconstructed = {
        "epoch_digest": bindings["epoch"], "challenge_digest": bindings["challenge"], "request_digest": bindings["request"],
        "process_before": epoch["process"], "process_after": epoch["process"],
        "clock_before": epoch["clock"], "clock_after": epoch["clock"], "peer": peer,
        "status": evidence["status"], "sequence_after": sequence, "ack_ns": ack, "received_ns": received,
    }
    _check(_encode(reconstructed) == reader_raw, "reader summary differs from raw evidence")
    return {"status": "CONSISTENT_READER_EVIDENCE", "evidence_digest": expected_evidence_digest,
            "reader_digest": expected_reader_digest, "reader_status": evidence["status"],
            "acquisition_authenticity_verified": False, "sensor_health_verified": False,
            "effect_authorized": False, "run_qualified": False}
