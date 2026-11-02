"""Independent replay of bounded DNS acquisition bytes; no native I/O.

Expected authority is caller-held. This module imports neither acquisition nor
context, DNS packet builder, private parsers or historical fixtures.
"""

import hashlib
import ipaddress
import json
import re

from .native_phase3_http_canary_contract import validate_fixture
from .oci_worker_protocol import canonical_json


_FLAGS = "interval_complete client_readiness_confirmed quiescence_verified final_queue_drained retention_verified blocked_pre_effect causal_attribution measurement_collected live_deployment_attested run_eligible phase3_exit_eligible".split()
_LIMITS = """APPLICATION_RECVMSG_SAMPLE_NOT_KERNEL_ARRIVAL_COMPLETENESS
NO_CLIENT_READINESS_RECEIPT_OR_ACTION_START_AUTHORITY
NO_SERIALIZED_DNS_QUIESCENCE_OR_FINAL_DRAIN_PROOF
RAW_PROC_AND_NAMESPACE_JOINS_NOT_DEPLOYED_KERNEL_OR_SOURCE_ATTESTATION
UINT32_DROP_EQUALITY_CANNOT_EXCLUDE_UNOBSERVED_FULL_WRAP
RETURNED_BYTES_NOT_DURABLE_RETENTION_OR_RETENTION_READBACK
SUBMISSION_UNKNOWN_EFFECT_INDETERMINATE
NO_PREVENTION_RUN_METRICS_OR_PHASE3_QUALIFICATION""".split()
_ERRORS = set("""INPUT_REFUSED ABI_UNAVAILABLE FIXTURE_CHANGED PROCESS_CHANGED CLOCK_CHANGED
CANCEL_IDENTITY_CHANGED CANCEL_READ_FAILED SOCKET_CHANGED BIND_REFUSED PROC_UDP_UNAVAILABLE
PROC_UDP_INVALID SOCKET_DROP_UNKNOWN SOCKET_DROP_RESET SOCKET_DROP_INCREASED POLL_FAILED
RECEIVE_FAILED RECEIVE_FLAGS_REFUSED DATAGRAM_TRUNCATED ANCILLARY_REFUSED PEER_REFUSED
READINESS_SEND_FAILED READINESS_REPLAY READ_LIMIT DATAGRAM_LIMIT CANCELLED EVIDENCE_LIMIT
INTERRUPTED FINAL_GUARD_FAILED""".split())
_CLEANUP = set("SOCKET_CLOSE_FAILED CANCEL_CLOSE_FAILED NAMESPACE_CLOSE_FAILED FIXTURE_CLOSE_FAILED".split())
_RAW_LIMITS = dict(stat_hex=4096, status_hex=16384, cgroup_hex=1024, init_stat_hex=4096,
                   init_status_hex=16384, init_cgroup_hex=1024, boot_hex=64, timens_offsets_hex=512)
_SNAPSHOT = "read_started_ns read_finished_ns observer clock_domain socket proc_udp_raw_hex proc_udp_row raw_process namespace_handles"
_SOCKET = "device inode mode uid gid fd_link host port type reuse_address reuse_port nonblocking cloexec"
_ROW = "sequence call_started_ns call_finished_ns call_flags outcome errno peer_host peer_port raw_hex returned_bytes receive_flags ancillary"


def _check(test):
    if not test:
        raise ValueError("DNS_ACQUISITION_RECORD_INVALID")


def _object(value, names):
    _check(type(value) is dict and set(value) == set(names.split() if type(names) is str else names))
    return value


def _integer(value, low=0, high=2**63):
    _check(type(value) is int and low <= value < high)
    return value


def _optional_int(value, low=0, high=2**63):
    return None if value is None else _integer(value, low, high)


def _equal(left, right):
    _check(canonical_json(left) == canonical_json(right))


def _hex(value, maximum):
    _check(type(value) is str and len(value) <= maximum * 2 and re.fullmatch(r"(?:[0-9a-f]{2})*", value) is not None)
    return bytes.fromhex(value)


def _pin(raw, expected, maximum):
    _check(type(expected) is str and re.fullmatch(r"sha256:[0-9a-f]{64}", expected) is not None)
    _check(type(raw) is bytes and 0 < len(raw) <= maximum
           and "sha256:" + hashlib.sha256(raw).hexdigest() == expected)


def _unique(pairs):
    mapping = {}
    for key, value in pairs:
        _check(key not in mapping)
        mapping[key] = value
    return mapping


def _decode(raw):
    try:
        value = json.loads(raw.decode("ascii"), object_pairs_hook=_unique,
                           parse_float=lambda _: _check(False), parse_constant=lambda _: _check(False))
        _check(canonical_json(value) == raw)
        return value
    except (ValueError, UnicodeError, TypeError, RecursionError):
        raise ValueError("DNS_ACQUISITION_RECORD_INVALID") from None


def _identity(value):
    _object(value, "device inode mode uid gid")
    for key, number in value.items():
        _integer(number, 1 if key == "inode" else 0)
    return value


def _process_shape(value):
    _object(value, "pid start_time_ticks uid gid")
    for key, number in value.items():
        _integer(number, 1 if key in ("pid", "start_time_ticks") else 0)
    return value


def _domain_shape(value):
    _object(value, "clock_id boot_id time_namespace_device time_namespace_inode monotonic_offset_ns boottime_offset_ns")
    _check(value["clock_id"] == "CLOCK_BOOTTIME" and type(value["boot_id"]) is str
           and re.fullmatch(r"[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}", value["boot_id"]) is not None)
    _integer(value["time_namespace_device"])
    _integer(value["time_namespace_inode"], 1)
    for name in ("monotonic_offset_ns", "boottime_offset_ns"):
        _integer(value[name], -2**63)
    return value


def _request(raw, pin):
    _pin(raw, pin, 16383)
    value = _object(_decode(raw), "schema abi_profile attempt_id readiness_nonce fixture observer_process clock_domain cancellation_identity")
    _check(value["schema"] == "aragorn/native-dns-acquisition-request/v1"
           and value["abi_profile"] == "linux-le-proc-udp-v6.12-layout-v1")
    _check(type(value["attempt_id"]) is str and re.fullmatch(r"p3-lab-a(?:02[6-9]|0[34][0-9]|050)", value["attempt_id"]) is not None)
    _check(type(value["readiness_nonce"]) is str and re.fullmatch(r"[0-9a-f]{32}", value["readiness_nonce"]) is not None)
    validate_fixture(value["fixture"])
    proc = _process_shape(value["observer_process"])
    _check(proc["uid"] == proc["gid"] == 0)
    _domain_shape(value["clock_domain"])
    _check(value["clock_domain"]["boot_id"] == value["fixture"]["boot_id"])
    cancel = _identity(value["cancellation_identity"])
    _check(cancel["mode"] & 0o170000 == 0o010000 and cancel["uid"] == cancel["gid"] == 0)
    return value


def _decimal(text, positive=False):
    _check(re.fullmatch(r"0|[1-9][0-9]*", text) is not None)
    return _integer(int(text), 1 if positive else 0)


def _proc_identity(stat_raw, status_raw):
    # Greedy comm capture deliberately finds the last closing parenthesis.
    stat_text = stat_raw.decode("ascii")
    match = re.fullmatch(r"([1-9][0-9]*) \((.*)\) ([^\n]+)\n", stat_text)
    _check(match is not None and "\0" not in stat_text)
    fields = match.group(3).split()
    _check(len(fields) >= 20)
    pid, start = _decimal(match.group(1), True), _decimal(fields[19], True)
    text = status_raw.decode("ascii")
    _check(text.endswith("\n") and "\0" not in text)
    uid, gid = [], []
    for line in text.split("\n"):
        label, colon, numbers = line.partition(":")
        if label == "Uid":
            uid.append(numbers.split() if colon else None)
        elif label == "Gid":
            gid.append(numbers.split() if colon else None)
    _check(uid == [["0", "0", "0", "0"]] and gid == [["0", "0", "0", "0"]])
    return {"pid": pid, "start_time_ticks": start, "uid": 0, "gid": 0}


def _clock_offsets(raw):
    text = raw.decode("ascii")
    _check(text.endswith("\n") and "\0" not in text)
    lines = text[:-1].split("\n")
    _check(len(lines) == 2)
    result = {}
    for line in lines:
        match = re.fullmatch(r"[ \t]*(monotonic|boottime)[ \t]+(0|-?[1-9][0-9]*)[ \t]+(0|[1-9][0-9]*)[ \t]*", line)
        _check(match is not None and match[1] not in result)
        ns = int(match[3])
        _check(ns <= 999999999)
        result[match[1]] = _integer(int(match[2]) * 1000000000 + ns, -2**63)
    _check(set(result) == {"monotonic", "boottime"})
    return {name + "_offset_ns": result[name] for name in result}


class _AbsentRow(ValueError):
    pass


def _udp_table(raw, socket_inode):
    text = raw.decode("ascii")
    _check(0 < len(raw) <= 16384 and text.endswith("\n") and "\0" not in text)
    lines = text[:-1].split("\n")
    _check(lines[0].split() == "sl local_address rem_address st tx_queue rx_queue tr tm->when retrnsmt uid timeout inode ref pointer drops".split()
           and len(lines) <= 65)
    targets = []
    for line in lines[1:]:
        fields = line.split()
        _check(len(fields) == 13 and fields[0].endswith(":"))
        _decimal(fields[0][:-1])
        for pos, pattern in {1: r"[0-9A-F]{8}:[0-9A-F]{4}", 2: r"[0-9A-F]{8}:[0-9A-F]{4}",
                             3: r"[0-9A-F]{2}", 4: r"[0-9A-F]{8}:[0-9A-F]{8}",
                             5: r"[0-9A-F]{2}:[0-9A-F]{8}", 6: r"[0-9A-F]{8}", 11: r"[0-9a-f]{16}"}.items():
            _check(re.fullmatch(pattern, fields[pos]) is not None)
        uid, timeout, inode, refs, drops = [_decimal(fields[pos]) for pos in (7, 8, 9, 10, 12)]
        _check(refs > 0 and drops < 4294967296 and timeout == 0
               and fields[5] == "00:00000000" and fields[6] == "00000000")
        address, port = fields[1].split(":")
        if port == "BA10" and address in ("00000000", "0100007F"):
            _check(inode == socket_inode)
        if inode != socket_inode:
            continue
        _check(fields[1:4] == ["0100007F:BA10", "00000000:0000", "07"] and uid == 0)
        tx, rx = map(lambda x: int(x, 16), fields[4].split(":"))
        targets.append({"socket_inode": inode, "uid": uid, "local_host": "127.0.0.1", "local_port": 47632,
                        "remote_host": "0.0.0.0", "remote_port": 0, "state": 7,
                        "tx_queue": tx, "rx_queue": rx, "drops": drops})
    _check(len(targets) <= 1)
    if not targets:
        raise _AbsentRow("DNS_ACQUISITION_RECORD_INVALID")
    return targets[0]


def _join(test, code, errors):
    _check(test or code in errors)


def _ordered(earlier, later):
    # Null plus its independently required clock-failure code makes a comparison
    # unavailable. A code alone never excuses contradictory known timestamps.
    if earlier is not None and later is not None:
        _check(earlier <= later)


def _snapshot(value, request, errors, normal):
    if value is None:
        _check(not normal)
        return None
    _object(value, _SNAPSHOT)
    start = _optional_int(value["read_started_ns"])
    finish = _optional_int(value["read_finished_ns"])
    _check(start is not None)
    if finish is not None:
        _check(finish >= start)
    else:
        _check(not normal and "CLOCK_CHANGED" in errors)
    handles = _object(value["namespace_handles"], "network init_network time time_for_children")
    for role, item in handles.items():
        if item is None:
            _check(not normal)
            continue
        _object(item, "held_device held_inode named_device named_inode")
        for key, number in item.items():
            _integer(number, 1 if "inode" in key else 0)
        device = request["clock_domain"]["time_namespace_device"] if role.startswith("time") else request["fixture"]["netns_device"]
        inode = request["clock_domain"]["time_namespace_inode"] if role.startswith("time") else request["fixture"]["netns_inode"]
        _join(item == dict(held_device=device, named_device=device, held_inode=inode, named_inode=inode),
              "CLOCK_CHANGED" if role.startswith("time") else "FIXTURE_CHANGED", errors)
    sock = value["socket"]
    if sock is not None:
        _object(sock, _SOCKET)
        for key in ("device", "inode", "mode", "uid", "gid"):
            _integer(sock[key], 1 if key == "inode" else 0)
        for key in ("type", "reuse_address", "reuse_port"):
            _integer(sock[key])
        _check(type(sock["nonblocking"]) is bool and type(sock["cloexec"]) is bool
               and type(sock["fd_link"]) is str and len(sock["fd_link"].encode("ascii")) <= 64)
        _join(sock["mode"] & 0o170000 == 0o140000 and sock["uid"] == sock["gid"] == 0
              and sock["fd_link"] == f"socket:[{sock['inode']}]" and sock["host"] == "127.0.0.1"
              and type(sock["port"]) is int and sock["port"] == 47632 and sock["type"] == 2
              and sock["reuse_address"] == sock["reuse_port"] == 0 and sock["nonblocking"] and sock["cloexec"], "SOCKET_CHANGED", errors)
    else:
        _check(not normal)
    raw_fields = _object(value["raw_process"], _RAW_LIMITS)
    raw = {name: None if encoded is None else _hex(encoded, _RAW_LIMITS[name]) for name, encoded in raw_fields.items()}
    if normal:
        _check(all(item is not None for item in raw.values()))
    identities = None
    if all(raw[name] is not None for name in ("stat_hex", "status_hex", "init_stat_hex", "init_status_hex")):
        try:
            identities = (_proc_identity(raw["stat_hex"], raw["status_hex"]), _proc_identity(raw["init_stat_hex"], raw["init_status_hex"]))
            _join(identities[0] == request["observer_process"] and identities[1]["pid"] == 1, "PROCESS_CHANGED", errors)
        except (ValueError, UnicodeError):
            _check("PROCESS_CHANGED" in errors and value["observer"] is None)
    cgroup_root = ("0::/docker/" + request["fixture"]["container_id"]).encode("ascii")
    if raw["init_cgroup_hex"] is not None:
        _join(raw["init_cgroup_hex"] == cgroup_root + b"/init.scope\n", "FIXTURE_CHANGED", errors)
    if raw["cgroup_hex"] is not None:
        group = raw["cgroup_hex"]
        _join(group.endswith(b"\n") and group.count(b"\n") == 1
              and (group == cgroup_root + b"\n" or group.startswith(cgroup_root + b"/")), "FIXTURE_CHANGED", errors)
    observer = value["observer"]
    if observer is not None:
        _object(observer, "fixture process init_process socket_inode")
        validate_fixture(observer["fixture"])
        _process_shape(observer["process"])
        _process_shape(observer["init_process"])
        _integer(observer["socket_inode"], 1)
        _check(identities is not None and sock is not None)
        _equal(observer, dict(fixture=request["fixture"], process=identities[0], init_process=identities[1], socket_inode=sock["inode"]))
    else:
        _check(not normal)
    if raw["boot_hex"] is not None:
        _join(raw["boot_hex"] == (request["fixture"]["boot_id"] + "\n").encode("ascii"), "CLOCK_CHANGED", errors)
    offsets = None
    if raw["timens_offsets_hex"] is not None:
        try:
            offsets = _clock_offsets(raw["timens_offsets_hex"])
        except (ValueError, UnicodeError):
            _check("CLOCK_CHANGED" in errors and value["clock_domain"] is None)
    if value["clock_domain"] is not None:
        domain = _domain_shape(value["clock_domain"])
        _check(offsets is not None and handles["time"] is not None and raw["boot_hex"] is not None)
        observed = dict(clock_id="CLOCK_BOOTTIME", boot_id=raw["boot_hex"][:-1].decode("ascii"),
                        time_namespace_device=handles["time"]["held_device"], time_namespace_inode=handles["time"]["held_inode"], **offsets)
        _equal(domain, observed)
        _join(domain == request["clock_domain"], "CLOCK_CHANGED", errors)
    else:
        _check(not normal)
    table = value["proc_udp_raw_hex"]
    row = value["proc_udp_row"]
    parsed = None
    if table is not None:
        table_raw = _hex(table, 16384)
        _check(sock is not None)
        try:
            parsed = _udp_table(table_raw, sock["inode"])
        except _AbsentRow:
            _check("PROC_UDP_UNAVAILABLE" in errors and row is None)
        except (ValueError, UnicodeError):
            _check("PROC_UDP_INVALID" in errors and row is None)
    if row is not None:
        _object(row, "socket_inode uid local_host local_port remote_host remote_port state tx_queue rx_queue drops")
        _check(parsed is not None)
        _equal(row, parsed)
    else:
        _check(not normal)
    return parsed if row is not None else None


def _loopback(host, port):
    try:
        parsed = ipaddress.IPv4Address(host)
        return type(host) is str and str(parsed) == host and parsed.is_loopback and type(port) is int and 1 <= port <= 65535
    except (ValueError, TypeError):
        return False


def verify_dns_acquisition(acquisition_raw: bytes, *, expected_acquisition_digest: str,
                           expected_request_digest: str, expected_request_raw: bytes) -> dict:
    """Verify retained assertions and failure joins without authenticating custody."""
    try:
        return _verify(acquisition_raw, expected_acquisition_digest, expected_request_digest, expected_request_raw)
    except (ValueError, UnicodeError, TypeError, KeyError, IndexError, OverflowError, RecursionError):
        raise ValueError("DNS_ACQUISITION_RECORD_INVALID") from None


def _verify(raw, pin, request_pin, request_raw):
    request = _request(request_raw, request_pin)
    _pin(raw, pin, 524287)
    names = "schema status request_raw_hex request_digest kernel_release before after sample receives readiness_response counters cancellation socket_closed errors cleanup_codes limitations submission_state effect_disposition".split() + _FLAGS
    value = _object(_decode(raw), names)
    _check(value["schema"] == "aragorn/native-dns-acquisition/v1"
           and value["status"] in ("SAMPLED_NOT_COMPLETE", "REFUSED", "CANCELLED")
           and value["request_digest"] == request_pin and _hex(value["request_raw_hex"], 16383) == request_raw
           and value["limitations"] == _LIMITS and all(value[k] is False for k in _FLAGS)
           and value["submission_state"] == "UNKNOWN" and value["effect_disposition"] == "INDETERMINATE"
           and type(value["socket_closed"]) is bool)
    for name, codes in (("errors", _ERRORS), ("cleanup_codes", _CLEANUP)):
        items = value[name]
        _check(type(items) is list and len(items) <= 16 and all(type(code) is str and code in codes for code in items)
               and len(set(items)) == len(items))
    errors = value["errors"]
    normal = value["status"] == "SAMPLED_NOT_COMPLETE"
    _check(not normal or (not errors and not value["cleanup_codes"] and value["socket_closed"]))
    release = value["kernel_release"]
    _check(release is None and not normal or type(release) is str and 1 <= len(release) <= 128 and all(32 <= ord(c) <= 126 for c in release))
    cancel = _object(value["cancellation"], "identity_before identity_after fd_link status_flags descriptor_flags event observed_ns read_count read_errno would_block_reads closed")
    _check(type(cancel["closed"]) is bool)
    _integer(cancel["would_block_reads"])
    for edge in ("identity_before", "identity_after"):
        actual = cancel[edge]
        if actual is not None:
            _identity(actual)
            _join(actual == request["cancellation_identity"], "CANCEL_IDENTITY_CHANGED", errors + value["cleanup_codes"])
        else:
            _check(not normal)
    link = cancel["fd_link"]
    _check(link is None and not normal or type(link) is str and len(link.encode("ascii")) <= 64)
    _join(link is None or link == f"pipe:[{request['cancellation_identity']['inode']}]", "CANCEL_IDENTITY_CHANGED", errors)
    for key in ("status_flags", "descriptor_flags"):
        _optional_int(cancel[key])
    if cancel["status_flags"] is not None:
        _join(cancel["status_flags"] & 3 == 0 and bool(cancel["status_flags"] & 2048), "CANCEL_IDENTITY_CHANGED", errors)
    if cancel["descriptor_flags"] is not None:
        _join(bool(cancel["descriptor_flags"] & 1), "CANCEL_IDENTITY_CHANGED", errors)
    event = cancel["event"]
    _check(event in ("NOT_OBSERVED", "BYTE", "EOF", "READ_ERROR", "IDENTITY_CHANGE"))
    _optional_int(cancel["observed_ns"])
    _optional_int(cancel["read_count"])
    _optional_int(cancel["read_errno"], 1, 2**31)
    if event == "NOT_OBSERVED":
        _check(cancel["observed_ns"] is cancel["read_count"] is cancel["read_errno"] is None)
    elif event in ("BYTE", "EOF"):
        _check(cancel["read_count"] == (1 if event == "BYTE" else 0) and cancel["read_errno"] is None
               and value["status"] == "CANCELLED" and "CANCELLED" in errors)
    elif event == "READ_ERROR":
        _check(cancel["read_count"] is None and ("CANCEL_READ_FAILED" in errors or "INTERRUPTED" in errors
               or cancel["read_errno"] is None and "EVIDENCE_LIMIT" in errors))
    else:
        _check(cancel["read_count"] is cancel["read_errno"] is None and "CANCEL_IDENTITY_CHANGED" in errors)
    _check((value["status"] == "CANCELLED") == (event in ("BYTE", "EOF")))
    if normal:
        _check(cancel["closed"] and event == "NOT_OBSERVED" and link is not None
               and cancel["status_flags"] is not None and cancel["descriptor_flags"] is not None)
    if not cancel["closed"]:
        _check("CANCEL_CLOSE_FAILED" in value["cleanup_codes"])
    else:
        _check(cancel["identity_before"] is not None and cancel["identity_after"] is not None)
        _equal(cancel["identity_before"], cancel["identity_after"])
    drops = [_snapshot(value[edge], request, errors, normal) for edge in ("before", "after")]
    acquired_socket = bool(value["receives"]) or value["readiness_response"] is not None or "BIND_REFUSED" in errors
    acquired_socket = acquired_socket or any(value[e] is not None and value[e]["socket"] is not None for e in ("before", "after"))
    if acquired_socket and not value["socket_closed"]:
        _check("SOCKET_CLOSE_FAILED" in value["cleanup_codes"])
    before_end = None
    if value["before"] is not None:
        # A failed finishing clock read cannot erase the known snapshot start.
        before_end = value["before"]["read_finished_ns"]
        if before_end is None:
            before_end = value["before"]["read_started_ns"]
    if all(value[edge] is not None for edge in ("before", "after")):
        before, after = value["before"], value["after"]
        _ordered(before_end, after["read_started_ns"])
        if before["socket"] is not None and after["socket"] is not None:
            _join(all(before["socket"][k] == after["socket"][k] for k in ("device", "inode", "mode", "uid", "gid")), "SOCKET_CHANGED", errors)
        if before["observer"] is not None and after["observer"] is not None:
            _join(before["observer"] == after["observer"], "PROCESS_CHANGED", errors)
    sample = _object(value["sample"], "started_ns deadline_ns finished_ns terminal")
    start, deadline, finish = [_optional_int(sample[k]) for k in ("started_ns", "deadline_ns", "finished_ns")]
    _check(sample["terminal"] in ("NOT_STARTED", "DEADLINE", "CANCELLED", "REFUSED"))
    if start is None:
        _check(deadline is finish is None and not normal and sample["terminal"] in ("NOT_STARTED", "CANCELLED"))
    else:
        _check(deadline == start + 2000000000 and deadline < 2**63)
        _check(finish is None and "CLOCK_CHANGED" in errors or finish is not None and finish >= start)
        _check(value["before"] is not None and value["before"]["read_finished_ns"] is not None
               and value["before"]["read_finished_ns"] <= start)
    if normal:
        _check(sample["terminal"] == "DEADLINE" and start is not None and finish >= deadline)
        _check(value["after"]["read_started_ns"] >= finish)
    if value["status"] == "CANCELLED":
        _check(sample["terminal"] == "CANCELLED")
    if value["status"] == "REFUSED":
        _check(sample["terminal"] == ("NOT_STARTED" if start is None else "REFUSED"))
    rows = value["receives"]
    _check(type(rows) is list and len(rows) <= 64 and (not rows or start is not None))
    tallies = dict(received_datagrams=0, observer_drops=0, receive_errors=0, truncated_datagrams=0, would_block_calls=0)
    previous = start
    _ordered(start, cancel["observed_ns"])
    after_start = value["after"]["read_started_ns"] if value["after"] is not None else None
    _ordered(start, after_start)
    query = bytes.fromhex("ffff00000001000000000000") + b"\x0daragorn-ready\x20" + request["readiness_nonce"].encode("ascii") + b"\x07invalid\x00\x00\x01\x00\x01"
    valid_queries = []
    fatal_rows = []
    for sequence, row in enumerate(rows):
        _object(row, _ROW)
        _integer(row["sequence"])
        _check(row["sequence"] == sequence and type(row["call_flags"]) is int and row["call_flags"] == 64)
        begun, ended = [_optional_int(row[k]) for k in ("call_started_ns", "call_finished_ns")]
        if begun is None or ended is None:
            _check(not normal and "CLOCK_CHANGED" in errors)
            fatal_rows.append(sequence)
        if begun is not None:
            _check(previous is None or begun >= previous)
            _check(begun < deadline)
        if ended is not None:
            _check(begun is None or ended >= begun)
            previous = ended
            if finish is not None:
                _check(ended <= finish)
        _ordered(before_end, begun)
        _ordered(ended if ended is not None else begun, finish)
        _ordered(ended if ended is not None else begun, after_start)
        _ordered(ended if ended is not None else begun, cancel["observed_ns"])
        _optional_int(row["errno"], 1, 2**31)
        outcome = row["outcome"]
        _check(outcome in ("RECEIVED", "ERROR", "WOULD_BLOCK"))
        if outcome != "RECEIVED":
            _check(all(row[k] is None for k in ("peer_host", "peer_port", "raw_hex", "returned_bytes", "receive_flags", "ancillary")))
            if outcome == "WOULD_BLOCK":
                _check(type(row["errno"]) is int and row["errno"] == 11)
                tallies["would_block_calls"] += 1
            else:
                _check(row["errno"] != 11)
                causes = {"RECEIVE_FAILED", "INTERRUPTED"}
                if row["errno"] is None:
                    causes.update(("EVIDENCE_LIMIT", "CLOCK_CHANGED"))
                _check(not normal and bool(set(errors) & causes))
                fatal_rows.append(sequence)
                tallies["receive_errors"] += 1
            continue
        tallies["received_datagrams"] += 1
        packet = _hex(row["raw_hex"], 4096)
        _check(row["errno"] is None and _integer(row["returned_bytes"]) == len(packet))
        flags = _integer(row["receive_flags"], 0, 2**32)
        if flags & 40:
            tallies["truncated_datagrams"] += 1
        _join(not flags & ~40, "RECEIVE_FLAGS_REFUSED", errors)
        _join(not flags & 40, "DATAGRAM_TRUNCATED", errors)
        _check(type(row["peer_host"]) is str)
        _integer(row["peer_port"], 0, 65536)
        valid_peer = _loopback(row["peer_host"], row["peer_port"])
        _join(valid_peer, "PEER_REFUSED", errors)
        controls = row["ancillary"]
        _check(type(controls) is list and len(controls) <= 8)
        size = 0
        for control in controls:
            _object(control, "level type raw_hex")
            _integer(control["level"])
            _integer(control["type"])
            size += len(_hex(control["raw_hex"], 256))
        _check(size <= 256)
        _join(not controls, "ANCILLARY_REFUSED", errors)
        if flags or controls or not valid_peer:
            _check(not normal)
            fatal_rows.append(sequence)
        if packet == query and not flags and not controls and valid_peer:
            valid_queries.append(sequence)
            if len(valid_queries) > 1:
                fatal_rows.append(sequence)
        if tallies["received_datagrams"] == 16:
            _check(sequence == len(rows) - 1)
    _join(len(valid_queries) <= 1, "READINESS_REPLAY", errors)
    if fatal_rows:
        _check(not normal and min(fatal_rows) == len(rows) - 1)
    response = value["readiness_response"]
    recorded = False
    if response is not None:
        _object(response, "receive_sequence call_started_ns call_finished_ns peer_host peer_port response_hex returned_bytes errno")
        index = _integer(response["receive_sequence"])
        _check(valid_queries and index == valid_queries[0])
        _check(not fatal_rows or index < min(fatal_rows))
        incoming = rows[index]
        _equal([response["peer_host"], response["peer_port"]], [incoming["peer_host"], incoming["peer_port"]])
        _check(_hex(response["response_hex"], 4096) == query[:2] + b"\x80\x00" + query[4:])
        begun, ended = [_optional_int(response[k]) for k in ("call_started_ns", "call_finished_ns")]
        if begun is not None:
            _check(incoming["call_finished_ns"] is not None and incoming["call_finished_ns"] <= begun < deadline)
        if ended is not None:
            _ordered(begun, ended)
            _ordered(incoming["call_finished_ns"], ended)
            if index + 1 < len(rows) and rows[index + 1]["call_started_ns"] is not None:
                _check(ended <= rows[index + 1]["call_started_ns"])
        _ordered(before_end, begun)
        _ordered(ended if ended is not None else begun, finish)
        _ordered(ended if ended is not None else begun, after_start)
        _ordered(ended if ended is not None else begun, cancel["observed_ns"])
        if begun is None or ended is None:
            _check(not normal and "CLOCK_CHANGED" in errors)
        count = _optional_int(response["returned_bytes"])
        send_errno = _optional_int(response["errno"], 1, 2**31)
        _check(count is None or send_errno is None)
        success = count == len(query) and send_errno is None and begun is not None and ended is not None
        _check(success or "READINESS_SEND_FAILED" in errors or "INTERRUPTED" in errors or "CLOCK_CHANGED" in errors
               or count is None and send_errno is None and "EVIDENCE_LIMIT" in errors)
        if not success:
            _check(not normal and index == len(rows) - 1)
        recorded = success
    elif valid_queries:
        _check(not normal and bool(errors) and valid_queries[0] == len(rows) - 1)
    counters = _object(value["counters"], "received_datagrams observer_drops receive_errors truncated_datagrams would_block_calls socket_drop_delta socket_drop_state")
    unknown = [counters[k] is None for k in tallies]
    if any(unknown):
        _check(not normal and counters["observer_drops"] is None and ("EVIDENCE_LIMIT" in errors or "RECEIVE_FAILED" in errors))
    for key, number in tallies.items():
        if counters[key] is not None:
            _check(_integer(counters[key]) == number)
    _check(tallies["received_datagrams"] <= 16)
    _check(len(rows) < 64 or "READ_LIMIT" in errors or bool(fatal_rows))
    _check(tallies["received_datagrams"] < 16 or "DATAGRAM_LIMIT" in errors or bool(fatal_rows))
    if None in drops:
        state, delta = "UNKNOWN", None
        _check("SOCKET_DROP_UNKNOWN" in errors)
    else:
        old, new = drops[0]["drops"], drops[1]["drops"]
        state, delta = ("RESET", None) if new < old else ("INCREASED", new - old) if new > old else ("UNCHANGED", 0)
        if state != "UNCHANGED":
            _check("SOCKET_DROP_" + state in errors)
    _optional_int(counters["socket_drop_delta"])
    _check(counters["socket_drop_state"] == state and counters["socket_drop_delta"] == delta)
    _check(not normal or state == "UNCHANGED")
    _check(normal or bool(errors) or bool(value["cleanup_codes"]))
    result = dict(schema="aragorn/native-dns-acquisition-verification/v1", status="CONSISTENT_BOUNDED_ACQUISITION_RECORD",
                  acquisition_digest=pin, request_digest=request_pin, record_status=value["status"],
                  received_datagrams=counters["received_datagrams"], readiness_response_recorded=recorded,
                  socket_drop_state=state, limitations=list(_LIMITS), submission_state="UNKNOWN", effect_disposition="INDETERMINATE")
    result.update(dict.fromkeys(_FLAGS, False))
    return result
