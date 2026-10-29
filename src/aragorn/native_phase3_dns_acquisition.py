"""One bounded UDP receive journal, invoked by the owning DNS context only.

This is application sampling. No complete DNS interval or effect authority is
manufactured from readiness sends, socket-drop equality or an empty queue.
"""

import errno
import hashlib
import ipaddress
import json
import re
import select
import sys

from .native_phase3_http_canary_contract import validate_fixture
from .native_phase3_workload_dns_canary import readiness_request
from .oci_worker_protocol import canonical_json


HOST, PORT = "127.0.0.1", 47632
CAP = 524287
FALSE_FLAGS = tuple("interval_complete client_readiness_confirmed quiescence_verified final_queue_drained retention_verified blocked_pre_effect causal_attribution measurement_collected live_deployment_attested run_eligible phase3_exit_eligible".split())
LIMITATIONS = """APPLICATION_RECVMSG_SAMPLE_NOT_KERNEL_ARRIVAL_COMPLETENESS
NO_CLIENT_READINESS_RECEIPT_OR_ACTION_START_AUTHORITY
NO_SERIALIZED_DNS_QUIESCENCE_OR_FINAL_DRAIN_PROOF
RAW_PROC_AND_NAMESPACE_JOINS_NOT_DEPLOYED_KERNEL_OR_SOURCE_ATTESTATION
UINT32_DROP_EQUALITY_CANNOT_EXCLUDE_UNOBSERVED_FULL_WRAP
RETURNED_BYTES_NOT_DURABLE_RETENTION_OR_RETENTION_READBACK
SUBMISSION_UNKNOWN_EFFECT_INDETERMINATE
NO_PREVENTION_RUN_METRICS_OR_PHASE3_QUALIFICATION""".split()
ERRORS = """INPUT_REFUSED ABI_UNAVAILABLE FIXTURE_CHANGED PROCESS_CHANGED CLOCK_CHANGED
CANCEL_IDENTITY_CHANGED CANCEL_READ_FAILED SOCKET_CHANGED BIND_REFUSED
PROC_UDP_UNAVAILABLE PROC_UDP_INVALID SOCKET_DROP_UNKNOWN SOCKET_DROP_RESET
SOCKET_DROP_INCREASED POLL_FAILED RECEIVE_FAILED RECEIVE_FLAGS_REFUSED
DATAGRAM_TRUNCATED ANCILLARY_REFUSED PEER_REFUSED READINESS_SEND_FAILED
READINESS_REPLAY READ_LIMIT DATAGRAM_LIMIT CANCELLED EVIDENCE_LIMIT INTERRUPTED
FINAL_GUARD_FAILED""".split()
CLEANUP = "SOCKET_CLOSE_FAILED CANCEL_CLOSE_FAILED NAMESPACE_CLOSE_FAILED FIXTURE_CLOSE_FAILED".split()
RAW_SOURCES = (
    ("stat_hex", "/proc/self/stat", 4096),
    ("status_hex", "/proc/self/status", 16384),
    ("cgroup_hex", "/proc/self/cgroup", 1024),
    ("init_stat_hex", "/proc/1/stat", 4096),
    ("init_status_hex", "/proc/1/status", 16384),
    ("init_cgroup_hex", "/proc/1/cgroup", 1024),
    ("boot_hex", "/proc/sys/kernel/random/boot_id", 64),
    ("timens_offsets_hex", "/proc/self/timens_offsets", 512),
)
_HEADER = b"sl local_address rem_address st tx_queue rx_queue tr tm->when retrnsmt uid timeout inode ref pointer drops".split()


class DnsAcquisitionError(ValueError):
    def __init__(self, reason_code, partial_raw, cleanup_codes=()):
        super().__init__("DNS_ACQUISITION_REFUSED")
        self.reason_code = reason_code
        self.partial_raw = partial_raw
        self.cleanup_codes = tuple(cleanup_codes)


class _Fault(ValueError):
    def __init__(self, code):
        super().__init__(code)
        self.code = code


def _require(condition, code="INPUT_REFUSED"):
    if not condition:
        raise _Fault(code)


def _uint(value, minimum=0):
    return type(value) is int and minimum <= value < 2**63


def _keys(value, keys, code="INPUT_REFUSED"):
    _require(type(value) is dict and set(value) == set(keys.split()), code)
    return value


def _same(a, b, code):
    _require(canonical_json(a) == canonical_json(b), code)


def _digest(raw):
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def _pairs(items):
    result = {}
    for key, value in items:
        _require(key not in result)
        result[key] = value
    return result


def _input(raw, pin):
    _require(type(pin) is str and re.fullmatch(r"sha256:[0-9a-f]{64}", pin) is not None)
    _require(type(raw) is bytes and 0 < len(raw) < 16384 and _digest(raw) == pin)
    try:
        value = json.loads(raw.decode("ascii"), object_pairs_hook=_pairs,
                           parse_float=lambda _: _require(False), parse_constant=lambda _: _require(False))
        _require(canonical_json(value) == raw)
        _keys(value, "schema abi_profile attempt_id readiness_nonce fixture observer_process clock_domain cancellation_identity")
        _require(value["schema"] == "aragorn/native-dns-acquisition-request/v1"
                 and value["abi_profile"] == "linux-le-proc-udp-v6.12-layout-v1")
        _require(type(value["attempt_id"]) is str and re.fullmatch(r"p3-lab-a(?:02[6-9]|0[34][0-9]|050)", value["attempt_id"]) is not None)
        _require(type(value["readiness_nonce"]) is str and re.fullmatch(r"[0-9a-f]{32}", value["readiness_nonce"]) is not None)
        validate_fixture(value["fixture"])
        proc = _keys(value["observer_process"], "pid start_time_ticks uid gid")
        _require(all(_uint(proc[k], 1) for k in ("pid", "start_time_ticks"))
                 and all(type(proc[k]) is int and proc[k] == 0 for k in ("uid", "gid")))
        domain = _keys(value["clock_domain"], "clock_id boot_id time_namespace_device time_namespace_inode monotonic_offset_ns boottime_offset_ns")
        _require(domain["clock_id"] == "CLOCK_BOOTTIME" and domain["boot_id"] == value["fixture"]["boot_id"]
                 and _uint(domain["time_namespace_device"]) and _uint(domain["time_namespace_inode"], 1)
                 and all(type(domain[k]) is int and -2**63 <= domain[k] < 2**63 for k in ("monotonic_offset_ns", "boottime_offset_ns")))
        identity = _keys(value["cancellation_identity"], "device inode mode uid gid")
        _require(all(_uint(v, 1 if k == "inode" else 0) for k, v in identity.items())
                 and identity["mode"] & 0o170000 == 0o010000 and identity["uid"] == identity["gid"] == 0)
        return value
    except (ValueError, UnicodeError, TypeError, RecursionError):
        raise _Fault("INPUT_REFUSED") from None


def _document(raw, pin):
    result = dict(schema="aragorn/native-dns-acquisition/v1", status="REFUSED", request_raw_hex=raw.hex(),
                  request_digest=pin, kernel_release=None, before=None, after=None,
                  sample=dict(started_ns=None, deadline_ns=None, finished_ns=None, terminal="NOT_STARTED"),
                  receives=[], readiness_response=None,
                  counters=dict(received_datagrams=0, observer_drops=0, receive_errors=0, truncated_datagrams=0,
                                would_block_calls=0, socket_drop_delta=None, socket_drop_state="UNKNOWN"),
                  cancellation=dict(identity_before=None, identity_after=None, fd_link=None, status_flags=None,
                                    descriptor_flags=None, event="NOT_OBSERVED", observed_ns=None, read_count=None,
                                    read_errno=None, would_block_reads=0, closed=False),
                  socket_closed=False, errors=[], cleanup_codes=[], limitations=list(LIMITATIONS),
                  submission_state="UNKNOWN", effect_disposition="INDETERMINATE")
    result.update(dict.fromkeys(FALSE_FLAGS, False))
    return result


def _code(record, code, cleanup=False):
    key, permitted = ("cleanup_codes", CLEANUP) if cleanup else ("errors", ERRORS)
    _require(code in permitted)
    if code not in record[key]:
        _require(len(record[key]) < 16, "EVIDENCE_LIMIT")
        record[key].append(code)


def _reserve(record):
    # One maximum syscall row, a complete maximum after snapshot and cleanup.
    _require(len(canonical_json(record)) + 12000 + 128000 + 8192 <= CAP, "EVIDENCE_LIMIT")


def _raw(raw, maximum, code):
    _require(type(raw) is bytes and len(raw) <= maximum, code)
    return raw


def _proc(raw_stat, raw_status, code="PROCESS_CHANGED"):
    _require(type(raw_stat) is bytes and raw_stat.endswith(b"\n") and b"\0" not in raw_stat, code)
    try:
        text = raw_stat.decode("ascii")
        prefix, marker, suffix = text.rpartition(") ")
        pid_text, opening, _comm = prefix.partition(" (")
        parts = suffix.split()
        _require(marker and opening and re.fullmatch(r"[1-9][0-9]*", pid_text) is not None
                 and len(parts) >= 20 and re.fullmatch(r"[1-9][0-9]*", parts[19]) is not None, code)
        pid, ticks = int(pid_text), int(parts[19])
        _require(_uint(pid, 1) and _uint(ticks, 1), code)
        accounts = {}
        for line in raw_status.decode("ascii").splitlines():
            name, separator, tail = line.partition(":")
            if name in ("Uid", "Gid"):
                _require(separator and name not in accounts and tail.split() == ["0"] * 4, code)
                accounts[name] = 0
        _require(set(accounts) == {"Uid", "Gid"} and raw_status.endswith(b"\n") and b"\0" not in raw_status, code)
        return dict(pid=pid, start_time_ticks=ticks, uid=0, gid=0)
    except (UnicodeError, IndexError, ValueError):
        raise _Fault(code) from None


def _offsets(raw):
    _require(type(raw) is bytes and len(raw) <= 512 and raw.endswith(b"\n") and b"\0" not in raw, "CLOCK_CHANGED")
    values = {}
    for line in raw[:-1].split(b"\n"):
        pieces = line.split()
        _require(len(pieces) == 3 and pieces[0] in (b"monotonic", b"boottime")
                 and pieces[0] not in values and re.fullmatch(rb"(?:0|-?[1-9][0-9]*)", pieces[1]) is not None
                 and re.fullmatch(rb"(?:0|[1-9][0-9]*)", pieces[2]) is not None, "CLOCK_CHANGED")
        seconds, nanos = int(pieces[1]), int(pieces[2])
        value = seconds * 1000000000 + nanos
        _require(0 <= nanos <= 999999999 and -2**63 <= value < 2**63, "CLOCK_CHANGED")
        values[pieces[0].decode() + "_offset_ns"] = value
    _require(len(values) == 2, "CLOCK_CHANGED")
    return values


def _udp(raw, inode):
    _require(type(raw) is bytes and 0 < len(raw) <= 16384 and raw.endswith(b"\n") and b"\0" not in raw, "PROC_UDP_INVALID")
    try:
        raw.decode("ascii")
        lines = raw[:-1].split(b"\n")
        _require(lines[0].split() == _HEADER and len(lines) <= 65, "PROC_UDP_INVALID")
        matches = []
        for line in lines[1:]:
            p = line.split()
            _require(len(p) == 13, "PROC_UDP_INVALID")
            formats = ((0, rb"(?:0|[1-9][0-9]*):"), (1, rb"[0-9A-F]{8}:[0-9A-F]{4}"),
                       (2, rb"[0-9A-F]{8}:[0-9A-F]{4}"), (3, rb"[0-9A-F]{2}"),
                       (4, rb"[0-9A-F]{8}:[0-9A-F]{8}"), (5, rb"[0-9A-F]{2}:[0-9A-F]{8}"),
                       (6, rb"[0-9A-F]{8}"), (11, rb"[0-9a-f]{16}"))
            _require(all(re.fullmatch(pattern, p[i]) is not None for i, pattern in formats), "PROC_UDP_INVALID")
            for i in (7, 8, 9, 10, 12):
                _require(re.fullmatch(rb"(?:0|[1-9][0-9]*)", p[i]) is not None and _uint(int(p[i])), "PROC_UDP_INVALID")
            _require(int(p[10]) > 0 and int(p[12]) < 2**32 and p[5] == b"00:00000000"
                     and p[6] == b"00000000" and p[8] == b"0", "PROC_UDP_INVALID")
            local, remote = p[1].split(b":"), p[2].split(b":")
            if int(local[1], 16) == PORT and local[0] in (b"00000000", b"0100007F"):
                _require(int(p[9]) == inode, "PROC_UDP_INVALID")
            if int(p[9]) == inode:
                _require(p[1] == b"0100007F:BA10" and p[2] == b"00000000:0000"
                         and p[3] == b"07" and int(p[7]) == 0, "PROC_UDP_INVALID")
                tx, rx = (int(x, 16) for x in p[4].split(b":"))
                matches.append(dict(socket_inode=inode, uid=0, local_host=HOST, local_port=PORT,
                                    remote_host="0.0.0.0", remote_port=0, state=7,
                                    tx_queue=tx, rx_queue=rx, drops=int(p[12])))
        _require(len(matches) <= 1, "PROC_UDP_INVALID")
        _require(len(matches) == 1, "PROC_UDP_UNAVAILABLE")
        return matches[0]
    except UnicodeError:
        raise _Fault("PROC_UDP_INVALID") from None


def _peer(host, port):
    try:
        address = ipaddress.IPv4Address(host)
        return type(host) is str and str(address) == host and address.is_loopback and _uint(port, 1) and port <= 65535
    except (ValueError, TypeError):
        return False


def _counts(record, lost=False):
    counters = record["counters"]
    if lost or counters["observer_drops"] is None:
        for key in ("received_datagrams", "observer_drops", "receive_errors", "truncated_datagrams", "would_block_calls"):
            counters[key] = None
        return
    rows = record["receives"]
    counters.update(received_datagrams=sum(r["outcome"] == "RECEIVED" for r in rows), observer_drops=0,
                    receive_errors=sum(r["outcome"] == "ERROR" for r in rows),
                    truncated_datagrams=sum(r["outcome"] == "RECEIVED" and r["receive_flags"] is not None and bool(r["receive_flags"] & 40) for r in rows),
                    would_block_calls=sum(r["outcome"] == "WOULD_BLOCK" for r in rows))


def _finish_mark(session, row, key):
    primary = sys.exception()
    try:
        row[key] = session.tick()
    except BaseException:
        _code(session.record, "CLOCK_CHANGED")
        if primary is None:
            raise
        primary.add_note("DNS_FINAL_CLOCK_SAMPLE_FAILED")


def _drop_join(record):
    rows = [record[edge]["proc_udp_row"] if record[edge] is not None else None for edge in ("before", "after")]
    counters = record["counters"]
    if None in rows:
        counters.update(socket_drop_delta=None, socket_drop_state="UNKNOWN")
        _code(record, "SOCKET_DROP_UNKNOWN")
    else:
        old, new = (row["drops"] for row in rows)
        state = "RESET" if new < old else "INCREASED" if new > old else "UNCHANGED"
        counters.update(socket_drop_delta=None if new < old else new - old, socket_drop_state=state)
        if state != "UNCHANGED":
            _code(record, "SOCKET_DROP_" + state)


def _receive_once(session):
    record = session.record
    session.guard()
    session.check_cancel()
    _reserve(record)
    session.operation_guard()
    started = session.tick()
    if started >= record["sample"]["deadline_ns"]:
        record["sample"].update(finished_ns=started, terminal="DEADLINE")
        return False
    row = dict(sequence=len(record["receives"]), call_started_ns=started, call_finished_ns=None,
               call_flags=64, outcome="ERROR", errno=None, peer_host=None, peer_port=None,
               raw_hex=None, returned_bytes=None, receive_flags=None, ancillary=None)
    record["receives"].append(row)
    returned, published = False, False
    try:
        try:
            facts = session.sock.recvmsg(4096, 256, 64)
            returned = True
            _require(type(facts) is tuple and len(facts) == 4, "RECEIVE_FAILED")
            data, controls, flags, peer = facts
        except OSError as exc:
            row["errno"] = exc.errno if type(exc.errno) is int and 0 < exc.errno < 2**31 else None
            if exc.errno in (errno.EAGAIN, errno.EWOULDBLOCK):
                row["outcome"] = "WOULD_BLOCK"
                return
            raise _Fault("RECEIVE_FAILED") from None
        _require(type(data) is bytes and type(flags) is int and 0 <= flags < 2**32
                 and type(peer) is tuple and len(peer) == 2 and type(peer[0]) is str
                 and len(peer[0]) <= 64 and peer[0].isascii() and _uint(peer[1]) and peer[1] <= 65535, "RECEIVE_FAILED")
        row.update(outcome="RECEIVED", raw_hex=data[:4096].hex(), returned_bytes=min(len(data), 4096),
                   receive_flags=flags, peer_host=peer[0], peer_port=peer[1], ancillary=[])
        published = True
        if flags & ~40:
            _code(record, "RECEIVE_FLAGS_REFUSED")
        if flags & 40 or len(data) > 4096:
            _code(record, "DATAGRAM_TRUNCATED")
        if not _peer(*peer):
            _code(record, "PEER_REFUSED")
        if controls:
            _code(record, "ANCILLARY_REFUSED")
        _require(type(controls) is list, "ANCILLARY_REFUSED")
        total = 0
        for control in controls[:8]:
            _require(type(control) is tuple and len(control) == 3 and _uint(control[0])
                     and _uint(control[1]) and type(control[2]) is bytes, "ANCILLARY_REFUSED")
            available = control[2][:max(0, 256 - total)]
            row["ancillary"].append(dict(level=control[0], type=control[1], raw_hex=available.hex()))
            total += len(available)
            _require(len(available) == len(control[2]), "ANCILLARY_REFUSED")
        _require(len(controls) <= 8, "ANCILLARY_REFUSED")
        _require(not flags & ~40, "RECEIVE_FLAGS_REFUSED")
        _require(not flags & 40 and len(data) <= 4096, "DATAGRAM_TRUNCATED")
        _require(not controls, "ANCILLARY_REFUSED")
        _require(_peer(*peer), "PEER_REFUSED")
    except MemoryError:
        _counts(record, lost=True)
        raise
    finally:
        if returned and not published:
            _counts(record, lost=True)
            _code(record, "RECEIVE_FAILED")
        _counts(record)
        _finish_mark(session, row, "call_finished_ns")
    session.guard()
    if row["raw_hex"] == session.query.hex():
        _require(record["readiness_response"] is None, "READINESS_REPLAY")
        _respond_once(session, row)


def _respond_once(session, receive):
    session.guard()
    session.check_cancel()
    session.operation_guard()
    started = session.tick()
    _require(started < session.record["sample"]["deadline_ns"], "READINESS_SEND_FAILED")
    response = session.query[:2] + b"\x80\x00" + session.query[4:]
    row = dict(receive_sequence=receive["sequence"], call_started_ns=started, call_finished_ns=None,
               peer_host=receive["peer_host"], peer_port=receive["peer_port"], response_hex=response.hex(),
               returned_bytes=None, errno=None)
    session.record["readiness_response"] = row
    try:
        try:
            count = session.sock.sendto(response, 64, (row["peer_host"], row["peer_port"]))
        except OSError as exc:
            row["errno"] = exc.errno if type(exc.errno) is int and 0 < exc.errno < 2**31 else None
            raise _Fault("READINESS_SEND_FAILED") from None
        if _uint(count):
            row["returned_bytes"] = count
        _require(type(count) is int and count == len(response), "READINESS_SEND_FAILED")
    finally:
        _finish_mark(session, row, "call_finished_ns")
    session.guard()


def _sample(session):
    record = session.record
    session.guard()
    _reserve(record)
    start = session.tick()
    _require(start + 2000000000 < 2**63, "CLOCK_CHANGED")
    record["sample"].update(started_ns=start, deadline_ns=start + 2000000000, terminal="REFUSED")
    poller = select.poll()
    poller.register(session.cancel_fd, select.POLLIN | select.POLLHUP | select.POLLERR | select.POLLNVAL)
    poller.register(session.sock.fileno(), select.POLLIN | select.POLLHUP | select.POLLERR | select.POLLNVAL)
    while True:
        session.guard()
        remaining = record["sample"]["deadline_ns"] - session.tick()
        if remaining <= 0:
            record["sample"].update(finished_ns=session.tick(), terminal="DEADLINE")
            return
        session.check_cancel()
        session.operation_guard()
        now = session.tick()
        remaining = record["sample"]["deadline_ns"] - now
        if remaining <= 0:
            record["sample"].update(finished_ns=now, terminal="DEADLINE")
            return
        try:
            events = poller.poll(min(50, max(1, (remaining + 999999) // 1000000)))
        except OSError:
            raise _Fault("POLL_FAILED") from None
        session.guard()
        if any(fd == session.cancel_fd for fd, _ in events):
            session.cancel_events([(fd, flags) for fd, flags in events if fd == session.cancel_fd])
        for fd, flags in events:
            if fd == session.cancel_fd:
                continue
            _require(fd == session.sock.fileno() and flags == select.POLLIN, "POLL_FAILED")
            if session.tick() >= record["sample"]["deadline_ns"]:
                record["sample"].update(finished_ns=session.tick(), terminal="DEADLINE")
                return
            if _receive_once(session) is False:
                return
            _require(len(record["receives"]) < 64, "READ_LIMIT")
            _require(record["counters"]["received_datagrams"] < 16, "DATAGRAM_LIMIT")
