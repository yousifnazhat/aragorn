"""One authenticated reader exchange on a borrowed protected Linux connection.

Providers own durable claims/retention; a sender-bound ACK is not sensor progress,
loss coverage, submission state, effect authority or independent custody proof.
"""

import base64
import hashlib
import json
import os
from pathlib import Path
import re
import select
import socket
import struct
import sys
import threading

from . import native_phase3_clock_domain as clock
from . import runtime_process_profile as process
from .native_phase3_run_acquisition import _canonical, _digest, _keys, _pin, _uint


# Linux UAPI values absent from some Python builds; no alternative transport.
_PASSCRED = getattr(socket, "SO_PASSCRED", 16)
_PEERCRED = getattr(socket, "SO_PEERCRED", 17)
_PASSPIDFD = getattr(socket, "SO_PASSPIDFD", 76)
_CREDENTIALS = getattr(socket, "SCM_CREDENTIALS", 2)
_PIDFD = getattr(socket, "SCM_PIDFD", 4)
_CLOEXEC = getattr(socket, "MSG_CMSG_CLOEXEC", 0x40000000)
_NOSIGNAL = getattr(socket, "MSG_NOSIGNAL", 0x4000)
_UCREDS = struct.Struct("=iII")
_MAX_EVIDENCE = 131072


class ReaderResponseError(ValueError):
    """No usable reader record; exact bounded partial evidence remains attached."""

    def __init__(self, original, partial_evidence, cleanup_failures=(), retention_failure=None):
        super().__init__("reader acquisition refused; preserve partial evidence and claim")
        self.original_failure = original
        self.partial_evidence = partial_evidence
        self.cleanup_failures = tuple(cleanup_failures)
        self.retention_failure = retention_failure


def _require(condition, reason):
    if not condition:
        raise ValueError(reason)


def _raw_digest(raw):
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def _decode(raw, maximum):
    _require(type(raw) is bytes and 0 < len(raw) <= maximum, "record size")
    value = json.loads(raw)
    _require(_canonical(value) == raw, "record canonical encoding")
    return value


def _inputs(epoch_raw, challenge_raw, bindings, connection_epoch):
    _keys(bindings, "epoch challenge request process clock loss_scope policy")
    for value in bindings.values():
        _pin(value)
    _require(type(connection_epoch) is str and re.fullmatch(r"[0-9a-f]{64}", connection_epoch), "connection epoch")
    e = _keys(_decode(epoch_raw, 32768), "process clock loss_scope policy deployment_digest")
    c = _keys(_decode(challenge_raw, 4096), "epoch_digest request_digest boundary nonce issued_ns deadline_ns sequence_before")
    _require(_raw_digest(epoch_raw) == bindings["epoch"] and _raw_digest(challenge_raw) == bindings["challenge"], "input pins")
    for key in ("process", "clock", "loss_scope", "policy"):
        _require(_digest(e[key]) == bindings[key], "component pin")
    p = _keys(e["process"], "boot_id reader_pid reader_start_ticks sensor_pid sensor_start_ticks reader_uid reader_gid "
              "sensor_uid sensor_gid reader_source_digest sensor_source_digest stream_digest program_map_digest")
    _require(type(p["boot_id"]) is str and re.fullmatch(r"[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}", p["boot_id"]), "boot pin")
    for key, value in p.items():
        if key.endswith("_digest"):
            _pin(value)
        elif key != "boot_id":
            _uint(value, 1 if key.endswith(("_pid", "_ticks")) else 0)
    _pin(e["deployment_digest"])
    _keys(e["clock"], "boot_id clock_id time_namespace_inode")
    _require(e["clock"]["boot_id"] == p["boot_id"] and e["clock"]["clock_id"] == "CLOCK_BOOTTIME", "clock pin")
    _uint(e["clock"]["time_namespace_inode"], 1)
    scope = e["loss_scope"]
    _require(type(scope) is list and 1 <= len(scope) <= 32, "loss scope")
    for value in scope:
        _pin(value)
    _require(scope == sorted(set(scope)), "loss inventory")
    _keys(e["policy"], "timeout_ns max_age_ns")
    for value in e["policy"].values():
        _uint(value, 1)
    _require(c["epoch_digest"] == bindings["epoch"] and c["request_digest"] == bindings["request"]
             and c["boundary"] == "BEFORE_FIRST_EFFECT", "challenge binding")
    _require(type(c["nonce"]) is str and re.fullmatch(r"[0-9a-f]{64}", c["nonce"]), "nonce")
    for key in ("issued_ns", "deadline_ns", "sequence_before"):
        _uint(c[key])
    _require(c["deadline_ns"] == c["issued_ns"] + e["policy"]["timeout_ns"], "challenge duration")
    return e, c


def _put(evidence, key, value):
    candidate = {**evidence, key: value}
    # Reserve space for failure/cleanup metadata; overflow can never be success.
    if len(_canonical(candidate)) > _MAX_EVIDENCE - 49152:
        evidence["overflow"] = {"field": key, "digest": _digest(value), "bytes": len(_canonical(value))}
        raise ValueError("partial evidence capacity exceeded")
    evidence[key] = value


def _bytes(evidence, key, raw):
    _put(evidence, key, base64.b64encode(raw).decode("ascii"))


def _peer(connection, expected):
    _require(connection.family == socket.AF_UNIX
             and connection.getsockopt(socket.SOL_SOCKET, socket.SO_TYPE) == socket.SOCK_SEQPACKET
             and connection.gettimeout() == 0 and not connection.get_inheritable(), "borrowed connection")
    _require(connection.getsockopt(socket.SOL_SOCKET, _PASSCRED) == 1
             and connection.getsockopt(socket.SOL_SOCKET, _PASSPIDFD) == 0, "credential options")
    raw = connection.getsockopt(socket.SOL_SOCKET, _PEERCRED, _UCREDS.size)
    _require(type(raw) is bytes and len(raw) == _UCREDS.size, "peer credentials size")
    values = _UCREDS.unpack(raw)
    _require(values == tuple(expected["reader_" + key] for key in ("pid", "uid", "gid")), "peer identity")
    return raw


def _proc_record(pid, raw_stat, raw_status, raw_after, *, restricted):
    def start(raw):
        text = raw.decode("ascii")
        marker = text.rfind(") ")
        fields = text[marker + 2:].split() if marker >= 0 else []
        _require(text.startswith(f"{pid} (") and len(fields) >= 20 and fields[19].isdigit(), "proc stat")
        return _uint(int(fields[19]), 1)
    before = start(raw_stat)
    _require(start(raw_after) == before, "proc start changed")
    wanted = {"Uid", "Gid", "CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb", "NoNewPrivs"}
    values = {}
    for line in raw_status.decode("ascii").splitlines():
        name, separator, rest = line.partition(":")
        if name in wanted:
            _require(separator and name not in values, "duplicate proc field")
            values[name] = rest.split()
    accounts = {}
    for name in ("Uid", "Gid"):
        vector = values.get(name, [])
        _require(len(vector) == 4 and all(re.fullmatch(r"0|[1-9][0-9]*", v) for v in vector), "account vector")
        numbers = [_uint(int(v)) for v in vector]
        _require(len(set(numbers)) == 1, "mixed account identity")
        accounts[name.lower()] = numbers[0]
    if restricted:
        _require(values.get("NoNewPrivs") == ["1"], "reader privilege escalation allowed")
        for name in wanted - {"Uid", "Gid", "NoNewPrivs"}:
            parts = values.get(name, [])
            _require(len(parts) == 1 and re.fullmatch(r"[0-9a-fA-F]+", parts[0]) and int(parts[0], 16) == 0, "reader capabilities")
    return {"pid": pid, "start_time_ticks": before, **accounts}


def _readbacks(evidence, edge, pidfd, namespaces, epoch, observer, tick):
    process.require_live_pidfd(pidfd)
    _put(evidence, edge + "_started_ns", tick())
    fdinfo = process._read_virtual_file(Path(f"/proc/self/fdinfo/{pidfd}"), 4096)
    _bytes(evidence, edge + "_pidfd_info_base64", fdinfo)
    _require([line.partition(":")[2].strip() for line in fdinfo.decode("ascii").splitlines()
              if line.startswith("Pid:")] == [str(epoch["process"]["reader_pid"])], "held pidfd changed")
    process.require_live_pidfd(pidfd)
    actual = {}
    for role, pid in (("reader", epoch["process"]["reader_pid"]), ("observer", observer)):
        raws = []
        for suffix, leaf in (("stat_before", "stat"), ("status", "status"), ("stat_after", "stat")):
            process.require_live_pidfd(pidfd)
            raw = process._read_virtual_file(Path(f"/proc/{pid}/{leaf}"), 16384)
            _bytes(evidence, f"{edge}_{role}_{suffix}_base64", raw)
            process.require_live_pidfd(pidfd)
            raws.append(raw)
        actual[role] = _proc_record(pid, *raws, restricted=role == "reader")
    process.require_live_pidfd(pidfd)
    boot_raw = process._read_virtual_file(Path("/proc/sys/kernel/random/boot_id"), 64)
    _bytes(evidence, edge + "_boot_base64", boot_raw)
    _require(boot_raw == (epoch["clock"]["boot_id"] + "\n").encode("ascii"), "boot changed")
    views = {role: clock._namespace(pid, descriptor) for role, (pid, descriptor) in namespaces.items()}
    _put(evidence, edge + "_namespaces", views)
    _require(views["reader"] == views["observer"] and views["reader"]["inode"] == epoch["clock"]["time_namespace_inode"], "time domain mismatch")
    expected = epoch["process"]
    _require(actual["reader"] == {"pid": expected["reader_pid"], "start_time_ticks": expected["reader_start_ticks"],
                                   "uid": expected["reader_uid"], "gid": expected["reader_gid"]}, "reader epoch mismatch")
    _require(os.getpid() == observer == threading.get_native_id()
             and actual["observer"]["uid"] == os.geteuid() and actual["observer"]["gid"] == os.getegid(), "observer changed")
    process.require_live_pidfd(pidfd)
    _put(evidence, edge + "_finished_ns", tick())
    _put(evidence, edge + "_processes", actual)
    return actual


def _wait(connection, pidfd, event, deadline, tick):
    poller = select.poll()
    poller.register(connection.fileno(), event | select.POLLERR | select.POLLHUP | select.POLLNVAL)
    poller.register(pidfd, select.POLLIN | select.POLLERR | select.POLLHUP | select.POLLNVAL)
    while True:
        remaining = deadline - tick()
        if remaining <= 0:
            return False
        try:
            events = poller.poll(min((remaining + 999999) // 1000000, 2**31 - 1))
        except InterruptedError:
            continue
        process.require_live_pidfd(pidfd)
        for fd, flags in events:
            _require(fd == connection.fileno() and not flags & ~event, "peer exit or transport poll error")
        if any(flags & event for _, flags in events):
            return tick() < deadline


def _unread(connection):
    poller = select.poll()
    poller.register(connection.fileno(), select.POLLIN | select.POLLERR | select.POLLHUP | select.POLLNVAL)
    _require(not poller.poll(0), "prequeued traffic or closed connection")


def _ancillary(controls, cleanup, closed):
    credentials, forbidden = [], False
    for level, kind, raw in controls:
        if level == socket.SOL_SOCKET and kind in (socket.SCM_RIGHTS, _PIDFD):
            forbidden = True
            # recvmsg installed these descriptors even when the packet is rejected.
            for offset in range(0, len(raw) - len(raw) % struct.calcsize("i"), struct.calcsize("i")):
                fd = struct.unpack_from("i", raw, offset)[0]
                if fd >= 0:
                    try:
                        os.close(fd)
                        closed.append([fd, "ANCILLARY", True])
                    except BaseException as exc:
                        cleanup.append(exc)
                        closed.append([fd, "ANCILLARY", False])
        elif level == socket.SOL_SOCKET and kind == _CREDENTIALS:
            credentials.append(raw)
        else:
            forbidden = True
    _require(not forbidden and len(credentials) == 1 and len(credentials[0]) == _UCREDS.size, "ancillary refused")
    return credentials[0]


def acquire_reader_response(connection, *, epoch_raw, challenge_raw, bindings,
                            connection_epoch, consume_once, retain):
    """Consume one challenge; return only an acquired reader record after retention."""
    evidence = {"schema": "aragorn/native-phase3-run-reader-evidence/v1", "status": "REFUSED",
                "claim_attempted": False, "claim_confirmed": False, "send_attempted": False,
                "sensor_health_verified": False, "effect_authorized": False, "run_qualified": False}
    owned, cleanup, closed, original, retention_failure, reader = [], [], [], None, None, None
    last = -1

    def tick():
        nonlocal last
        current = clock._stamp()
        _require(current >= last, "clock rollback")
        last = current
        return current

    try:
        _require(sys.platform == "linux", "Linux required")
        for key, raw, bound in (("epoch", epoch_raw, 32768), ("challenge", challenge_raw, 4096)):
            if type(raw) is bytes and len(raw) <= bound:
                _bytes(evidence, key + "_base64", raw)
        epoch, challenge = _inputs(epoch_raw, challenge_raw, bindings, connection_epoch)
        bindings = dict(bindings)
        _require(callable(consume_once) and callable(retain), "trusted providers missing")
        _put(evidence, "connection_epoch", connection_epoch)
        _put(evidence, "observed_fields", ["reader_pid", "reader_start_ticks", "reader_uid", "reader_gid", "boot_id", "clock"])
        _put(evidence, "supplied_process_fields", sorted(set(epoch["process"]) - {"reader_pid", "reader_start_ticks", "reader_uid", "reader_gid", "boot_id"}))
        deadline = challenge["deadline_ns"]
        _require(challenge["issued_ns"] <= tick() < deadline, "challenge outside budget")
        peer = _peer(connection, epoch["process"])
        _bytes(evidence, "peer_credentials_base64", peer)
        pidfd = process.open_peer_pidfd(connection, epoch["process"]["reader_pid"])
        owned.append(pidfd)
        observer = os.getpid()
        _require(observer != epoch["process"]["reader_pid"], "reader must be external")
        namespaces = {}
        for role, pid in (("reader", epoch["process"]["reader_pid"]), ("observer", observer)):
            fd = os.open(f"/proc/{pid}/ns/time", os.O_RDONLY | os.O_CLOEXEC)
            owned.append(fd)
            namespaces[role] = pid, fd
        before = _readbacks(evidence, "before", pidfd, namespaces, epoch, observer, tick)
        _unread(connection)
        _require(tick() < deadline, "preflight expired")
        claim = _canonical({"schema": "aragorn/native-phase3-run-reader-claim/v1", "connection_epoch": connection_epoch, "challenge": challenge})
        _require(len(claim) <= 4096, "claim size")
        _bytes(evidence, "claim_base64", claim)
        evidence["claim_attempted"] = True
        claimed = consume_once(claim)
        if type(claimed) is bytes and len(claimed) <= 4096:
            _bytes(evidence, "claim_readback_base64", claimed)
        _require(type(claimed) is bytes and claimed == claim, "claim readback refused")
        evidence["claim_confirmed"] = True
        _require(_peer(connection, epoch["process"]) == peer, "peer changed after claim")
        _unread(connection)
        while True:
            process.require_live_pidfd(pidfd)
            _unread(connection)
            send_started = tick()
            _require(send_started < deadline, "send budget expired")
            evidence["send_attempted"] = True
            evidence["send_started_ns"] = send_started
            evidence["send_call_flags"] = socket.MSG_DONTWAIT | _NOSIGNAL
            try:
                sent = connection.send(challenge_raw, evidence["send_call_flags"])
            except BlockingIOError:
                _require(_wait(connection, pidfd, select.POLLOUT, deadline, tick), "send timeout")
                continue
            evidence["send_finished_ns"] = tick()
            evidence["send_bytes"] = sent
            _require(type(sent) is int and sent == len(challenge_raw), "short or ambiguous send")
            _require(last < deadline, "send finished late")
            break
        response, received = None, None
        while _wait(connection, pidfd, select.POLLIN, deadline, tick):
            process.require_live_pidfd(pidfd)
            _require(_peer(connection, epoch["process"]) == peer, "connection changed before receive")
            evidence["recvmsg_call_flags"] = socket.MSG_DONTWAIT | _CLOEXEC
            try:
                payload, controls, flags, _address = connection.recvmsg(4097, 4096, evidence["recvmsg_call_flags"])
            except BlockingIOError:
                continue
            # Close kernel-installed FDs before any evidence/clock/parser failure.
            packet_error = None
            try:
                sender = _ancillary(controls, cleanup, closed)
            except BaseException as exc:
                packet_error = exc
            try:
                _bytes(evidence, "response_base64", payload)
                _put(evidence, "controls", [[level, kind, base64.b64encode(raw).decode("ascii")] for level, kind, raw in controls])
                evidence["receive_flags"] = flags
            except BaseException as exc:
                packet_error = packet_error or exc
            if packet_error is not None:
                raise packet_error
            received = tick()
            evidence["received_ns"] = received
            process.require_live_pidfd(pidfd)
            _require(not flags & ~(socket.MSG_EOR | _CLOEXEC), "receive flags")
            _require(sender == peer and received < deadline, "sender or receive deadline")
            response = _keys(_decode(payload, 4096), "schema epoch_digest challenge_digest request_digest sequence_after ack_ns")
            _require(response["schema"] == "aragorn/native-phase3-run-reader-response/v1", "response schema")
            for role in ("epoch", "challenge", "request"):
                _require(response[role + "_digest"] == bindings[role], "response binding")
            _require(_uint(response["sequence_after"]) > challenge["sequence_before"], "checkpoint did not advance")
            _require(challenge["issued_ns"] <= send_started <= _uint(response["ack_ns"]) <= received, "ACK chronology")
            break
        if response is None:
            _unread(connection)
        after = _readbacks(evidence, "after", pidfd, namespaces, epoch, observer, tick)
        _require(before == after and _peer(connection, epoch["process"]) == peer, "final identity changed")
        accepted = tick()
        evidence["accepted_ns"] = accepted
        _require(accepted < deadline if response is not None else accepted >= deadline, "final deadline")
        process.require_live_pidfd(pidfd)
        if response is None:
            _unread(connection)
        reader = {
            "epoch_digest": bindings["epoch"], "challenge_digest": bindings["challenge"], "request_digest": bindings["request"],
            "process_before": epoch["process"], "process_after": epoch["process"],
            "clock_before": epoch["clock"], "clock_after": epoch["clock"],
            "peer": dict(zip(("pid", "uid", "gid"), _UCREDS.unpack(peer), strict=True)),
            "status": "ACK" if response is not None else "TIMEOUT",
            "sequence_after": response["sequence_after"] if response else challenge["sequence_before"],
            "ack_ns": response["ack_ns"] if response else None, "received_ns": received,
        }
    except BaseException as exc:
        original = exc
    finally:
        for fd in reversed(owned):
            try:
                os.close(fd)
                closed.append([fd, "OWNED", True])
            except BaseException as exc:
                cleanup.append(exc)
                closed.append([fd, "OWNED", False])
    if original is None and cleanup:
        original = cleanup[0]
    evidence["status"] = reader["status"] if original is None and reader else "REFUSED"
    evidence["failure_type"] = type(original).__name__[:128] if original else None
    evidence["cleanup_failure_count"] = len(cleanup)
    evidence["cleanup_failure_types"] = [type(exc).__name__[:128] for exc in cleanup[:8]]
    evidence["cleanup_failure_types_complete"] = len(cleanup) <= 8
    evidence["descriptor_cleanup"] = closed
    evidence_raw = _canonical(evidence)
    try:
        _require(len(evidence_raw) <= _MAX_EVIDENCE, "evidence size")
        acknowledgment = retain(evidence_raw, expected_digest=_raw_digest(evidence_raw))
        _keys(acknowledgment, "digest bytes")
        _require(acknowledgment["digest"] == _raw_digest(evidence_raw)
                 and type(acknowledgment["bytes"]) is int and acknowledgment["bytes"] == len(evidence_raw), "retention readback")
    except BaseException as exc:
        retention_failure = exc
    if original is not None or retention_failure is not None:
        raise ReaderResponseError(original or retention_failure, evidence_raw, cleanup, retention_failure) from (original or retention_failure)
    return reader
