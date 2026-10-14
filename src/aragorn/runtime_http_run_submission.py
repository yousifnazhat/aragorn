"""Durable submission observations under the original broker's borrowed lock.

This is not a health gate. Production use still requires protected acquisition,
independent consumers and a reviewed single-owner caller that never releases or
transfers the borrowed descriptors during this object's lifetime. Linux fdinfo
proves held-at-read state only, not an uninterrupted lock interval by itself.
"""

from __future__ import annotations

import fcntl
import os
from pathlib import Path
import re
import stat
import sys
import threading
import time

from . import native_phase3_broker_reader_protocol as packet
from .runtime_action_broker import _file_identity, write_all


_ORIGINAL_PID = os.getpid()
_CONTROL = Path("/var/lib/aragorn-runtime-action/control")
_LOCK = _CONTROL / "broker.lock"
_MAX_TRANSCRIPT = 786432
_FAILURES = packet.ERROR_CODES | {
    "POLICY_REFUSED", "TRANSPORT_REFUSED", "TRANSPORT_INDETERMINATE", "JOURNAL_REFUSED",
}


def _description(error: BaseException) -> dict:
    return {"type": type(error).__name__[:64], "message": str(error)[:256]}


class SubmissionJournalError(RuntimeError):
    """Bounded local refusal evidence, including uncertainty and cleanup errors."""

    def __init__(self, journal):
        super().__init__("HTTP submission journal refused; inspect bounded local evidence")
        self.original_error = dict(journal._original_error)
        self.cleanup_failures = tuple(dict(item) for item in journal._cleanup_failures)
        self.last_completed_event = journal._events[-1] if journal._events else None
        self.known_intent = journal._intent
        self.intent_attempted = journal._intent_attempted
        self.effect_possible = True if (self.known_intent or self.intent_attempted) else None
        self.partial_bytes = journal._partial
        self.custody_observations = {"begin": journal._fdinfo_begin, "latest": journal._fdinfo_latest}


def _context(raw: bytes, expected: str) -> dict:
    packet._pin(expected)
    value = packet._decode(raw, 8192)
    packet._require(packet._digest(raw) == expected, "context digest differs")
    packet._keys(value, (
        "schema", "request_digest", "effect_digest", "grant_digest", "deployment_digest",
        "epoch_digest", "broker", "provider", "clock", "exchange_id",
        "accepted_boottime_ns", "deadline_boottime_ns", "clock_bracket",
    ))
    packet._require(value["schema"] == "aragorn/native-phase3-broker-reader-context/v1",
                    "context schema differs")
    for name in ("request_digest", "effect_digest", "grant_digest", "deployment_digest", "epoch_digest"):
        packet._pin(value[name])
    packet._nonce(value["exchange_id"])
    packet._process(value["broker"])
    packet._process(value["provider"])
    packet._require(value["broker"]["uid"] > 0 and value["broker"]["gid"] > 0
                    and value["provider"]["uid"] == value["provider"]["gid"] == 0,
                    "context accounts differ")
    packet._clock(value["clock"])
    packet._uint(value["accepted_boottime_ns"])
    packet._uint(value["deadline_boottime_ns"], 1)
    bracket = value["clock_bracket"]
    packet._keys(bracket, ("boottime_before_ns", "monotonic_ns", "boottime_after_ns",
                           "original_monotonic_deadline_ns"))
    for number in bracket.values():
        packet._uint(number)
    remaining = bracket["original_monotonic_deadline_ns"] - bracket["monotonic_ns"]
    packet._require(0 < remaining <= 500000000
                    and value["accepted_boottime_ns"] <= bracket["boottime_before_ns"]
                    <= bracket["boottime_after_ns"] < value["deadline_boottime_ns"]
                    and value["deadline_boottime_ns"] == bracket["boottime_before_ns"] + remaining,
                    "context clock budget differs")
    return value


class SubmissionJournal:
    """Created only through begin_http_submission_locked; no recovery or retry."""

    def __init__(self):
        self._owned = {}
        self._ancestors = []
        self._files = []
        self._events = []
        self._packets = {}
        self._phase = None
        self._intent = False
        self._intent_attempted = False
        self._partial = b""
        self._original_error = None
        self._cleanup_failures = []
        self._fdinfo_begin = self._fdinfo_latest = None
        self._lock_mount = None
        self._closed = self._poisoned = False
        self._total = 0
        self._response = self._first_response = None
        self._first_response_pin = None
        self._connect_checked_ns = None

    def _failure(self, error):
        self._poisoned = True
        if self._original_error is None:
            self._original_error = _description(error)
        return SubmissionJournalError(self)

    def _perform(self, action):
        try:
            packet._require(not self._closed and not self._poisoned, "journal unavailable")
            return action()
        except BaseException as exc:
            raise self._failure(exc) from exc

    def _take(self, descriptor):
        self._owned[descriptor] = None
        self._owned[descriptor] = _file_identity(os.fstat(descriptor))[:5]
        packet._require(not os.get_inheritable(descriptor), "owned descriptor inheritable")
        return descriptor

    def _close_one(self, descriptor):
        # Consume before close: never retry an ambiguous descriptor number.
        identity = self._owned.pop(descriptor)
        try:
            packet._require(identity is not None and _file_identity(os.fstat(descriptor))[:5] == identity,
                            "owned descriptor custody lost; foreign handle not closed")
            os.close(descriptor)
        except BaseException as exc:
            self._cleanup_failures.append(_description(exc))
            raise

    def _close_owned(self):
        for descriptor in tuple(reversed(self._owned)):
            try:
                self._close_one(descriptor)
            except BaseException:
                pass
        self._closed = True

    def _read_virtual(self, path: str, maximum: int) -> bytes:
        descriptor = self._take(os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC))
        original = None
        result = bytearray()
        try:
            while True:
                chunk = os.read(descriptor, min(8192, maximum + 1 - len(result)))
                if not chunk:
                    break
                result.extend(chunk)
                packet._require(len(result) <= maximum, "virtual file byte bound")
        except BaseException as exc:
            original = exc
        if path == f"/proc/self/fdinfo/{self._lock_fd}":
            self._fdinfo_latest = bytes(result[:4096])
            if self._fdinfo_begin is None:
                self._fdinfo_begin = self._fdinfo_latest
        try:
            self._close_one(descriptor)
        except BaseException as exc:
            if original is None:
                original = exc
        if original is not None:
            raise original
        return bytes(result)

    def _environment(self):
        broker = self._context["broker"]
        packet._require(sys.platform == "linux" and os.getpid() == _ORIGINAL_PID == broker["pid"]
                        and threading.get_native_id() == broker["pid"]
                        and os.getresuid() == (broker["uid"],) * 3
                        and os.getresgid() == (broker["gid"],) * 3,
                        "original broker main process accounts differ")
        raw = self._read_virtual(f"/proc/{broker['pid']}/stat", 16384)
        text = raw.decode("ascii")
        marker = text.rfind(") ")
        fields = text[marker + 2:].split() if marker >= 0 else []
        packet._require(text.startswith(f"{broker['pid']} (") and len(fields) >= 20
                        and re.fullmatch(r"[0-9]{1,19}", fields[19]) is not None
                        and int(fields[19]) == broker["start_time_ticks"], "broker process epoch differs")

    def _directory(self, parent, name, descriptor, *, control=False):
        held = os.fstat(descriptor)
        named = os.stat(name, dir_fd=parent, follow_symlinks=False)
        identity = _file_identity(held)[:5]
        packet._require(identity == _file_identity(named)[:5] and stat.S_ISDIR(held.st_mode)
                        and held.st_uid == (self._context["broker"]["uid"] if control else 0)
                        and not stat.S_IMODE(held.st_mode) & 0o022, "unsafe directory ancestry")
        if control:
            packet._require(held.st_uid == self._context["broker"]["uid"]
                            and held.st_gid == self._context["broker"]["gid"]
                            and stat.S_IMODE(held.st_mode) == 0o700, "control directory differs")
        self._ancestors.append((parent, name, descriptor, identity))

    def _begin(self, control_fd, lock_fd, config, context_raw, expected_context_digest):
        if type(context_raw) is bytes:
            self._partial = context_raw[:8192]
        self._context = _context(context_raw, expected_context_digest)
        self._context_raw, self._context_pin = context_raw, expected_context_digest
        self._control_fd, self._lock_fd = control_fd, lock_fd
        self._prefix = "run-reader-" + self._context["request_digest"][7:]
        for descriptor in (control_fd, lock_fd):
            packet._uint(descriptor)
        packet._require(control_fd != lock_fd and config.control_root == _CONTROL
                        and config.lock_path == _LOCK
                        and type(config.expected_broker_uid) is int
                        and config.expected_broker_uid == self._context["broker"]["uid"],
                        "fixed broker config differs")
        runtime_uid = getattr(config, "expected_runtime_uid", None)
        runtime_gid = getattr(config, "expected_runtime_gid", None)
        packet._require((runtime_uid is None) == (runtime_gid is None),
                        "runtime account binding is incomplete")
        if runtime_uid is not None:
            packet._uint(runtime_uid)
            packet._uint(runtime_gid)
            packet._require(runtime_uid != self._context["broker"]["uid"],
                            "runtime and broker user identities overlap")
        # The installed broker intentionally uses the runtime primary group.
        # Isolation is distinct UIDs plus the unchanged 0700 control directory,
        # 0600 lock, 0400 records and non-writable root-owned ancestors.
        self._last_boot = self._context["clock_bracket"]["boottime_after_ns"]
        self._last_mono = self._context["clock_bracket"]["monotonic_ns"]
        self._environment()
        directory_flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
        root = self._take(os.open("/", directory_flags))
        self._directory(None, "/", root)
        parent = root
        for name in ("var", "lib", "aragorn-runtime-action"):
            child = self._take(os.open(name, directory_flags, dir_fd=parent))
            self._directory(parent, name, child)
            parent = child
        self._directory(parent, "control", control_fd, control=True)
        run = self._take(os.open("run", directory_flags, dir_fd=root))
        self._directory(root, "run", run)
        packet._require(os.fstat(run).st_uid == 0, "boot bind parent is not root-owned")
        self._boot_parent = run
        self._boot_fd = self._take(os.open("aragorn-broker-boot-id",
            os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=run))
        boot = os.fstat(self._boot_fd)
        packet._require(stat.S_ISREG(boot.st_mode) and boot.st_uid == boot.st_gid == 0
                        and boot.st_nlink == 1 and not stat.S_IMODE(boot.st_mode) & 0o022,
                        "boot bind custody differs")
        self._boot_identity = _file_identity(boot)
        self._namespace_path = f"/proc/{self._context['broker']['pid']}/ns/time"
        # The active kernel namespace is an intentional proc magic-link target.
        self._namespace_fd = self._take(os.open(self._namespace_path, os.O_RDONLY | os.O_CLOEXEC))
        held = os.fstat(lock_fd)
        packet._require(stat.S_ISREG(held.st_mode) and held.st_uid == self._context["broker"]["uid"]
                        and held.st_gid == self._context["broker"]["gid"] and held.st_nlink == 1
                        and stat.S_IMODE(held.st_mode) == 0o600, "broker lock custody differs")
        self._lock_identity = _file_identity(held)
        self._guard()
        self._publish(self._prefix + "-context.json", context_raw)
        self._event("BOUND")

    def _fdinfo(self):
        status_flags = fcntl.fcntl(self._lock_fd, fcntl.F_GETFL)
        descriptor_flags = fcntl.fcntl(self._lock_fd, fcntl.F_GETFD)
        packet._require(type(status_flags) is int and type(descriptor_flags) is int
                        and status_flags & os.O_ACCMODE == os.O_RDWR
                        and descriptor_flags & fcntl.FD_CLOEXEC
                        and not os.get_inheritable(self._lock_fd), "borrowed lock flags differ")
        raw = self._read_virtual(f"/proc/self/fdinfo/{self._lock_fd}", 4096)
        self._fdinfo_latest = raw
        if self._fdinfo_begin is None:
            self._fdinfo_begin = raw
        packet._require(all(byte in (9, 10) or 32 <= byte <= 126 for byte in raw),
                        "fdinfo non-ASCII separator")
        fields = {}
        for line in raw.decode("ascii").splitlines():
            name, separator, value = line.partition(":")
            packet._require(separator and name in ("pos", "flags", "mnt_id", "ino", "lock")
                            and name not in fields, "fdinfo fields differ")
            fields[name] = value.strip(" \t")
        packet._require(set(fields) == {"pos", "flags", "mnt_id", "ino", "lock"}, "fdinfo incomplete")
        numbers = {}
        for name in ("pos", "flags", "mnt_id", "ino"):
            pattern = r"[0-7]{1,22}" if name == "flags" else r"[0-9]{1,19}"
            packet._require(re.fullmatch(pattern, fields[name]) is not None, "fdinfo number differs")
            numbers[name] = int(fields[name], 8 if name == "flags" else 10)
            packet._uint(numbers[name])
        packet._require(numbers["flags"] == status_flags | os.O_CLOEXEC, "fdinfo flags differ")
        lock = re.split(r"[ \t]+", fields["lock"])
        packet._require(len(lock) == 8 and lock[:4] == ["1:", "FLOCK", "ADVISORY", "WRITE"]
                        and lock[4] == str(self._context["broker"]["pid"])
                        and lock[6:] == ["0", "EOF"], "fdinfo exclusive owner differs")
        device = re.fullmatch(r"([0-9a-fA-F]{1,16}):([0-9a-fA-F]{1,16}):([0-9]{1,19})", lock[5])
        packet._require(device is not None, "fdinfo device differs")
        major, minor, inode = (int(device[1], 16), int(device[2], 16), int(device[3]))
        packet._require(major == os.major(self._lock_identity[0])
                        and minor == os.minor(self._lock_identity[0])
                        and inode == numbers["ino"] == self._lock_identity[1], "fdinfo lock identity differs")
        if self._lock_mount is None:
            self._lock_mount = numbers["mnt_id"]
        packet._require(numbers["mnt_id"] == self._lock_mount, "fdinfo mount changed")

    def _clock_guard(self, allow_expired=False):
        clock = self._context["clock"]
        held, named = os.fstat(self._namespace_fd), os.stat(self._namespace_path)
        namespace = clock["time_namespace"]
        packet._require(stat.S_ISREG(held.st_mode) and stat.S_ISREG(named.st_mode)
                        and (held.st_dev, held.st_ino) == (named.st_dev, named.st_ino)
                        == (namespace["device"], namespace["inode"])
                        and os.readlink(self._namespace_path) == f"time:[{held.st_ino}]",
                        "active time namespace differs")
        boot_before = _file_identity(os.fstat(self._boot_fd))
        boot_named = _file_identity(os.stat("aragorn-broker-boot-id", dir_fd=self._boot_parent,
                                           follow_symlinks=False))
        raw = os.pread(self._boot_fd, 65, 0)
        packet._require(boot_before == boot_named == self._boot_identity
                        == _file_identity(os.fstat(self._boot_fd))
                        == _file_identity(os.stat("aragorn-broker-boot-id", dir_fd=self._boot_parent,
                                                 follow_symlinks=False))
                        and raw == (clock["boot_id"] + "\n").encode("ascii"), "boot identity changed")
        return self._read_clocks(allow_expired)

    def _read_clocks(self, allow_expired=False):
        before = time.clock_gettime_ns(time.CLOCK_BOOTTIME)
        mono = time.clock_gettime_ns(time.CLOCK_MONOTONIC)
        boot = time.clock_gettime_ns(time.CLOCK_BOOTTIME)
        packet._uint(before)
        packet._uint(boot)
        packet._uint(mono)
        packet._require(boot >= before >= self._last_boot and mono >= self._last_mono, "clock rollback")
        self._last_boot, self._last_mono = boot, mono
        if not allow_expired:
            packet._require(boot < self._context["deadline_boottime_ns"]
                            and mono < self._context["clock_bracket"]["original_monotonic_deadline_ns"],
                            "original deadline expired")
        return boot

    def _readback(self, name, descriptor, identity, raw):
        packet._require(_file_identity(os.fstat(descriptor)) == identity
                        == _file_identity(os.stat(name, dir_fd=self._control_fd, follow_symlinks=False)),
                        "journal file identity changed")
        observed = bytearray()
        while len(observed) <= len(raw):
            chunk = os.pread(descriptor, min(8192, len(raw) + 1 - len(observed)), len(observed))
            if not chunk:
                break
            observed.extend(chunk)
        packet._require(bytes(observed) == raw
                        and _file_identity(os.fstat(descriptor)) == identity
                        == _file_identity(os.stat(name, dir_fd=self._control_fd, follow_symlinks=False)),
                        "journal readback differs")

    def _custody(self):
        self._environment()
        for parent, name, descriptor, identity in self._ancestors:
            packet._require(_file_identity(os.fstat(descriptor))[:5] == identity
                            == _file_identity(os.stat(name, dir_fd=parent, follow_symlinks=False))[:5]
                            and not os.get_inheritable(descriptor), "directory identity changed")
        packet._require(_file_identity(os.fstat(self._lock_fd)) == self._lock_identity
                        == _file_identity(os.stat("broker.lock", dir_fd=self._control_fd,
                                                 follow_symlinks=False)), "held/named lock changed")
        self._fdinfo()

    def _guard(self, allow_expired=False):
        self._custody()
        for record in self._files:
            self._readback(*record)
        self._clock_guard(allow_expired)
        self._custody()
        # Last stamp follows all potentially blocking proc/boot/file readbacks.
        return self._read_clocks(allow_expired)

    def _publish(self, name, raw, *, allow_expired=False):
        self._partial = raw
        packet._require(self._total + len(raw) <= _MAX_TRANSCRIPT, "transcript byte bound")
        self._guard(allow_expired)
        descriptor = self._take(os.open(name, os.O_RDWR | os.O_CREAT | os.O_EXCL
                                       | os.O_NOFOLLOW | os.O_CLOEXEC, 0o400, dir_fd=self._control_fd))
        initial = os.fstat(descriptor)
        packet._require(stat.S_ISREG(initial.st_mode) and initial.st_nlink == 1
                        and initial.st_uid == self._context["broker"]["uid"]
                        and initial.st_gid == self._context["broker"]["gid"]
                        and stat.S_IMODE(initial.st_mode) == 0o400 and initial.st_size == 0
                        and _file_identity(initial) == _file_identity(os.stat(
                            name, dir_fd=self._control_fd, follow_symlinks=False)), "new journal file unsafe")
        write_all(descriptor, raw)
        os.fsync(descriptor)
        os.fsync(self._control_fd)
        identity = _file_identity(os.fstat(descriptor))
        packet._require(identity[:6] == _file_identity(initial)[:6] and identity[6] == len(raw),
                        "published journal metadata differs")
        record = (name, descriptor, identity, raw)
        self._readback(*record)
        self._files.append(record)
        self._guard(allow_expired)
        self._total += len(raw)

    def _event(self, phase, *, request_pin=None, response_pin=None,
               transport_pin=None, failure_code=None, receipt=None):
        packet._require(len(self._events) < 6, "event count bound")
        checked = self._guard(allow_expired=phase == "TERMINAL")
        if receipt is not None:
            self._receipt(*receipt, checked)
        intent = self._intent or phase in ("CONNECT_INTENT", "PAYLOAD_CHECKED", "PAYLOAD_INTENT")
        value = {
            "schema": "aragorn/native-phase3-broker-submission-event/v1",
            "context_digest": self._context_pin, "sequence": len(self._events),
            "previous_digest": packet._digest(self._events[-1]) if self._events else None,
            "phase": phase, "checked_ns": checked, "request_packet_digest": request_pin,
            "response_packet_digest": response_pin, "transport_digest": transport_pin,
            "failure_code": failure_code, "intent": intent,
            "effect_possible": True if intent else (None if phase == "TERMINAL" else False),
        }
        raw = packet._canonical(value)
        packet._require(len(raw) <= 8192, "event byte bound")
        self._publish(self._prefix + f"-event-{len(self._events)}.json", raw,
                      allow_expired=phase == "TERMINAL")
        if receipt is not None:
            self._receipt(*receipt, self._last_boot)
        self._events.append(raw)
        self._phase, self._intent = phase, intent
        if phase == "CONNECT_INTENT":
            self._connect_checked_ns = checked
        return checked

    def _packet(self, raw, *, allow_expired=False):
        pin = packet._digest(raw)
        packet._require(len(self._packets) < 5 and pin not in self._packets, "packet duplicate/count bound")
        self._publish(self._prefix + "-packet-" + pin[7:] + ".json", raw, allow_expired=allow_expired)
        self._packets[pin] = raw
        return pin

    def _receipt(self, request, response, checked):
        context = self._context
        for name in ("exchange_id", "epoch_digest", "request_digest", "effect_digest",
                     "deadline_boottime_ns"):
            packet._require(request[name] == context[name], "request context differs")
        packet._require(request["context_digest"] == self._context_pin, "request context pin differs")
        before_connect = request["phase"] == "BEFORE_CONNECT"
        cap = 250000000 if before_connect else 100000000
        packet._require(context["clock_bracket"]["boottime_after_ns"] <= response["received_ns"]
                        <= response["finished_ns"] <= checked < context["deadline_boottime_ns"]
                        and response["finished_ns"] - response["received_ns"] <= cap
                        and checked - response["finished_ns"] < 200000000, "packet late or stale")
        if not before_connect:
            packet._require(request["previous_response_digest"] == self._first_response_pin
                            and self._connect_checked_ns <= response["received_ns"], "phase predecessor differs")
            for name in ("reader_evidence", "reader_summary", "bindings", "reader_connection_epoch",
                         "reader_retention"):
                packet._require(response[name] == self._first_response[name], "original reader evidence changed")
        loss_raw = packet._artifact(response["loss_record"], 8192)
        loss = packet._loss(loss_raw, response["bindings"]) if loss_raw is not None else None
        if loss is not None and loss["after"] is not None:
            packet._require(response["received_ns"] <= loss["after"]["start_ns"]
                            <= loss["after"]["end_ns"] <= response["finished_ns"], "loss sample not fresh")
        if not before_connect:
            first_raw = packet._artifact(self._first_response["loss_record"], 8192)
            first = packet._loss(first_raw, self._first_response["bindings"]) if first_raw is not None else None
            packet._require((loss is None) == (first is None), "loss baseline availability changed")
            if loss is not None:
                for name in ("epoch_digest", "challenge_digest", "request_digest", "scope_digest", "before"):
                    packet._require(loss[name] == first[name], "original loss baseline changed")
        return loss

    def record_check(self, phase: str, *, request_raw: bytes, response_raw: bytes):
        def action():
            if type(response_raw) is bytes:
                self._partial = response_raw[:packet.RESPONSE_LIMIT]
            expected = "BEFORE_CONNECT" if self._phase == "BOUND" else (
                "BEFORE_PAYLOAD_SEND" if self._phase == "CONNECT_INTENT" else None)
            packet._require(phase == expected and expected is not None, "check phase out of order")
            request = packet.validate_guard_request(request_raw)
            response = packet.validate_guard_response(response_raw, request_raw=request_raw)
            packet._require(request["phase"] == phase, "check phase substituted")
            self._receipt(request, response, self._guard())
            request_pin = self._packet(request_raw)
            response_pin = self._packet(response_raw)
            self._receipt(request, response, self._guard())
            self._event("CONNECT_CHECKED" if phase == "BEFORE_CONNECT" else "PAYLOAD_CHECKED",
                        request_pin=request_pin, response_pin=response_pin, receipt=(request, response))
            self._request, self._response = request, response
            if phase == "BEFORE_CONNECT":
                self._first_response, self._first_response_pin = response, response_pin
        return self._perform(action)

    def _record_intent(self, phase):
        def action():
            packet._require(self._phase == ("CONNECT_CHECKED" if phase == "CONNECT_INTENT" else "PAYLOAD_CHECKED"),
                            "intent phase out of order")
            loss = self._receipt(self._request, self._response, self._guard())
            packet._require(self._response["status"] == "EVIDENCE" and loss is not None
                            and loss["before"] is not None and loss["after"] is not None,
                            "intent evidence unavailable")
            packet._require(all(before is not None and after is not None and before == after
                                for before, after in zip(loss["before"]["counters"], loss["after"]["counters"])),
                            "intent loss unknown, reset or increased")
            self._intent_attempted = True
            self._event(phase, receipt=(self._request, self._response))
            # Publication latency cannot turn a once-fresh packet into authority.
            self._receipt(self._request, self._response, self._guard())
        return self._perform(action)

    def record_connect_intent(self):
        return self._record_intent("CONNECT_INTENT")

    def record_payload_intent(self):
        return self._record_intent("PAYLOAD_INTENT")

    def submission_snapshot(self) -> bytes:
        def action():
            checked = self._guard()
            packet._require(self._phase != "TERMINAL" and self._response is not None
                            and self._response["bindings"] is not None, "checked reader binding unavailable")
            value = {
                "epoch_digest": self._context["epoch_digest"],
                "challenge_digest": self._response["bindings"]["challenge"],
                "request_digest": self._context["request_digest"], "checked_ns": checked,
                "custody": "EXCLUSIVE", "intent": self._intent, "effect_possible": self._intent,
            }
            return packet._canonical(value)
        return self._perform(action)

    def finish(self, *, transport_raw: bytes | None, failure_code: str | None):
        def action():
            packet._require(self._phase is not None and self._phase != "TERMINAL", "terminal phase out of order")
            packet._require(failure_code is None or (type(failure_code) is str and failure_code in _FAILURES),
                            "terminal failure code differs")
            packet._require(failure_code is not None or (self._phase == "PAYLOAD_INTENT" and transport_raw is not None),
                            "terminal observation incomplete")
            transport_pin = None
            if transport_raw is not None:
                if type(transport_raw) is bytes:
                    self._partial = transport_raw[:32768]
                packet._decode(transport_raw, 32768)
                transport_pin = self._packet(transport_raw, allow_expired=True)
            self._event("TERMINAL", transport_pin=transport_pin, failure_code=failure_code)
        return self._perform(action)

    def final_readback(self):
        return self._perform(lambda: self._final_readback())

    def _final_readback(self):
        self._guard(allow_expired=True)

    def close(self):
        if self._closed:
            if self._poisoned:
                raise SubmissionJournalError(self)
            return
        if not self._poisoned:
            try:
                self._final_readback()
            except BaseException as exc:
                self._failure(exc)
        self._close_owned()
        if self._cleanup_failures and self._original_error is None:
            self._original_error = dict(self._cleanup_failures[0])
            self._poisoned = True
        if self._poisoned:
            raise SubmissionJournalError(self)


def begin_http_submission_locked(control_fd: int, lock_fd: int, config, *,
                                 context_raw: bytes, expected_context_digest: str) -> SubmissionJournal:
    """Borrow an already-held original broker lock; create one immutable attempt."""
    journal = SubmissionJournal()
    try:
        journal._begin(control_fd, lock_fd, config, context_raw, expected_context_digest)
        return journal
    except BaseException as exc:
        journal._failure(exc)
        journal._close_owned()
        raise SubmissionJournalError(journal) from exc
