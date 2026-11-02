"""One protected checkpoint readback and permanent Root archive attempt.

This observes files, not the reader's pipe operations or sensor health. The
caller supplies independently held provisioning and original ACK expectations.
No path, syscall provider, retry, cleanup or health callback is accepted.
"""

import hashlib
import json
import os
import re
import select
import stat
import sys
import threading
import time


_ORIGINAL_PID = os.getpid()
_SOURCE = "/var/lib/aragorn-phase3-reader-events"
_ARCHIVE = "/var/lib/aragorn-phase3-reader-checkpoints"
_PATHS = ("/", "/var", "/var/lib", _SOURCE, _ARCHIVE)
_PREFIX = "aragorn/native-phase3-reader-checkpoint"
_FLAGS = ("acquisition_authenticity_verified", "sensor_health_verified",
          "effect_authorized", "run_qualified", "phase3_qualified")
_IDENTITY_KEYS = ("device", "inode", "mode", "uid", "gid", "nlink", "bytes", "mtime_ns", "ctime_ns")


def _require(condition, reason):
    if not condition:
        raise ValueError(reason)


def _keys(value, names):
    _require(type(value) is dict and set(value) == set(names.split()), "record fields differ")
    return value


def _uint(value, minimum=0, maximum=2**63 - 1):
    _require(type(value) is int and minimum <= value <= maximum, "integer outside bounds")
    return value


def _pin(value):
    _require(type(value) is str and re.fullmatch(r"sha256:[0-9a-f]{64}", value), "invalid digest")


def _nonce(value):
    _require(type(value) is str and re.fullmatch(r"[0-9a-f]{64}", value), "invalid nonce")


def _digest(raw):
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def _canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
                      allow_nan=False).encode("ascii")


def _decode(raw, maximum):
    _require(type(raw) is bytes and 0 < len(raw) <= maximum, "record size differs")

    def pairs(items):
        result = {}
        for key, value in items:
            _require(key not in result, "duplicate JSON key")
            result[key] = value
        return result

    def invalid(_value):
        raise ValueError("noninteger JSON number")

    value = json.loads(raw.decode("ascii"), object_pairs_hook=pairs,
                       parse_float=invalid, parse_constant=invalid)
    _require(type(value) is dict and _canonical(value) == raw, "noncanonical JSON object")
    return value


def _process(value):
    _keys(value, "pid start_time_ticks uid gid")
    _uint(value["pid"], 1, 2147483647)
    _uint(value["start_time_ticks"], 1)
    for key in ("uid", "gid"):
        _uint(value[key], 0, 2**32 - 1)


def _clock(value):
    _keys(value, "boot_id clock_id time_namespace")
    _require(type(value["boot_id"]) is str and re.fullmatch(
        r"[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}", value["boot_id"]), "invalid boot identity")
    _require(value["clock_id"] == "CLOCK_BOOTTIME", "clock differs")
    _keys(value["time_namespace"], "device inode")
    _uint(value["time_namespace"]["device"])
    _uint(value["time_namespace"]["inode"], 1)


def _inputs(provision_raw, provision_digest, expectation_raw, expectation_digest):
    _pin(provision_digest)
    _pin(expectation_digest)
    p = _keys(_decode(provision_raw, 8192), "schema epoch_digest session_id reader observer clock "
              "stream_digest source_inventory_digest access_inventory_digest directories session_deadline_ns")
    e = _keys(_decode(expectation_raw, 8192), "schema provision_digest phase epoch_digest request_digest "
              "challenge_digest trigger_digest trigger_issued_ns trigger_deadline_ns deadline_ns previous_checkpoint_digest "
              "sequence_before sequence_after offset_before records_before reader_evidence_digest reader_summary_digest "
              "reader_connection_epoch reader_ack_ns loss_scope_digest")
    _require(_digest(provision_raw) == provision_digest and _digest(expectation_raw) == expectation_digest,
             "protected input pin differs")
    _require(p["schema"] == _PREFIX + "-provision/v1" and e["schema"] == _PREFIX + "-expectation/v1",
             "protected input schema differs")
    for key in ("epoch_digest", "stream_digest", "source_inventory_digest", "access_inventory_digest"):
        _pin(p[key])
    for key in ("provision_digest", "epoch_digest", "request_digest", "challenge_digest", "trigger_digest",
                "reader_evidence_digest", "reader_summary_digest", "loss_scope_digest"):
        _pin(e[key])
    _nonce(p["session_id"])
    _nonce(e["reader_connection_epoch"])
    _process(p["reader"])
    _process(p["observer"])
    _clock(p["clock"])
    _require(p["reader"]["uid"] > 0 and p["reader"]["gid"] > 0
             and p["observer"]["uid"] == p["observer"]["gid"] == 0
             and p["reader"]["pid"] != p["observer"]["pid"], "process roles differ")
    _uint(p["session_deadline_ns"])
    _require(type(p["directories"]) is list and len(p["directories"]) == 5, "directory inventory differs")
    for path, directory in zip(_PATHS, p["directories"]):
        _keys(directory, "path device inode mode uid gid")
        _require(directory["path"] == path, "directory path differs")
        for key in ("device", "inode", "mode", "uid", "gid"):
            _uint(directory[key], 1 if key == "inode" else 0,
                  2**32 - 1 if key in ("uid", "gid") else 2**63 - 1)
        _require(stat.S_ISDIR(directory["mode"]) and not directory["mode"] & 0o022,
                 "directory custody differs")
        if path in (_SOURCE, _ARCHIVE):
            owner = p["reader"] if path == _SOURCE else p["observer"]
            _require(stat.S_IMODE(directory["mode"]) == 0o700 and directory["uid"] == owner["uid"]
                     and directory["gid"] == owner["gid"], "private directory custody differs")
        else:
            _require(directory["uid"] == 0, "ancestor is not root-owned")
    for key in ("trigger_issued_ns", "trigger_deadline_ns", "deadline_ns", "sequence_before", "sequence_after",
                "offset_before", "records_before", "reader_ack_ns"):
        _uint(e[key])
    _require(e["provision_digest"] == provision_digest and e["epoch_digest"] == p["epoch_digest"]
             and e["phase"] in ("CHALLENGE", "REFRESH")
             and e["sequence_after"] == e["sequence_before"] + 1
             and e["offset_before"] <= 4194304 and e["records_before"] <= 4096
             and e["trigger_issued_ns"] < e["trigger_deadline_ns"] <= e["deadline_ns"] <= p["session_deadline_ns"],
             "expectation context differs")
    if e["previous_checkpoint_digest"] is None:
        _require(e["sequence_before"] == e["offset_before"] == e["records_before"] == 0,
                 "initial checkpoint differs")
    else:
        _pin(e["previous_checkpoint_digest"])
        _require(e["sequence_before"] > 0, "previous checkpoint on initial sequence")
    if e["phase"] == "CHALLENGE":
        _require(e["trigger_digest"] == e["challenge_digest"]
                 and e["trigger_issued_ns"] <= e["reader_ack_ns"] < e["trigger_deadline_ns"], "challenge timing differs")
    else:
        _require(e["sequence_before"] > 0 and e["previous_checkpoint_digest"] is not None
                 and e["reader_ack_ns"] <= e["trigger_issued_ns"]
                 and e["reader_ack_ns"] + 200000000 < 2**63
                 and e["deadline_ns"] <= e["reader_ack_ns"] + 200000000, "refresh timing differs")
    return p, e


def _manifest(raw, p, e):
    m = _keys(_decode(raw, 16384), "schema provision_digest epoch_digest session_id stream_digest phase request_digest "
              "challenge_digest trigger_digest previous_checkpoint_digest sequence_before sequence_after offset_before "
              "offset_after records_before records_after clock trigger_received_ns reads drain_finished_ns raw_digest "
              "raw_bytes raw_records raw_publish_started_ns raw_readback_finished_ns manifest_prepared_ns "
              "loss_scope_digest loss_evidence_digest upstream_loss_state")
    _require(m["schema"] == _PREFIX + "/v1", "manifest schema differs")
    for key in ("provision_digest", "epoch_digest", "phase", "request_digest", "challenge_digest", "trigger_digest",
                "previous_checkpoint_digest", "sequence_before", "sequence_after", "offset_before", "records_before",
                "loss_scope_digest"):
        _require(type(m[key]) is type(e[key]) and m[key] == e[key], "manifest expectation differs")
    for key in ("session_id", "stream_digest", "clock"):
        _require(m[key] == p[key], "manifest provision differs")
    _clock(m["clock"])
    _pin(m["raw_digest"])
    for key in ("offset_after", "records_after", "trigger_received_ns", "drain_finished_ns", "raw_bytes",
                "raw_records", "raw_publish_started_ns", "raw_readback_finished_ns", "manifest_prepared_ns"):
        _uint(m[key])
    _require(m["raw_bytes"] <= 262144 and m["raw_records"] <= 256
             and m["offset_after"] == m["offset_before"] + m["raw_bytes"] <= 4194304
             and m["records_after"] == m["records_before"] + m["raw_records"] <= 4096
             and m["loss_evidence_digest"] is None and m["upstream_loss_state"] == "UNKNOWN",
             "manifest accounting differs")
    _require(type(m["reads"]) is list and 1 <= len(m["reads"]) <= 64, "read inventory differs")
    offset, finished = m["offset_before"], 0
    for read in m["reads"]:
        _keys(read, "started_ns finished_ns offset bytes outcome")
        for key in ("started_ns", "finished_ns", "offset", "bytes"):
            _uint(read[key])
        _require(finished <= read["started_ns"] <= read["finished_ns"] and read["offset"] == offset,
                 "read chronology or offset differs")
        _require((read["outcome"] == "DATA" and 1 <= read["bytes"] <= 65536)
                 or (read["outcome"] == "EAGAIN" and read["bytes"] == 0), "read outcome differs")
        offset += read["bytes"]
        finished = read["finished_ns"]
    _require(offset == m["offset_after"] and m["reads"][-1]["outcome"] == "EAGAIN"
             and e["trigger_issued_ns"] <= m["trigger_received_ns"] <= m["reads"][-1]["started_ns"]
             and finished <= m["drain_finished_ns"] <= m["raw_publish_started_ns"]
             <= m["raw_readback_finished_ns"] <= m["manifest_prepared_ns"] < e["trigger_deadline_ns"],
             "manifest publication chronology differs")
    return m


def _publication(raw, manifest_raw, m, e, batch):
    r = _keys(_decode(raw, 2048), "schema manifest_digest raw_digest sequence_after manifest_publish_started_ns "
              "manifest_readback_finished_ns receipt_prepared_ns")
    _require(r["schema"] == _PREFIX + "-publication/v1" and r["manifest_digest"] == _digest(manifest_raw)
             and r["raw_digest"] == m["raw_digest"] == _digest(batch), "publication pins differ")
    for key in ("sequence_after", "manifest_publish_started_ns", "manifest_readback_finished_ns", "receipt_prepared_ns"):
        _uint(r[key])
    _require(r["sequence_after"] == m["sequence_after"] and m["manifest_prepared_ns"]
             <= r["manifest_publish_started_ns"] <= r["manifest_readback_finished_ns"]
             <= r["receipt_prepared_ns"] < e["trigger_deadline_ns"], "publication timing differs")
    if e["phase"] == "CHALLENGE":
        _require(r["receipt_prepared_ns"] <= e["reader_ack_ns"], "receipt follows ACK")
    _require(len(batch) == m["raw_bytes"] and batch.count(b"\n") == m["raw_records"], "batch count differs")
    records = batch.split(b"\n")
    _require(records[-1] == b"" and len(records) - 1 == m["raw_records"]
             and all(record and not record.endswith(b"\r") and len(record) + 1 <= 65536
                     for record in records[:-1]), "batch record boundaries differ")
    return r


def _identity(metadata):
    return (metadata.st_dev, metadata.st_ino, metadata.st_mode, metadata.st_uid, metadata.st_gid,
            metadata.st_nlink, metadata.st_size, metadata.st_mtime_ns, metadata.st_ctime_ns)


class ReaderCheckpointAcquisitionError(ValueError):
    def __init__(self, original, cleanup, observed):
        super().__init__("reader checkpoint acquisition refused; preserve claims and observed bytes")
        self.original_failure = original
        self.cleanup_failures = tuple(cleanup[:32])
        self.observed = observed


class _Acquisition:
    def __init__(self):
        self.owned = {}
        self.cleanup = []
        self.directories = []
        self.files = []
        self.namespaces = []
        self.last = -1
        self.observed = {"manifest_raw": None, "publication_raw": None, "batch_raw": None,
                         "acquisition_raw": None, "source_files": [], "retained_files": [],
                         "claim_attempted": False}

    def _own(self, fd):
        _require(fd not in self.owned, "owned descriptor number reused")
        self.owned[fd] = None
        self.owned[fd] = _identity(os.fstat(fd))[:5]
        return fd

    def _close(self, fd):
        identity = self.owned.pop(fd)
        try:
            _require(identity is not None and _identity(os.fstat(fd))[:5] == identity,
                     "owned descriptor custody lost; not closed")
            os.close(fd)
        except BaseException as exc:
            self.cleanup.append(exc)
            raise

    def _close_all(self):
        for fd in reversed(tuple(self.owned)):
            try:
                self._close(fd)
            except BaseException:
                pass

    def _environment(self):
        _require(sys.platform == "linux" and os.getresuid() == os.getresgid() == (0, 0, 0)
                 and os.getpid() == threading.get_native_id() == _ORIGINAL_PID == self.p["observer"]["pid"],
                 "original root process/thread required")

    def _tick(self):
        now = _uint(time.clock_gettime_ns(time.CLOCK_BOOTTIME))
        _require(now >= self.last and max(self.e["reader_ack_ns"], self.e["trigger_issued_ns"]) <= now
                 < self.e["deadline_ns"] and now - self.e["reader_ack_ns"] < 200000000, "clock budget differs")
        self.last = now
        return now

    def _read_virtual(self, path, maximum):
        fd = self._own(os.open(path, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW | os.O_CLOEXEC))
        original, raw = None, bytearray()
        try:
            _require(stat.S_ISREG(os.fstat(fd).st_mode), "proc source is not regular")
            while True:
                part = os.read(fd, min(4096, maximum + 1 - len(raw)))
                if not part:
                    break
                raw.extend(part)
                _require(len(raw) <= maximum, "proc source exceeds bound")
        except BaseException as exc:
            original = exc
        try:
            self._close(fd)
        except BaseException as exc:
            if original is None:
                original = exc
        if original is not None:
            raise original
        return bytes(raw)

    def _live(self):
        _require(_identity(os.fstat(self.pidfd))[:5] == self.owned[self.pidfd], "PIDFD descriptor changed")
        poller = select.poll()
        poller.register(self.pidfd, select.POLLIN | select.POLLERR | select.POLLHUP | select.POLLNVAL)
        _require(not poller.poll(0), "reader PIDFD is not live")
        raw = self._read_virtual(f"/proc/self/fdinfo/{self.pidfd}", 4096)
        _require([line.partition(":")[2].strip() for line in raw.decode("ascii").splitlines()
                  if line.startswith("Pid:")] == [str(self.p["reader"]["pid"])], "PIDFD PID differs")
        _require(not poller.poll(0), "reader exited during PIDFD readback")

    def _process_readback(self, role):
        expected = self.p[role]
        pid = expected["pid"]
        before = self._read_virtual(f"/proc/{pid}/stat", 16384)
        status = self._read_virtual(f"/proc/{pid}/status", 16384)
        after = self._read_virtual(f"/proc/{pid}/stat", 16384)
        for raw in (before, after):
            text = raw.decode("ascii")
            marker = text.rfind(") ")
            fields = text[marker + 2:].split() if marker >= 0 else []
            _require(text.startswith(f"{pid} (") and len(fields) >= 20 and fields[19].isdigit()
                     and int(fields[19]) == expected["start_time_ticks"], "process start differs")
        wanted = {"Uid", "Gid", "CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb", "NoNewPrivs"}
        values = {}
        for line in status.decode("ascii").splitlines():
            key, separator, rest = line.partition(":")
            if key in wanted:
                _require(separator and key not in values, "duplicate proc field")
                values[key] = rest.split()
        _require(values.get("Uid") == [str(expected["uid"])] * 4
                 and values.get("Gid") == [str(expected["gid"])] * 4, "process accounts differ")
        if role == "reader":
            _require(values.get("NoNewPrivs") == ["1"], "reader privilege escalation permitted")
            for key in wanted - {"Uid", "Gid", "NoNewPrivs"}:
                parts = values.get(key, [])
                _require(len(parts) == 1 and re.fullmatch(r"[0-9a-fA-F]+", parts[0])
                         and int(parts[0], 16) == 0, "reader capabilities differ")

    def _custody(self):
        self._environment()
        for parent, name, fd, identity in self.directories:
            _require(identity == _identity(os.fstat(fd))[:5]
                     == _identity(os.stat(name, dir_fd=parent, follow_symlinks=False))[:5], "directory replaced")
        expected = self.p["clock"]["time_namespace"]
        for path, fd in self.namespaces:
            held, named = os.fstat(fd), os.stat(path)
            _require(stat.S_ISREG(held.st_mode) and stat.S_ISREG(named.st_mode)
                     and _identity(held)[:5] == self.owned[fd]
                     and (held.st_dev, held.st_ino) == (named.st_dev, named.st_ino)
                     == (expected["device"], expected["inode"])
                     and os.readlink(path) == f"time:[{held.st_ino}]", "active time namespace differs")

    def _guard(self):
        self._tick()
        self._custody()
        self._live()
        self._process_readback("reader")
        self._process_readback("observer")
        _require(self._read_virtual("/proc/sys/kernel/random/boot_id", 64)
                 == (self.p["clock"]["boot_id"] + "\n").encode("ascii"), "boot identity differs")
        self._live()
        self._custody()
        return self._tick()

    def _open_context(self):
        self._environment()
        self.started = self._tick()
        parents = (None, 0, 1, 2, 2)
        for index, expected in enumerate(self.p["directories"]):
            parent = None if parents[index] is None else self.directories[parents[index]][2]
            name = "/" if index == 0 else expected["path"].rsplit("/", 1)[1]
            fd = self._own(os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                                   dir_fd=parent))
            identity = tuple(expected[key] for key in _IDENTITY_KEYS[:5])
            _require(_identity(os.fstat(fd))[:5] == identity, "provisioned directory differs")
            self.directories.append((parent, name, fd, identity))
        self.pidfd = self._own(os.pidfd_open(self.p["reader"]["pid"], 0))
        for role in ("reader", "observer"):
            path = f"/proc/{self.p[role]['pid']}/ns/time"
            fd = self._own(os.open(path, os.O_RDONLY | os.O_CLOEXEC))
            self.namespaces.append((path, fd))
        self._guard()

    def _file_readback(self, parent, name, fd, identity, maximum, field=None):
        _require(identity == _identity(os.fstat(fd))
                 == _identity(os.stat(name, dir_fd=parent, follow_symlinks=False)), "file replaced before readback")
        _require(stat.S_ISREG(identity[2]) and 0 <= identity[6] <= maximum, "file type or size differs")
        for index, value in enumerate(identity):
            _uint(value, 1 if index == 1 else 0)
        raw = bytearray()
        while True:
            part = os.pread(fd, min(65536, identity[6] + 1 - len(raw)), len(raw))
            if not part:
                break
            raw.extend(part)
            if field is not None:
                self.observed[field] = bytes(raw[:maximum])
            _require(len(raw) <= identity[6], "file exceeds observed size")
        if field is not None:
            self.observed[field] = bytes(raw)
        _require(len(raw) == identity[6] and identity == _identity(os.fstat(fd))
                 == _identity(os.stat(name, dir_fd=parent, follow_symlinks=False)), "file changed during readback")
        return bytes(raw)

    def _entry(self, role, identity, raw):
        return {"role": role, **dict(zip(_IDENTITY_KEYS, identity)), "digest": _digest(raw)}

    def _read_source(self, role, name, maximum):
        self._guard()
        parent = self.directories[3][2]
        fd = self._own(os.open(name, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=parent))
        identity = _identity(os.fstat(fd))
        _require(stat.S_ISREG(identity[2]) and stat.S_IMODE(identity[2]) == 0o400 and identity[5] == 1
                 and identity[3:5] == (self.p["reader"]["uid"], self.p["reader"]["gid"]), "source custody differs")
        raw = self._file_readback(parent, name, fd, identity, maximum, role.lower() + "_raw")
        self._guard()
        entry = self._entry(role, identity, raw)
        self.observed["source_files"].append(entry)
        self.observed["source_files"].sort(key=lambda item: ("BATCH", "MANIFEST", "PUBLICATION").index(item["role"]))
        self._distinct_files()
        self.files.append((parent, name, fd, identity, raw))
        return raw

    def _distinct_files(self):
        entries = self.observed["source_files"] + self.observed["retained_files"]
        _require(len({(entry["device"], entry["inode"]) for entry in entries}) == len(entries),
                 "source and retained artifact identities alias")

    def _publish(self, name, raw, field=None):
        self._guard()
        parent = self.directories[4][2]
        fd = self._own(os.open(name, os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                               0o400, dir_fd=parent))
        initial = _identity(os.fstat(fd))
        _require(stat.S_ISREG(initial[2]) and stat.S_IMODE(initial[2]) == 0o400
                 and initial[3:7] == (0, 0, 1, 0)
                 and initial == _identity(os.stat(name, dir_fd=parent, follow_symlinks=False)), "new archive custody differs")
        written = 0
        while written < len(raw):
            count = os.write(fd, raw[written:])
            _require(type(count) is int and 0 < count <= len(raw) - written, "short archive write")
            written += count
            if field is not None:
                self.observed[field] = raw[:written]
        identity = _identity(os.fstat(fd))
        _require(identity[:6] == initial[:6] and identity[6] == len(raw), "archive write custody differs")
        self._guard()
        os.fsync(fd)
        os.fsync(parent)
        actual = self._file_readback(parent, name, fd, identity, len(raw), field)
        _require(actual == raw, "archive readback differs")
        self._guard()
        self.files.append((parent, name, fd, identity, raw))
        return identity

    def run(self, provision_raw, provision_digest, expectation_raw, expectation_digest):
        self.p, self.e = _inputs(provision_raw, provision_digest, expectation_raw, expectation_digest)
        self._open_context()
        manifest_name = self.e["phase"].lower() + "-" + self.e["trigger_digest"][7:] + ".json"
        manifest_raw = self._read_source("MANIFEST", manifest_name, 16384)
        manifest = _manifest(manifest_raw, self.p, self.e)
        publication_raw = self._read_source("PUBLICATION", "receipt-" + _digest(manifest_raw)[7:] + ".json", 2048)
        batch_raw = self._read_source("BATCH", f"batch-{self.p['session_id']}-{self.e['sequence_after']}.ndjson", 262144)
        publication = _publication(publication_raw, manifest_raw, manifest, self.e, batch_raw)
        finished = self._guard()
        _require(publication["receipt_prepared_ns"] <= finished, "receipt is in the future")
        self.observed["source_files"].sort(key=lambda entry: ("BATCH", "MANIFEST", "PUBLICATION").index(entry["role"]))
        prefix = "checkpoint-" + self.e["trigger_digest"][7:] + "-"
        self.observed["claim_attempted"] = True
        self._publish(prefix + "claim.json", _canonical({"schema": _PREFIX + "-claim/v1",
                      "expectation_digest": expectation_digest, "manifest_digest": _digest(manifest_raw),
                      "trigger_digest": self.e["trigger_digest"]}))
        retention_started = self._guard()
        for role, suffix, raw in (("BATCH", "batch.ndjson", batch_raw), ("MANIFEST", "manifest.json", manifest_raw),
                                  ("PUBLICATION", "publication.json", publication_raw)):
            identity = self._publish(prefix + suffix, raw)
            self.observed["retained_files"].append(self._entry(role, identity, raw))
            self._distinct_files()
        retention_finished = self._guard()
        acquisition = {"schema": _PREFIX + "-acquisition/v1", "provision_digest": provision_digest,
                       "expectation_digest": expectation_digest, "phase": self.e["phase"],
                       "trigger_digest": self.e["trigger_digest"], "manifest_digest": _digest(manifest_raw),
                       "publication_digest": _digest(publication_raw), "batch_digest": _digest(batch_raw),
                       "started_ns": self.started, "source_readback_finished_ns": finished,
                       "retention_started_ns": retention_started, "retention_finished_ns": retention_finished,
                       "observer": self.p["observer"], "clock": self.p["clock"],
                       "source_files": self.observed["source_files"], "retained_files": self.observed["retained_files"],
                       **dict.fromkeys(_FLAGS, False)}
        acquisition_raw = _canonical(acquisition)
        _require(len(acquisition_raw) <= 16384, "acquisition record exceeds bound")
        self._publish(prefix + "acquisition.json", acquisition_raw, "acquisition_raw")
        for parent, name, fd, identity, raw in self.files:
            self._guard()
            _require(self._file_readback(parent, name, fd, identity, len(raw)) == raw, "final bytes differ")
            self._guard()
        return {"acquisition_raw": acquisition_raw, "acquisition_digest": _digest(acquisition_raw),
                "manifest_raw": manifest_raw, "publication_raw": publication_raw, "batch_raw": batch_raw}


def acquire_reader_checkpoint(*, provision_raw, expected_provision_digest,
                              expectation_raw, expected_expectation_digest):
    """Acquire once; on any error retain bounded observations and leave residue."""
    owner = _Acquisition()
    original, result = None, None
    try:
        result = owner.run(provision_raw, expected_provision_digest, expectation_raw, expected_expectation_digest)
    except BaseException as exc:
        original = exc
    owner._close_all()
    if original is None and not owner.cleanup:
        try:
            owner._environment()
            owner._tick()
        except BaseException as exc:
            original = exc
    if original is not None or owner.cleanup:
        error = ReaderCheckpointAcquisitionError(original, owner.cleanup, owner.observed)
        raise error from original
    return result
