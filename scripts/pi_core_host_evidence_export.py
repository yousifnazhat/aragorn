"""B46: seal one B45 attempt's evidence; separately acknowledge its local cleanup.

All roots must be canonical, private and exclusively owned by cooperating operators.
The watchdog is an external host-child observation; the supplied semantic result must
come directly from the coordinator's B45 replay. Neither is evidence of guest boot.
"""
from contextlib import ExitStack, contextmanager
import fcntl
from itertools import accumulate
import json
import os
from pathlib import Path
import re
import stat
import uuid

from scripts.build_pi_core_linux import canonical, require, sha256
from scripts.pi_core_host_watchdog import BUDGET_NS


SCHEMA = "aragorn/b46-host-evidence-export/v1"
WATCH = "aragorn/b46-owned-host-watchdog/v1"
SOURCE = {"serial.raw": 8 << 20, "binding.json": 65536, "binding-failure.json": 65536}
LIMIT = 65536
D = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
R = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK


def _uuid(name):
    require(isinstance(name, str) and
            re.fullmatch(r"[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}", name)
            and str(uuid.UUID(name)) == name and uuid.UUID(name).int != 0, "expected nonzero canonical attempt UUID")
    return name


def _digest(value):
    return isinstance(value, str) and re.fullmatch("[a-f0-9]{64}", value) is not None


def _dirid(s):
    require(stat.S_ISDIR(s.st_mode) and s.st_uid == os.geteuid() and stat.S_IMODE(s.st_mode) == 0o700,
            "expected owned private directory")
    return {"dev": s.st_dev, "ino": s.st_ino}


def _fileid(s):
    require(stat.S_ISREG(s.st_mode) and s.st_uid == os.geteuid() and s.st_nlink == 1 and
            stat.S_IMODE(s.st_mode) in (0o400, 0o600), "expected owned private single-link evidence file")
    return {"dev": s.st_dev, "ino": s.st_ino, "mode": stat.S_IMODE(s.st_mode), "bytes": s.st_size,
            "mtime_ns": s.st_mtime_ns, "ctime_ns": s.st_ctime_ns}


def _named(fd, name):
    return os.stat(name, dir_fd=fd, follow_symlinks=False)


@contextmanager
def _root(path):
    path = Path(path)
    require(path.is_absolute() and path.anchor == "/" and ".." not in path.parts, "expected absolute root")
    with ExitStack() as s:
        fd = os.open("/", D)
        s.callback(os.close, fd)
        for name in path.parts[1:]:
            fd = os.open(name, D, dir_fd=fd)
            s.callback(os.close, fd)
        ident = _dirid(os.fstat(fd))
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        yield fd, ident


@contextmanager
def _directory(parent, name):
    fd = os.open(name, D, dir_fd=parent)
    try:
        ident = _dirid(os.fstat(fd))
        require(ident == _dirid(_named(parent, name)), "directory identity changed")
        yield fd, ident
    finally:
        os.close(fd)


def _read(fd, name, limit, sealed=False):
    """Read and verify the named object before and after the bounded read."""
    before = _fileid(_named(fd, name))
    with os.fdopen(os.open(name, R, dir_fd=fd), "rb") as stream:
        info = _fileid(os.fstat(stream.fileno()))
        require(info == before and info["bytes"] <= limit and (not sealed or info["mode"] == 0o400),
                "invalid identity, size or seal")
        data = stream.read(limit + 1)
        require(len(data) == info["bytes"] and info == _fileid(os.fstat(stream.fileno())) ==
                _fileid(_named(fd, name)), "evidence changed during read")
        return data, info


def _write(fd, name, data):
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW
    with os.fdopen(os.open(name, flags, 0o600, dir_fd=fd), "wb") as stream:
        require(stream.write(data) == len(data), "short evidence export")
        stream.flush()
        os.fchmod(stream.fileno(), 0o400)
        os.fsync(stream.fileno())
    readback, ident = _read(fd, name, len(data), sealed=True)
    require(readback == data, "export bytewise readback mismatch")
    return ident


def _json(data, *, newline=True):
    result = json.loads(data)
    require(isinstance(result, dict) and canonical(result) + (b"\n" if newline else b"") == data,
            "noncanonical evidence export")
    return result


def _roots(attempt, dest):
    attempt, dest = Path(attempt), Path(dest)
    _uuid(attempt.name)
    parent = attempt.parent
    require(parent != dest and parent not in dest.parents and dest not in parent.parents,
            "attempt fixture and export root must be disjoint")
    return parent, dest


def _eligible(name, files, replay, watch, raw, binding, fixture):
    if set(files) != {"binding.json", "serial.raw"} or raw != b"" or not replay:
        return False
    if any(info["source"]["mode"] != 0o400 for info in files.values()):
        return False
    try:
        b = json.loads(binding)
    except (UnicodeError, ValueError):
        return False
    if not isinstance(b, dict) or not isinstance(b.get("capture"), dict):
        return False
    expected = {"status": "matched_no_boot_binding", "attempt_uuid": name, "binding_sha256": sha256(binding),
                "runner_sha256": b.get("runner_sha256"), "boot_observed": False, "phase3_exit_eligible": False}
    start, end, bound = (watch.get(k) for k in ("start_raw_ns", "exit_observed_raw_ns", "run_deadline_raw_ns"))
    capture = b["capture"]
    enter, finish = capture.get("attempt_start_ns"), capture.get("record_end_ns")
    deadline_fields = ("run_deadline_raw_ns", "graceful_deadline_raw_ns", "force_deadline_raw_ns")
    if (not all(type(n) is int for n in (start, enter, finish, end, bound)) or
            not 0 < start <= enter <= finish <= end < bound):
        return False
    expected_deadlines = list(accumulate(BUDGET_NS, initial=start))[1:]
    return (_digest(expected["runner_sha256"]) and canonical(replay) == canonical(expected) and
            b.get("schema") == "aragorn/b44-host-binding/v1" and b.get("attempt_uuid") == name and
            b.get("fixture_identity") == fixture and b.get("mode") == "preview" and b.get("store") is None and
            b.get("vm_created") is False and b.get("boot_observed") is False and b.get("phase3_exit_eligible") is False
            and watch.get("schema") == WATCH and watch.get("attempt_uuid") == name and
            watch.get("outcome") == "child-exited" and watch.get("child_reaped") is True and
            type(watch.get("child_pid")) is int and watch["child_pid"] > 0 and
            type(watch.get("child_returncode")) is int and watch["child_returncode"] == 0 and
            "error_type" not in watch and "host_kill_errno" not in watch and
            all(watch.get(k) is False for k in ("interrupted", "host_kill_requested", "vm_stopped_verified")) and
            all(k in watch and watch[k] is None for k in ("graceful", "force", "interrupt_signal", "host_kill_raw_ns")) and
            watch.get("clock") == capture.get("clock") == "CLOCK_MONOTONIC_RAW" and
            canonical([watch.get(k) for k in deadline_fields]) == canonical(expected_deadlines) and
            canonical(watch.get("effective_deadlines_raw_ns")) == canonical(expected_deadlines))


def export_attempt(attempt, destination_root, watchdog, *, replay_result=None):
    """Exclusively publish one previously unexported UUID. No attempt data is removed.

    A failed/partial attempt may be archived, but is never eligible for cleanup.
    On a write failure, leave all source and partial destination bytes for investigation.
    Return the SHA-256 of the reread manifest, to be independently read and acknowledged.
    """
    attempt = Path(attempt)
    parent, dest = _roots(attempt, destination_root)
    name = attempt.name
    require(isinstance(watchdog, dict) and watchdog.get("schema") == WATCH and
            watchdog.get("attempt_uuid") == name, "watchdog belongs to another attempt")
    wdata = canonical(watchdog)  # Exact encoding of the durable external watchdog terminal record.
    require(len(wdata) <= LIMIT and (replay_result is None or
            (isinstance(replay_result, dict) and len(canonical(replay_result)) <= LIMIT // 2)), "oversized report")
    with _root(parent) as (p, pid), _root(dest) as (d, did), _directory(p, name) as (src, sid):
        require(pid != did and sid != did, "aliased export root")
        names = set(os.listdir(src))
        require(names <= SOURCE.keys(), "unexpected source entries; leave untouched")
        inputs = {n: _read(src, n, SOURCE[n]) for n in sorted(names)}
        os.mkdir(name, 0o700, dir_fd=d)  # Never overwrite/repair an old or partial export.
        with _directory(d, name) as (out, oid):
            files = {n: {"source": ident, "export": _write(out, n, data), "sha256": sha256(data)}
                     for n, (data, ident) in inputs.items()}
            wfile = {"export": _write(out, "watchdog.json", wdata), "sha256": sha256(wdata)}
            eligible = _eligible(name, files, replay_result, watchdog, inputs.get("serial.raw", (None,))[0],
                                 inputs.get("binding.json", (None,))[0], pid)
            require(set(os.listdir(src)) == names and _dirid(_named(p, name)) == sid and
                    all(_fileid(_named(src, n)) == row["source"] for n, row in files.items()),
                    "source changed before export sealed")
            manifest = {"schema": SCHEMA, "attempt_uuid": name, "fixture": pid, "attempt": sid, "root": did,
                        "export": oid, "files": files, "watchdog": wfile, "b45_replay": replay_result,
                        "eligible_for_local_evidence_cleanup": eligible, "boot_observed": False,
                        "phase3_exit_eligible": False}
            data = canonical(manifest) + b"\n"
            require(len(data) <= LIMIT, "oversized export manifest")
            _write(out, "export.json", data)
            os.fsync(out)
            os.fsync(d)
            digest = sha256(data)
            _check(did, out, oid, name, digest)
            return digest


def _check(did, fd, oid, name, digest):
    require(_digest(digest), "expected externally acknowledged manifest SHA-256")
    raw, _ = _read(fd, "export.json", LIMIT, sealed=True)
    require(sha256(raw) == digest, "export digest mismatch")
    doc = _json(raw)
    require(doc["schema"] == SCHEMA and doc["attempt_uuid"] == name and doc["export"] == oid and
            doc["root"] == did and doc["phase3_exit_eligible"] is False and doc["boot_observed"] is False and
            set(doc["files"]) <= SOURCE.keys() and set(os.listdir(fd)) == set(doc["files"]) | {"export.json", "watchdog.json"},
            "export identity or contents changed")
    for n, record in {**doc["files"], "watchdog.json": doc["watchdog"]}.items():
        data, ident = _read(fd, n, SOURCE.get(n, LIMIT), sealed=True)
        require(ident == record["export"] and sha256(data) == record["sha256"], "exported evidence changed")
    return doc


def read_export(destination_root, attempt_uuid, expected_digest):
    """Independent, read-only receipt/content verification before operator acknowledgment."""
    name = _uuid(attempt_uuid)
    with _root(destination_root) as (d, did), _directory(d, name) as (out, oid):
        return _check(did, out, oid, name, expected_digest)


def cleanup_attempt(attempt, destination_root, acknowledged_digest):
    """Retire only known local evidence after separate acknowledgment. Never touch VM/media/EFI.

    Requires exclusive, cooperating roots. Validate *all* entries before the first
    unlink; an OS error during removal leaves the verified independent copy and
    remaining source intact. Never auto-retry or recursively remove anything.
    """
    attempt = Path(attempt)
    parent, dest = _roots(attempt, destination_root)
    name = attempt.name
    with (_root(parent) as (p, pid), _root(dest) as (d, did),
          _directory(p, name) as (src, sid), _directory(d, name) as (out, oid)):
        doc = _check(did, out, oid, name, acknowledged_digest)
        files = doc["files"]
        require(doc["eligible_for_local_evidence_cleanup"] is True and pid == doc["fixture"] and
                sid == doc["attempt"] and set(os.listdir(src)) == set(files) == {"binding.json", "serial.raw"},
                "source not eligible; preserve all evidence")
        inputs = {}
        for n, record in files.items():
            data, ident = _read(src, n, SOURCE[n], sealed=True)
            require(ident == record["source"] and sha256(data) == record["sha256"], "source bytes or identity changed")
            inputs[n] = data
        watch, _ = _read(out, "watchdog.json", LIMIT, sealed=True)
        require(_eligible(name, files, doc["b45_replay"], _json(watch, newline=False), inputs["serial.raw"], inputs["binding.json"], pid),
                "missing independent replay or normal host-child retirement")
        require(sid == _dirid(_named(p, name)) and oid == _dirid(_named(d, name)) and
                set(os.listdir(src)) == set(files) and
                all(_fileid(_named(src, n)) == record["source"] for n, record in files.items()),
                "attempt changed before cleanup")
        for n in sorted(files):
            os.unlink(n, dir_fd=src)
        os.fsync(src)
        os.rmdir(name, dir_fd=p)
        os.fsync(p)
    return {"attempt_uuid": name, "acknowledged_export_sha256": acknowledged_digest,
            "removed_evidence": sorted(files), "vm_stopped_verified": False, "phase3_exit_eligible": False}
