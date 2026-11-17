"""Pinned VM-host coordinator bootstrap; no operation occurs on import.

Interpreter, wrapper, bootstrap stdlib and native code are the independently
approved host TCB, not retrospectively proven consumed source. Aragorn imports
use the existing same-byte loader only after this host closure is held.
"""

import hashlib
import json
import math
import os
from pathlib import Path
import re
import stat
import sys
import time
import types

_PRIVATE = "_aragorn_pi_coordinator_bootstrap"
_SOURCE_PRIVATE = "_aragorn_pi_service_source"
_WRAPPER = Path("/opt/aragorn/bin/coordinator.py")
_SOURCE_ROOT = Path("/opt/aragorn/src")
_LOADER = _SOURCE_ROOT / "aragorn/pi_core_service_source.py"
_TOOLS = tuple(Path("/usr/bin") / name for name in ("systemd-run", "systemctl", "busctl"))
_PIN = re.compile(r"sha256:[0-9a-f]{64}\Z")
_DIRECTORY = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
_FILE = os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW | os.O_CLOEXEC
_MAX_FILES, _MAX_BYTES, _MAX_FILE = 4096, 512 * 1024 * 1024, 128 * 1024 * 1024
_SEAL = object()


def _require(value, reason):
    if not value:
        raise ValueError(reason)


def _path(value):
    _require(type(value) is str and value.startswith("/") and value != "/" and len(value) <= 4096 and
             all(part not in ("", ".", "..") for part in value.split("/")[1:]) and
             all(32 < ord(char) < 127 for char in value) and "\\" not in value, "unsafe host path")
    return Path(value)


def _digest(raw):
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def _canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False).encode("ascii")


def _document(raw):
    def pairs(items):
        result = {}
        for key, value in items:
            _require(key not in result, "duplicate document key")
            result[key] = value
        return result

    def unsupported(value):
        raise ValueError("non-integer JSON number")

    _require(type(raw) is bytes and 0 < len(raw) <= 2 * 1024 * 1024, "bounded host document required")
    value = json.loads(raw, object_pairs_hook=pairs, parse_float=unsupported, parse_constant=unsupported)
    _require(type(value) is dict and _canonical(value) == raw, "canonical host document required")
    return value


def _identity(info):
    return tuple(getattr(info, key) for key in ("st_dev", "st_ino", "st_mode", "st_nlink",
        "st_uid", "st_gid", "st_size", "st_mtime_ns", "st_ctime_ns"))


def _directory(info):
    _require(stat.S_ISDIR(info.st_mode) and info.st_uid == info.st_gid == 0 and
             not stat.S_IMODE(info.st_mode) & 0o7022 and info.st_nlink > 0, "unsafe host directory")


def _file(info, path):
    _require(stat.S_ISREG(info.st_mode) and info.st_uid == info.st_gid == 0 and
             info.st_nlink == 1 and not stat.S_IMODE(info.st_mode) & 0o7022 and
             0 <= info.st_size <= _MAX_FILE, "unsafe host file")
    if path.is_relative_to(_SOURCE_ROOT) or path == _WRAPPER:
        _require(stat.S_IMODE(info.st_mode) == 0o444, "bootstrap source must be immutable")


def _flags():
    _require(sys.platform == "linux" and os.uname().machine in ("arm64", "aarch64") and
             sys.version_info[:2] == (3, 12) and sys.implementation.name == "cpython" and
             os.getuid() == os.geteuid() == os.getgid() == os.getegid() == 0 and
             sys.flags.isolated == sys.flags.no_site == 1 and sys.dont_write_bytecode is True,
             "protected Linux arm64 Python 3.12 required")
    denied = {"http_proxy", "https_proxy", "all_proxy", "no_proxy", "ssl_cert_file", "ssl_cert_dir",
        "requests_ca_bundle", "curl_ca_bundle", "node_extra_ca_certs", "randfile", "glibc_tunables",
        "gconv_path", "credentials_directory"}
    _require(not any(key.lower() in denied or key.lower().startswith(
        ("python", "openssl_", "ld_", "dyld_", "openai_")) for key in os.environ), "unsafe environment")


class PiCoordinatorHostCustody:
    """Held fixed-host inputs, not a new importer or effect authority."""

    def __init__(self, seal, deadline):
        _require(seal is _SEAL, "protected host factory required")
        self._seal, self._deadline, self._pid = seal, deadline, os.getpid()
        self._directories, self._files, self._expected = {}, {}, {}
        self._profile, self._manifest_digest = None, None
        self._active, self._closed, self._failed = False, False, False
        self._ambiguous = []

    def _time(self, deadline=None):
        limit = self._deadline if deadline is None else deadline
        _require(type(limit) in (int, float) and math.isfinite(limit) and
                 time.monotonic() < limit <= self._deadline and os.getpid() == self._pid,
                 "host deadline or owner differs")

    def _directory_fd(self, path):
        if path in self._directories:
            return self._directories[path][0]
        self._time()
        parent = None if path == Path("/") else self._directory_fd(path.parent)
        fd = os.open("/" if parent is None else path.name, _DIRECTORY, dir_fd=parent)
        self._directories[path] = (fd, None)
        info = os.fstat(fd)
        _directory(info)
        named = os.stat("/", follow_symlinks=False) if parent is None else os.stat(
            path.name, dir_fd=parent, follow_symlinks=False)
        _require(_identity(info) == _identity(named), "host directory changed during open")
        self._directories[path] = (fd, _identity(info))
        return fd

    def _read_file(self, path, pin, *, size=None, maximum=_MAX_FILE, mode=None):
        self._time()
        _require(type(pin) is str and _PIN.fullmatch(pin) and path not in self._files,
                 "invalid or repeated host input")
        parent = self._directory_fd(path.parent)
        fd = os.open(path.name, _FILE, dir_fd=parent)
        self._files[path] = (fd, None, pin)
        before = os.fstat(fd)
        _file(before, path)
        _require(before.st_size <= maximum and (size is None or before.st_size == size) and
                 (mode is None or stat.S_IMODE(before.st_mode) == mode), "host input metadata differs")
        identity = _identity(before)
        _require(_identity(os.stat(path.name, dir_fd=parent, follow_symlinks=False)) == identity,
                 "host input changed during open")
        raw = bytearray()
        while True:
            self._time()
            chunk = os.read(fd, min(65536, before.st_size + 1 - len(raw)))
            if not chunk:
                break
            raw.extend(chunk)
            _require(len(raw) <= before.st_size, "host input grew")
        _require(len(raw) == before.st_size and _digest(raw) == pin and
                 _identity(os.fstat(fd)) == identity == _identity(os.stat(
                     path.name, dir_fd=parent, follow_symlinks=False)), "host input bytes changed")
        self._files[path] = (fd, identity, pin)
        return bytes(raw)

    def _inventory(self, root):
        actual = set()
        pending = [root]
        while pending:
            path = pending.pop()
            self._time()
            fd = self._directory_fd(path)
            with os.scandir(fd) as entries:
                for entry in entries:
                    self._time()
                    child = path / entry.name
                    _path(str(child))
                    info = os.stat(entry.name, dir_fd=fd, follow_symlinks=False)
                    if stat.S_ISDIR(info.st_mode):
                        _require(len(self._directories) + len(pending) < _MAX_FILES, "host directory bound")
                        pending.append(child)
                    else:
                        _require(stat.S_ISREG(info.st_mode), "host import subtree contains a link or special file")
                        actual.add(child)
                        _require(len(actual) <= _MAX_FILES, "host inventory bound")
        expected = {path for path in self._expected if path.is_relative_to(root)}
        _require(actual == expected, "host import subtree differs from approved inventory")

    def _search_paths(self):
        _require(sys.path == self._profile["sys_path"], "ambient Python search path")
        for name in self._profile["absent_sys_path"]:
            path = Path(name)
            parent = self._directory_fd(path.parent)
            try:
                os.stat(path.name, dir_fd=parent, follow_symlinks=False)
            except FileNotFoundError:
                continue
            raise ValueError("approved absent Python zip appeared")

    def _mapped_files(self, raw):
        _require(type(raw) is bytes and 0 < len(raw) <= 2 * 1024 * 1024, "bounded host mapping observation required")
        mapped = set()
        for line in raw.decode("ascii").splitlines():
            fields = line.split(None, 5)
            _require(len(fields) in (5, 6) and re.fullmatch(r"[0-9a-f]+-[0-9a-f]+", fields[0]) and
                     re.fullmatch(r"[r-][w-][x-][ps]", fields[1]) and
                     re.fullmatch(r"[0-9a-f]+", fields[2]) and
                     re.fullmatch(r"[0-9a-f]+:[0-9a-f]+", fields[3]) and fields[4].isdecimal(),
                     "malformed host mapping")
            permissions, inode = fields[1], int(fields[4])
            name = fields[5] if len(fields) == 6 else ""
            _require(not ("w" in permissions and "x" in permissions), "writable executable host mapping")
            if inode == 0:
                _require("x" not in permissions or name == "[vdso]", "unbound executable host mapping")
                continue
            path = _path(name)
            _require(path in self._expected, "mapped file outside approved host closure")
            info = os.fstat(self._files[path][0])
            major, minor = (int(part, 16) for part in fields[3].split(":"))
            _require((major, minor, inode) == (os.major(info.st_dev), os.minor(info.st_dev), info.st_ino),
                     "mapped host object identity differs")
            mapped.add(path)
        _require(Path(self._profile["python_executable"]) in mapped, "Python executable mapping absent")
        return mapped

    def _process(self):
        python = Path(self._profile["python_executable"])
        _require(sys.executable == str(python), "ambient Python executable")
        # /proc/self/exe is deliberately the kernel's magic link, not input data.
        descriptor = os.open("/proc/self/exe", os.O_RDONLY | os.O_CLOEXEC)
        try:
            _require(_identity(os.fstat(descriptor)) == self._files[python][1], "running Python identity differs")
        finally:
            try:
                os.close(descriptor)
            except BaseException:
                self._ambiguous.append(descriptor)
                raise
        with open("/proc/self/maps", "rb") as stream:
            self._mapped_files(stream.read(2 * 1024 * 1024 + 1))

    def _loaded_modules(self):
        for name, module in sys.modules.copy().items():
            if module is None:
                continue
            if name in ("typing.io", "typing.re"):
                typing = sys.modules.get("typing")
                _require(typing is not None and type(typing) is types.ModuleType and
                         module is vars(typing).get(name.rpartition(".")[2]) and
                         getattr(module, "__module__", None) == "typing",
                         "unbound typing compatibility namespace")
                continue
            origin = getattr(getattr(module, "__spec__", None), "origin", None)
            path = getattr(module, "__file__", None)
            if origin in ("built-in", "frozen"):
                continue
            _require(type(path) is str and _path(path) in self._expected,
                     "loaded module outside approved host closure")
            cached = getattr(module, "__cached__", None)
            if cached is not None:
                cache = _path(cached)
                _require(any(cache.is_relative_to(Path(root)) for root in self._profile["stdlib_roots"]) or
                         cache.is_relative_to(_SOURCE_ROOT), "unapproved bytecode search path")
                if os.path.lexists(cache):
                    _require(cache in self._expected, "loaded bytecode outside approved closure")

    def guard(self, deadline=None):
        try:
            _require(type(self) is PiCoordinatorHostCustody and self._seal is _SEAL and self._active and
                     not self._closed and not self._failed and
                     getattr(sys.modules.get(_PRIVATE), "PiCoordinatorHostCustody", None) is type(self),
                     "host custody unavailable")
            self._time(deadline)
            _flags()
            self._search_paths()
            for path, (fd, identity) in tuple(self._directories.items()):
                self._time(deadline)
                named = os.stat("/", follow_symlinks=False) if path == Path("/") else os.stat(
                    path.name, dir_fd=self._directories[path.parent][0], follow_symlinks=False)
                _require(_identity(os.fstat(fd)) == identity == _identity(named), "host directory custody changed")
            for path, (fd, identity, pin) in self._files.items():
                self._time(deadline)
                _require(_identity(os.fstat(fd)) == identity == _identity(os.stat(
                    path.name, dir_fd=self._directories[path.parent][0], follow_symlinks=False)),
                    "host file custody changed")
            for root in (*self._profile["stdlib_roots"], str(_SOURCE_ROOT)):
                self._inventory(Path(root))
            self._process()
            self._loaded_modules()
        except BaseException:
            self._failed = True
            raise

    @property
    def manifest_digest(self):
        self.guard()
        return self._manifest_digest

    def snapshot(self):
        self.guard()
        return {"schema": "aragorn/pi-core-coordinator-host-observation/v1",
                "authority": "PINNED_HOST_TCB_ONLY_NOT_CONSUMED_CODE_OR_PHASE3",
                "host_profile_digest": self._manifest_digest, "pid": self._pid,
                "python_executable": self._profile["python_executable"],
                "files": len(self._expected), "phase3_exit_eligible": False}

    def close(self):
        if self._closed:
            _require(not self._failed, "host cleanup hold; no retry")
            return
        self._closed, self._active = True, False
        descriptors = [row[0] for row in self._files.values()] + [row[0] for row in self._directories.values()]
        self._files, self._directories = {}, {}
        for fd in reversed(descriptors):
            try:
                os.close(fd)
            except BaseException:
                self._ambiguous.append(fd)
        if self._ambiguous:
            self._failed = True
            raise ValueError("host cleanup hold; no retry")


def _profile(value):
    _require(set(value) == {"schema", "target", "python_executable", "wrapper_path", "stdlib_roots",
                           "sys_path", "absent_sys_path", "files"} and
             value["schema"] == "aragorn/pi-core-coordinator-host/v1" and
             value["target"] == "linux-arm64-cpython312" and value["wrapper_path"] == str(_WRAPPER),
             "fixed host profile required")
    python = _path(value["python_executable"])
    roots, paths, absent = (value[key] for key in ("stdlib_roots", "sys_path", "absent_sys_path"))
    _require(type(roots) is list and 0 < len(roots) <= 4 and roots == sorted(set(roots)) and
             type(paths) is list and 0 < len(paths) <= 8 and len(paths) == len(set(paths)) and
             type(absent) is list and len(absent) <= 2 and absent == sorted(set(absent)), "host import path bounds")
    roots = [_path(path) for path in roots]
    _require(all(root != _SOURCE_ROOT and not root.is_relative_to(_SOURCE_ROOT) and
                 not _SOURCE_ROOT.is_relative_to(root) for root in roots) and
             all(not left.is_relative_to(right) for left in roots for right in roots if left != right),
             "host stdlib roots overlap")
    for path in paths:
        selected = _path(path)
        _require((path in absent and selected.name == "python312.zip" and
                  any(selected.parent == root.parent for root in roots)) or
                 (path not in absent and any(selected.is_relative_to(root) for root in roots)),
                 "host search path is outside approved stdlib")
    _require(set(absent) <= set(paths) and all(str(root) in paths for root in roots), "host stdlib search roots differ")
    rows = value["files"]
    _require(type(rows) is list and 0 < len(rows) <= _MAX_FILES, "host file bound")
    expected, total = {}, 0
    for row in rows:
        _require(type(row) is dict and set(row) == {"path", "digest", "size"}, "host file fields")
        path = _path(row["path"])
        _require(path not in expected and type(row["digest"]) is str and _PIN.fullmatch(row["digest"]) and
                 type(row["size"]) is int and 0 <= row["size"] <= _MAX_FILE, "host file pin or size")
        expected[path] = row
        total += row["size"]
    _require(list(expected) == sorted(expected) and total <= _MAX_BYTES, "host file ordering or byte bound")
    required = {python, _WRAPPER, _LOADER, _SOURCE_ROOT / "aragorn/__init__.py",
                _SOURCE_ROOT / "aragorn/pi_core_coordinator_entry.py", *_TOOLS}
    _require(required <= expected.keys(), "host closure lacks fixed entrypoints")
    _require(all(not path.is_relative_to(_SOURCE_ROOT) or
                 (path.is_relative_to(_SOURCE_ROOT / "aragorn") and path.suffix == ".py") for path in expected),
             "Aragorn source closure contains foreign files or bytecode")
    sources = [row for path, row in expected.items() if path.is_relative_to(_SOURCE_ROOT)]
    _require(len(sources) <= 512 and sum(row["size"] for row in sources) <= 32 * 1024 * 1024 and
             all(row["size"] <= 4 * 1024 * 1024 for row in sources) and
             0 < expected[_LOADER]["size"] <= 4 * 1024 * 1024 and
             0 < expected[_WRAPPER]["size"] <= 4 * 1024 * 1024,
             "bootstrap source bounds differ")
    return expected


class PiCoordinatorHostAcquisitionError(ValueError):
    def __init__(self, cleanup_status):
        super().__init__("host acquisition refused; owned cleanup " + cleanup_status)
        self.host_cleanup_status = cleanup_status


def _hold_host(path, expected_digest, deadline):
    host = PiCoordinatorHostCustody(_SEAL, deadline)
    try:
        raw = host._read_file(path, expected_digest, maximum=2 * 1024 * 1024, mode=0o400)
        host._profile = _document(raw)
        host._expected = _profile(host._profile)
        host._manifest_digest = expected_digest
        for selected, row in host._expected.items():
            host._read_file(selected, row["digest"], size=row["size"])
        for selected in (_TOOLS + (Path(host._profile["python_executable"]),)):
            _require(os.fstat(host._files[selected][0]).st_mode & stat.S_IXUSR, "host control executable mode differs")
        host._active = True
        host.guard()
        return host
    except BaseException as error:
        try:
            host.close()
        except BaseException:
            raise PiCoordinatorHostAcquisitionError("CLEANUP_HOLD") from error
        raise


def _bootstrap(host):
    host.guard()
    _require(_SOURCE_PRIVATE not in sys.modules and not any(
        name == "aragorn" or name.startswith("aragorn.") for name in sys.modules), "source imported before bootstrap")
    fd, identity, pin = host._files[_LOADER]
    raw = os.pread(fd, identity[6] + 1, 0)
    _require(len(raw) == identity[6] and _digest(raw) == pin, "bootstrap source changed")
    pins = {str(path)[1:]: row["digest"] for path, row in host._expected.items() if path.is_relative_to(_SOURCE_ROOT)}
    module = types.ModuleType(_SOURCE_PRIVATE)
    module.__file__ = str(_LOADER)
    sys.modules[_SOURCE_PRIVATE] = module
    try:
        exec(compile(raw, str(_LOADER), "exec", dont_inherit=True), module.__dict__)
        return module.install(_SOURCE_ROOT, pins, deadline=host._deadline)
    except BaseException:
        sys.modules.pop(_SOURCE_PRIVATE, None)
        raise


def _public_observation(observation):
    """Keep root custody metadata; never serialize raw managed/provider content."""
    report = {"schema": "aragorn/pi-core-coordinator-report/v1",
        "authority": "MANAGED_RESULT_DIGEST_ONLY_NOT_RAW_EFFECT_EVIDENCE",
        "phase3_exit_eligible": False, "entry_status": "NOT_RETURNED",
        "managed_call_attempted": False, "managed_status": None, "managed_result_digest": None,
        "managed_cleanup_complete": False, "owned_inputs_closed": False,
        "entry_failure_stage": None,
        "plan_digest": None, "deployment_digest": None,
        "host_before": None, "host_after": None, "source_before": None, "source_after": None}
    if observation is None:
        return report
    _require(type(observation) is dict and observation.get("phase3_exit_eligible") is False,
             "invalid coordinator observation")
    status = observation.get("status")
    _require(status in {"REFUSED", "REFUSED_OR_INDETERMINATE", "CLEANUP_HOLD",
                        "MANAGED_CALL_RETURNED_NOT_QUALIFIED"}, "invalid coordinator status")
    report["entry_status"] = status
    stage = observation.get("failure_stage")
    _require(stage is None or stage in {"PREFLIGHT", "PREPARED_INPUTS", "HELD_INPUTS", "MANAGED_CALL",
        "POST_CALL_CUSTODY", "HOLDER_CLEANUP", "INPUT_CLEANUP"}, "invalid coordinator failure stage")
    report["entry_failure_stage"] = stage
    for name in ("managed_call_attempted", "owned_inputs_closed"):
        _require(type(observation.get(name)) is bool, "invalid coordinator boolean")
        report[name] = observation[name]
    for name in ("plan_digest", "deployment_digest"):
        value = observation.get(name)
        _require(value is None or type(value) is str and _PIN.fullmatch(value), "invalid coordinator binding")
        report[name] = value
    for name in ("host_before", "host_after"):
        value = observation.get(name)
        if value is not None:
            _require(type(value) is dict and set(value) == {"schema", "authority", "host_profile_digest", "pid",
                "python_executable", "files", "phase3_exit_eligible"} and
                value["schema"] == "aragorn/pi-core-coordinator-host-observation/v1" and
                value["authority"] == "PINNED_HOST_TCB_ONLY_NOT_CONSUMED_CODE_OR_PHASE3" and
                type(value["host_profile_digest"]) is str and _PIN.fullmatch(value["host_profile_digest"]) and
                type(value["pid"]) is int and value["pid"] == os.getpid() and
                type(value["files"]) is int and 0 < value["files"] <= _MAX_FILES and
                value["phase3_exit_eligible"] is False, "invalid host observation")
            _path(value["python_executable"])
            report[name] = dict(value)
    for name in ("source_before", "source_after"):
        value = observation.get(name)
        if value is not None:
            _require(type(value) is list and 0 < len(value) <= 512, "invalid source observation")
            rows = []
            for row in value:
                _require(type(row) is dict and set(row) == {"module", "path", "digest"} and
                    type(row["module"]) is str and re.fullmatch(r"aragorn(?:\.[A-Za-z_][A-Za-z0-9_]*)*", row["module"]) and
                    type(row["path"]) is str and row["path"].startswith("opt/aragorn/src/aragorn/") and
                    row["path"].endswith(".py") and type(row["digest"]) is str and _PIN.fullmatch(row["digest"]),
                    "invalid source observation row")
                _path("/" + row["path"])
                rows.append(dict(row))
            report[name] = rows
    managed = observation.get("managed_result")
    if managed is not None:
        _require(type(managed) is dict, "invalid managed result")
        raw = _canonical(managed)
        _require(len(raw) <= 4 * 1024 * 1024, "managed result exceeds report bound")
        report["managed_result_digest"] = _digest(raw)
        status = managed.get("status")
        report["managed_status"] = status if status in {"BOOTSTRAP_COMPLETE", "REFUSED", "CLEANUP_HOLD"} else "UNRECOGNIZED"
        report["managed_cleanup_complete"] = all(type(managed.get(owner)) is dict and
            type(managed[owner].get("cleanup")) is dict and
            managed[owner]["cleanup"].get("status") == "VERIFIED_OWNED_CLEANUP" for owner in ("worker", "services"))
    _require(len(_canonical(report)) <= 256 * 1024, "coordinator report exceeds bound")
    return report


def main():
    host = loader = None
    result, observation, phase = 126, None, "PREFLIGHT"
    entry_invoked = False
    cleanup = {"source_loader": "NOT_ACQUIRED", "host": "NOT_ACQUIRED"}
    try:
        _flags()
        _require(len(sys.argv) == 6 and type(sys.argv[5]) is str and sys.argv[5].isascii() and
                 sys.argv[5].isdecimal() and 0 < int(sys.argv[5]) < 2**63, "fixed coordinator arguments required")
        profile_path, plan_path = _path(sys.argv[1]), _path(sys.argv[3])
        _require(all(_PIN.fullmatch(value) for value in (sys.argv[2], sys.argv[4])), "independent pins required")
        deadline_ns = int(sys.argv[5])
        deadline = math.nextafter(deadline_ns / 1_000_000_000, 0.0)
        _require(time.monotonic() < deadline <= time.monotonic() + 30, "original bounded coordinator deadline required")
        _require(Path(__file__) == _WRAPPER and _PRIVATE not in sys.modules, "fixed coordinator origin required")
        sys.modules[_PRIVATE] = sys.modules[__name__]
        phase = "HOST_CUSTODY"
        cleanup["host"] = "NOT_RETURNED_CLEANUP_UNVERIFIED"
        host = _hold_host(profile_path, sys.argv[2], deadline)
        phase = "SOURCE_BOOTSTRAP"
        cleanup["source_loader"] = "NOT_RETURNED_CLEANUP_UNVERIFIED"
        loader = _bootstrap(host)
        from aragorn.pi_core_coordinator_entry import run
        host.guard()
        phase = "ENTRY_CALL"
        entry_invoked = True
        observation = run(plan_path, sys.argv[4], deadline_ns=deadline_ns, source_loader=loader, host_custody=host)
        phase = "POST_CALL_CUSTODY"
        host.guard()
        report = _public_observation(observation)
        result = (0 if report["entry_status"] == "MANAGED_CALL_RETURNED_NOT_QUALIFIED" and
            report["managed_call_attempted"] and report["owned_inputs_closed"] and
            report["managed_status"] == "BOOTSTRAP_COMPLETE" and report["managed_cleanup_complete"] else 126)
    except BaseException as error:
        if type(error) is PiCoordinatorHostAcquisitionError:
            cleanup["host"] = error.host_cleanup_status
        if observation is None:
            observation = getattr(error, "observation", None)
        result = 126
    finally:
        for name, held in (("source_loader", loader), ("host", host)):
            if held is not None:
                try:
                    held.close()
                    cleanup[name] = "CLOSED"
                except BaseException:
                    cleanup[name] = "CLEANUP_HOLD"
                    phase = "WRAPPER_CLEANUP"
                    result = 126
    try:
        report = _public_observation(observation)
        if observation is None and entry_invoked:
            report["managed_call_attempted"] = None
    except BaseException:
        report = _public_observation(None)
        attempted = observation.get("managed_call_attempted") if type(observation) is dict else None
        report["managed_call_attempted"] = attempted if type(attempted) is bool else None if entry_invoked else False
        phase, result = "REPORT_REFUSED", 126
    report.update(status="MANAGED_BOOTSTRAP_RETURNED_NOT_QUALIFIED" if result == 0 else "REFUSED_OR_CLEANUP_HOLD",
                  wrapper_stage=phase, wrapper_cleanup=cleanup, entry_call_attempted=entry_invoked)
    print(_canonical(report).decode("ascii"))
    return result


if __name__ == "__main__":
    raise SystemExit(main())
