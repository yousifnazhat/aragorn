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
_ACTION_BASE_OK = "BASE_CONTROLS_INSTALLED_NOT_READY_OR_QUALIFIED"
_PROVIDER_BASE_OK = "PROVIDER_BASE_INSTALLED_NOT_READY_OR_QUALIFIED"
_PROVIDER_POLICY_OK = "INITIAL_PROVIDER_POLICY_RECORDED_NOT_READY_OR_QUALIFIED"


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
                        "MANAGED_CALL_RETURNED_NOT_QUALIFIED", "INVENTORIES_PREPARED_NOT_QUALIFIED",
                        "INSTALLED_NOT_ACTIVATED_OR_QUALIFIED", "BROKER_PREPARED_NOT_ACTIVATED_OR_QUALIFIED",
                        _ACTION_BASE_OK, _PROVIDER_BASE_OK, _PROVIDER_POLICY_OK},
             "invalid coordinator status")
    report["entry_status"] = status
    stage = observation.get("failure_stage")
    _require(stage is None or stage in {"PREFLIGHT", "PREPARED_INPUTS", "HELD_INPUTS", "MANAGED_CALL",
        "POST_CALL_CUSTODY", "HOLDER_CLEANUP", "INPUT_CLEANUP", "INVENTORY_PREPARATION",
        "INSTALLATION", "DESTINATION_CLEANUP", "PREPARATION_CALL", "BASE_INSTALLATION"},
        "invalid coordinator failure stage")
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


def _public_preparation(observation):
    report = _public_observation(observation)
    report.update(schema="aragorn/pi-core-installed-inventory-report/v1",
        authority="INSTALLED_VIEW_PREPARATION_ONLY_NOT_SOURCE_CONSUMPTION_HEALTH_OR_LAUNCH",
        preparation_attempted=False, owned_views_closed=False, artifacts=None, artifact_digests=None,
        input_cleanup_uncertainty=[])
    if observation is None:
        return report
    _require(observation.get("schema") == "aragorn/pi-core-installed-inventory-result/v1" and
             observation.get("managed_result") is None and report["managed_call_attempted"] is False and
             report["deployment_digest"] is None, "preparation cannot carry execution authority")
    for name in ("preparation_attempted", "owned_views_closed"):
        _require(type(observation.get(name)) is bool, "invalid preparation boolean")
        report[name] = observation[name]
    uncertainty = observation.get("input_cleanup_uncertainty", [])
    _require(type(uncertainty) is list and len(uncertainty) <= 512, "cleanup uncertainty bound")
    fields = {"INVENTORY_HELPER_DESCRIPTORS": {"scope", "held_fds", "ambiguous_fds"},
              "OBSERVER_ROOT_CLOSE": {"scope", "descriptors"},
              "DESCRIPTOR_CLOSE": {"scope", "descriptors"},
              "ANCESTRY_ACQUISITION": {"scope", "path"}}
    for row in uncertainty:
        _require(type(row) is dict and type(row.get("scope")) is str and
                 row["scope"] in fields and set(row) == fields[row["scope"]], "invalid cleanup uncertainty")
        for name in set(row) - {"scope"}:
            if name == "path":
                _path(row[name])
            else:
                _require(type(row[name]) is list and len(row[name]) <= 8192 and
                         all(type(fd) is int and 0 <= fd < 2**31 for fd in row[name]),
                         "invalid cleanup descriptor metadata")
    _require(len(_canonical(uncertainty)) <= 256 * 1024, "cleanup uncertainty byte bound")
    report["input_cleanup_uncertainty"] = json.loads(_canonical(uncertainty))
    artifacts, pins = observation.get("artifacts"), observation.get("artifact_digests")
    if artifacts is None:
        _require(pins is None and report["entry_status"] != "INVENTORIES_PREPARED_NOT_QUALIFIED",
                 "preparation artifacts absent")
        return report
    _require(report["entry_status"] == "INVENTORIES_PREPARED_NOT_QUALIFIED" and
             report["preparation_attempted"] and report["owned_views_closed"] and
             report["owned_inputs_closed"] and not uncertainty, "unreleased preparation artifacts")
    shapes = {
        "source_inventory": ("aragorn/pi-core-node-source-inventory/v2", {"schema", "sources"}),
        "loader_inventory": ("aragorn/pi-core-loader-inventory/v1", {"schema", "loaders"}),
        "profile": ("aragorn/pi-core-node-source-profile/v1",
                    {"schema", "pins", "sources", "required_sources", "loader_files"}),
        "preparation": ("aragorn/pi-core-source-inventory-preparation/v1",
            {"schema", "authority", "phase3_exit_eligible", "expected_manifest_digest", "profile_digest",
             "source_inventory_digest", "loader_inventory_digest", "worker_root_identity",
             "observer_root_identity", "code", "source_files", "loader_files"})}
    _require(type(artifacts) is dict and type(pins) is dict and set(artifacts) == set(pins) == set(shapes),
             "fixed preparation artifacts required")
    for name, (schema, fields) in shapes.items():
        value = artifacts[name]
        _require(type(value) is dict and set(value) == fields and value["schema"] == schema and
                 type(pins[name]) is str and _PIN.fullmatch(pins[name]) and
                 _digest(_canonical(value)) == pins[name], "preparation artifact fields or digest differ")

    def identity(value):
        _require(type(value) is dict and set(value) ==
            {"device", "inode", "mode", "nlink", "uid", "gid", "size", "mtime_ns", "ctime_ns"} and
            all(type(number) is int and 0 <= number < 2**63 for number in value.values()),
            "invalid public inventory identity")

    def rows(value, installed=False):
        _require(type(value) is list and 0 < len(value) <= 512, "public inventory row bound")
        for row in value:
            _require(type(row) is dict and set(row) == ({"path", "digest", "identity", "readonly_view"}
                if installed else {"path", "digest"}) and type(row["digest"]) is str and
                _PIN.fullmatch(row["digest"]), "invalid public inventory row")
            _path(row["path"])
            if installed:
                identity(row["identity"])
                _require(row["readonly_view"] is True, "inventory lacks read-only view")

    rows(artifacts["source_inventory"]["sources"], True)
    rows(artifacts["loader_inventory"]["loaders"], True)
    profile, receipt = artifacts["profile"], artifacts["preparation"]
    rows(profile["sources"])
    rows(profile["loader_files"])
    _require(type(profile["required_sources"]) is list and 0 < len(profile["required_sources"]) <= 512 and
             all(type(path) is str and path in {row["path"] for row in profile["sources"]}
                 for path in profile["required_sources"]), "invalid public required sources")
    _require(type(profile["pins"]) is dict and set(profile["pins"]) == {"gate_digest", "node_digest",
        "producer_digest", "node_observer_digest", "source_inventory_digest", "loader_inventory_digest"} and
        all(type(pin) is str and _PIN.fullmatch(pin) for pin in profile["pins"].values()), "invalid profile pins")
    for name in ("source_inventory", "loader_inventory"):
        _require(profile["pins"][name + "_digest"] == receipt[name + "_digest"] == pins[name],
                 "inventory output join differs")
    _require(receipt["profile_digest"] == pins["profile"] and receipt["phase3_exit_eligible"] is False and
        receipt["authority"] == report["authority"] and type(receipt["expected_manifest_digest"]) is str and
        _PIN.fullmatch(receipt["expected_manifest_digest"]), "invalid preparation receipt")
    for name in ("worker_root_identity", "observer_root_identity"):
        identity(receipt[name])
    for name, key in (("source_files", "source_inventory"), ("loader_files", "loader_inventory")):
        _require(type(receipt[name]) is int and receipt[name] == len(artifacts[key]["sources" if key == "source_inventory" else "loaders"]),
                 "inventory output count differs")
    _require(type(receipt["code"]) is list and len(receipt["code"]) == 4, "invalid public code inventory")
    for row in receipt["code"]:
        _require(type(row) is dict and set(row) == {"view", "path", "digest", "identity", "protection"} and
            row["view"] in {"worker", "observer"} and row["protection"] ==
            ("ROOT_OWNED_READONLY_VIEW" if row["view"] == "worker" else "ROOT_OWNED_NO_WRITE_BITS") and
            type(row["digest"]) is str and _PIN.fullmatch(row["digest"]), "invalid public code record")
        _path(row["path"])
        identity(row["identity"])
    report.update(artifacts=artifacts, artifact_digests=pins)
    _require(len(_canonical(report)) <= 4 * 1024 * 1024, "preparation report exceeds bound")
    return report


def _public_install(observation):
    report = _public_observation(observation)
    report.update(schema="aragorn/pi-core-bundle-install-report/v1",
        authority="PROTECTED_MATERIALIZATION_ONLY_NOT_ACTIVATION_OR_PHASE3",
        context_digest=None, installation_attempted=False, owned_destination_closed=False,
        publication_state="NOT_ATTEMPTED", transaction_digest=None, recovery_digest=None,
        input_cleanup_uncertainty_digest=None)
    if observation is None:
        return report
    _require(observation.get("schema") == "aragorn/pi-core-bundle-install-result/v1" and
             observation.get("authority") == report["authority"] and
             observation.get("managed_result") is None and report["managed_call_attempted"] is False,
             "installation cannot carry managed authority")
    for name in ("installation_attempted", "owned_destination_closed"):
        _require(type(observation.get(name)) is bool, "invalid installation boolean")
        report[name] = observation[name]
    pin = observation.get("context_digest")
    _require(pin is None or type(pin) is str and _PIN.fullmatch(pin), "invalid context pin")
    report["context_digest"] = pin
    state = observation.get("publication_state")
    _require(state in {"NOT_ATTEMPTED", "PUBLISHER_RETURNED", "RECOVERY_RECORD_RETAINED", "UNKNOWN"} and
             (report["installation_attempted"] or state == "NOT_ATTEMPTED"), "invalid publication state")
    report["publication_state"] = state
    for name in ("transaction", "recovery"):
        value = observation.get(name)
        if value is not None:
            _require(type(value) is dict and report["installation_attempted"], "invalid private installation record")
            if name == "transaction":
                _require(value.get("schema") == "aragorn/protected-install-transaction/v1",
                         "invalid installation transaction schema")
            raw = _canonical(value)
            _require(len(raw) <= 256 * 1024, "installation record exceeds report bound")
            report[name + "_digest"] = _digest(raw)
    uncertainty = observation.get("input_cleanup_uncertainty")
    _require(type(uncertainty) is list and len(uncertainty) <= 512, "invalid input cleanup uncertainty")
    raw = _canonical(uncertainty)
    _require(len(raw) <= 256 * 1024, "input cleanup uncertainty exceeds bound")
    report["input_cleanup_uncertainty_digest"] = _digest(raw)
    if report["entry_status"] == "INSTALLED_NOT_ACTIVATED_OR_QUALIFIED":
        _require(report["installation_attempted"] and report["owned_inputs_closed"] and
                 report["owned_destination_closed"] and not uncertainty and
                 state == "PUBLISHER_RETURNED" and report["transaction_digest"] is not None and
                 report["recovery_digest"] is None and pin is not None,
                 "installation success lacks complete owned custody")
    _require(len(_canonical(report)) <= 256 * 1024, "installation report exceeds bound")
    return report


def _public_broker_preparation(observation):
    report = _public_observation(observation)
    report.update(schema="aragorn/pi-core-broker-preparation-report/v1",
        authority="PROTECTED_GRANT_PREPARATION_ONLY_NOT_ACTIVATION_OR_PHASE3",
        preparation_attempted=False, owned_holders_closed=False, context_digest=None,
        preparation_result_digest=None, preparation_status=None, preparation_cleanup_complete=False,
        input_cleanup_uncertainty_digest=None)
    if observation is None:
        return report
    _require(observation.get("schema") == "aragorn/pi-core-broker-preparation-result/v1" and
        observation.get("authority") == report["authority"] and observation.get("managed_result") is None and
        report["managed_call_attempted"] is False, "broker preparation cannot carry managed authority")
    for name in ("preparation_attempted", "owned_holders_closed"):
        _require(type(observation.get(name)) is bool, "invalid broker preparation boolean")
        report[name] = observation[name]
    pin = observation.get("context_digest")
    _require(pin is None or type(pin) is str and _PIN.fullmatch(pin), "invalid broker context pin")
    report["context_digest"] = pin
    uncertainty = observation.get("input_cleanup_uncertainty")
    _require(type(uncertainty) is list and len(uncertainty) <= 512, "invalid broker input cleanup uncertainty")
    raw = _canonical(uncertainty)
    _require(len(raw) <= 256 * 1024, "broker input uncertainty exceeds bound")
    report["input_cleanup_uncertainty_digest"] = _digest(raw)
    value = observation.get("preparation_result")
    complete = False
    if value is not None:
        _require(type(value) is dict and report["preparation_attempted"] and
            value.get("schema") == "aragorn/pi-core-service-lifecycle/v1" and
            value.get("phase3_exit_eligible") is False and value.get("loaded_code_verified") is False,
            "invalid broker preparation lifecycle")
        raw = _canonical(value)
        _require(len(raw) <= 4 * 1024 * 1024, "broker preparation result exceeds bound")
        report["preparation_result_digest"] = _digest(raw)
        prepared = value.get("broker_preparation")
        if prepared is not None:
            _require(type(prepared) is dict and prepared.get("schema") == "aragorn/pi-core-broker-preparation/v1" and
                prepared.get("authority") == "EXPLICIT_GRANT_PREPARATION_NOT_ACTIVATION_OR_PHASE3" and
                prepared.get("phase3_exit_eligible") is False and
                prepared.get("status") in {"PREPARED", "REFUSED", "INDETERMINATE", "CLEANUP_HOLD"},
                "invalid broker preparation record")
            report["preparation_status"] = prepared["status"]
            complete = (prepared["status"] == "PREPARED" and prepared.get("phase") == "COMPLETE" and
                all(prepared.get(key) is True for key in ("command_attempted", "ack_attempted", "ack_sent")) and
                all(type(prepared.get(key)) is dict for key in ("command", "result_packet", "readback")))
        report["preparation_cleanup_complete"] = (value.get("status") == "CLOSED" and
            type(value.get("cleanup")) is dict and value["cleanup"].get("status") == "VERIFIED_OWNED_CLEANUP")
    if report["entry_status"] == "BROKER_PREPARED_NOT_ACTIVATED_OR_QUALIFIED":
        _require(complete and report["preparation_cleanup_complete"] and report["preparation_attempted"] and
            report["owned_inputs_closed"] and report["owned_holders_closed"] and not uncertainty and pin is not None,
            "broker preparation lacks complete owned custody")
    _require(len(_canonical(report)) <= 256 * 1024, "broker preparation report exceeds bound")
    return report


def _public_broker_base_install(observation, *, provider=False, initial_policy=False):
    _require(not (provider and initial_policy), "ambiguous broker preparation result")
    if initial_policy:
        route = "provider-initial-policy"
        success = _PROVIDER_POLICY_OK
        entry_authority = "PROTECTED_INITIAL_PROVIDER_POLICY_ONLY_NOT_HEALTH_OR_EXECUTION"
        inner_schema = "aragorn/pi-core-provider-initial-policy/v1"
        inner_authority = "PINNED_INITIAL_POLICY_AND_REVOCATIONS_ONLY_NOT_HEALTH_OR_EXECUTION"
    else:
        route = "provider-base" if provider else "broker-base"
        success = _PROVIDER_BASE_OK if provider else _ACTION_BASE_OK
        entry_authority = ("PROTECTED_PROVIDER_BASE_INSTALLATION_ONLY_NOT_ACTIVATION_OR_PHASE3" if provider else
                           "PROTECTED_BASE_INSTALLATION_ONLY_NOT_ACTIVATION_OR_PHASE3")
        inner_schema = f"aragorn/pi-core-{route}-installation/v1"
        inner_authority = "FRESH_BASE_CONTROLS_ONLY_NOT_POLICY_HEALTH_GRANT_OR_PHASE3"
    report = _public_observation(observation)
    report.update(schema=f"aragorn/pi-core-{route}-report/v1", authority=entry_authority,
        base_installation_attempted=False, owned_holders_closed=False, context_digest=None,
        base_installation_result_digest=None, base_installation_status=None, base_cleanup_complete=False,
        input_cleanup_uncertainty_digest=None)
    if observation is None:
        return report
    _require(observation.get("schema") == f"aragorn/pi-core-{route}-result/v1" and
        report["entry_status"] in {success, "REFUSED", "REFUSED_OR_INDETERMINATE", "CLEANUP_HOLD"} and
        observation.get("authority") == report["authority"] and observation.get("managed_result") is None and
        report["managed_call_attempted"] is False and observation.get("preparation_attempted") is False and
        observation.get("preparation_result") is None, "base installation cannot carry execution authority")
    for name in ("base_installation_attempted", "owned_holders_closed"):
        _require(type(observation.get(name)) is bool, "invalid base installation boolean")
        report[name] = observation[name]
    pin = observation.get("context_digest")
    _require(pin is None or type(pin) is str and _PIN.fullmatch(pin), "invalid base context pin")
    report["context_digest"] = pin
    uncertainty = observation.get("input_cleanup_uncertainty")
    _require(type(uncertainty) is list and len(uncertainty) <= 512, "invalid base input cleanup uncertainty")
    raw = _canonical(uncertainty)
    _require(len(raw) <= 256 * 1024, "base input uncertainty exceeds bound")
    report["input_cleanup_uncertainty_digest"] = _digest(raw)
    value = observation.get("base_installation_result")
    complete = False
    if value is not None:
        _require(type(value) is dict and report["base_installation_attempted"] and
            value.get("schema") == inner_schema and value.get("authority") == inner_authority and
            value.get("status") in {"INSTALLED", "REFUSED", "PARTIAL_OR_INDETERMINATE", "CLEANUP_HOLD"} and
            all(value.get(key) is False for key in ("activation_performed", "service_ready",
                                                   "current_grant_authority", "phase3_exit_eligible")),
            "invalid base installation result")
        raw = _canonical(value)
        _require(len(raw) <= 4 * 1024 * 1024, "base installation result exceeds bound")
        report["base_installation_result_digest"] = _digest(raw)
        report["base_installation_status"] = value["status"]
        report["base_cleanup_complete"] = value.get("owned_handles_closed") is True
        complete = (value["status"] == "INSTALLED" and value.get("mutation_attempted") is True and
                    type(value.get("readback")) is dict and value.get("cleanup_uncertainty") == [])
    if report["entry_status"] == success:
        _require(complete and report["base_cleanup_complete"] and report["base_installation_attempted"] and
            report["owned_inputs_closed"] and report["owned_holders_closed"] and not uncertainty and pin is not None,
            "base installation lacks complete owned custody")
    _require(len(_canonical(report)) <= 256 * 1024, "base installation report exceeds bound")
    return report


def main():
    host = loader = None
    result, observation, phase = 126, None, "PREFLIGHT"
    entry_invoked = False
    prepare = len(sys.argv) > 1 and sys.argv[1] == "--prepare-inventories"
    install = len(sys.argv) > 1 and sys.argv[1] == "--install-bundle"
    broker_prepare = len(sys.argv) > 1 and sys.argv[1] == "--prepare-broker-control"
    provider_base = len(sys.argv) > 1 and sys.argv[1] == "--install-provider-base"
    initial_policy = len(sys.argv) > 1 and sys.argv[1] == "--initialize-provider-policy"
    base_install = initial_policy or provider_base or (len(sys.argv) > 1 and sys.argv[1] == "--install-broker-base")
    base_success = _PROVIDER_POLICY_OK if initial_policy else _PROVIDER_BASE_OK if provider_base else _ACTION_BASE_OK
    public = (_public_broker_preparation if broker_prepare else _public_install if install else
              _public_preparation if prepare else _public_observation)
    if base_install:
        public = lambda value: _public_broker_base_install(value, provider=provider_base, initial_policy=initial_policy)
    attempt_field = "base_installation_attempted" if base_install else "installation_attempted" if install else "preparation_attempted" if prepare or broker_prepare else "managed_call_attempted"
    args = sys.argv[2:] if prepare or install or broker_prepare or base_install else sys.argv[1:]
    cleanup = {"source_loader": "NOT_ACQUIRED", "host": "NOT_ACQUIRED"}
    try:
        _flags()
        _require(len(args) == 5 and type(args[4]) is str and args[4].isascii() and
                 args[4].isdecimal() and 0 < int(args[4]) < 2**63, "fixed coordinator arguments required")
        profile_path, plan_path = _path(args[0]), _path(args[2])
        _require(all(_PIN.fullmatch(value) for value in (args[1], args[3])), "independent pins required")
        deadline_ns = int(args[4])
        deadline = math.nextafter(deadline_ns / 1_000_000_000, 0.0)
        _require(time.monotonic() < deadline <= time.monotonic() + 30, "original bounded coordinator deadline required")
        _require(Path(__file__) == _WRAPPER and _PRIVATE not in sys.modules, "fixed coordinator origin required")
        sys.modules[_PRIVATE] = sys.modules[__name__]
        phase = "HOST_CUSTODY"
        cleanup["host"] = "NOT_RETURNED_CLEANUP_UNVERIFIED"
        host = _hold_host(profile_path, args[1], deadline)
        phase = "SOURCE_BOOTSTRAP"
        cleanup["source_loader"] = "NOT_RETURNED_CLEANUP_UNVERIFIED"
        loader = _bootstrap(host)
        if broker_prepare or base_install:
            from aragorn.pi_core_broker_preparation_entry import run
        elif install:
            from aragorn.pi_core_bundle_install_entry import run
        elif prepare:
            from aragorn.pi_core_installed_inventory_entry import run
        else:
            from aragorn.pi_core_coordinator_entry import run
        host.guard()
        phase = "ENTRY_CALL"
        entry_invoked = True
        mode = ({"initialize_provider_policy": True} if initial_policy else {"install_provider_base": True}
                if provider_base else {"install_base": True} if base_install else {})
        observation = run(plan_path, args[3], deadline_ns=deadline_ns, source_loader=loader, host_custody=host, **mode)
        phase = "POST_CALL_CUSTODY"
        host.guard()
        report = public(observation)
        if base_install:
            result = 0 if report["entry_status"] == base_success else 126
        elif broker_prepare:
            result = 0 if report["entry_status"] == "BROKER_PREPARED_NOT_ACTIVATED_OR_QUALIFIED" else 126
        elif install:
            result = 0 if report["entry_status"] == "INSTALLED_NOT_ACTIVATED_OR_QUALIFIED" else 126
        elif prepare:
            result = (0 if report["entry_status"] == "INVENTORIES_PREPARED_NOT_QUALIFIED" and
                report["preparation_attempted"] and report["owned_inputs_closed"] and
                report["owned_views_closed"] and report["artifacts"] is not None else 126)
        else:
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
        report = public(observation)
        if observation is None and entry_invoked:
            report[attempt_field] = None
    except BaseException:
        report = public(None)
        attempted = observation.get(attempt_field) if type(observation) is dict else None
        report[attempt_field] = attempted if type(attempted) is bool else None if entry_invoked else False
        phase, result = "REPORT_REFUSED", 126
    report.update(status=(base_success if base_install else
                  "BROKER_PREPARED_NOT_ACTIVATED_OR_QUALIFIED" if broker_prepare else
                  "INSTALLED_NOT_ACTIVATED_OR_QUALIFIED" if install else
                  "INVENTORIES_PREPARED_NOT_QUALIFIED" if prepare else
                  "MANAGED_BOOTSTRAP_RETURNED_NOT_QUALIFIED") if result == 0 else "REFUSED_OR_CLEANUP_HOLD",
                  wrapper_stage=phase, wrapper_cleanup=cleanup, entry_call_attempted=entry_invoked)
    if prepare and result != 0:
        report.update(artifacts=None, artifact_digests=None)
    print(_canonical(report).decode("ascii"))
    return result


if __name__ == "__main__":
    raise SystemExit(main())
