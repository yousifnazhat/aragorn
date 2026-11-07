"""Consume pinned Aragorn source bytes in the fixed trusted service wrappers.

The wrapper verifies this bootstrap module before any Aragorn import. Interpreter,
stdlib and native libraries remain the separately pinned image TCB. These records
are not independent worker provenance or proof of arbitrary in-memory behavior.
"""

from __future__ import annotations

import hashlib
import importlib.machinery
import math
import os
from pathlib import Path
import re
import stat
import sys
import time

_PREFIX = "opt/aragorn/src/"
_BOOTSTRAP = "_aragorn_pi_service_source"
_NAME = re.compile(r"[A-Za-z_][A-Za-z0-9_]*\Z")
_PIN = re.compile(r"sha256:[0-9a-f]{64}\Z")
_DIRECTORY = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
_FILE = os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW | os.O_CLOEXEC
_SEAL = object()
_MAX_FILES = 512
_MAX_FILE = 4 * 1024 * 1024
_MAX_BYTES = 32 * 1024 * 1024


class PiServiceSourceError(RuntimeError):
    """A failed import permanently prevents this loader's readiness evidence."""


def _require(condition, reason):
    if not condition:
        raise PiServiceSourceError(reason)


def _identity(value):
    return (value.st_dev, value.st_ino, value.st_mode, value.st_nlink,
            value.st_uid, value.st_gid, value.st_size,
            value.st_mtime_ns, value.st_ctime_ns)


def _directory_identity(value):
    return (value.st_dev, value.st_ino, value.st_mode, value.st_uid, value.st_gid)


def _directory(info, *, final=False):
    _require(stat.S_ISDIR(info.st_mode) and info.st_uid == info.st_gid == 0 and
             info.st_nlink >= 1 and not stat.S_IMODE(info.st_mode) & 0o022 and
             (not final or stat.S_IMODE(info.st_mode) == 0o555),
             "source directory is not protected")


def _file(info):
    _require(stat.S_ISREG(info.st_mode) and info.st_uid == info.st_gid == 0 and
             stat.S_IMODE(info.st_mode) == 0o444 and info.st_nlink == 1 and
             0 <= info.st_size <= _MAX_FILE, "source file is not protected or bounded")


def _inventory(pins):
    _require(type(pins) is dict and 0 < len(pins) <= _MAX_FILES,
             "source inventory is empty or exceeds its bound")
    modules = {}
    for path, digest in pins.items():
        _require(type(path) is str and path.startswith(_PREFIX + "aragorn/") and
                 len(path) <= 1024 and path.endswith(".py") and
                 type(digest) is str and _PIN.fullmatch(digest), "source pin is invalid")
        parts = path[len(_PREFIX):-3].split("/")
        _require(all(_NAME.fullmatch(part) for part in parts) and len(parts) <= 32,
                 "source module path is invalid")
        package = parts[-1] == "__init__"
        name = ".".join(parts[:-1] if package else parts)
        _require(name and name not in modules and "__init__" not in name.split("."),
                 "source module is ambiguous")
        modules[name] = (path, digest, package)
    _require("aragorn" in modules and modules["aragorn"][2], "Aragorn package source is absent")
    for name in modules:
        parent = name.rpartition(".")[0]
        _require(not parent or parent in modules and modules[parent][2],
                 "namespace packages are not permitted")
    return modules


class PiServiceSourceLoader:
    """One-use source execution and held-name custody; constructed by install."""

    def __init__(self, seal, root, modules, deadline):
        _require(seal is _SEAL, "source loader requires its protected factory")
        self._seal, self._root, self._modules, self._deadline = seal, root, modules, deadline
        self._directories, self._files, self._records = {}, {}, []
        self._executing, self._executed = set(), {}
        self._active, self._failed, self._bytes = False, False, 0
        self._closed = False

    def _time(self):
        _require(type(self._deadline) in (int, float) and math.isfinite(self._deadline) and
                 time.monotonic() < self._deadline, "source deadline expired or invalid")

    def _guard(self):
        self._time()
        _require(type(self) is PiServiceSourceLoader and self._seal is _SEAL and
                 getattr(sys.modules.get(_BOOTSTRAP), "PiServiceSourceLoader", None) is type(self) and
                 self._active and not self._failed and not self._closed and
                 sys.meta_path and sys.meta_path[0] is self, "source loader custody is unavailable")
        for path, (fd, identity) in self._directories.items():
            self._time()
            named = os.stat("/", follow_symlinks=False) if path == Path("/") else os.stat(
                path.name, dir_fd=self._directories[path.parent][0], follow_symlinks=False)
            _require(_directory_identity(os.fstat(fd)) == identity == _directory_identity(named),
                     "source directory changed")
        for path, (fd, identity) in self._files.items():
            self._time()
            _require(_identity(os.fstat(fd)) == identity == _identity(os.stat(
                path.name, dir_fd=self._directories[path.parent][0], follow_symlinks=False)),
                "consumed source identity changed")
        _require(all(sys.modules.get(name) is module for name, module in self._executed.items()),
                 "consumed source module was replaced")

    def _open_directory(self, path):
        if path in self._directories:
            return self._directories[path][0]
        parent = None if path == Path("/") else self._open_directory(path.parent)
        self._time()
        fd = os.open("/" if parent is None else path.name, _DIRECTORY, dir_fd=parent)
        try:
            info = os.fstat(fd)
            _directory(info, final=path == self._root or self._root in path.parents)
            named = os.stat("/", follow_symlinks=False) if parent is None else os.stat(
                path.name, dir_fd=parent, follow_symlinks=False)
            _require(_directory_identity(info) == _directory_identity(named),
                     "source directory changed while opening")
            self._directories[path] = (fd, _directory_identity(info))
            return fd
        except BaseException:
            os.close(fd)
            raise

    def find_spec(self, fullname, path=None, target=None):
        if fullname != "aragorn" and not fullname.startswith("aragorn."):
            return None
        try:
            self._guard()
            _require(target is None and fullname not in self._executed and fullname not in self._executing,
                     "source reload or execution retry refused")
            _require(fullname in self._modules, "source module is not admitted")
            parent = fullname.rpartition(".")[0]
            expected = [str(self._root.joinpath(*parent.split(".")))] if parent else None
            _require(path == expected, "alternate source search path refused")
            relative, _, package = self._modules[fullname]
            origin = str(self._root / relative[len(_PREFIX):])
            spec = importlib.machinery.ModuleSpec(fullname, self, origin=origin, is_package=package)
            spec.has_location = True
            if package:
                spec.submodule_search_locations = [str(Path(origin).parent)]
            return spec
        except BaseException:
            self._failed = True
            raise

    def create_module(self, spec):
        return None

    def exec_module(self, module):
        name = module.__name__
        try:
            self._guard()
            _require(name in self._modules and name not in self._executed and name not in self._executing and
                     sys.modules.get(name) is module and module.__spec__.loader is self,
                     "source execution identity differs or was reused")
            relative, expected, package = self._modules[name]
            path = self._root / relative[len(_PREFIX):]
            _require(module.__spec__.origin == str(path) and module.__file__ == str(path) and
                     (not package or module.__path__ == [str(path.parent)]),
                     "source module location differs")
            parent = self._open_directory(path.parent)
            self._time()
            descriptor = os.open(path.name, _FILE, dir_fd=parent)
            try:
                before = os.fstat(descriptor)
                _file(before)
                identity = _identity(before)
                _require(identity == _identity(os.stat(path.name, dir_fd=parent, follow_symlinks=False)),
                         "source changed before reading")
                self._bytes += before.st_size
                _require(self._bytes <= _MAX_BYTES, "consumed source byte limit exceeded")
                chunks, size = [], 0
                while True:
                    self._time()
                    chunk = os.read(descriptor, min(65536, _MAX_FILE + 1 - size))
                    if not chunk:
                        break
                    chunks.append(chunk)
                    size += len(chunk)
                    _require(size <= before.st_size, "source changed size while reading")
                raw = b"".join(chunks)
                _require(size == before.st_size and "sha256:" + hashlib.sha256(raw).hexdigest() == expected,
                         "consumed source bytes differ from approved pin")
                _require(identity == _identity(os.fstat(descriptor)) == _identity(os.stat(
                    path.name, dir_fd=parent, follow_symlinks=False)), "source changed while reading")
                self._files[path] = (descriptor, identity)
                descriptor = -1
            finally:
                if descriptor >= 0:
                    os.close(descriptor)
            self._executing.add(name)
            code = compile(raw, str(path), "exec", dont_inherit=True)
            self._time()
            exec(code, module.__dict__)
            self._time()
            self._executed[name] = module
            self._executing.remove(name)
            self._guard()
            self._records.append({"module": name, "path": relative, "digest": expected})
        except BaseException:
            self._failed = True
            raise

    def snapshot(self):
        """Return successful executions only; incomplete or failed imports refuse."""
        try:
            self._guard()
            _require(not self._executing and self._records and
                     len(self._records) == len(self._executed), "source execution is incomplete")
            _require({name for name in sys.modules if name == "aragorn" or name.startswith("aragorn.")} ==
                     set(self._executed), "unrecorded Aragorn module appeared")
            return [dict(row) for row in self._records]
        except BaseException:
            self._failed = True
            raise

    @property
    def source_digests(self):
        try:
            self._guard()
            return {path: digest for path, digest, _ in self._modules.values()}
        except BaseException:
            self._failed = True
            raise

    def close(self):
        """Revoke first and close only owned descriptors; never retry failures."""
        if self._closed:
            _require(not self._failed, "source loader already failed; no cleanup retry")
            return
        self._active, self._closed = False, True
        if self in sys.meta_path:
            sys.meta_path.remove(self)
        pending = [fd for fd, _ in (*self._files.values(), *self._directories.values())]
        self._files, self._directories = {}, {}
        failed = False
        for fd in reversed(pending):
            try:
                os.close(fd)
            except BaseException:
                failed = True
        if failed:
            self._failed = True
            raise PiServiceSourceError("source descriptor cleanup is uncertain")


def install(source_root, source_digests, *, deadline):
    """Install before any Aragorn import; inventory pins come from the wrapper."""
    _require(isinstance(source_root, Path) and source_root.is_absolute() and
             source_root != Path("/") and ".." not in source_root.parts, "source root is invalid")
    _require(not any(name == "aragorn" or name.startswith("aragorn.") for name in sys.modules),
             "Aragorn source was already imported")
    loader = PiServiceSourceLoader(_SEAL, source_root, _inventory(source_digests), deadline)
    try:
        loader._open_directory(source_root)
        sys.meta_path.insert(0, loader)
        loader._active = True
        loader._guard()
        return loader
    except BaseException:
        loader._failed = True
        loader.close()
        raise
