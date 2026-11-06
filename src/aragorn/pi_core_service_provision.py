"""Pinned operator-reviewed service bytes, without execution or service readiness.

The operator supplies the complete reviewed Python/native/source closure. Exact
inventory and essential-file checks do not infer dynamic-import completeness,
ELF compatibility or loaded-code provenance. No packages, credentials, services,
host Python fallback, cleanup retries or automatic repairs are introduced.
"""

from __future__ import annotations

from contextlib import contextmanager
import hashlib
import json
import os
from pathlib import Path
import re
import stat

from . import pi_core_os_provision as provision
from .oci_worker_protocol import canonical_digest, canonical_json
from .runtime_action_broker import _directory_identity

PYTHON = "usr/bin/python3"
STDLIB = "usr/lib/python3.12"
IMPORT_ROOT = "opt/aragorn/src"
SOURCE_ROOT = IMPORT_ROOT + "/aragorn"
LOADER = "lib/ld-linux-aarch64.so.1"
RECEIPT = "service-runtime-receipt.json"
BINDING_SCHEMA = "aragorn/pi-core-service-runtime-binding/v1"
BINDING_SCHEMA_V2 = "aragorn/pi-core-service-runtime-binding/v2"
LIBPYTHON = "usr/lib/libpython3.12.so.1.0"
WRAPPER_ROOT = "opt/aragorn/bin"
SCHEMA = "aragorn/pi-core-service-runtime/v1"
STATUS = "PROVISIONED_SERVICE_BYTES_NOT_EXECUTED_OR_SERVICE_READY"
AUTHORITY = "HELD_INSTALLED_SERVICE_BYTES_NOT_LOADED_CODE_OR_PROCESS_AUTHORITY"
ROLES = {
    "provider": {"module": "aragorn.pi_core_provider_service", "handler": "handle_pi_provider_service",
                 "path": SOURCE_ROOT + "/pi_core_provider_service.py"},
    "action": {"module": "aragorn.pi_core_request_service", "handler": "handle_pi_broker_request",
               "path": SOURCE_ROOT + "/pi_core_request_service.py"},
    "sensor": {"module": "aragorn.pi_core_request_sensor", "handler": "run_pi_sensor_request",
               "path": SOURCE_ROOT + "/pi_core_request_sensor.py"},
}
_LIB_DIRS = ("lib/aarch64-linux-gnu", "usr/lib/aarch64-linux-gnu")
_ESSENTIAL_STDLIB = ("os.py", "ssl.py", "socket.py", "encodings/__init__.py", "json/__init__.py", "ctypes/__init__.py")
_SEAL = object()


class PiServiceProvisionError(provision.PiOsProvisionError):
    """Preserve partial output and evidence; never infer a retry authorization."""


def _require(condition, reason):
    if not condition:
        raise PiServiceProvisionError(reason)


def _copy(value):
    return json.loads(canonical_json(value))


def validate_service_runtime_inputs(manifest, manifest_digest, runtime_binding, runtime_binding_digest):
    """Validate independent expected pins and fixed roles, never measure a host."""
    pinned = provision._manifest(manifest, manifest_digest)
    _require(type(runtime_binding_digest) is str and provision._DIGEST.fullmatch(runtime_binding_digest),
             "invalid service binding pin")
    raw = canonical_json(runtime_binding)
    _require(len(raw) <= 2 * 1024 * 1024, "service binding exceeds bound")
    binding = json.loads(raw)
    _require(canonical_digest(binding) == runtime_binding_digest, "service binding pin mismatch")
    _require(type(binding) is dict, "invalid service binding fields")
    wrapped = binding.get("schema") == BINDING_SCHEMA_V2
    _require(set(binding) == {
        "schema", "target", "python", "import_root", "stdlib_directory", "loader_path",
        "native_extension_paths", "shared_library_paths", "source_digests", "roles"} |
        ({"wrappers"} if wrapped else set()),
        "invalid service binding fields")
    _require(binding["schema"] in (BINDING_SCHEMA, BINDING_SCHEMA_V2) and binding["target"] == "linux-arm64-glibc" and
             binding["import_root"] == IMPORT_ROOT and binding["stdlib_directory"] == STDLIB and
             binding["loader_path"] == LOADER and binding["roles"] == ROLES,
             "service runtime layout or fixed role mapping differs")
    files = {row["path"]: row for row in pinned["files"]}
    expected_directories = sorted(set().union(*(provision._parents(name) for name in files)))
    _require(pinned["directories"] == expected_directories, "service closure has unbound empty directories")
    python = binding["python"]
    _require(type(python) is dict and set(python) == {"path", "digest"} and python["path"] == PYTHON and
             PYTHON in files and files[PYTHON]["executable"] and python["digest"] == files[PYTHON]["digest"] and
             LOADER in files and files[LOADER]["executable"], "service Python or loader identity is absent or differs")
    wrapper_paths = {WRAPPER_ROOT + "/" + role + ".py" for role in ROLES} if wrapped else set()
    if wrapped:
        _require(LIBPYTHON in files and SOURCE_ROOT + "/pi_core_service_entry.py" in files and
                 wrapper_paths <= files.keys(), "service image lacks libpython or fixed wrappers")
        expected_wrappers = {role: {
            "path": WRAPPER_ROOT + "/" + role + ".py",
            "digest": files[WRAPPER_ROOT + "/" + role + ".py"]["digest"],
            "argv": ["/" + PYTHON, "-I", "-S", "-B", "/" + WRAPPER_ROOT + "/" + role + ".py"],
        } for role in ROLES}
        _require(binding["wrappers"] == expected_wrappers and
                 all(files[name]["executable"] and files[name]["size"] > 0 for name in wrapper_paths),
                 "service wrapper bytes, roles or isolated invocation differ")
    for name in files:
        _require(not any(part == "__pycache__" for part in name.split("/")) and not name.endswith((".pyc", ".pyo")),
                 "service closure contains unreviewable Python caches")
        _require(name in (PYTHON, LOADER) or name in wrapper_paths or (wrapped and name == LIBPYTHON) or name.startswith(STDLIB + "/") or
                 name.startswith(SOURCE_ROOT + "/") or any(name.startswith(folder + "/") for folder in _LIB_DIRS),
                 "service closure contains a path outside the fixed runtime/source layout")
    sources = {name: row["digest"] for name, row in files.items() if name.startswith(SOURCE_ROOT + "/")}
    _require(sources and all(name.endswith(".py") and not files[name]["executable"] for name in sources) and
             binding["source_digests"] == sources and SOURCE_ROOT + "/__init__.py" in sources and
             all(role["path"] in sources for role in ROLES.values()),
             "service source closure or fixed handler modules differ")
    _require(all(STDLIB + "/" + name in files for name in _ESSENTIAL_STDLIB),
             "service closure lacks declared essential Python stdlib files")
    native = binding["native_extension_paths"]
    _require(type(native) is list and native and len(native) <= 1024 and
             all(type(name) is str for name in native) and native == sorted(set(native)),
             "invalid service native extension inventory")
    actual_native = sorted(name for name in files if name.startswith(STDLIB + "/") and name.endswith(".so"))
    _require(native == actual_native and all(name.startswith(STDLIB + "/lib-dynload/") and
             "/" not in name[len(STDLIB + "/lib-dynload/"):] for name in native) and
             all(any(re.fullmatch(re.escape(prefix) + r"(?:\.[A-Za-z0-9_-]+)*\.so", Path(name).name)
                     for name in native) for prefix in ("_ssl", "_socket", "_ctypes")),
             "service native extension closure lacks required identities or contains overrides")
    libraries = binding["shared_library_paths"]
    actual_libraries = sorted(name for name in files if (wrapped and name == LIBPYTHON) or
                              any(name.startswith(folder + "/") for folder in _LIB_DIRS))
    _require(type(libraries) is list and len(libraries) <= 1024 and all(type(name) is str for name in libraries) and
             libraries == sorted(set(libraries)) and libraries == actual_libraries and
             all(((wrapped and name == LIBPYTHON) or any(Path(name).parent.as_posix() == folder for folder in _LIB_DIRS)) and
                 re.fullmatch(r"lib[A-Za-z0-9_.+-]+\.so(?:\.[0-9]+)*", Path(name).name) for name in libraries) and
             {"libssl.so.3", "libcrypto.so.3", "libc.so.6"}.issubset({Path(name).name for name in libraries}),
             "service shared-library closure lacks reviewed OpenSSL/libc identities")
    _require(all(files[name]["size"] > 0 for name in (PYTHON, LOADER, *native, *libraries)),
             "service executable or native library is empty")
    return pinned, binding


def _exact_names(fd, expected, deadline):
    names = set()
    with os.scandir(fd) as entries:
        for entry in entries:
            provision._deadline(deadline)
            _require(entry.name in expected and entry.name not in names, "service tree contains unexpected entries")
            names.add(entry.name)
    _require(names == expected, "service tree is missing declared entries")


def _tree(root, manifest, deadline, *, protected):
    """Hash exact declared paths with bounded scans and per-chunk deadlines."""
    paths = ("", *manifest["directories"])
    children = {name: set() for name in paths}
    for name in (*manifest["directories"], *(row["path"] for row in manifest["files"])):
        parent, _, leaf = name.rpartition("/")
        children[parent].add(leaf)
    identities = {}
    for name in paths:
        provision._deadline(deadline)
        fd = provision._walk(root, name.split("/") if name else [])
        try:
            if protected:
                provision._owner(fd, 0o555 if name else 0o755, directory=True)
            identities[name] = provision._identity(os.fstat(fd))
            _exact_names(fd, children[name], deadline)
        finally:
            provision._close_all([fd])
    for row in manifest["files"]:
        provision._deadline(deadline)
        parts = row["path"].split("/")
        parent = descriptor = -1
        try:
            parent = provision._walk(root, parts[:-1])
            before = os.stat(parts[-1], dir_fd=parent, follow_symlinks=False)
            _require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and before.st_size == row["size"],
                     "service member type, links or size differs")
            descriptor = os.open(parts[-1], provision._FILE, dir_fd=parent)
            _require(provision._identity(os.fstat(descriptor)) == provision._identity(before),
                     "service member changed before read")
            if protected:
                provision._owner(descriptor, 0o555 if row["executable"] else 0o444, directory=False)
            _require(bool(before.st_mode & 0o111) == row["executable"], "service executable mode differs")
            digest, size = hashlib.sha256(), 0
            while True:
                provision._deadline(deadline)
                chunk = os.read(descriptor, min(1024 * 1024, row["size"] + 1 - size))
                if not chunk:
                    break
                size += len(chunk)
                _require(size <= row["size"], "service member grew while read")
                digest.update(chunk)
            _require(size == row["size"] and "sha256:" + digest.hexdigest() == row["digest"] and
                     provision._identity(os.fstat(descriptor)) == provision._identity(before) ==
                     provision._identity(os.stat(parts[-1], dir_fd=parent, follow_symlinks=False)),
                     "service member bytes or identity changed")
        finally:
            provision._close_all([descriptor, parent])
    for name in paths:
        provision._deadline(deadline)
        fd = provision._walk(root, name.split("/") if name else [])
        try:
            _require(provision._identity(os.fstat(fd)) == identities[name], "service directory changed during read")
            _exact_names(fd, children[name], deadline)
        finally:
            provision._close_all([fd])


def _path(path):
    _require(isinstance(path, Path) and path.is_absolute() and path != Path("/") and ".." not in path.parts,
             "service deployment path must be absolute and safe")


def _ancestor(fd):
    info = os.fstat(fd)
    _require(stat.S_ISDIR(info.st_mode) and info.st_uid == provision._ROOT_UID and
             info.st_gid == provision._ROOT_GID and not stat.S_IMODE(info.st_mode) & 0o022,
             "service protected ancestry is unsafe")


def _open_chain(path, deadline):
    _path(path)
    fds = []
    try:
        fds.append(os.open("/", provision._DIRECTORY))
        _ancestor(fds[-1])
        for name in path.parts[1:]:
            provision._deadline(deadline)
            fds.append(os.open(name, provision._DIRECTORY, dir_fd=fds[-1]))
            _ancestor(fds[-1])
        return fds
    except BaseException:
        provision._close_all(list(reversed(fds)))
        raise


def _chain_guard(path, fds, identities, deadline):
    for index, fd in enumerate(fds):
        provision._deadline(deadline)
        _ancestor(fd)
        held = os.fstat(fd)
        named = os.lstat("/") if index == 0 else os.stat(path.parts[index], dir_fd=fds[index - 1], follow_symlinks=False)
        identity = provision._identity if index == len(fds) - 1 else _directory_identity
        _require(identity(held) == identities[index] == identity(named),
                 "service protected ancestor custody changed")


def _receipt(root, manifest_digest, binding, binding_digest):
    return {"schema": SCHEMA, "status": STATUS, "runtime_root": str(root),
            "runtime_closure_digest": manifest_digest, "binding_digest": binding_digest,
            "python_digest": binding["python"]["digest"], "credential_read": False,
            "activation_performed": False, "service_ready": False,
            "loaded_code_attested": False, "phase3_exit_eligible": False}


def provision_pi_service_runtime(*, source, manifest, manifest_digest, runtime_binding,
                                 runtime_binding_digest, destination_parent, deployment_name, deadline):
    """Copy an approved complete service tree once; retain every failed write."""
    observation = {"schema": "aragorn/pi-core-service-provisioning-observation/v1",
                   "created": False, "completed": False, "activation_performed": False,
                   "credential_read": False, "rollback_performed": False}
    fds = []
    try:
        provision._require_root()
        provision._deadline(deadline)
        pinned, binding = validate_service_runtime_inputs(manifest, manifest_digest, runtime_binding, runtime_binding_digest)
        _path(source)
        _path(destination_parent)
        _require(type(deployment_name) is str and provision._NAME.fullmatch(deployment_name), "invalid service deployment name")
        target = destination_parent / deployment_name
        _require(not target.is_relative_to(source) and not source.is_relative_to(target), "service source and destination overlap")
        source_fd = provision._source(source)
        fds.append(source_fd)
        _tree(source_fd, pinned, deadline, protected=False)
        parent = provision.lineage._open_protected_root(destination_parent, provision._ROOT_UID)
        fds.append(parent)
        _require(os.fstat(parent).st_gid == provision._ROOT_GID, "service destination group is unsafe")
        provision._deadline(deadline)
        observation["created"] = None
        deployment = provision._new_directory(parent, deployment_name)
        fds.append(deployment)
        observation.update(created=True, destination=str(target))
        root = provision._new_directory(deployment, "root")
        fds.append(root)
        provision._install_tree(source_fd, root, pinned, deadline)
        _tree(root, pinned, deadline, protected=True)
        _tree(source_fd, pinned, deadline, protected=False)
        receipt = _receipt(target / "root", manifest_digest, binding, runtime_binding_digest)
        raw = canonical_json(receipt)
        descriptor = os.open(RECEIPT, os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                             0o600, dir_fd=deployment)
        fds.append(descriptor)
        os.fchown(descriptor, provision._ROOT_UID, provision._ROOT_GID)
        provision._write_all(descriptor, raw, deadline)
        os.fchmod(descriptor, 0o444)
        provision._owner(descriptor, 0o444, directory=False)
        os.fsync(descriptor)
        os.lseek(descriptor, 0, os.SEEK_SET)
        _require(os.read(descriptor, len(raw) + 1) == raw, "service receipt readback differs")
        os.fchmod(deployment, 0o755)
        provision._owner(deployment, 0o755, directory=True)
        os.fsync(deployment)
        os.fsync(parent)
        named_parent = provision.lineage._open_protected_root(destination_parent, provision._ROOT_UID)
        fds.append(named_parent)
        _require(provision._identity(os.fstat(named_parent)) == provision._identity(os.fstat(parent)),
                 "service destination parent changed")
        for held, owner, name in ((deployment, parent, deployment_name), (root, deployment, "root"),
                                  (descriptor, deployment, RECEIPT)):
            _require(provision._identity(os.fstat(held)) == provision._identity(
                os.stat(name, dir_fd=owner, follow_symlinks=False)), "service installed name custody changed")
        _exact_names(deployment, {"root", RECEIPT}, deadline)
        provision._deadline(deadline)
        observation.update(completed=True, receipt_digest=canonical_digest(receipt))
        return receipt
    except BaseException as error:
        error.pi_service_provisioning_observation = observation
        raise
    finally:
        try:
            provision._close_all(list(reversed(fds)))
        except BaseException as error:
            observation["completed"] = False
            error.pi_service_provisioning_observation = observation
            raise


class PiServiceRuntime:
    """An active root-held exact installed-byte lease, not process authority."""
    __slots__ = ("_seal", "_path", "_chain", "_identities", "_root_fd", "_receipt_fd", "_root_identity",
                 "_receipt_identity", "_manifest", "_binding", "_receipt", "_deadline", "_active", "_observation")

    def __init__(self, seal, path, chain, root_fd, receipt_fd, manifest, binding, receipt, deadline):
        _require(seal is _SEAL, "service runtime requires verified installed custody")
        self._seal = seal
        self._path, self._chain = path, chain
        self._identities = [(provision._identity if index == len(chain) - 1 else _directory_identity)(os.fstat(fd))
                            for index, fd in enumerate(chain)]
        self._root_fd, self._receipt_fd = root_fd, receipt_fd
        self._root_identity = provision._identity(os.fstat(root_fd))
        self._receipt_identity = provision._identity(os.fstat(receipt_fd))
        self._manifest, self._binding, self._receipt = _copy(manifest), _copy(binding), _copy(receipt)
        self._deadline, self._active = deadline, True
        self._observation = {"schema": "aragorn/pi-core-held-service-runtime/v1", "authority": AUTHORITY,
            "runtime_closure_digest": receipt["runtime_closure_digest"], "binding_digest": receipt["binding_digest"],
            "receipt_digest": canonical_digest(receipt), "python_digest": receipt["python_digest"],
            "loaded_code_attested": False, "service_ready": False, "phase3_exit_eligible": False}

    def _live(self):
        _require(type(self) is PiServiceRuntime and getattr(self, "_seal", None) is _SEAL and
                 getattr(self, "_active", False), "service runtime custody is no longer active or was not minted")
        provision._require_root()
        provision._deadline(self._deadline)

    @property
    def root(self):
        self._live()
        return self._path / "root"

    @property
    def root_fd(self):
        self._live()
        return self._root_fd

    @property
    def deadline(self):
        self._live()
        return self._deadline

    @property
    def binding(self):
        self._live()
        return _copy(self._binding)

    @property
    def receipt(self):
        self._live()
        return _copy(self._receipt)

    @property
    def observation(self):
        self._live()
        return _copy(self._observation)

    def guard(self, *, deadline=None):
        # Full rehashes do not promise to fit a short egress permit. Callers must
        # retain their original tighter deadline; this lease never widens it.
        self._live()
        bounded = self._deadline if deadline is None else deadline
        provision._deadline(bounded)
        _require(bounded <= self._deadline, "service guard deadline cannot extend the held budget")
        _chain_guard(self._path, self._chain, self._identities, bounded)
        deployment = self._chain[-1]
        provision._owner(deployment, 0o755, directory=True)
        _exact_names(deployment, {"root", RECEIPT}, bounded)
        for fd, name, expected in ((self._root_fd, "root", self._root_identity),
                                    (self._receipt_fd, RECEIPT, self._receipt_identity)):
            _require(provision._identity(os.fstat(fd)) == expected == provision._identity(
                os.stat(name, dir_fd=deployment, follow_symlinks=False)), "held service member custody changed")
        provision._owner(self._receipt_fd, 0o444, directory=False)
        provision._deadline(bounded)
        os.lseek(self._receipt_fd, 0, os.SEEK_SET)
        raw = canonical_json(self._receipt)
        _require(os.read(self._receipt_fd, len(raw) + 1) == raw, "held service receipt bytes changed")
        provision._deadline(bounded)
        _tree(self._root_fd, self._manifest, bounded, protected=True)
        _chain_guard(self._path, self._chain, self._identities, bounded)
        _require(provision._identity(os.fstat(self._receipt_fd)) == self._receipt_identity,
                 "held service receipt changed during guard")
        provision._deadline(bounded)


@contextmanager
def hold_pi_service_runtime(deployment_path, *, receipt_digest, manifest, manifest_digest,
                            runtime_binding, runtime_binding_digest, deadline):
    """Open/measure actual installed bytes against caller-held independent pins.

    The borrowed root descriptor must not be closed by callers. Every guard and
    successful exit rehashes the declared tree; no JSON receipt mints this lease.
    """
    fds, held = [], None
    try:
        provision._require_root()
        provision._deadline(deadline)
        pinned, binding = validate_service_runtime_inputs(manifest, manifest_digest, runtime_binding, runtime_binding_digest)
        _require(type(receipt_digest) is str and provision._DIGEST.fullmatch(receipt_digest), "invalid service receipt pin")
        chain = _open_chain(deployment_path, deadline)
        fds.extend(chain)
        deployment = chain[-1]
        provision._owner(deployment, 0o755, directory=True)
        _exact_names(deployment, {"root", RECEIPT}, deadline)
        root = os.open("root", provision._DIRECTORY, dir_fd=deployment)
        fds.append(root)
        descriptor = os.open(RECEIPT, provision._FILE, dir_fd=deployment)
        fds.append(descriptor)
        provision._owner(descriptor, 0o444, directory=False)
        expected = _receipt(deployment_path / "root", manifest_digest, binding, runtime_binding_digest)
        _require(canonical_digest(expected) == receipt_digest and os.fstat(descriptor).st_size == len(canonical_json(expected)),
                 "installed service receipt disagrees with independent pins")
        held = PiServiceRuntime(_SEAL, deployment_path, chain, root, descriptor, pinned, binding, expected, deadline)
        held.guard()
        yield held
        held.guard()
    finally:
        if held is not None:
            held._active = False
        provision._close_all(list(reversed(fds)))
