"""Read-only preparation of installed Pi source identities; no launch authority.

The caller supplies two already-held installed views and independently pinned
content intent. This module neither assembles a filesystem view nor discovers
what ought to be trusted from it. Importing it performs no filesystem operation.
"""

from __future__ import annotations

from dataclasses import dataclass
import os
from pathlib import PurePosixPath
import platform
import stat

from . import pi_core_node_source_observer as node
from . import pi_core_source_observer as base
from . import pi_core_os_provision as provision
from .pi_core_source_observation_verify import _document, _fields, _identity, _pin


PLAN_SCHEMA = "aragorn/pi-core-source-plan/v1"
RECEIPT_SCHEMA = "aragorn/pi-core-source-inventory-preparation/v1"
AUTHORITY = "INSTALLED_VIEW_PREPARATION_ONLY_NOT_SOURCE_CONSUMPTION_HEALTH_OR_LAUNCH"
_CODE_PINS = {"gate_digest", "node_digest", "producer_digest", "node_observer_digest"}
_DIRECTORY_FLAGS = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
_FILE_FLAGS = os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK


class PiSourceInventoryPreparationError(ValueError):
    """No profile is returned after a failed or ambiguous preparation."""

    def __init__(self, message, *, held_fds=(), ambiguous_fds=()):
        super().__init__(message)
        self.held_fds = tuple(held_fds)
        self.ambiguous_fds = tuple(ambiguous_fds)


@dataclass(frozen=True, slots=True)
class PreparedPiSourceInventories:
    source_inventory_raw: bytes
    loader_inventory_raw: bytes
    profile_raw: bytes
    preparation_raw: bytes


def _require(value, reason):
    if not value:
        raise PiSourceInventoryPreparationError(reason)


def _path(value):
    _require(type(value) is str and value.startswith("/") and len(value) <= 4096 and
             not any(part in {"", ".", ".."} for part in value.split("/")[1:]) and
             not any(ord(char) < 32 or ord(char) == 127 for char in value), "SOURCE_PLAN_PATH")
    return value


def _plan(raw, pin):
    _pin(pin)
    value = _document(raw)
    _require(base.canonical_digest(value) == pin, "SOURCE_PLAN_PIN")
    _fields(value, {"schema", "pins", "sources", "required_sources", "loader_files"})
    _require(value["schema"] == PLAN_SCHEMA, "SOURCE_PLAN_SCHEMA")
    _fields(value["pins"], _CODE_PINS)
    for digest in value["pins"].values():
        _pin(digest)
    paths = {}
    for role in ("sources", "loader_files"):
        rows = value[role]
        _require(type(rows) is list and 0 < len(rows) <= 512, "SOURCE_PLAN_INVENTORY_BOUND")
        selected = set()
        for row in rows:
            _fields(row, {"path", "digest"})
            path = _path(row["path"])
            _pin(row["digest"])
            _require(path not in selected, "SOURCE_PLAN_DUPLICATE_PATH")
            selected.add(path)
        paths[role] = selected
    required = value["required_sources"]
    _require(type(required) is list and required and all(type(path) is str for path in required) and
             len(required) == len(set(required)) and set(required) <= paths["sources"], "SOURCE_PLAN_REQUIRED_SUBSET")
    _require(not paths["sources"] & paths["loader_files"], "SOURCE_PLAN_ROLE_ALIAS")
    fixed = {str(base.GATE_PATH): "gate_digest", str(base.NODE_PATH): "node_digest"}
    for row in value["sources"] + value["loader_files"]:
        if row["path"] in fixed:
            _require(row["digest"] == value["pins"][fixed[row["path"]]], "SOURCE_PLAN_FIXED_CODE_CONFLICT")
    return value


def _directory(fd, *, readonly):
    info = os.fstat(fd)
    _require(stat.S_ISDIR(info.st_mode) and info.st_uid == info.st_gid == 0 and
             not info.st_mode & 0o7022 and info.st_nlink > 0, "SOURCE_VIEW_DIRECTORY")
    if readonly:
        _require(os.fstatvfs(fd).f_flag & os.ST_RDONLY, "SOURCE_VIEW_NOT_READONLY")
    return base._file_identity(info)


def prepare_pi_source_inventories(expected_manifest_raw: bytes, *, expected_manifest_digest: str,
        worker_root_fd: int, expected_worker_root_identity: dict,
        observer_root_fd: int, expected_observer_root_identity: dict,
        deadline: float) -> PreparedPiSourceInventories:
    """Prepare metadata from protected installed views without starting anything.

    Root descriptors are borrowed, never closed here. The caller must already
    hold and independently identify the exact completed worker-view root and
    the observer/controller root. A writable staging image is not an installed
    read-only view. The reviewed manifest's source/loader blobs must separately
    remain retained in the evidence CAS; returned records do not supply them.

    The original bounded provisioning deadline is mandatory. This function
    returns immutable canonical bytes only after closing its own descriptors.
    It never changes modes, mounts views, launches a process, invokes ptrace,
    creates services or invents future file identities.
    """
    held, ambiguous = [], []
    failure = None
    result = None
    try:
        # Pin and validate intent before even examining a caller descriptor.
        plan = _plan(expected_manifest_raw, expected_manifest_digest)
        provision._deadline(deadline)
        _require(platform.system() == "Linux" and platform.machine() in {"arm64", "aarch64"} and
                 os.getuid() == os.geteuid() == os.getgid() == os.getegid() == 0, "SOURCE_VIEW_LINUX_ARM64_ROOT")
        _require(type(worker_root_fd) is int and worker_root_fd >= 0 and
                 type(observer_root_fd) is int and observer_root_fd >= 0, "SOURCE_VIEW_DESCRIPTOR")
        roots = {}
        directories = []
        files = {}
        objects = {}
        expected_roots = {"worker": dict(_identity(expected_worker_root_identity)),
                          "observer": dict(_identity(expected_observer_root_identity))}

        def check_budget():
            provision._deadline(deadline)

        for role, borrowed in (("worker", worker_root_fd), ("observer", observer_root_fd)):
            expected = expected_roots[role]
            check_budget()
            descriptor = os.dup(borrowed)
            held.append(descriptor)
            observed = _directory(descriptor, readonly=role == "worker")
            _require(observed == expected and _directory(borrowed, readonly=role == "worker") == expected,
                     "SOURCE_VIEW_ROOT_IDENTITY")
            roots[role] = (descriptor, borrowed, expected)
            directories.append((role, descriptor, None, None, expected))
        directory_cache = {(role, ()): value[0] for role, value in roots.items()}

        def open_file(role, path):
            parts = PurePosixPath(_path(path)).parts[1:]
            _require(len(parts) <= 64, "SOURCE_VIEW_PATH_DEPTH")
            parent = roots[role][0]
            prefix = ()
            for name in parts[:-1]:
                check_budget()
                prefix += (name,)
                key = role, prefix
                if key not in directory_cache:
                    before = os.stat(name, dir_fd=parent, follow_symlinks=False)
                    descriptor = os.open(name, _DIRECTORY_FLAGS, dir_fd=parent)
                    held.append(descriptor)
                    observed = _directory(descriptor, readonly=role == "worker")
                    _require(base._file_identity(before) == observed, "SOURCE_VIEW_ANCESTRY_RACE")
                    directories.append((role, descriptor, parent, name, observed))
                    directory_cache[key] = descriptor
                parent = directory_cache[key]
            check_budget()
            before = os.stat(parts[-1], dir_fd=parent, follow_symlinks=False)
            descriptor = os.open(parts[-1], _FILE_FLAGS, dir_fd=parent)
            held.append(descriptor)
            _require(base._file_identity(before) == base._file_identity(os.fstat(descriptor)), "SOURCE_VIEW_LEAF_RACE")
            return descriptor, parent, parts[-1]

        def observe(role, path, pin, maximum):
            key = role, path
            if key in files:
                record = files[key]
                _require(record["digest"] == pin, "SOURCE_VIEW_ROLE_PIN_CONFLICT")
                return record
            descriptor, parent, name = open_file(role, path)
            check_budget()
            digest, metadata = (node._hash_readonly(descriptor, deadline, maximum) if role == "worker"
                                else base._hash(descriptor, deadline, maximum))
            _require(digest == pin, "SOURCE_VIEW_CONTENT_PIN")
            object_id = metadata["device"], metadata["inode"]
            _require(object_id not in objects, "SOURCE_VIEW_CODE_OR_FILE_ALIAS")
            objects[object_id] = key
            record = dict(fd=descriptor, parent=parent, name=name, digest=digest, identity=metadata, maximum=maximum)
            files[key] = record
            return record

        code = []
        for role, path, pin_name, maximum in (
                ("worker", str(base.GATE_PATH), "gate_digest", base.process._MAX_EXECUTABLE_BYTES),
                ("worker", str(base.NODE_PATH), "node_digest", base.process._MAX_EXECUTABLE_BYTES),
                ("observer", str(base.PRODUCER_PATH), "producer_digest", base.MAX_FILE),
                ("observer", str(node.ORIGIN), "node_observer_digest", base.MAX_FILE)):
            observed = observe(role, path, plan["pins"][pin_name], maximum)
            code.append(dict(view=role, path=path, digest=observed["digest"], identity=observed["identity"],
                             protection="ROOT_OWNED_READONLY_VIEW" if role == "worker" else "ROOT_OWNED_NO_WRITE_BITS"))

        source_rows, loader_rows, identities = [], [], set()
        for field, output, maximum in (("sources", source_rows, base.MAX_FILE),
                                       ("loader_files", loader_rows, base.process._MAX_EXECUTABLE_BYTES)):
            for row in sorted(plan[field], key=lambda row: row["path"]):
                observed = observe("worker", row["path"], row["digest"], maximum)
                _require(observed["identity"]["size"] <= maximum, "SOURCE_VIEW_ROLE_SIZE")
                identity = observed["identity"]["device"], observed["identity"]["inode"]
                _require(identity not in identities, "SOURCE_VIEW_FILE_ALIAS")
                identities.add(identity)
                output.append(dict(row, identity=observed["identity"], readonly_view=True))

        # Held and named objects must still describe one snapshot. This is
        # readback of caller-selected objects, not adoption of replacements.
        for role, descriptor, parent, name, expected in directories:
            check_budget()
            _require(_directory(descriptor, readonly=role == "worker") == expected, "SOURCE_VIEW_DIRECTORY_CHANGED")
            if parent is not None:
                _require(base._file_identity(os.stat(name, dir_fd=parent, follow_symlinks=False)) == expected,
                         "SOURCE_VIEW_ANCESTRY_CHANGED")
        for role, (descriptor, borrowed, expected) in roots.items():
            _require(_directory(borrowed, readonly=role == "worker") == expected, "SOURCE_VIEW_BORROWED_ROOT_CHANGED")
        for (role, path), row in files.items():
            check_budget()
            actual = (node._readonly(row["fd"], row["maximum"]) if role == "worker"
                      else base._protected_file(row["fd"], row["maximum"]))
            _require(actual == row["identity"] and
                     base._file_identity(os.stat(row["name"], dir_fd=row["parent"], follow_symlinks=False)) == actual,
                     "SOURCE_VIEW_FILE_CHANGED")

        source_raw = base.canonical_json(dict(schema=node.SOURCE_SCHEMA, sources=source_rows))
        loader_raw = base.canonical_json(dict(schema=node.LOADER_SCHEMA, loaders=loader_rows))
        profile = dict(schema=node.PROFILE_SCHEMA,
            pins={**plan["pins"], "source_inventory_digest": base.canonical_digest(_document(source_raw)),
                  "loader_inventory_digest": base.canonical_digest(_document(loader_raw))},
            sources=plan["sources"], required_sources=plan["required_sources"], loader_files=plan["loader_files"])
        profile_raw = base.canonical_json(node.validate_node_profile(profile))
        receipt = dict(schema=RECEIPT_SCHEMA, authority=AUTHORITY, phase3_exit_eligible=False,
            expected_manifest_digest=expected_manifest_digest, profile_digest=base.canonical_digest(profile),
            source_inventory_digest=profile["pins"]["source_inventory_digest"],
            loader_inventory_digest=profile["pins"]["loader_inventory_digest"],
            worker_root_identity=roots["worker"][2], observer_root_identity=roots["observer"][2], code=code,
            source_files=len(source_rows), loader_files=len(loader_rows))
        preparation_raw = base.canonical_json(receipt)
        _require(all(0 < len(raw) <= base.MAX_RAW for raw in (source_raw, loader_raw, profile_raw, preparation_raw)),
                 "SOURCE_PREPARATION_OUTPUT_BOUND")
        check_budget()
        result = PreparedPiSourceInventories(source_raw, loader_raw, profile_raw, preparation_raw)
    except BaseException as error:
        failure = error
    finally:
        # Only our duplicates/opened descriptors are closed, exactly once.
        # Ambiguous closes retain explicit custody and never trigger a retry.
        for descriptor in reversed(held.copy()):
            try:
                os.close(descriptor)
                held.remove(descriptor)
            except OSError:
                ambiguous.append(descriptor)
    if failure is not None or ambiguous:
        raise PiSourceInventoryPreparationError(
            "SOURCE_PREPARATION_CLOSE_AMBIGUOUS_NO_RETRY" if ambiguous else str(failure),
            held_fds=held, ambiguous_fds=ambiguous) from failure
    return result
