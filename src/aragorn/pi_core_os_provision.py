"""Absent-only installation of reviewed Pi OS and compiled-runtime closures.

No distro selection, package resolution, extraction, target execution, mount,
service activation or rollback occurs here. Inputs must already be materialized
regular-file trees with independently reviewed exact pins. Partial destinations
are retained on every failure and cannot be retried or repaired by this API.
"""

from __future__ import annotations

import hashlib
import json
import math
import os
from pathlib import Path
import re
import stat
import sys
import time
from collections.abc import Mapping

from . import pi_core_confined_launch as confined
from . import runtime_active_skill_lineage as lineage
from .acquire import inventory_open_directory
from .oci_worker_protocol import canonical_digest, canonical_json

_ROOT_UID = 0
_ROOT_GID = 0
_DIRECTORY = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
_FILE = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC
_NAME = re.compile(r"[a-z0-9][a-z0-9._-]{0,127}\Z")
_DIGEST = re.compile(r"sha256:[a-f0-9]{64}\Z")
_EMPTY_MOUNTS = frozenset({"dev", "proc", "sys", "tmp", "var/tmp", "run/aragorn-pi-bootstrap",
                          "opt/aragorn/pi-runtime", "var/lib/aragorn/admitted"})
_LIMITS = dict(max_depth=32, max_files=30_000, max_file_size=256 * 1024 * 1024,
               max_total_bytes=512 * 1024 * 1024)


class PiOsProvisionError(RuntimeError):
    """Failure may retain partial files; it does not authorize cleanup or retry."""


def _require(value: bool, reason: str) -> None:
    if not value:
        raise PiOsProvisionError(reason)


def _require_root() -> None:
    _require(sys.platform == "linux" and os.geteuid() == _ROOT_UID and os.getegid() == _ROOT_GID,
             "Pi provisioning requires the protected Linux root supervisor")


def _deadline(deadline: float) -> None:
    now = time.monotonic()
    _require(type(deadline) in (float, int) and math.isfinite(deadline) and now < deadline <= now + 600,
             "Pi provisioning original deadline is expired or invalid")


def _relative(value: object) -> str:
    _require(type(value) is str and bool(value) and len(value) <= 4096 and
             all(part not in ("", ".", "..") for part in value.split("/")) and
             "\\" not in value and not any(ord(char) < 32 for char in value), "unsafe closure path")
    return value


def _parents(path: str) -> set[str]:
    parts = path.split("/")
    return {"/".join(parts[:index]) for index in range(1, len(parts))}


def _manifest(value: Mapping, expected_digest: str) -> dict:
    _require(type(expected_digest) is str and _DIGEST.fullmatch(expected_digest) is not None,
             "invalid expected source closure digest")
    raw = canonical_json(value)
    _require(len(raw) <= 8 * 1024 * 1024, "source closure document exceeds bound")
    result = json.loads(raw)
    _require(canonical_digest(result) == expected_digest, "reviewed OS manifest pin mismatch")
    _require(set(result) == {"schema", "files", "directories"} and
             result["schema"] == "aragorn/pi-core-protected-tree/v1", "unsupported protected tree manifest")
    files, directories = result["files"], result["directories"]
    _require(type(files) is list and type(directories) is list and files and
             len(files) + len(directories) <= _LIMITS["max_files"], "invalid closure inventory size")
    names: list[str] = []
    total = 0
    for entry in files:
        _require(type(entry) is dict and set(entry) == {"path", "size", "digest", "executable"},
                 "invalid closure file fields")
        name = _relative(entry["path"])
        _require(len(name.split("/")) <= 33 and type(entry["size"]) is int and
                 0 <= entry["size"] <= _LIMITS["max_file_size"] and
                 type(entry["digest"]) is str and _DIGEST.fullmatch(entry["digest"]) is not None and
                 type(entry["executable"]) is bool, "invalid closure file identity")
        total += entry["size"]
        names.append(name)
    _require(total <= _LIMITS["max_total_bytes"], "source closure byte limit exceeded")
    _require(names == sorted(set(names)), "closure files are duplicated or unsorted")
    for name in directories:
        _relative(name)
        _require(len(name.split("/")) <= 32, "closure directory depth exceeded")
    _require(directories == sorted(set(directories)) and not set(names).intersection(directories),
             "closure directories are duplicated, unsorted or collide with files")
    _require(all(_parents(name).issubset(directories) for name in (*names, *directories)),
             "closure is missing directory parents")
    return result


def _inventory(fd: int) -> dict:
    manifest, directories = inventory_open_directory(fd, **_LIMITS)
    return {"schema": "aragorn/pi-core-protected-tree/v1", "files": manifest["files"],
            "directories": list(directories)}


def _source(path: Path) -> int:
    """Open every source component without following links, including ancestors."""
    _require(isinstance(path, Path), "source path must be a Path")
    _require(path.is_absolute() and path != Path("/") and ".." not in path.parts, "invalid absolute source path")
    descriptor = os.open("/", _DIRECTORY)
    try:
        for name in path.parts[1:]:
            child = os.open(name, _DIRECTORY, dir_fd=descriptor)
            os.close(descriptor)
            descriptor = child
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def _walk(root: int, parts: list[str]) -> int:
    descriptor = os.dup(root)
    try:
        for name in parts:
            child = os.open(name, _DIRECTORY, dir_fd=descriptor)
            os.close(descriptor)
            descriptor = child
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def _identity(value: os.stat_result) -> tuple:
    return (value.st_dev, value.st_ino, value.st_mode, value.st_nlink, value.st_uid,
            value.st_gid, value.st_size, value.st_mtime_ns, value.st_ctime_ns)


def _owner(fd: int, mode: int, *, directory: bool) -> None:
    info = os.fstat(fd)
    _require((stat.S_ISDIR(info.st_mode) if directory else stat.S_ISREG(info.st_mode)) and
             info.st_uid == _ROOT_UID and info.st_gid == _ROOT_GID and
             stat.S_IMODE(info.st_mode) == mode and (directory or info.st_nlink == 1),
             "installed Pi member is not exclusively root-owned with exact mode")


def _new_directory(parent: int, name: str) -> int:
    os.mkdir(name, 0o700, dir_fd=parent)
    descriptor = os.open(name, _DIRECTORY, dir_fd=parent)
    try:
        os.fchown(descriptor, _ROOT_UID, _ROOT_GID)
        os.fchmod(descriptor, 0o700)
        _owner(descriptor, 0o700, directory=True)
        os.fsync(descriptor)
        os.fsync(parent)
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def _write_all(fd: int, raw: bytes, deadline: float) -> None:
    position = 0
    while position < len(raw):
        _deadline(deadline)
        count = os.write(fd, raw[position:])
        _require(count > 0, "Pi provisioning short write")
        position += count


def _close_all(descriptors: list[int]) -> None:
    primary = sys.exception()
    failure = None
    for descriptor in descriptors:
        if descriptor >= 0:
            try:
                os.close(descriptor)
            except BaseException as error:
                failure = failure or error
    if failure is not None:
        error = PiOsProvisionError("Pi provisioning descriptor close failed; preserve all output")
        error.add_note(f"Descriptor close failure: {failure}")
        raise error from (primary if primary is not None else failure)


def _copy_file(source: int, destination: int, entry: dict, deadline: float) -> None:
    parts = entry["path"].split("/")
    source_parent = destination_parent = source_file = output = -1
    try:
        source_parent = _walk(source, parts[:-1])
        destination_parent = _walk(destination, parts[:-1])
        before_path = os.stat(parts[-1], dir_fd=source_parent, follow_symlinks=False)
        source_file = os.open(parts[-1], _FILE, dir_fd=source_parent)
        before = os.fstat(source_file)
        _require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and
                 _identity(before) == _identity(before_path) and before.st_size == entry["size"],
                 "source member changed before copying")
        output = os.open(parts[-1], os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                         0o600, dir_fd=destination_parent)
        os.fchown(output, _ROOT_UID, _ROOT_GID)
        digest = hashlib.sha256()
        size = 0
        while chunk := os.read(source_file, 1024 * 1024):
            _deadline(deadline)
            size += len(chunk)
            _require(size <= entry["size"], "source member grew while copying")
            digest.update(chunk)
            _write_all(output, chunk, deadline)
        _require(size == entry["size"] and "sha256:" + digest.hexdigest() == entry["digest"] and
                 _identity(os.fstat(source_file)) == _identity(before) ==
                 _identity(os.stat(parts[-1], dir_fd=source_parent, follow_symlinks=False)),
                 "source member changed or disagrees with reviewed bytes")
        mode = 0o555 if entry["executable"] else 0o444
        os.fchmod(output, mode)
        _owner(output, mode, directory=False)
        os.fsync(output)
        os.fsync(destination_parent)
    finally:
        _close_all([output, source_file, destination_parent, source_parent])


def _install_tree(source: int, destination: int, manifest: dict, deadline: float) -> None:
    for name in sorted(manifest["directories"], key=lambda item: (item.count("/"), item)):
        _deadline(deadline)
        parts = name.split("/")
        parent = _walk(destination, parts[:-1])
        try:
            child = _new_directory(parent, parts[-1])
            os.close(child)
        finally:
            os.close(parent)
    for entry in manifest["files"]:
        _copy_file(source, destination, entry, deadline)
    for name in sorted(manifest["directories"], key=lambda item: (item.count("/"), item), reverse=True):
        _deadline(deadline)
        child = _walk(destination, name.split("/"))
        try:
            os.fchmod(child, 0o555)
            _owner(child, 0o555, directory=True)
            os.fsync(child)
        finally:
            os.close(child)
    # The existing confined plan requires owner-writable protected ROOTS, while
    # all descendants are immutable. Root remains the trusted provisioning TCB.
    os.fchmod(destination, 0o755)
    _owner(destination, 0o755, directory=True)
    os.fsync(destination)


def provision_pi_os_runtime(*, os_source: Path, os_manifest: Mapping, os_manifest_digest: str,
                            runtime_source: Path, compiled_receipt: Mapping, compiled_receipt_digest: str,
                            destination_parent: Path, deployment_name: str, deadline: float) -> dict:
    """Copy one exact reviewed OS/runtime closure into a NEW protected sibling pair.

    This installs bytes only. Static loader closure provenance must be reviewed
    before supplying the OS pin; a matching manifest is not Linux execution proof.
    Failure attaches ``pi_provisioning_observation`` and preserves every write.
    """
    observation = {"schema": "aragorn/pi-core-provisioning-observation/v1", "created": False,
                   "completed": False, "activation_performed": False, "rollback_performed": False}
    descriptors: list[int] = []
    try:
        _require_root()
        _deadline(deadline)
        _require(type(deployment_name) is str and _NAME.fullmatch(deployment_name) is not None,
                 "invalid deployment destination name")
        _require(isinstance(destination_parent, Path) and destination_parent.is_absolute() and
                 ".." not in destination_parent.parts, "invalid destination parent")
        os_pin = _manifest(os_manifest, os_manifest_digest)
        files = {entry["path"]: entry for entry in os_pin["files"]}
        _require(all(name in files and files[name]["executable"] for name in
                     ("usr/bin/env", "lib/ld-linux-aarch64.so.1")), "OS closure lacks pinned env or arm64 loader")
        names = set(files) | set(os_pin["directories"])
        _require(_EMPTY_MOUNTS.issubset(os_pin["directories"]) and
                 not any(any(name.startswith(mount + "/") for name in names) for mount in _EMPTY_MOUNTS),
                 "OS closure must contain exact empty namespace mountpoints")
        compiled = json.loads(canonical_json(compiled_receipt))
        _require(type(compiled_receipt_digest) is str and _DIGEST.fullmatch(compiled_receipt_digest) is not None,
                 "invalid compiled receipt digest")
        parent = lineage._open_protected_root(destination_parent, _ROOT_UID)
        descriptors.append(parent)
        _require(os.fstat(parent).st_gid == _ROOT_GID, "destination parent is not root-group owned")
        target = destination_parent / deployment_name
        _require(all(not target.is_relative_to(path) and not path.is_relative_to(target)
                     for path in (os_source, runtime_source)) and os_source != runtime_source,
                 "source and destination trees overlap")
        source_os, source_runtime = _source(os_source), -1
        descriptors.append(source_os)
        source_runtime = _source(runtime_source)
        descriptors.append(source_runtime)
        observed_os, observed_runtime = _inventory(source_os), _inventory(source_runtime)
        _require(observed_os == os_pin, "materialized OS source differs from reviewed full closure")
        runtime_digest = confined._runtime_inventory({"files": observed_runtime["files"]}, compiled,
                                                    compiled_receipt_digest)
        runtime_pin = json.loads(canonical_json(observed_runtime))
        runtime_pin["directories"] = sorted(set().union(*(_parents(row["path"]) for row in runtime_pin["files"])))
        _require(runtime_pin["directories"] == observed_runtime["directories"],
                 "compiled runtime contains unbound empty directories")
        for entry in runtime_pin["files"]:
            entry["executable"] = entry["path"] == "node/bin/node"
        _deadline(deadline)
        # mkdir is the exclusive no-replace boundary. Existing partial or complete
        # deployments fail identically; never accept, repair, erase or overwrite.
        observation["created"] = None
        deployment = _new_directory(parent, deployment_name)
        descriptors.append(deployment)
        observation["created"] = True
        observation["destination"] = str(target)
        root = _new_directory(deployment, "os")
        descriptors.append(root)
        runtime = _new_directory(deployment, "runtime")
        descriptors.append(runtime)
        _install_tree(source_os, root, os_pin, deadline)
        _install_tree(source_runtime, runtime, runtime_pin, deadline)
        _require(_inventory(source_os) == observed_os and _inventory(source_runtime) == observed_runtime,
                 "source tree changed during provisioning")
        os_installed, _, os_digest = confined._tree(root)
        runtime_installed, _, runtime_closure = confined._tree(runtime)
        _require(os_digest == os_manifest_digest and _inventory(root) == os_pin and
                 _inventory(runtime) == runtime_pin, "installed closure differs from pinned bytes or modes")
        _require(confined._runtime_inventory(runtime_installed, compiled, compiled_receipt_digest) == runtime_digest,
                 "installed runtime receipt binding changed")
        _owner(root, 0o755, directory=True)
        _owner(runtime, 0o755, directory=True)
        _require((os.fstat(deployment).st_dev, os.fstat(deployment).st_ino) ==
                 (os.stat(deployment_name, dir_fd=parent, follow_symlinks=False).st_dev,
                  os.stat(deployment_name, dir_fd=parent, follow_symlinks=False).st_ino),
                 "deployment destination changed")
        _deadline(deadline)
        receipt = {
            "schema": "aragorn/pi-core-provisioned-runtime/v1",
            "status": "PROVISIONED_EXACT_REVIEWED_CLOSURE_NOT_EXECUTED_OR_OS_QUALIFIED",
            "os_root": str(target / "os"), "os_closure_digest": os_digest,
            "runtime_root": str(target / "runtime"), "runtime_inventory_digest": runtime_digest,
            "runtime_protected_tree_digest": runtime_closure,
            "compiled_receipt_digest": compiled_receipt_digest,
            "runtime_executable_policy": "ONLY_NODE_BIN_NODE_EXECUTABLE_OTHER_RUNTIME_FILES_0444",
            "activation_performed": False, "runtime_executed": False, "phase3_exit_eligible": False,
        }
        raw = canonical_json(receipt)
        receipt_fd = os.open("provision-receipt.json", os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                             0o600, dir_fd=deployment)
        descriptors.append(receipt_fd)
        os.fchown(receipt_fd, _ROOT_UID, _ROOT_GID)
        _write_all(receipt_fd, raw, deadline)
        os.fchmod(receipt_fd, 0o444)
        _owner(receipt_fd, 0o444, directory=False)
        os.fsync(receipt_fd)
        os.lseek(receipt_fd, 0, os.SEEK_SET)
        _require(os.read(receipt_fd, len(raw) + 1) == raw, "provisioning receipt readback mismatch")
        os.fchmod(deployment, 0o755)
        _owner(deployment, 0o755, directory=True)
        os.fsync(deployment)
        os.fsync(parent)
        observation["completed"] = True
        observation["receipt_digest"] = canonical_digest(receipt)
        return receipt
    except BaseException as error:
        error.pi_provisioning_observation = observation
        raise
    finally:
        try:
            _close_all(list(reversed(descriptors)))
        except BaseException as error:
            observation["completed"] = False
            error.pi_provisioning_observation = observation
            raise
