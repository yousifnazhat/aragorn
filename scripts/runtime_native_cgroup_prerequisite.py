"""Read-only PID-controller prerequisites for one owned Docker/systemd fixture."""

from __future__ import annotations

import os
import re
import sys
from pathlib import Path

_SOURCE = "scripts/runtime_native_cgroup_prerequisite.py"
_ROOT = Path("/sys/fs/cgroup")
_WORKER = "aragorn-runtime-action-worker.service"
_INTERFACES = (
    "cgroup.controllers",
    "cgroup.subtree_control",
    "cgroup.type",
    "pids.current",
    "pids.max",
    "pids.events",
)


def _read(descriptor: int, name: str) -> str | list[str]:
    fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=descriptor)
    try:
        raw = os.read(fd, 513)
    finally:
        os.close(fd)
    if len(raw) > 512 or not raw.endswith(b"\n"):
        raise ValueError("invalid cgroup interface length")
    value = raw.decode("ascii").strip()
    if name in {"cgroup.controllers", "cgroup.subtree_control"}:
        controllers = value.split()
        if len(set(controllers)) != len(controllers) or any(
            re.fullmatch(r"[a-z_]{1,32}", item) is None for item in controllers
        ):
            raise ValueError("invalid controller list")
        return sorted(controllers)
    patterns = {
        "cgroup.type": r"(?:domain|threaded|domain threaded|domain \(invalid\))",
        "pids.current": r"[0-9]{1,20}",
        "pids.max": r"(?:max|[0-9]{1,20})",
        "pids.events": r"max [0-9]{1,20}",
    }
    if re.fullmatch(patterns[name], value) is None:
        raise ValueError("invalid cgroup interface")
    return value


def _node(path: Path) -> dict:
    result = {"status": "READ", "interfaces": {}, "unavailable": {}}
    try:
        if path.resolve(strict=True) != path:
            return {"status": "UNSAFE_PATH"}
        fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    except FileNotFoundError:
        return {"status": "ABSENT"}
    except OSError:
        return {"status": "UNREADABLE"}
    try:
        identity = os.fstat(fd)
        result["identity"] = {"device": identity.st_dev, "inode": identity.st_ino}
        for name in _INTERFACES:
            try:
                result["interfaces"][name] = _read(fd, name)
            except FileNotFoundError:
                result["unavailable"][name] = "ABSENT"
            except (ValueError, UnicodeError):
                result["unavailable"][name] = "MALFORMED"
            except OSError:
                result["unavailable"][name] = "UNREADABLE"
        try:
            after = path.stat(follow_symlinks=False)
            if (after.st_dev, after.st_ino) != (identity.st_dev, identity.st_ino):
                result["status"] = "CHANGED"
        except OSError:
            result["status"] = "CHANGED"
    finally:
        os.close(fd)
    return result


def _snapshot(root: Path, container: str, *, after_activation: bool) -> dict:
    owned = "/docker/" + container
    paths = (
        "/",
        "/docker",
        owned,
        owned + "/system.slice",
        owned + "/system.slice/" + _WORKER,
    )
    hierarchy = {name: _node(root / name.lstrip("/")) for name in paths}
    failures = []
    # Docker/host ancestors must already make pids available to the container.
    # Inside the owned container, systemd may enable its descendants on demand.
    required = paths if after_activation else paths[:3]
    for index, name in enumerate(required):
        node = hierarchy[name]
        if node["status"] != "READ":
            failures.append({"path": name, "reason": "CGROUP_" + node["status"]})
            continue
        interfaces = node["interfaces"]
        if "pids" not in interfaces.get("cgroup.controllers", []):
            failures.append({"path": name, "reason": "PIDS_CONTROLLER_UNAVAILABLE"})
        if index < len(required) - 1 and "pids" not in interfaces.get(
            "cgroup.subtree_control", []
        ):
            failures.append({"path": name, "reason": "PIDS_NOT_ENABLED_FOR_CHILD"})
        if index and any(
            key not in interfaces for key in ("pids.current", "pids.max", "pids.events")
        ):
            failures.append({"path": name, "reason": "PIDS_INTERFACE_UNAVAILABLE"})
    return {
        "schema": "aragorn/native-cgroup-prerequisite-observation/v1",
        "authority": "OWNED_READ_ONLY_PREREQUISITES_NOT_STARTUP_RELIABILITY_OR_PHASE3_CONFORMANCE",
        "status": "REFUSED" if failures else "READY",
        "phase": "AFTER_ACTIVATION" if after_activation else "BEFORE_ACTIVATION",
        "fixture_container": container,
        "hierarchy": hierarchy,
        "failures": failures,
        "controller_configuration_changed": False,
        "retry_performed": False,
    }


def observe(container: str, *, after_activation: bool = False) -> dict:
    if (
        type(container) is not str
        or re.fullmatch(r"[0-9a-f]{64}", container) is None
        or type(after_activation) is not bool
        or sys.platform != "linux"
        or os.geteuid() != 0
    ):
        raise RuntimeError("cgroup preflight requires the owned root Linux fixture")
    with Path("/proc/1/cgroup").open("rb") as stream:
        identity = stream.read(1025)
    if identity != ("0::/docker/" + container + "/init.scope\n").encode("ascii"):
        raise RuntimeError("cgroup preflight fixture identity changed")
    return _snapshot(_ROOT, container, after_activation=after_activation)
